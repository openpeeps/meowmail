# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

import std/[posix, options, os, times]

import pkg/flysystem
import ../imap/mailstore

## This module implements the SMTP delivery logic for MeowMail. It defines the
## `SMTPDelivery` type, which is responsible for handling message deliveries, either
## by delivering locally into a Maildir store, by spooling messages to disk, or
## by using a custom delivery provider.
## 
## The module also defines the `DeliveryRequest` type, which encapsulates the
## information about a message that needs to be delivered, including the envelope sender,
## recipients, message data, and HELO name. The `DeliveryDecision` type is an enum that
## indicates the result of a delivery attempt, such as success, temporary failure, or
## permanent failure.

type
  DeliveryDecision* = enum
    ddOk, ddTempFail, ddPermFail

  RcptFailure* = object
    rcpt*: string
      ## The recipient address rejected by the remote host.
    permanent*: bool
      ## true = 5xx at RCPT TO; false = temporary 4xx rejection.

  DeliveryOutcome* = object
    decision*: DeliveryDecision
      ## Overall transaction result for this delivery request.
    failedRcpts*: seq[RcptFailure]
      ## Recipients the remote host rejected while others were accepted
      ## (partial acceptance). Empty on whole-request failures.

proc okOutcome*(decision = ddOk, failed: seq[RcptFailure] = @[]): DeliveryOutcome {.inline.} =
  DeliveryOutcome(decision: decision, failedRcpts: failed)

func isOk*(o: DeliveryOutcome): bool {.inline.} =
  o.decision == ddOk

type
  DeliveryRequest* = object
    mailFrom*: string
      ## The envelope sender address specified in the MAIL FROM command.
    rcptTo*: seq[string]
      ## The list of recipient addresses specified in the RCPT TO commands
    data*: string
      ## The raw message data received after the DATA command, including headers and body
    heloName*: string
      ## The HELO/EHLO name provided by the client during the SMTP session.
      ## This can be useful for making delivery decisions based on the
      ## client's identity or for logging purposes

  DeliveryProvider* = proc(req: DeliveryRequest): DeliveryOutcome {.gcsafe.}

  SMTPDelivery* = ref object
    deliveryProvider*: DeliveryProvider
      ## Optional custom delivery provider. If set, this provider will be used to handle
      ## message deliveries. If not set, messages will be spooled to disk by default
    spoolDir*: Option[string]
      ## Optional directory path where messages will be spooled
      ## if no delivery provider is configured. If not set, a
      ## default temporary directory will be used
    spoolStore*: StorageDriver
      ## Flysystem-backed storage for the spool directory (atomic writes,
      ## traversal-safe paths). Created eagerly for the resolved spool dir.
    localStore*: MaildirStore
      ## Optional Maildir store. When set, recipients in `localStore.localDomains`
      ## are delivered directly into their per-user Maildir instead of being
      ## spooled or MX-delivered.

var spoolSeq {.threadvar.}: uint64

proc defaultSpoolDir*(smtpd: SMTPDelivery): string =
  ## Returns the default spool directory path. This is used when no
  ## custom spool directory is configured.
  result = getTempDir() / "meowmail-spool"

proc newSMTPDelivery*(spoolDir: Option[string],
                provider: DeliveryProvider = nil,
                localStore: MaildirStore = nil): SMTPDelivery =
  ## Creates a new SMTPDelivery instance with the
  ## specified spool directory and delivery provider
  new(result)
  result.deliveryProvider = provider
  result.spoolDir = spoolDir
  result.spoolStore = newLocalDriver(
    (if spoolDir.isSome: spoolDir.get else: result.defaultSpoolDir()))
  result.localStore = localStore

proc spoolDeliver*(smtpd: SMTPDelivery, req: DeliveryRequest): DeliveryOutcome =
  ## Spools the message to disk in the configured spool directory.
  ## The message is saved in a simple format with envelope information
  ## in custom headers and the raw message data following a blank line.
  ## Writes go through the flysystem driver (temp file + rename) so a crash
  ## mid-write never leaves a partially written message behind.
  inc spoolSeq # increment the spool sequence number for unique filenames
  let tsMs = int64(epochTime() * 1000.0) # current timestamp in milliseconds
  let fileName = $tsMs & "-" & $getpid() & "-" & $spoolSeq & ".eml"

  var payload: string
  payload.add("X-MeowMail-Envelope-From: " & req.mailFrom & "\r\n")
  for rcpt in req.rcptTo:
    payload.add("X-MeowMail-Envelope-To: " & rcpt & "\r\n")
  if req.heloName.len > 0:
    payload.add("X-MeowMail-Helo: " & req.heloName & "\r\n")
  payload.add("\r\n")
  payload.add(req.data)

  try:
    {.cast(gcsafe).}:
      smtpd.spoolStore.write(fileName, payload)
    okOutcome()
  except CatchableError:
    okOutcome(ddTempFail)

proc deliverMessage*(smtpd: SMTPDelivery, req: DeliveryRequest): DeliveryOutcome =
  ## Delivers a message using local Maildir delivery (for local recipients),
  ## a custom delivery provider, or by spooling to disk.
  if smtpd.localStore != nil:
    # Route local recipients into their Maildir; hand the rest to the
    # provider / spool.
    var remote = DeliveryRequest(mailFrom: req.mailFrom, heloName: req.heloName, data: req.data)
    var sawLocal = false
    for rcpt in req.rcptTo:
      if smtpd.localStore.isLocal(rcpt):
        sawLocal = true
        if not smtpd.localStore.deliver(req.mailFrom, rcpt, req.data):
          return okOutcome(ddTempFail)
      else:
        remote.rcptTo.add(rcpt)
    if remote.rcptTo.len == 0:
      return okOutcome()
    if smtpd.deliveryProvider != nil:
      return smtpd.deliveryProvider(remote)
    return smtpd.spoolDeliver(remote)
  if smtpd.deliveryProvider != nil:
    return smtpd.deliveryProvider(req)
  smtpd.spoolDeliver(req)

proc setProvider*(smtpd: var SMTPDelivery, provider: DeliveryProvider) =
  ## Sets the delivery provider for the SMTP server. This provider
  ## will be used to handle message deliveries. If not set,
  ## messages will be spooled to disk by default.
  smtpd.deliveryProvider = provider

proc setSpoolDir*(smtpd: var SMTPDelivery, spoolDir: string) =
  ## Sets the directory where messages will be spooled if no delivery
  ## provider is configured. If not set, a default temporary directory will be used.
  smtpd.spoolDir =
    if spoolDir.len > 0: some(spoolDir)
    else: none(string)
  smtpd.spoolStore = newLocalDriver(
    (if smtpd.spoolDir.isSome: smtpd.spoolDir.get else: smtpd.defaultSpoolDir()))
