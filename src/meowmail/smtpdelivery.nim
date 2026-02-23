# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

import std/[posix, options, os, times]

## This module implements the SMTP delivery logic for MeowMail. It defines the
## `SMTPDelivery` type, which is responsible for handling message deliveries, either
## by spooling messages to disk or by using a custom delivery provider.
## 
## The module also defines the `DeliveryRequest` type, which encapsulates the
## information about a message that needs to be delivered, including the envelope sender,
## recipients, message data, and HELO name. The `DeliveryDecision` type is an enum that
## indicates the result of a delivery attempt, such as success, temporary failure, or
## permanent failure.

type
  DeliveryDecision* = enum
    ddOk, ddTempFail, ddPermFail

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

  DeliveryProvider* = proc(req: DeliveryRequest): DeliveryDecision {.gcsafe.}

  SMTPDelivery* = ref object
    deliveryProvider*: DeliveryProvider
      ## Optional custom delivery provider. If set, this provider will be used to handle
      ## message deliveries. If not set, messages will be spooled to disk by default
    spoolDir*: Option[string]
      ## Optional directory path where messages will be spooled
      ## if no delivery provider is configured. If not set, a
      ## default temporary directory will be used

var spoolSeq {.threadvar.}: uint64

proc newSMTPDelivery*(spoolDir: Option[string],
                provider: DeliveryProvider = nil): SMTPDelivery =
  ## Creates a new SMTPDelivery instance with the
  ## specified spool directory and delivery provider
  new(result)
  result.deliveryProvider = provider
  result.spoolDir = spoolDir

proc defaultSpoolDir*(smtpd: SMTPDelivery): string =
  ## Returns the default spool directory path. This is used when no
  ## custom spool directory is configured.
  result = getTempDir() / "meowmail-spool"

proc spoolDeliver*(smtpd: SMTPDelivery, req: DeliveryRequest): DeliveryDecision =
  ## Spools the message to disk in the configured spool directory.
  ## The message is saved in a simple format with envelope information
  ## in custom headers and the raw message data following a blank line.
  ## The filename is generated using a timestamp, process ID, and a sequence
  ## number to ensure uniqueness
  let dir =
    if smtpd.spoolDir.isSome: smtpd.spoolDir.get
    else: smtpd.defaultSpoolDir()
  
  try:
    # ensure the spool directory exists, creating it if necessary
    discard existsOrCreateDir(dir)
  except CatchableError:
    return ddTempFail

  inc spoolSeq # increment the spool sequence number for unique filenames
  let tsMs = int64(epochTime() * 1000.0) # current timestamp in milliseconds
  let fileName = $tsMs & "-" & $getpid() & "-" & $spoolSeq & ".eml"
  let path = dir / fileName # full path to the spooled message file

  var payload: string
  payload.add("X-MeowMail-Envelope-From: " & req.mailFrom & "\r\n")
  for rcpt in req.rcptTo:
    payload.add("X-MeowMail-Envelope-To: " & rcpt & "\r\n")
  if req.heloName.len > 0:
    payload.add("X-MeowMail-Helo: " & req.heloName & "\r\n")
  payload.add("\r\n")
  payload.add(req.data)

  try:
    writeFile(path, payload)
    ddOk
  except CatchableError:
    ddTempFail

proc deliverMessage*(smtpd: SMTPDelivery, req: DeliveryRequest): DeliveryDecision =
  ## Delivers a message using the configured delivery
  ## provider or by spooling to disk if no provider is set.
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
  smtpd.spoolDir = (if spoolDir.len > 0: some(spoolDir) else: none(string))
