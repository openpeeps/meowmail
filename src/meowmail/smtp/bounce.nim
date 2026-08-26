## MeowMail — DSN (Delivery Status Notification) bounce generation (RFC 3461).
##
## Generates bounce messages when delivery fails permanently.
## Bounces are delivered to the original sender's MAIL FROM address.

import std/[strutils, times, os, monotimes]
import ./smtpdelivery
import ../imap/mailstore

type
  DsnStatus* = enum
    dsnDelivered       ## 2.0.0
    dsnDelayed         ## 4.0.0
    dsnRejected        ## 5.0.0
    dsnFailed          ## 5.1.x
    dsnBadDestination  ## 5.1.x
    dsnMailboxFull     ## 4.2.x
    dsnMessageExpired  ## 4.4.x

proc dsnCode(status: DsnStatus): string =
  case status
  of dsnDelivered: "2.0.0"
  of dsnDelayed: "4.0.0"
  of dsnRejected: "5.0.0"
  of dsnFailed: "5.1.1"
  of dsnBadDestination: "5.1.0"
  of dsnMailboxFull: "4.2.2"
  of dsnMessageExpired: "4.4.7"

proc dsnText(status: DsnStatus): string =
  case status
  of dsnDelivered: "Delivery successful"
  of dsnDelayed: "Delivery temporarily delayed"
  of dsnRejected: "Delivery rejected"
  of dsnFailed: "Delivery failed"
  of dsnBadDestination: "Bad destination mailbox address"
  of dsnMailboxFull: "Mailbox full"
  of dsnMessageExpired: "Message expired"

proc generateBounce*(originalFrom, originalTo, heloName: string,
                     status: DsnStatus, diag: string = ""): (string, string) =
  ## Generate a DSN bounce message. Returns (bounceRecipient, bounceBody).
  ##
  ## The bounce is sent to the original MAIL FROM address (the "return-path").
  ## If the original sender is empty (bounce address) or a postmaster, no
  ## bounce is generated (avoids loops).

  # Don't bounce to empty sender or to postmaster (loop prevention)
  let returnPath = originalFrom.strip().strip(chars = {'<', '>'})
  if returnPath.len == 0 or returnPath.toLowerAscii.contains("postmaster"):
    return ("", "")

  let now = now().utc()
  let dateStr = now.format("ddd, dd MMM yyyy HH:mm:ss") & " GMT"
  let msgId = "<bounce-" & $epochTime().int & "-" &
              $getCurrentProcessId() & "@meowmail.local>"
  let bodyRef = "<" & $epochTime().int & "." & $getCurrentProcessId() & "@meowmail.local>"

  let boundary = "---=_Part_" & $getCurrentProcessId() & "_" & $epochTime().int

  var body: string
  # Headers
  body.add("From: MAILER-DAEMON@meowmail.local\r\n")
  body.add("To: " & returnPath & "\r\n")
  body.add("Date: " & dateStr & "\r\n")
  body.add("Subject: Delivery Status Notification (Failure)\r\n")
  body.add("Message-ID: " & msgId & "\r\n")
  body.add("MIME-Version: 1.0\r\n")
  body.add("Content-Type: multipart/report; report-type=delivery-status;\r\n")
  body.add(' ' & boundary & "\r\n")
  body.add("Auto-Submitted: auto-replied\r\n")
  body.add("\r\n")

  # Part 1: Human-readable explanation
  body.add("--" & boundary & "\r\n")
  body.add("Content-Type: text/plain; charset=utf-8\r\n")
  body.add("Content-Transfer-Encoding: 7bit\r\n")
  body.add("\r\n")
  body.add("This is the mail system at host meowmail.local.\r\n\r\n")
  body.add("I was unable to deliver your message to the following recipients:\r\n\r\n")
  body.add("  " & originalTo & "\r\n")
  body.add("\r\nReason: " & dsnText(status) & "\r\n")
  if diag.len > 0:
    body.add("Diagnostic: " & diag & "\r\n")
  body.add("\r\n")
  case status
  of dsnMessageExpired, dsnDelayed:
    body.add("The message will continue to be retried. If delivery does not\r\n")
    body.add("succeed, a further failure notification will be sent.\r\n")
  else:
    body.add("No further delivery attempts will be made for this message.\r\n")
  body.add("\r\n")

  # Part 2: Message/delivery-status (RFC 3461 §2.2)
  body.add("--" & boundary & "\r\n")
  body.add("Content-Type: message/delivery-status\r\n")
  body.add("\r\n")
  body.add("Reporting-MTA: dns; meowmail.local\r\n")
  body.add("Arrival-Date: " & dateStr & "\r\n")
  body.add("Received-From-MTA: dns; " & heloName & "\r\n")
  body.add("\r\n")
  body.add("Final-Recipient: rfc822; " & originalTo & "\r\n")
  body.add("Action: " & (if status in [dsnDelayed]: "delayed" else: "failed") & "\r\n")
  body.add("Status: " & dsnCode(status) & "\r\n")
  let rcptParts = originalTo.split('@')
  if rcptParts.len == 2:
    body.add("Remote-MTA: dns; " & rcptParts[1] & "\r\n")
  body.add("Diagnostic-Code: smtp; " & dsnCode(status) & " " & dsnText(status) & "\r\n")
  body.add("\r\n")

  # Part 3: Original message (headers only, truncated)
  body.add("--" & boundary & "\r\n")
  body.add("Content-Type: message/rfc822\r\n")
  body.add("Content-Transfer-Encoding: 7bit\r\n")
  body.add("\r\n")
  body.add("From: " & originalFrom & "\r\n")
  body.add("To: " & originalTo & "\r\n")
  body.add("Date: " & dateStr & "\r\n")
  body.add("Subject: (original message subject not available)\r\n")
  body.add("\r\n")
  body.add("--" & boundary & "--\r\n")

  (returnPath, body)
