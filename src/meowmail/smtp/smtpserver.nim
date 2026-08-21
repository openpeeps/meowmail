# MeowMail - A high-performance SMTP based on powpow
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

import std/[posix, tables, strutils,
      options, threadpool, base64, os]
from std/net import Port, `$`

import powpow
import powpow/net/tlsapi
import ./smtpauth, ./smtpdelivery, ./mxprovider, ./dkim, ./queue, ./bounce, ./ratelimit, ./address
import ./auth/inbound
import ../imap/msgparse
import pkg/spf
import ../imap/mailstore
import ../utils/logger

export mxprovider

## This module implements a high-performance SMTP server using powpow's
## non-blocking event loop and TCP/TLS transport.
##
## It uses a single-threaded reactor to efficiently handle multiple
## concurrent SMTP sessions. The server supports basic SMTP commands,
## authentication, TLS (STARTTLS + implicit SMTPS), and message delivery
## through a configurable `SMTPDelivery` provider.
##
## Use the `SMTPSendPolicy` and `SMTPSettings` types to configure the server's
## behavior, including whether to allow relaying, require authentication,
## and how to handle TLS.

const
  MaxCommandLineLen = 510 # 512 including CRLF
  MaxDataLineLen = 998    # 1000 including CRLF

type
  SMTPCommand* = enum
    ## Represents the various SMTP commands that
    ## the server can process. This is used
    smtpUnknownCmd,
    HELO = "HELO",
    EHLO = "EHLO",
    STARTTLS = "STARTTLS",
    AUTH = "AUTH",
    MAIL = "MAIL",
    RCPT = "RCPT",
    DATA = "DATA",
    QUIT = "QUIT",
    RSET = "RSET",
    NOOP = "NOOP",
    VRFY = "VRFY",
    EXPN = "EXPN",
    HELP = "HELP"

  SMTPSession* = ref object
    ## Represents the state of an individual SMTP session/connection.
    inbuf: string
      # Buffer for accumulating incoming data until complete lines are received.
    greeted: bool
      # Whether the client has sent a HELO/EHLO command yet.
    heloName: string
      # The argument provided in the HELO/EHLO command.
    mailFrom: string
      # The email address specified in the MAIL FROM command.
    rcptTo: seq[string]
      # A sequence of email addresses specified in RCPT TO commands.
    inData: bool
      # Whether the session is currently in the DATA command state.
    dataLines: seq[string]
      # Accumulates lines of email content during the DATA command.
    quitting: bool
      # Whether the client has issued a QUIT command.
    authenticated: bool
      # Whether the client has successfully authenticated.
    authUser: string
      # The authenticated username (set on successful auth).
    authProgress: AuthProgress
      # Tracks the current step in the authentication process, if any.
    authTempUser: string
      # Temporarily holds the username during multi-step authentication flows.
    tlsActive: bool
      # Whether the session has an active TLS connection.

  SMTPSendPolicy* = enum
    ## Represents the policy for SMTP server, such as whether to allow
    ## relaying messages from external clients, or to restrict to local delivery only.
    spLocalSendOnly     ## Only allow sending from localhost (127.0.0.1 / ::1)
    spDefault           ## Allow relaying for authenticated users (default)
    spInternalSendOnly  ## Only allow sending from trusted internal networks
    spNoRelay           ## No relaying, only accept mail for local domains

  SMTPSettings* = object
    ## Configuration settings for the SMTP server, including TLS options,
    ## authentication requirements, and delivery configuration.
    certifications*: Option[(string, string)] = none((string, string))
      ## Optional tuple of (certFile, keyFile) for TLS configuration.
    spoolDirectory*: Option[string] = none(string)
      ## Directory path for spooling messages that cannot be immediately delivered.
    enableMxDelivery*: bool = true
      ## Whether to enable direct MX delivery of incoming messages.
    enablePort587*: bool = true
      ## Whether to listen for SMTP submission on port 587
    enablePort465*: bool = true
      ## Whether to listen for SMTPS on port 465
    enablePort25*: bool = true
      ## Whether to listen for standard SMTP on port 25
    mxConfig*: MXProviderConfig
      ## Configuration for the MX delivery provider.
    deliveryProvider*: DeliveryProvider = nil
      ## Optional custom delivery provider. If set, this provider will be used
      ## instead of the default MX provider.
    maildirBase*: Option[string] = none(string)
      ## Base directory for the Maildir store. When set (or `MEOWMAIL_MAILDIR`
      ## is provided), messages for local domains are delivered into per-user
      ## Maildirs and can be read over IMAP.
    localDomains*: seq[string] = @[]
      ## Domains treated as local. Defaults to the server hostname, "localhost"
      ## and "meowmail.local" when a Maildir base is configured.
    sendPolicy*: SMTPSendPolicy = spDefault
      ## The sending policy for the server.
    checkSenderDomain*: bool = false
      ## When true, validate the sender domain has MX/A records at MAIL FROM time.
    checkRcptDomain*: bool = false
      ## When true, validate recipient domain has MX/A records at RCPT TO time.
    msgPerHour*: int = 100
      ## Max messages per IP per hour (0 = unlimited).
    msgPerDay*: int = 1000
      ## Max messages per IP per day (0 = unlimited).
    userMsgPerHour*: int = 0
      ## Max messages per authenticated user per hour (0 = unlimited).
    userMsgPerDay*: int = 0
      ## Max messages per authenticated user per day (0 = unlimited).
    smtpCommandsLog*: bool = false
      ## Log each SMTP command with IP and reply code.

  SMTPListener = tuple
    ipv4: TcpServer
    ipv6: TcpServer

  SMTPServer* = ref object
    ## Represents the SMTP server instance, including its configuration and state.
    loop*: Loop
    ipMsgLimits*: RateLimiter
      ## Per-IP message rate limiter (hourly + daily windows).
    userMsgLimits*: RateLimiter
      ## Per-authenticated-user message rate limiter.
      ## The powpow event loop driving all listeners and sessions.
    listener*: SMTPListener
      ## Listener for standard SMTP (port 25).
    listener587*: SMTPListener
      ## Listener for SMTP submission (port 587).
    listener465*: SMTPListener
      ## Listener for implicit TLS SMTPS (port 465).
    tlsCtx*: SslContext
      ## Server-side TLS context for STARTTLS and implicit TLS connections.
    enableStartTls*: bool
      ## Whether to offer STARTTLS capability and handle TLS upgrades.
    requireTlsForAuth*: bool
      ## Whether to require TLS before allowing authentication.
    port*: Port
      ## The port number on which the SMTP server is listening.
    requireAuth*: bool
      ## Whether the server requires authentication before accepting MAIL commands.
    authUsers*: Table[string, string] # fallback local auth
      ## A table of username-password pairs for simple local authentication.
    authProvider*: AuthProvider
      ## An optional callback for handling authentication requests.
    delivery*: SMTPDelivery
      ## The SMTPDelivery configuration for handling message deliveries.
    settings*: SMTPSettings
      ## The original settings object used to configure the server.
    logger*: Logger
    dkimKey*: DkimKey
      ## Optional DKIM signing key. When set, outbound messages are signed.
    queue*: Queue
      ## Persistent outbound message queue with retry.
    spfServer*: pointer
      ## SPF server for inbound verification.
    rateLimit*: SmtpRateLimit
      ## Connection and auth rate limiting.

  SMTPServerError* = object of CatchableError

var
  globalLogger: Logger

#
# Utility functions for handling SMTP protocol details, session management, and other
# common tasks related to processing SMTP commands and managing client sessions.
#
proc ipv4HostOrder(sa: ptr SockAddr): uint32 {.inline.} =
  # Returns IPv4 address in host byte order; 0 if not AF_INET.
  if sa == nil or sa.sa_family != AF_INET.TSa_Family:
    return 0'u32
  let sin = cast[ptr Sockaddr_in](sa)
  result = ntohl(sin.sin_addr.s_addr)

proc isLoopbackIPv4(sa: ptr SockAddr): bool {.inline.} =
  # Determine if the given socket address is a loopback IPv4 address.
  let ip = ipv4HostOrder(sa)
  result = (ip and 0xFF00_0000'u32) == 0x7F00_0000'u32

proc isInternalIPv4(sa: ptr SockAddr): bool {.inline.} =
  # RFC1918 + loopback
  let ip = ipv4HostOrder(sa)
  if (ip and 0xFF00_0000'u32) == 0x0A00_0000'u32: return true       # 10.0.0.0/8
  if (ip and 0xFFF0_0000'u32) == 0xAC10_0000'u32: return true       # 172.16.0.0/12
  if (ip and 0xFFFF_0000'u32) == 0xC0A8_0000'u32: return true       # 192.168.0.0/16
  if (ip and 0xFF00_0000'u32) == 0x7F00_0000'u32: return true       # 127.0.0.0/8
  false

proc ipv6HostOrder(sa: ptr SockAddr): array[16, uint8] {.inline.} =
  # Returns IPv6 address as array; all zeros if not AF_INET6.
  if sa == nil or sa.sa_family != AF_INET6.TSa_Family:
    return
  let sin6 = cast[ptr Sockaddr_in6](sa)
  for i in 0 ..< 16:
    result[i] = ord(sin6.sin6_addr.s6_addr[i]).uint8

proc isLoopbackIPv6(sa: ptr SockAddr): bool {.inline.} =
  # Determine if the given socket address is the IPv6 loopback address (::1).
  if sa == nil or sa.sa_family != AF_INET6.TSa_Family:
    return false
  let sin6 = cast[ptr Sockaddr_in6](sa)
  for i in 0 ..< 15:
    if sin6.sin6_addr.s6_addr[i] != '\0': return false
  result = sin6.sin6_addr.s6_addr[15] == '\1'

proc isInternalIPv6(sa: ptr SockAddr): bool {.inline.} =
  # Determine if the given socket address is an internal IPv6 address
  # (Unique Local, Link-local, or Loopback).
  if sa == nil or sa.sa_family != AF_INET6.TSa_Family:
    return false

  let sin6 = cast[ptr Sockaddr_in6](sa)
  # fc00::/7 (Unique local), fe80::/10 (Link-local), ::1 (loopback)
  let b0 = ord(sin6.sin6_addr.s6_addr[0]).uint8
  let b1 = ord(sin6.sin6_addr.s6_addr[1]).uint8

  if b0 == 0xfc'u8 or b0 == 0xfd'u8:
    return true # fc00::/7

  if b0 == 0xfe'u8 and (b1 and 0xc0'u8) == 0x80'u8:
    return true # fe80::/10

  for i in 0 ..< 15:
    if sin6.sin6_addr.s6_addr[i] != '\0': return false

  if sin6.sin6_addr.s6_addr[15] == '\1':
    return true # ::1 is loopback
  false

proc clientIsLoopback(conn: Connection): bool =
  var sa = conn.getClientSockAddr()
  let p = cast[ptr SockAddr](addr sa)
  isLoopbackIPv4(p) or isLoopbackIPv6(p)

proc clientIsInternal(conn: Connection): bool =
  var sa = conn.getClientSockAddr()
  let p = cast[ptr SockAddr](addr sa)
  isInternalIPv4(p) or isInternalIPv6(p)

proc supportsAuth(server: SMTPServer): bool =
  # Determine if the server supports authentication based on its configuration.
  server.authProvider != nil or server.authUsers.len > 0

proc smtpReply(conn: Connection, code: int, msg: string) =
  # Send a single-line SMTP reply to the client.
  let line = $code & " " & msg & "\r\n"
  discard conn.send(line)

proc smtpReplyMulti(conn: Connection, code: int, msg: string, hasMore: bool) =
  # Send a multi-line SMTP reply. If hasMore is true, the line will end with a hyphen (-)
  let sep = if hasMore: "-" else: " "
  let line = $code & sep & msg & "\r\n"
  discard conn.send(line)

proc smtpHostname*: string =
  # Get the server's hostname for use in SMTP greetings and replies.
  var host = newString(256)
  if gethostname(host.cstring, host.len.cint) == 0:
    let nul = host.find('\0')
    result = if nul >= 0: host[0 ..< nul] else: host
    result = result.strip()
  if result.len == 0:
    result = "meowmail.local"

proc smtpReplyEhloCapabilities(conn: Connection, hostname: string,
                               s: SMTPSession, server: SMTPServer) =
  # Send the EHLO reply with the server's capabilities.
  smtpReplyMulti(conn, 250, hostname & " Hello", true)
  smtpReplyMulti(conn, 250, "PIPELINING", true)
  smtpReplyMulti(conn, 250, "8BITMIME", true)
  smtpReplyMulti(conn, 250, "SIZE 52428800", true)  # 50 MB max

  if server.enableStartTls and not s.tlsActive:
    smtpReplyMulti(conn, 250, "STARTTLS", true)

  # Common policy: AUTH only after TLS
  if supportsAuth(server) and not (server.requireTlsForAuth and not s.tlsActive):
    smtpReplyMulti(conn, 250, "AUTH PLAIN LOGIN", true)

  smtpReplyMulti(conn, 250, "HELP", false)

proc decodeB64Safe(encoded: string, decoded: var string): bool =
  # Decode a base64-encoded string safely, returning false if the input is not valid base64.
  try:
    decoded = decode(encoded.strip())
    result = true
  except CatchableError:
    result = false

proc extractRcptDomain(rcpt: string): string =
  ## Extract and lowercase the domain part of an envelope address.
  let a = rcpt.strip().strip(chars = {'<', '>'})
  let at = a.rfind('@')
  if at >= 0: result = a[at + 1 .. ^1].toLowerAscii()

proc isLocalRecipient(server: SMTPServer, rcpt: string): bool =
  ## Whether the recipient's domain is treated as local.
  let dom = extractRcptDomain(rcpt)
  if dom.len == 0: return false
  if server.delivery != nil and server.delivery.localStore != nil:
    return server.delivery.localStore.isLocal(rcpt)
  for d in server.settings.localDomains:
    if dom == d.toLowerAscii(): return true

proc validateAuth(server: SMTPServer, s: SMTPSession,
                      user, pass, mechanism: string): AuthDecision =
  # Validate authentication credentials using either the configured
  # authProvider callback or the local authUsers table.
  let req = AuthRequest(
    username: user,
    password: pass,
    mechanism: mechanism,
    remoteIp: "",
    heloName: s.heloName
  )

  if server.authProvider != nil:
    return server.authProvider(req)

  if server.authUsers.hasKey(user) and server.authUsers[user] == pass:
    return authOk

  authInvalid

proc smtpReplyAndClose(conn: Connection, code: int, msg: string) =
  # Send an SMTP reply to the client and then close the connection.
  let s = cast[SMTPSession](conn.data)
  if s != nil:
    s.quitting = true
  smtpReply(conn, code, msg)
  conn.closeAfterDrain()

proc resetTxn(s: SMTPSession) =
  # Reset the transaction state of the session.
  s.mailFrom.setLen(0)
  s.rcptTo.setLen(0)
  s.inData = false
  s.dataLines.setLen(0)
  s.authProgress = apNone
  s.authTempUser.setLen(0)
  s.authUser.setLen(0)

proc applyAuthDecision(conn: Connection, s: SMTPSession, d: AuthDecision,
                       server: SMTPServer = nil) =
  case d
  of authOk:
    s.authenticated = true
    s.authUser = s.authTempUser
    smtpReply(conn, 235, "Authentication successful")
  of authInvalid:
    smtpReply(conn, 535, "Authentication credentials invalid")
    # Track failed auth for rate limiting
    if server.rateLimit != nil:
      server.rateLimit.recordAuthFailure(conn.getClientIp())
  of authFailure:
    smtpReply(conn, 454, "Temporary authentication failure")

proc handleAuthFlow(conn: Connection, server: SMTPServer,
                  s: SMTPSession, line: string): bool =
  # Handle the multi-step authentication flows for mechanisms like PLAIN and LOGIN.
  if s.authProgress == apNone:
    return false

  if line == "*":
    s.authProgress = apNone
    s.authTempUser.setLen(0)
    smtpReply(conn, 501, "Authentication canceled")
    return true

  var decoded = ""
  if not decodeB64Safe(line, decoded):
    s.authProgress = apNone
    s.authTempUser.setLen(0)
    smtpReply(conn, 501, "Invalid base64 data")
    return true

  case s.authProgress
  of apPlain:
    let parts = decoded.split('\0') # [authzid] NUL authcid NUL passwd
    var user = ""
    var pass = ""
    if parts.len >= 3:
      user = parts[^2]
      pass = parts[^1]
    elif parts.len == 2:
      user = parts[0]
      pass = parts[1]

    s.authProgress = apNone
    let decision = validateAuth(server, s, user, pass, "PLAIN")
    applyAuthDecision(conn, s, decision, server)
    return true

  of apLoginUser:
    s.authTempUser = decoded
    s.authProgress = apLoginPass
    smtpReply(conn, 334, "UGFzc3dvcmQ6") # "Password:"
    return true

  of apLoginPass:
    let decision = validateAuth(server, s, s.authTempUser, decoded, "LOGIN")
    s.authProgress = apNone
    s.authTempUser.setLen(0)
    applyAuthDecision(conn, s, decision, server)
    return true

  of apNone:
    return false

proc handleStartTls(conn: Connection, server: SMTPServer, s: SMTPSession) =
  if s.tlsActive:
    smtpReply(conn, 503, "TLS already active")
    return
  if not server.enableStartTls or server.tlsCtx == nil:
    smtpReply(conn, 454, "TLS not available")
    return

  smtpReply(conn, 220, "Ready to start TLS")

  # Drop any pre-TLS pipelined bytes
  s.inbuf.setLen(0)

  # RFC 3207: reset protocol state after TLS is established
  s.tlsActive = true
  s.greeted = false
  s.heloName.setLen(0)
  s.authenticated = false
  resetTxn(s)

  try:
    conn.wrapTls(server.tlsCtx)
  except SslError:
    smtpReplyAndClose(conn, 454, "TLS initialization failed")

proc startBackgroundDelivery(server: SMTPServer, req: DeliveryRequest) {.thread, gcsafe.} =
  # Start a background thread to handle message delivery.
  let delivery: SMTPDelivery = server.delivery
  let d = delivery.deliverMessage(req)
  case d
  of ddOk:
    server.logger.info("[mx] Delivered message from " & req.mailFrom & " to " & req.rcptTo.join(", "))
  of ddTempFail:
    server.logger.warn("[mx] Temporary failure delivering message from " & req.mailFrom & " to " & req.rcptTo.join(", "))
    if server.queue != nil:
      let entryId = server.queue.enqueue(req)
      if entryId.len > 0:
        server.logger.info("[queue] Enqueued message " & entryId)
  of ddPermFail:
    server.logger.error("[mx] Permanent failure delivering message from " & req.mailFrom & " to " & req.rcptTo.join(", "))
    # Generate bounce to sender
    for rcpt in req.rcptTo:
      discard deliverBounce(delivery.localStore, req.mailFrom, rcpt, req.heloName,
                            dsnFailed, "Permanent delivery failure")

proc handleSmtpLine(conn: Connection, server: SMTPServer, line: string) =
  # This is the main command processing function.
  let s = cast[SMTPSession](conn.data)
  if s == nil: return

  # If we're in the middle of an auth flow,
  # handle that first before normal command processing
  if handleAuthFlow(conn, server, s, line): return

  if s.inData:
    if line.len > MaxDataLineLen:
      smtpReplyAndClose(conn, 500, "Line too long")
      return
  elif line.len > MaxCommandLineLen:
    smtpReplyAndClose(conn, 500, "Line too long")
    return

  if s.inData:
    if line == ".":
      # End of DATA command. Process the message delivery.
      var msgData = s.dataLines.join("\r\n") & "\r\n"

      # Enforce message size limit (50 MB)
      if msgData.len > 52428800:
        smtpReply(conn, 552, "Message size exceeds fixed maximum")
        resetTxn(s)
        return

      # Run inbound authentication (SPF/DKIM/DMARC)
      if server.spfServer != nil:
        try:
          let sep = msgData.find("\r\n\r\n")
          if sep >= 0:
            let headerBlock = msgData[0 ..< sep]
            let bodyPart = msgData[sep + 4 .. ^1]
            var headers: seq[Header]
            for line in headerBlock.split("\r\n"):
              if line.len == 0: continue
              if line[0] in {' ', '\t'}:
                if headers.len > 0:
                  headers[^1].value &= " " & line.strip()
                continue
              let colon = line.find(':')
              if colon > 0:
                headers.add((name: line[0 ..< colon], value: line[colon + 1 .. ^1].strip()))
            let clientIp = conn.getClientIp()
            let auth = authenticateMessage(server.spfServer, clientIp, s.heloName,
                                           headers, bodyPart)
            # Prepend Authentication-Results header
            msgData = auth.renderAuthHeader() & "\r\n" & msgData
        except CatchableError as e:
          globalLogger.warn("[smtp] Authentication failed: " & e.msg)

      # Sign with DKIM if configured
      if server.dkimKey != nil:
        try:
          msgData = signMessage(server.dkimKey, msgData)
        except CatchableError as e:
          globalLogger.warn("[smtp] DKIM signing failed: " & e.msg)

      let req = DeliveryRequest(
        mailFrom: s.mailFrom,
        rcptTo: s.rcptTo,
        data: msgData,
        heloName: s.heloName
      )

      # Check per-IP / per-user message quotas
      let clientIp = conn.getClientIp()
      if not server.ipMsgLimits.allow(clientIp):
        smtpReply(conn, 452, "Too many messages, try again later")
        return
      if s.authenticated and s.authUser.len > 0:
        if not server.userMsgLimits.allow("user:" & s.authUser):
          smtpReply(conn, 452, "Too many messages, try again later")
          return

      globalLogger.info("[smtp] received message: from=" & req.mailFrom & " to=" & req.rcptTo.join(", "))

      # Spawn a background thread to handle delivery so that we can respond
      # to the client immediately without blocking the SMTP session.
      spawn server.startBackgroundDelivery(req)
      smtpReply(conn, 250, "Message accepted for delivery")

      resetTxn(s)
      return # don't process "." as a normal command

    # collect DATA body lines
    if line.len > 0 and line[0] == '.':
      s.dataLines.add(line[1..^1]) # dot-unstuff
    else:
      s.dataLines.add(line)
    return

  let parts = line.split(' ', maxsplit = 1)
  let cmd = parts[0].toUpperAscii()
  let arg = if parts.len > 1: parts[1].strip() else: ""

  if server.settings.smtpCommandsLog:
    let clientIp = conn.getClientIp()
    let userTag = if s.authenticated and s.authUser.len > 0: " user=" & s.authUser else: ""
    server.logger.debug("[smtp] cmd=" & cmd & " ip=" & clientIp & userTag)

  case cmd
  of "HELO":
    s.greeted = true
    s.heloName = arg
    smtpReply(conn, 250, "meowmail.local Hello")
  of "EHLO":
    s.greeted = true
    s.heloName = arg
    smtpReplyEhloCapabilities(conn, smtpHostname(), s, server)
  of "STARTTLS":
    if s.mailFrom.len > 0 or s.rcptTo.len > 0 or s.inData:
      smtpReply(conn, 503, "Bad sequence of commands")
    else:
      handleStartTls(conn, server, s)
  of "AUTH":
    if not s.greeted:
      smtpReply(conn, 503, "Send EHLO/HELO first")
    elif s.inData or s.mailFrom.len > 0 or s.rcptTo.len > 0:
      smtpReply(conn, 503, "Bad sequence of commands")
    elif not supportsAuth(server):
      smtpReply(conn, 503, "Authentication not enabled")
    elif server.requireTlsForAuth and not s.tlsActive:
      smtpReply(conn, 530, "Must issue a STARTTLS command first")
    elif s.authenticated:
      smtpReply(conn, 503, "Already authenticated")
    elif server.rateLimit != nil and server.rateLimit.isLockedOut(conn.getClientIp()):
      smtpReply(conn, 421, "Too many failed authentication attempts, try again later")
    else:
      let p = arg.splitWhitespace()
      if p.len == 0:
        smtpReply(conn, 501, "Syntax: AUTH <mechanism> [initial-response]")
      else:
        let mech = p[0].toUpperAscii()
        let initial = if p.len > 1: p[1] else: ""
        case mech
        of "PLAIN":
          if initial.len == 0:
            s.authProgress = apPlain
            smtpReply(conn, 334, "")
          else:
            var decoded = ""
            if not decodeB64Safe(initial, decoded):
              smtpReply(conn, 501, "Invalid base64 data")
            else:
              let seg = decoded.split('\0')
              var user = ""
              var pass = ""
              if seg.len >= 3:
                user = seg[^2]
                pass = seg[^1]
              elif seg.len == 2:
                user = seg[0]
                pass = seg[1]
              applyAuthDecision(conn, s, validateAuth(server, s, user, pass, "PLAIN"))
        of "LOGIN":
          if initial.len > 0:
            var userDecoded = ""
            if not decodeB64Safe(initial, userDecoded):
              smtpReply(conn, 501, "Invalid base64 data")
            else:
              s.authTempUser = userDecoded
              s.authProgress = apLoginPass
              smtpReply(conn, 334, "UGFzc3dvcmQ6")
          else:
            s.authProgress = apLoginUser
            smtpReply(conn, 334, "VXNlcm5hbWU6")
        else:
          smtpReply(conn, 504, "Unsupported authentication mechanism")
  of "MAIL":
    if server.requireAuth and not s.authenticated:
      smtpReply(conn, 530, "Authentication required")
    elif not s.greeted:
      smtpReply(conn, 503, "Send HELO/EHLO first")
    elif not arg.toUpperAscii().startsWith("FROM:"):
      smtpReply(conn, 501, "Syntax: MAIL FROM:<address>")
    else:
      let fromPart = arg[5..^1].strip()
      # Validate sender address syntax via RFC 5321 parser
      if fromPart.len > 0 and fromPart != "<>":
        let mb = parseMailbox(fromPart)
        if not mb.hasValidSyntax():
          smtpReply(conn, 501, "Invalid sender address: " & mb.error)
          return
      # Parse SIZE parameter (RFC 1870): MAIL FROM:<addr> SIZE=<n>
      var claimedSize = 0
      let sizeIdx = fromPart.toUpperAscii.find(" SIZE=")
      if sizeIdx >= 0:
        let sizeStr = fromPart[sizeIdx + 6 .. ^1].strip()
        try:
          claimedSize = parseInt(sizeStr)
        except ValueError:
          discard
      if claimedSize > 52428800:  # 50 MB limit
        smtpReply(conn, 552, "Message size exceeds fixed maximum (52428800)")
        return
      s.mailFrom = fromPart
      s.rcptTo.setLen(0)
      smtpReply(conn, 250, "OK")
  of "RCPT":
    if s.mailFrom.len == 0:
      smtpReply(conn, 503, "Need MAIL FROM first")
    elif not arg.toUpperAscii().startsWith("TO:"):
      smtpReply(conn, 501, "Syntax: RCPT TO:<address>")
    elif s.rcptTo.len >= DefaultSmtpLimits.maxRecipients:
      smtpReply(conn, 552, "Too many recipients")
    else:
      let rcptAddr = arg[3..^1].strip()
      # Validate recipient address syntax
      if rcptAddr.len > 0:
        let mb = parseMailbox(rcptAddr)
        if not mb.hasValidSyntax():
          smtpReply(conn, 501, "Invalid recipient address: " & mb.error)
          return
      if server.settings.sendPolicy == spNoRelay and
           not isLocalRecipient(server, rcptAddr):
        server.logger.warn("[smtp] relay denied (spNoRelay) for recipient " & rcptAddr)
        smtpReply(conn, 554, "Relay access denied")
      else:
        s.rcptTo.add(rcptAddr)
        smtpReply(conn, 250, "OK")
  of "DATA":
    if s.rcptTo.len == 0:
      smtpReply(conn, 503, "Need RCPT TO first")
    else:
      s.inData = true
      s.dataLines.setLen(0)
      smtpReply(conn, 354, "End data with <CR><LF>.<CR><LF>")
  of "RSET":
    resetTxn(s)
    smtpReply(conn, 250, "OK")
  of "NOOP":
    smtpReply(conn, 250, "OK")
  of "VRFY", "EXPN":
    smtpReply(conn, 252, "Cannot VRFY/EXPN user")
  of "QUIT":
    s.quitting = true
    smtpReply(conn, 221, "Bye")
    conn.closeAfterDrain()
  else:
    smtpReply(conn, 500, "Command unrecognized")

proc handleSmtpData(server: SMTPServer, conn: Connection, data: openArray[byte]) =
  # Feed incoming bytes into the session buffer and process complete lines.
  let s = cast[SMTPSession](conn.data)
  if s == nil or s.quitting: return

  s.inbuf.add(cast[string](@data))

  let maxPendingLen = if s.inData: MaxDataLineLen + 2 else: MaxCommandLineLen + 2
  if s.inbuf.find("\r\n") < 0 and s.inbuf.len > maxPendingLen:
    smtpReplyAndClose(conn, 500, "Line too long")
    return

  while true:
    let idx = s.inbuf.find("\r\n")
    if idx < 0: break

    let line = s.inbuf[0 ..< idx]
    if idx + 2 <= s.inbuf.high:
      s.inbuf = s.inbuf[idx + 2 .. ^1]
    else:
      s.inbuf.setLen(0)

    handleSmtpLine(conn, server, line)
    if s.quitting or conn.state != Connected:
      break

proc hasAnyListener(l: SMTPListener): bool {.inline.} =
  l.ipv4 != nil or l.ipv6 != nil

proc handleAccept(server: SMTPServer, conn: Connection, tlsImplicit: bool) =
  # Called when a new client connection is accepted.

  # Enforce the send policy at the connection level.
  case server.settings.sendPolicy
  of spDefault:
    discard
  of spLocalSendOnly:
    if not clientIsLoopback(conn):
      server.logger.warn("[smtp] rejected connection from non-local address (spLocalSendOnly)")
      conn.close()
      return
  of spInternalSendOnly:
    if not clientIsInternal(conn):
      server.logger.warn("[smtp] rejected connection from non-internal address (spInternalSendOnly)")
      conn.close()
      return
  of spNoRelay:
    discard # relay restriction should be enforced during RCPT/DATA policy checks

  # Rate limiting: check per-IP connection limits
  if server.rateLimit != nil:
    let clientIp = conn.getClientIp()
    if not server.rateLimit.allowConnection(clientIp):
      server.logger.warn("[smtp] rate limit exceeded from " & clientIp)
      conn.close()
      return

  var tlsActiveNow = false
  if tlsImplicit:
    if server.tlsCtx == nil:
      conn.close()
      return
    try:
      conn.wrapTls(server.tlsCtx)
    except SslError:
      conn.close()
      return
    tlsActiveNow = true

  conn.data = cast[pointer](SMTPSession(
    tlsActive: tlsActiveNow
  ))

  # Track connection for rate limiting
  if server.rateLimit != nil:
    server.rateLimit.trackConnect(conn.getClientIp())

  # Send the initial SMTP greeting. For implicit TLS connections this is
  # buffered and delivered once the TLS handshake completes.
  smtpReply(conn, 220, "meowmail.local ESMTP ready")

proc handleClose(conn: Connection, server: SMTPServer) =
  # Session cleanup on connection close.
  if server.rateLimit != nil:
    server.rateLimit.trackDisconnect(conn.getClientIp())
  conn.data = nil

proc bindListenerOn(server: SMTPServer, port: Port, ipv6: static bool = false,
                    tlsImplicit: bool = false): TcpServer =
  # Create and bind a powpow TcpServer for the given port and IP version.
  let addrStr = when ipv6: "::" else: "0.0.0.0"
  result = newTcpServer(server.loop,
    onData = proc(conn: Connection, data: openArray[byte]) =
      handleSmtpData(server, conn, data)
    ,
    onAccept = proc(conn: Connection) =
      handleAccept(server, conn, tlsImplicit)
    ,
    onClose = proc(conn: Connection) =
      handleClose(conn, server)
    ,
  )
  result.listen(addrStr, port.int)

proc tryBindListenerOn(server: SMTPServer, port: Port, ipv6: static bool = false,
                       tlsImplicit: bool = false): TcpServer =
  # Bind a listener, logging and swallowing failures (e.g. no IPv6 support).
  try:
    result = bindListenerOn(server, port, ipv6, tlsImplicit)
  except NetError:
    stderr.writeLine(
      "[smtp] bind failed on port ", $port,
      (if ipv6: " (IPv6)" else: " (IPv4)"),
      ": ", getCurrentExceptionMsg()
    )
    result = nil

proc bindListener587*(server: SMTPServer, port: Port = Port(587)) =
  ## Binds a listener for SMTP submission on the specified port (default 587).
  server.enableStartTls = (server.tlsCtx != nil)

  if server.listener587.ipv4 == nil:
    server.listener587.ipv4 = tryBindListenerOn(server, port)

  if server.listener587.ipv6 == nil:
    server.listener587.ipv6 = tryBindListenerOn(server, port, true)

  assert hasAnyListener(server.listener587), "Failed to bind SMTP submission listener (587)"
  server.logger.info("[smtp] SMTP submission listener bound on port " & $port & " (STARTTLS " &
       (if server.enableStartTls: "enabled" else: "disabled") & ")")

proc bindListener465*(server: SMTPServer, port: Port = Port(465)) =
  ## Binds a listener for SMTPS on the specified port (default 465).
  ## This requires a valid TLS context to be set up.
  if server.tlsCtx == nil:
    raise newException(SMTPServerError, "Cannot bind SMTPS listener without TLS context configured")

  if server.listener465.ipv4 == nil:
    server.listener465.ipv4 = tryBindListenerOn(server, port, false, true)

  if server.listener465.ipv6 == nil:
    server.listener465.ipv6 = tryBindListenerOn(server, port, true, true)

  if not hasAnyListener(server.listener465):
    raise newException(SMTPServerError, "Failed to bind SMTPS listener on port " & $port)
  server.logger.info("[smtp] SMTPS listener bound on port " & $port & " (implicit TLS enabled)")

proc enableMxDelivery*(server: SMTPServer, cfg = MXProviderConfig()) =
  ## Installs MX delivery provider on this server instance.
  var mxCfg = cfg
  if mxCfg.heloName.len == 0 or mxCfg.heloName == "localhost":
    mxCfg.heloName = smtpHostname()
  # Initialize SPF server for inbound verification if not already set
  if server.spfServer == nil:
    let s = SPF_server_new(SPF_DNS_CACHE, 0)
    if s != nil:
      server.spfServer = cast[pointer](s)
  server.delivery.setProvider(newMXProvider(mxCfg))

proc opensslLastError*(): string =
  ## Retrieves the last OpenSSL error message.
  result = opensslError()

proc setupTlsCtx*(server: SMTPServer, certPath, keyPath: string): bool =
  ## Sets up the TLS context for the server using the provided certificate and key files.
  let certPath = absolutePath(certPath)
  let keyPath = absolutePath(keyPath)
  try:
    server.tlsCtx = newServerTlsContext(certPath, keyPath)
    server.enableStartTls = true
    result = true
  except SslError:
    stderr.writeLine("TLS error: ", getCurrentExceptionMsg())
    result = false

proc newSMTPServer*(settings: SMTPSettings): SMTPServer =
  ## Creates a new SMTP server instance based on the provided settings.
  new(result)
  result.loop = newLoop()
  result.port = Port(25) # default port for non-privileged testing
  let envPort = getEnv("MEOWMAIL_SMTP_PORT", "")
  if envPort.len > 0:
    try:
      result.port = Port(parseInt(envPort))
    except ValueError:
      discard
  result.authUsers = initTable[string, string]()
  result.settings = settings

  # setup logging with logs directory from env or default
  discard existsOrCreateDir(getCurrentDir() / "logs")
  result.logger = logger.newLogger(
    logsFolder = getCurrentDir() / "logs",
    namespace="MeowMail",
    logToFile = true,
    logToConsole = true,
    exitOnError = false
  )
  result.logger.start()
  globalLogger = result.logger # set global logger for use in other modules
  logger.setGlobalLogger(result.logger) # shared facility for modules without a server ref

  # initialize delivery mechanism with spool directory from env or default
  result.delivery =
      newSMTPDelivery(spoolDir = settings.spoolDirectory,
                      provider = settings.deliveryProvider)
  # initialize rate limiter
  result.rateLimit = newSmtpRateLimit()

  # initialize per-IP / per-user message quota limiters (powpow multi-window)
  result.ipMsgLimits = newMultiRateLimiter(
    result.loop,
    [(settings.msgPerHour, 3_600_000), (settings.msgPerDay, 86_400_000)])
  result.userMsgLimits = newMultiRateLimiter(
    result.loop,
    [(settings.userMsgPerHour, 3_600_000), (settings.userMsgPerDay, 86_400_000)])

  # Optional local Maildir delivery (env override takes precedence over config)
  let envMaildir = getEnv("MEOWMAIL_MAILDIR", "")
  let maildirBase =
    if envMaildir.len > 0: envMaildir
    elif settings.maildirBase.isSome: settings.maildirBase.get
    else: ""
  if maildirBase.len > 0:
    var domains = settings.localDomains
    let envDomains = getEnv("MEOWMAIL_LOCAL_DOMAINS", "")
    if envDomains.len > 0:
      for d in envDomains.split(','):
        let dd = d.strip()
        if dd.len > 0: domains.add(dd)
    if domains.len == 0:
      domains = @[smtpHostname(), "localhost", "meowmail.local"]
    result.delivery.localStore = newMaildirStore(maildirBase, domains)
    result.logger.info("[smtp] local Maildir delivery enabled at " & maildirBase)

  # Optional MX provider enablement (constructor arg and/or env toggle)
  if result.delivery.deliveryProvider == nil and settings.enableMxDelivery:
    result.enableMxDelivery(settings.mxConfig)

  # Optional local credentials
  let envUser = getEnv("MEOWMAIL_SMTP_USER", "")
  let envPass = getEnv("MEOWMAIL_SMTP_PASS", "")
  if envUser.len > 0 and envPass.len > 0:
    result.authUsers[envUser] = envPass

  # Optional HTTP auth proxy provider
  let authUrl = getEnv("MEOWMAIL_SMTP_AUTH_URL", "")
  if authUrl.len > 0:
    let token = getEnv("MEOWMAIL_SMTP_AUTH_TOKEN", "")
    result.authProvider = newHTTPAuthProvider(authUrl, token, 1200)

  # Require auth toggle
  let mustAuth = getEnv("MEOWMAIL_SMTP_REQUIRE_AUTH", "")
  if mustAuth.len > 0:
    result.requireAuth = mustAuth.toLowerAscii() in ["1", "true", "yes", "on"]
  else:
    result.requireAuth = supportsAuth(result)

  # Bind listeners according to settings.
  if settings.enablePort25:
    result.listener.ipv4 = tryBindListenerOn(result, result.port)
    result.listener.ipv6 = tryBindListenerOn(result, result.port, true)
    if not hasAnyListener(result.listener):
      raise newException(SMTPServerError, "Failed to bind SMTP listener on port " & $(result.port))

    if result.listener.ipv4 != nil:
      result.logger.info("[smtp] SMTP listener bound on port " & $(result.port) & " (IPv4)")
    if result.listener.ipv6 != nil:
      result.logger.info("[smtp] SMTP listener bound on port " & $(result.port) & " (IPv6)")
  else:
    result.logger.info("[smtp] Skipping port 25: disabled by settings")

  var enabledTls: bool
  if settings.certifications.isSome:
    let (certPath, keyPath) = settings.certifications.get()
    enabledTls = result.setupTlsCtx(certPath, keyPath)
    if not enabledTls:
      result.logger.info("[smtp] TLS disabled: setupTlsCtx failed (cert/key load error?)")

  if settings.enablePort587:
    result.bindListener587(Port(587))

  if settings.enablePort465:
    if enabledTls:
      result.bindListener465(Port(465))
    else:
      result.logger.info("[smtp] Skipping port 465: TLS setup failed")

proc start*(server: SMTPServer) =
  ## Starts the SMTP server event loop. This call blocks until the
  ## server is stopped or encounters a fatal error.
  if server.loop == nil:
    raise newException(SMTPServerError, "Cannot start SMTP server: event loop not initialized")
  let hasAnyListener =
          hasAnyListener(server.listener) or
          hasAnyListener(server.listener587) or
          hasAnyListener(server.listener465)
  if not hasAnyListener:
    raise newException(SMTPServerError, "Cannot start SMTP server: no listeners bound")
  server.logger.info("[smtp] SMTP server started on port " & $(server.port))
  server.loop.run()
