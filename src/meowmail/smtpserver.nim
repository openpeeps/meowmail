# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

import std/[posix, tables, strutils,
      options, threadpool, base64, os, openssl]
from std/net import Port, `$`

import libevent/bindings/[event, buffer, bufferevent,
              bufferevent_ssl, http, listener]

import ./smtpauth, ./smtpdelivery, ./mxprovider
export mxprovider

## This module implements a high-performance SMTP server using LibEvent.
## 
## It uses non-blocking I/O and an event-driven architecture to efficiently handle multiple
## concurrent SMTP sessions. The server supports basic SMTP commands, authentication,
## and message delivery through a configurable `SMTPDelivery` provider.

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
      # The argument provided in the HELO/EHLO command, which may be used for logging or authentication.
    mailFrom: string
      # The email address specified in the MAIL FROM command.
    rcptTo: seq[string]
      # A sequence of email addresses specified in RCPT TO commands.
    inData: bool
      # Whether the session is currently in the DATA command state, expecting email content.
    dataLines: seq[string]
      # Accumulates lines of email content during the DATA command.
    quitting: bool
      # Whether the client has issued a QUIT command, indicating the session should close after pending responses are sent.
    authenticated: bool
      # Whether the client has successfully authenticated.
    authProgress: AuthProgress
      # Tracks the current step in the authentication process, if any.
    authTempUser: string
      # Temporarily holds the username during multi-step authentication flows (e.g., LOGIN).
    tlsActive: bool
      # Whether the session has an active TLS connection (if STARTTLS is implemented in the future).

  SMTPSettings* = object
    ## Configuration settings for the SMTP server, including TLS options,
    ## authentication requirements, and delivery configuration.
    certifications*: Option[(string, string)] = none((string, string))
      ## Optional tuple of (certFile, keyFile) for TLS configuration.
    spoolDirectory*: Option[string] = none(string)
      ## Directory path for spooling messages that cannot be immediately delivered.
    enableMxDelivery*: bool = true
      ## Whether to enable direct MX delivery of incoming messages.
      ## If false, all messages will be spooled to disk for external processing.
    enable587*: bool = true
      ## Whether to listen for SMTP submission on port 587
    enable465*: bool = true
      ## Whether to listen for SMTPS on port 465
    mxConfig*: MXProviderConfig
      ## Configuration for the MX delivery provider,
      ## which handles direct delivery to recipient domains.
    deliveryProvider*: DeliveryProvider = nil
      ## Optional custom delivery provider. If set, this provider will be used to handle
      ## message deliveries instead of the default MX provider.

  SMTPServer* = ref object
    ## Represents the SMTP server instance, including its configuration and state.
    base*: ptr event_base
      ## The libevent event base used for managing events and the server loop.
    listener*: ptr evconnlistener
      ## The libevent connection listener that accepts incoming SMTP connections.
    listener587*: ptr evconnlistener
      ## Optional listener for port 587 (submission), if implemented in the future.
    listener465*: ptr evconnlistener
      ## Optional listener for port 465 (smtps), if implemented in the future.
    tlsCtx*: SslCtx
      ## Optional TLS context for handling STARTTLS or
      ## implicit TLS connections in the future.
    enableStartTls*: bool
      ## Whether to offer STARTTLS capability and handle
      ## TLS upgrades. (Not implemented in this version)
    requireTlsForAuth*: bool
      ## Whether to require TLS before allowing
      ## authentication. (Not implemented in this version)
    port*: Port
      ## The port number on which the SMTP server is listening for incoming connections.
    requireAuth*: bool
      ## Whether the server requires authentication
      ## before accepting MAIL commands.
    authUsers*: Table[string, string] # fallback local auth
      ## A table of username-password pairs for simple
      ## local authentication. This is used if no `authProvider` is set.
    authProvider*: AuthProvider
      ## An optional callback for handling authentication
      ## requests. If set, this will be used instead
      ## of `authUsers` for authentication decisions.
    delivery*: SMTPDelivery
      ## The SMTPDelivery configuration for handling message deliveries.

var
  sessions {.threadvar.}: Table[uint, SMTPSession]
  sessionsReady {.threadvar.}: bool

proc ensureSessionsInit() =
  if not sessionsReady:
    sessions = initTable[uint, SMTPSession]()
    sessionsReady = true

# forward decl
proc onSMTPRead(bev: ptr bufferevent, ctx: pointer) {.cdecl.}
proc onSMTPEvent(bev: ptr bufferevent, events: cshort, ctx: pointer) {.cdecl.}

proc bevKey(bev: ptr bufferevent): uint {.inline.} =
  # Generate a unique key for the session map based on the
  # bufferevent pointer. This is a common technique to
  # associate state with libevent connections.
  cast[uint](bev)

proc supportsAuth(server: SMTPServer): bool =
  # Determine if the server supports authentication based on its configuration.
  server.authProvider != nil or server.authUsers.len > 0

proc smtpReply(bev: ptr bufferevent, code: int, msg: string) =
  # Send a single-line SMTP reply to the client. The code is a 3-digit SMTP status code,
  let line = $code & " " & msg & "\r\n"
  discard bufferevent_write(bev, line.cstring, line.len.csize_t)

proc smtpReplyMulti(bev: ptr bufferevent, code: int, msg: string, hasMore: bool) =
  # Send a multi-line SMTP reply. If hasMore is true, the line will end with a hyphen (-)
  let sep = if hasMore: "-" else: " "
  let line = $code & sep & msg & "\r\n"
  discard bufferevent_write(bev, line.cstring, line.len.csize_t)

proc smtpHostname(): string =
  # Get the server's hostname for use in SMTP greetings and replies.
  # This tries to get the system hostname, but falls back to a default if that
  # fails or returns an empty string.
  var host = newString(256)
  if gethostname(host.cstring, host.len.cint) == 0:
    let nul = host.find('\0')
    result = if nul >= 0: host[0 ..< nul] else: host
    result = result.strip()
  if result.len == 0:
    result = "meowmail.local"

proc smtpReplyEhloCapabilities(bev: ptr bufferevent, hostname: string,
                              s: SMTPSession, server: SMTPServer) =
  # Send the EHLO reply with the server's capabilities. This includes
  # standard capabilities like PIPELINING and 8BITMIME,
  smtpReplyMulti(bev, 250, hostname & " Hello", true)
  smtpReplyMulti(bev, 250, "PIPELINING", true)
  smtpReplyMulti(bev, 250, "8BITMIME", true)

  if server.enableStartTls and not s.tlsActive:
    smtpReplyMulti(bev, 250, "STARTTLS", true)

  # Common policy: AUTH only after TLS
  if supportsAuth(server):
    smtpReplyMulti(bev, 250, "AUTH PLAIN LOGIN", true)

  smtpReplyMulti(bev, 250, "HELP", false)

proc decodeB64Safe(encoded: string, decoded: var string): bool =
  try:
    decoded = decode(encoded.strip())
    result = true
  except CatchableError:
    result = false

proc validateAuth(server: SMTPServer, s: SMTPSession, user, pass, mechanism: string): AuthDecision =
  let req = AuthRequest(
    username: user,
    password: pass,
    mechanism: mechanism,
    remoteIp: "",
    heloName: s.heloName
  )

  if server.authProvider != nil: return server.authProvider(req)
  if server.authUsers.hasKey(user) and server.authUsers[user] == pass:
    return authOk
  authInvalid

proc smtpReplyAndClose(bev: ptr bufferevent, code: int, msg: string) =
  let k = bevKey(bev)
  if sessions.hasKey(k):
    sessions[k].quitting = true
  smtpReply(bev, code, msg)

proc resetTxn(s: SMTPSession) =
  s.mailFrom.setLen(0)
  s.rcptTo.setLen(0)
  s.inData = false
  s.dataLines.setLen(0)
  s.authProgress = apNone
  s.authTempUser.setLen(0)

proc applyAuthDecision(bev: ptr bufferevent, s: SMTPSession, d: AuthDecision) =
  case d
  of authOk:
    s.authenticated = true
    smtpReply(bev, 235, "Authentication successful")
  of authInvalid:
    smtpReply(bev, 535, "Authentication credentials invalid")
  of authFailure:
    smtpReply(bev, 454, "Temporary authentication failure")

proc handleAuthFlow(bev: ptr bufferevent, server: SMTPServer, s: SMTPSession, line: string): bool =
  if s.authProgress == apNone:
    return false

  if line == "*":
    s.authProgress = apNone
    s.authTempUser.setLen(0)
    smtpReply(bev, 501, "Authentication canceled")
    return true

  var decoded = ""
  if not decodeB64Safe(line, decoded):
    s.authProgress = apNone
    s.authTempUser.setLen(0)
    smtpReply(bev, 501, "Invalid base64 data")
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
    applyAuthDecision(bev, s, decision)
    return true

  of apLoginUser:
    s.authTempUser = decoded
    s.authProgress = apLoginPass
    smtpReply(bev, 334, "UGFzc3dvcmQ6") # "Password:"
    return true

  of apLoginPass:
    let decision = validateAuth(server, s, s.authTempUser, decoded, "LOGIN")
    s.authProgress = apNone
    s.authTempUser.setLen(0)
    applyAuthDecision(bev, s, decision)
    return true

  of apNone:
    return false

proc closeSession(bev: ptr bufferevent) =
  # Clean up session state and close the connection. This is
  # called when a session needs to be terminated, either due to
  # client QUIT, an error, or other conditions.
  let k = bevKey(bev)
  if sessions.hasKey(k):
    sessions.del(k)
  bufferevent_free(bev)

proc onSMTPWrite(bev: ptr bufferevent, ctx: pointer) {.cdecl.} =
  # LibEvent may call this when the output buffer is drained. If the session is
  # marked as quitting and there's no more data to send, we can safely close the connection.
  discard

proc handleStartTls(bev: ptr bufferevent, server: SMTPServer, s: SMTPSession) =
  if s.tlsActive:
    smtpReply(bev, 503, "TLS already active")
    return
  if not server.enableStartTls or server.tlsCtx == nil:
    smtpReply(bev, 454, "TLS not available")
    return

  smtpReply(bev, 220, "Ready to start TLS")
  discard bufferevent_flush(bev, EV_WRITE, BEV_FLUSH)

  # Drop any pre-TLS pipelined bytes
  s.inbuf.setLen(0)
  let inBuf = bufferevent_get_input(bev)
  if inBuf != nil:
    discard evbuffer_drain(inBuf, evbuffer_get_length(inBuf))

  let ssl = SSL_new(server.tlsCtx)
  if ssl == nil:
    smtpReplyAndClose(bev, 454, "TLS initialization failed")
    return

  let tlsBev = bufferevent_openssl_filter_new(
    server.base,
    bev, # underlying plaintext bufferevent
    ssl,
    BUFFEREVENT_SSL_ACCEPTING,
    (BEV_OPT_CLOSE_ON_FREE or BEV_OPT_DEFER_CALLBACKS).cint
  )

  if tlsBev == nil:
    when declared(SSL_free):
      SSL_free(ssl)
    smtpReplyAndClose(bev, 454, "TLS initialization failed")
    return

  # Session map key changes because bufferevent pointer changes
  let oldKey = bevKey(bev)
  let newKey = bevKey(tlsBev)
  if sessions.hasKey(oldKey):
    let sess = sessions[oldKey]
    sessions.del(oldKey)
    sessions[newKey] = sess

  # RFC 3207: reset protocol state after TLS is established
  s.tlsActive = true
  s.greeted = false
  s.heloName.setLen(0)
  s.authenticated = false
  resetTxn(s)

  bufferevent_setcb(tlsBev, onSMTPRead, onSMTPWrite, onSMTPEvent, cast[pointer](server))
  discard bufferevent_enable(tlsBev, EV_READ or EV_WRITE)

proc startBackgroundDelivery(delivery: SMTPDelivery, req: DeliveryRequest) {.thread, gcsafe.} =
  # Start a background thread to handle message delivery. This allows the SMTP session to respond
  let d = delivery.deliverMessage(req)
  case d
  of ddOk:
    echo "[mx] delivered: from=", req.mailFrom, " to=", req.rcptTo.join(",")
  of ddTempFail:
    echo "[mx] tempfail: from=", req.mailFrom, " to=", req.rcptTo.join(","), " -> spooling"
    discard delivery.spoolDeliver(req)
  of ddPermFail:
    echo "[mx] permfail: from=", req.mailFrom, " to=", req.rcptTo.join(","), " -> spooling"
    discard delivery.spoolDeliver(req)

proc handleSmtpLine(bev: ptr bufferevent, server: SMTPServer, line: string) =
  # This is the main command processing function. It takes a
  # complete line of input from the client and processes it according
  # to the SMTP protocol.
  let k = bevKey(bev)
  if not sessions.hasKey(k): return
  let s = sessions[k]

  # If we're in the middle of an auth flow,
  # handle that first before normal command processing
  if handleAuthFlow(bev, server, s, line): return

  if s.inData:
    if line.len > MaxDataLineLen:
      smtpReplyAndClose(bev, 500, "Line too long")
      return
  elif line.len > MaxCommandLineLen:
    smtpReplyAndClose(bev, 500, "Line too long")
    return

  if s.inData:
    if line == ".":
      let req = DeliveryRequest(
        mailFrom: s.mailFrom,
        rcptTo: s.rcptTo,
        data: s.dataLines.join("\r\n") & "\r\n",
        heloName: s.heloName
      )
      spawn startBackgroundDelivery(server.delivery, req)
      smtpReply(bev, 250, "Message accepted for delivery")
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

  case cmd
  of "HELO":
    s.greeted = true
    s.heloName = arg
    smtpReply(bev, 250, "meowmail.local Hello")
  of "EHLO":
    s.greeted = true
    s.heloName = arg
    smtpReplyEhloCapabilities(bev, smtpHostname(), s, server)
  of "STARTTLS":
    if s.mailFrom.len > 0 or s.rcptTo.len > 0 or s.inData:
      smtpReply(bev, 503, "Bad sequence of commands")
    else:
      handleStartTls(bev, server, s)
  of "AUTH":
    if not s.greeted:
      smtpReply(bev, 503, "Send EHLO/HELO first")
    elif s.inData or s.mailFrom.len > 0 or s.rcptTo.len > 0:
      smtpReply(bev, 503, "Bad sequence of commands")
    elif not supportsAuth(server):
      smtpReply(bev, 503, "Authentication not enabled")
    elif s.authenticated:
      smtpReply(bev, 503, "Already authenticated")
    else:
      let p = arg.splitWhitespace()
      if p.len == 0:
        smtpReply(bev, 501, "Syntax: AUTH <mechanism> [initial-response]")
      else:
        let mech = p[0].toUpperAscii()
        let initial = if p.len > 1: p[1] else: ""
        case mech
        of "PLAIN":
          if initial.len == 0:
            s.authProgress = apPlain
            smtpReply(bev, 334, "")
          else:
            var decoded = ""
            if not decodeB64Safe(initial, decoded):
              smtpReply(bev, 501, "Invalid base64 data")
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
              applyAuthDecision(bev, s, validateAuth(server, s, user, pass, "PLAIN"))
        of "LOGIN":
          if initial.len > 0:
            var userDecoded = ""
            if not decodeB64Safe(initial, userDecoded):
              smtpReply(bev, 501, "Invalid base64 data")
            else:
              s.authTempUser = userDecoded
              s.authProgress = apLoginPass
              smtpReply(bev, 334, "UGFzc3dvcmQ6")
          else:
            s.authProgress = apLoginUser
            smtpReply(bev, 334, "VXNlcm5hbWU6")
        else:
          smtpReply(bev, 504, "Unsupported authentication mechanism")
  of "MAIL":
    if server.requireAuth and not s.authenticated:
      smtpReply(bev, 530, "Authentication required")
    elif not s.greeted:
      smtpReply(bev, 503, "Send HELO/EHLO first")
    elif not arg.toUpperAscii().startsWith("FROM:"):
      smtpReply(bev, 501, "Syntax: MAIL FROM:<address>")
    else:
      s.mailFrom = arg[5..^1].strip()
      s.rcptTo.setLen(0)
      smtpReply(bev, 250, "OK")
  of "RCPT":
    if s.mailFrom.len == 0:
      smtpReply(bev, 503, "Need MAIL FROM first")
    elif not arg.toUpperAscii().startsWith("TO:"):
      smtpReply(bev, 501, "Syntax: RCPT TO:<address>")
    else:
      s.rcptTo.add(arg[3..^1].strip())
      smtpReply(bev, 250, "OK")
  of "DATA":
    if s.rcptTo.len == 0:
      smtpReply(bev, 503, "Need RCPT TO first")
    else:
      s.inData = true
      s.dataLines.setLen(0)
      smtpReply(bev, 354, "End data with <CR><LF>.<CR><LF>")
  of "RSET":
    resetTxn(s)
    smtpReply(bev, 250, "OK")
  of "NOOP":
    smtpReply(bev, 250, "OK")
  of "VRFY", "EXPN":
    smtpReply(bev, 252, "Cannot VRFY/EXPN user")
  of "QUIT":
    s.quitting = true
    smtpReply(bev, 221, "Bye")
    # Stop reading new bytes; let write callback drain and close cleanly.
    discard bufferevent_disable(bev, EV_READ)
    discard bufferevent_flush(bev, EV_WRITE, BEV_FLUSH)
  else:
    smtpReply(bev, 500, "Command unrecognized")

proc onSMTPRead(bev: ptr bufferevent, ctx: pointer) {.cdecl.} =
  # LibEvent calls this when there's data to read from the client.
  # We read complete lines (ending with CRLF) and pass them to `handleSmtpLine`
  # for processing. If the session is in the middle of an authentication flow,
  # we handle that first before normal command processing.
  let server = cast[SMTPServer](ctx)
  let input = bufferevent_get_input(bev)
  let n = evbuffer_get_length(input).int
  if n <= 0: return

  var chunk = newString(n)
  let got = evbuffer_remove(input, addr(chunk[0]), n.csize_t)
  if got <= 0: return
  if got < n: chunk.setLen(got)

  let k = bevKey(bev)
  if not sessions.hasKey(k): return
  let s = sessions[k]
  s.inbuf.add(chunk)

  let maxPendingLen = if s.inData: MaxDataLineLen + 2 else: MaxCommandLineLen + 2
  if s.inbuf.find("\r\n") < 0 and s.inbuf.len > maxPendingLen:
    smtpReplyAndClose(bev, 500, "Line too long")
    return

  while true:
    let idx = s.inbuf.find("\r\n")
    if idx < 0: break

    let line = s.inbuf[0 ..< idx]
    if idx + 2 <= s.inbuf.high:
      s.inbuf = s.inbuf[idx + 2 .. ^1]
    else:
      s.inbuf.setLen(0)

    handleSmtpLine(bev, server, line)
    if not sessions.hasKey(k):
      break

proc onSMTPEvent(bev: ptr bufferevent, events: cshort, ctx: pointer) {.cdecl.} =
  let k = bevKey(bev)

  # QUIT path: never hard-close before pending 221 is drained.
  if sessions.hasKey(k) and sessions[k].quitting:
    let outBuf = bufferevent_get_output(bev)
    if outBuf != nil and evbuffer_get_length(outBuf) > 0:
      discard bufferevent_disable(bev, EV_READ)
      discard bufferevent_flush(bev, EV_WRITE, BEV_FLUSH)
      return
    closeSession(bev)
    return

  if (events and BEV_EVENT_ERROR) != 0 or
     (events and BEV_EVENT_TIMEOUT) != 0 or
     (events and BEV_EVENT_EOF) != 0:
    closeSession(bev)

proc onSMTPConnection(listener: ptr evconnlistener, fd: cint,
                      sockAddr: ptr SockAddr, socklen: cint, ctx: pointer) {.cdecl.} =
  # LibEvent calls this when a new client connection is accepted.
  # We create a new bufferevent for the connection,
  ensureSessionsInit()
  
  if ctx == nil:
    discard close(fd)
    return

  let server = cast[SMTPServer](ctx)
  if server == nil or server.base == nil:
    discard close(fd)
    return

  var
    tlsActiveNow = false
    bev: ptr bufferevent = nil

  if listener == server.listener465:
    if server.tlsCtx == nil:
      discard close(fd)
      return

    let ssl = SSL_new(server.tlsCtx)
    if ssl == nil:
      discard close(fd)
      return
    
    bev = bufferevent_openssl_socket_new(
      server.base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
      (BEV_OPT_CLOSE_ON_FREE or BEV_OPT_DEFER_CALLBACKS).cint
    )
    tlsActiveNow = true
  else:
    bev = bufferevent_socket_new(server.base, fd, BEV_OPT_CLOSE_ON_FREE)

  if bev == nil:
    discard close(fd) # bufferevent creation failed, close the socket and give up
    return

  let k = bevKey(bev)
  sessions[k] = SMTPSession(
    greeted: false,
    heloName: "",
    inData: false,
    quitting: false,
    authenticated: false,
    authProgress: apNone,
    tlsActive: tlsActiveNow
  )

  bufferevent_setcb(bev, onSMTPRead, onSMTPWrite, onSMTPEvent, ctx)
  discard bufferevent_enable(bev, EV_READ or EV_WRITE)
  smtpReply(bev, 220, "meowmail.local ESMTP ready")

proc onListenerError(listener: ptr evconnlistener, ctx: pointer) {.cdecl.} =
  # LibEvent calls this if there's an error on the listener socket. We log the
  # error and break the event loop to shut down the server.
  let server = cast[SMTPServer](ctx)
  let errMsg = $strerror(errno)
  stderr.writeLine("SMTP listener error: ", errMsg, " (errno=", $errno, ")")
  assert event_base_loopbreak(server.base) == 0

proc bindListenerOn(server: SMTPServer, port: Port): ptr evconnlistener =
  var sin: Sockaddr_in
  zeroMem(addr sin, sizeof(sin))
  sin.sin_family = AF_INET.TSa_Family
  sin.sin_port = htons(port.uint16)
  sin.sin_addr.s_addr = htonl(INADDR_ANY)

  let flags = LEV_OPT_REUSEABLE or LEV_OPT_CLOSE_ON_FREE
  result = evconnlistener_new_bind(
    server.base,
    onSMTPConnection,
    cast[pointer](server),
    flags.cuint,
    -1,
    cast[ptr SockAddr](addr sin),
    sizeof(sin).cint
  )
  if result != nil:
    evconnlistener_set_error_cb(result, onListenerError)

proc bindListener587*(server: SMTPServer, port: Port = Port(587)) =
  if server.listener587 != nil: return
  server.enableStartTls = (server.tlsCtx != nil)
  server.listener587 = bindListenerOn(server, port)
  assert server.listener587 != nil, "Failed to bind SMTP submission listener (587)"

proc bindListener465*(server: SMTPServer, port: Port = Port(465)) =
  if server.listener465 != nil: return
  assert server.tlsCtx != nil, "tlsCtx is nil (required for implicit TLS on 465)"
  server.listener465 = bindListenerOn(server, port)
  assert server.listener465 != nil, "Failed to bind SMTPS listener (465)"

proc enableMxDelivery*(server: SMTPServer, cfg = MXProviderConfig()) =
  ## Installs MX delivery provider on this server instance.
  ## If heloName is default/empty, use local hostname.
  var mxCfg = cfg
  if mxCfg.heloName.len == 0 or mxCfg.heloName == "localhost":
    mxCfg.heloName = smtpHostname()
  server.delivery.setProvider(newMXProvider(mxCfg))

proc opensslLastError*(): string =
  let e = ERR_get_error()
  if e == 0: return "no openssl error"
  var buf = newString(256)
  discard ERR_error_string(e, buf.cstring)
  let z = buf.find('\0')
  result = (if z >= 0: buf[0 ..< z] else: buf)

proc setupTlsCtx*(server: SMTPServer, certPath, keyPath: string): bool =
  let certPath = absolutePath(certPath)
  let keyPath = absolutePath(keyPath)

  discard SSL_library_init()

  let tlsMethod = TLS_server_method()
  if tlsMethod == nil:
    stderr.writeLine("TLS error: TLS_server_method() failed")
    return false

  let ctx = SSL_CTX_new(tlsMethod)
  if ctx == nil:
    stderr.writeLine("TLS error: SSL_CTX_new() failed")
    return false

  # discard SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION.cint)

  if SSL_CTX_use_certificate_file(ctx, certPath.cstring, SSL_FILETYPE_PEM.cint) != 1:
    stderr.writeLine("TLS error: certificate load failed: ", opensslLastError())
    SSL_CTX_free(ctx)
    return false

  if SSL_CTX_use_PrivateKey_file(ctx, keyPath.cstring, SSL_FILETYPE_PEM.cint) != 1:
    stderr.writeLine("TLS error: private key load failed: ", opensslLastError())
    SSL_CTX_free(ctx)
    return false

  if SSL_CTX_check_private_key(ctx) != 1:
    stderr.writeLine("TLS error: cert/key mismatch: ", opensslLastError())
    SSL_CTX_free(ctx)
    return false

  if server.tlsCtx != nil:
    SSL_CTX_free(server.tlsCtx)

  server.tlsCtx = ctx
  server.enableStartTls = true
  result = true

proc newSMTPServer*(settings: SMTPSettings): SMTPServer =
  ## Creates a new SMTP server instance based on the provided settings.
  new(result)
  result.base = event_base_new()
  assert result.base != nil, "Failed to create event base"
  result.port = Port(2525) # default port for non-privileged testing
  result.authUsers = initTable[string, string]()
  result.requireAuth = false
  
  # initialize delivery mechanism with spool directory from env or default
  result.delivery = newSMTPDelivery(spoolDir = settings.spoolDirectory, provider = settings.deliveryProvider)

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

  var sin: Sockaddr_in
  zeroMem(addr sin, sizeof(sin)) 
  sin.sin_family = AF_INET.TSa_Family
  sin.sin_port = htons(result.port.uint16)
  sin.sin_addr.s_addr = htonl(INADDR_ANY)

  let flags = LEV_OPT_REUSEABLE or LEV_OPT_CLOSE_ON_FREE
  result.listener = evconnlistener_new_bind(
    result.base,
    onSMTPConnection,
    cast[pointer](result),
    flags.cuint,
    -1,
    cast[ptr SockAddr](addr sin),
    sizeof(sin).cint
  )
  assert result.listener != nil, "Failed to bind SMTP listener"
  evconnlistener_set_error_cb(result.listener, onListenerError)

  var enabledTls: bool
  if settings.certifications.isSome:
    let (certPath, keyPath) = settings.certifications.get()
    enabledTls = result.setupTlsCtx(certPath, keyPath)
    if not enabledTls:
      echo "[smtp] TLS disabled: setupTlsCtx failed (cert/key load error?)"

  if settings.enable587:
    # Enabling submission port 587 is generally recommended to be available
    # regardless of TLS setup, since STARTTLS can be offered as an upgrade
    # if TLS is configured. If TLS isn't configured, the server will simply
    # not offer STARTTLS capability, but can still accept mail on 587.
    result.bindListener587(Port(587))

  if settings.enable465:
    # Port 465 for implicit TLS is only enabled if the TLS context was successfully set up,
    # since implicit TLS requires a TLS handshake immediately upon connection. If TLS isn't
    # available, we skip binding to port 465 to avoid accepting connections that we can't handle properly.
    if enabledTls:
      result.bindListener465(Port(465))
    else:
      echo "[smtp] Skipping 465: TLS context unavailable"

proc start*(server: SMTPServer) =
  ## Starts the SMTP server event loop. This call blocks until the
  ## server is stopped or encounters a fatal error.
  assert server.base != nil
  assert server.listener != nil or server.listener587 != nil or server.listener465 != nil, "No listeners configured"
  assert event_base_dispatch(server.base) > -1
