# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

import std/[posix, tables, strutils,
            base64, os, httpclient, json]
from std/net import Port, `$`

import pkg/libevent/bindings/[event, buffer, bufferevent, http, listener]

const
  MaxCommandLineLen = 510 # 512 including CRLF
  MaxDataLineLen = 998    # 1000 including CRLF

type
  SMTPCommand* = enum
    HELO, EHLO, AUTH, MAIL, RCPT, DATA, QUIT, RSET, NOOP, VRFY, EXPN

  AuthProgress* = enum
    apNone, apPlain, apLoginUser, apLoginPass

  AuthDecision* = enum
    adOk, adInvalid, adTempFail

  AuthRequest* = object
    username*: string
      ## The username provided by the client during authentication.
    password*: string
      ## The password provided by the client during authentication.
    mechanism*: string
      ## The authentication mechanism being used (e.g., "PLAIN", "LOGIN").
    remoteIp*: string
      ## The IP address of the client attempting to authenticate.
    heloName*: string
      ## The HELO/EHLO name provided by the client, which may be useful for
      ## logging or authentication decisions.

  AuthProvider* = proc(req: AuthRequest): AuthDecision {.gcsafe.}
    ## A callback type for providing authentication decisions. The server will call

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

  SMTPServer* = ref object
    ## Represents the SMTP server instance, including its configuration and state.
    base*: ptr event_base
      ## The libevent event base used for managing events and the server loop.
    listener*: ptr evconnlistener
      ## The libevent connection listener that accepts incoming SMTP connections.
    port*: Port
      ## The port number on which the SMTP server is listening for incoming connections.
    requireAuth*: bool
      ## Whether the server requires authentication before accepting MAIL commands.
    authUsers*: Table[string, string] # fallback local auth
      ## A table of username-password pairs for simple local authentication. This is used if no `authProvider` is set.
    authProvider*: AuthProvider
      ## An optional callback for handling authentication requests. If set, this will be used instead of `authUsers` for authentication decisions.

var sessions {.threadvar.}: Table[uint, SMTPSession]

proc bevKey(bev: ptr bufferevent): uint {.inline.} = cast[uint](bev)
proc supportsAuth(server: SMTPServer): bool = server.authProvider != nil or server.authUsers.len > 0

proc smtpReply(bev: ptr bufferevent, code: int, msg: string) =
  let line = $code & " " & msg & "\r\n"
  discard bufferevent_write(bev, line.cstring, line.len.csize_t)

proc smtpReplyMulti(bev: ptr bufferevent, code: int, msg: string, hasMore: bool) =
  let sep = if hasMore: "-" else: " "
  let line = $code & sep & msg & "\r\n"
  discard bufferevent_write(bev, line.cstring, line.len.csize_t)

proc smtpHostname(): string =
  var host = newString(256)
  if gethostname(host.cstring, host.len.cint) == 0:
    let nul = host.find('\0')
    result = if nul >= 0: host[0 ..< nul] else: host
    result = result.strip()
  if result.len == 0:
    result = "meowmail.local"

proc smtpReplyEhloCapabilities(bev: ptr bufferevent, hostname: string, offerAuth: bool) =
  smtpReplyMulti(bev, 250, hostname & " Hello", true)
  smtpReplyMulti(bev, 250, "PIPELINING", true)
  smtpReplyMulti(bev, 250, "8BITMIME", true)
  if offerAuth:
    smtpReplyMulti(bev, 250, "AUTH PLAIN LOGIN", true)
  smtpReplyMulti(bev, 250, "HELP", false)

proc decodeB64Safe(encoded: string, decoded: var string): bool =
  try:
    decoded = decode(encoded)
    result = true
  except CatchableError:
    result = false

proc newHTTPAuthProvider*(url: string, bearerToken = "", timeoutMs = 1200): AuthProvider =
  ## POST url with JSON: {"username":"...","password":"...","mechanism":"...","remoteIp":"...","heloName":"..."}
  ## Expected:
  ##   200 + {"ok":true} => adOk
  ##   401/403           => adInvalid
  ##   timeout/5xx/etc   => adTempFail
  var client = newHttpClient(timeout = timeoutMs)
  result = proc(req: AuthRequest): AuthDecision {.gcsafe, raises: [].} =
    try:
      var headers = newHttpHeaders()
      headers["Content-Type"] = "application/json"
      if bearerToken.len > 0:
        headers["Authorization"] = "Bearer " & bearerToken

      let payload = %*{
        "username": req.username,
        "password": req.password,
        "mechanism": req.mechanism,
        "remoteIp": req.remoteIp,
        "heloName": req.heloName
      }

      let resp = client.request(url, httpMethod = HttpPost, headers = headers, body = $payload)
      let code = resp.code.int

      if code == 200:
        try:
          let node = parseJson(resp.body)
          if node.kind == JObject and node.hasKey("ok") and node["ok"].getBool(false):
            return adOk
          return adInvalid
        except CatchableError:
          return adTempFail
      elif code == 401 or code == 403:
        return adInvalid
      elif code >= 500:
        return adTempFail
      else:
        return adInvalid
    except CatchableError:
      return adTempFail

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
    return adOk
  adInvalid

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
  of adOk:
    s.authenticated = true
    smtpReply(bev, 235, "Authentication successful")
  of adInvalid:
    smtpReply(bev, 535, "Authentication credentials invalid")
  of adTempFail:
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
  let k = bevKey(bev)
  if not sessions.hasKey(k): return
  let s = sessions[k]
  if s.quitting:
    let outBuf = bufferevent_get_output(bev)
    if outBuf == nil or evbuffer_get_length(outBuf) == 0:
      closeSession(bev)

proc handleSmtpLine(bev: ptr bufferevent, server: SMTPServer, line: string) =
  let k = bevKey(bev)
  if not sessions.hasKey(k): return
  let s = sessions[k]

  # If we're in the middle of an auth flow, handle that first before normal command processing
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
      smtpReply(bev, 250, "Message accepted for delivery")
      resetTxn(s)
      return
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
    smtpReplyEhloCapabilities(bev, smtpHostname(), supportsAuth(server) and not s.authenticated)

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
  # LibEvent calls this when certain events occur on the connection, such as EOF, errors, or timeouts.
  if (events and BEV_EVENT_EOF) != 0 or
     (events and BEV_EVENT_ERROR) != 0 or
     (events and BEV_EVENT_TIMEOUT) != 0:
    closeSession(bev)

proc onSMTPConnection(listener: ptr evconnlistener, fd: cint,
                      sockAddr: ptr SockAddr, socklen: cint, ctx: pointer) {.cdecl.} =
  # LibEvent calls this when a new client connection is accepted.
  # We create a new bufferevent for the connection,
  let server = cast[SMTPServer](ctx)
  let bev = bufferevent_socket_new(server.base, fd, BEV_OPT_CLOSE_ON_FREE)
  if bev == nil:
    discard close(fd)
    return

  let k = bevKey(bev)
  sessions[k] = SMTPSession(
    greeted: false,
    heloName: "",
    inData: false,
    quitting: false,
    authenticated: false,
    authProgress: apNone
  )

  bufferevent_setcb(bev, onSMTPRead, onSMTPWrite, onSMTPEvent, cast[pointer](server))
  discard bufferevent_enable(bev, EV_READ or EV_WRITE)
  smtpReply(bev, 220, "meowmail.local ESMTP ready")

proc onListenerError(listener: ptr evconnlistener, ctx: pointer) {.cdecl.} =
  # LibEvent calls this if there's an error on the listener socket. We log the
  # error and break the event loop to shut down the server.
  let server = cast[SMTPServer](ctx)
  let errMsg = $strerror(errno)
  stderr.writeLine("SMTP listener error: ", errMsg, " (errno=", $errno, ")")
  assert event_base_loopbreak(server.base) == 0

proc newSMTPServer*(port: Port = Port(2525)): SMTPServer =
  ## Creates a new SMTP server instance listening on the specified port. The server
  new(result)
  result.base = event_base_new()
  assert result.base != nil, "Failed to create event base"
  result.port = port
  result.authUsers = initTable[string, string]()
  result.requireAuth = false

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

proc start*(server: SMTPServer) =
  ## Starts the SMTP server event loop. This call blocks until the
  ## server is stopped or encounters a fatal error.
  assert server.base != nil
  assert server.listener != nil
  assert event_base_dispatch(server.base) > -1