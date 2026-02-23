# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

import std/[net, nativesockets, strutils,
          threadpool, base64, tables, openssl]

## This module implements a separate socket server for handling SMTP
## submissions on port 587. This allows the main SMTP server to focus on receiving
## messages from other mail servers, while the submission server can handle client connections
## for sending mail.
## 
## Initially, this was implemented using LibEvent's API,
## but looks like there is a bug that segfaults in `bufferevent_openssl_socket_new`
## https://github.com/libevent/libevent/issues/1774

import ./smtpdelivery, ./smtpauth, ./smtpserver

type
  AuthPhase* = enum
    ## Represents the current step in a multi-step authentication process.
    apNone, apUser, apPass

  SubmissionState* = object
    greeted: bool
      # Whether the client has sent EHLO/HELO yet. This is required before accepting MAIL FROM.
    tlsActive: bool
      # Whether the connection is currently using TLS. This affects whether we can allow authentication, and may also be relevant for policy decisions in the future.
    authenticated: bool
    authPhase: AuthPhase
    authUser: string
    mailFrom: string
    rcptTo: seq[string]
    inData: bool
    dataLines: seq[string]

  ClientConn = object
    sock: Socket
    fd: SocketHandle
    ssl: SSLPtr
    tlsActive: bool
    inBuf: string

proc deliverInBackground(delivery: SMTPDelivery, req: DeliveryRequest) {.thread, gcsafe.} =
  let d = delivery.deliverMessage(req)
  if d != ddOk:
    discard delivery.spoolDeliver(req)

proc nsSend(fd: SocketHandle, data: string): bool =
  var sent = 0
  while sent < data.len:
    let p = cast[pointer](unsafeAddr data[sent])
    let n = send(fd, p, cint(data.len - sent), 0)
    if n <= 0: return false
    sent += n
  true

proc tlsSend(ssl: SSLPtr, data: string): bool =
  var sent = 0
  while sent < data.len:
    let p = cast[cstring](unsafeAddr data[sent])
    let n = SSL_write(ssl, p, data.len - sent)   # int, not cint
    if n <= 0: return false
    sent += n
  true

proc sendLine(c: var ClientConn, s: string): bool =
  let wire = s & "\r\n"
  if c.tlsActive:
    tlsSend(c.ssl, wire) else: nsSend(c.fd, wire)

proc reply(c: var ClientConn, code: int, msg: string): bool {.discardable.} =
  sendLine(c, $code & " " & msg)

proc connReadByte(c: var ClientConn, ch: var char): bool =
  if c.tlsActive:
    var b: array[1, char]
    let n = SSL_read(c.ssl, cast[cstring](addr b[0]), 1)  # cstring + int
    if n == 1:
      ch = b[0]
      return true
    return false
  else:
    let n = recv(c.fd, addr ch, 1, 0)
    result = n == 1

proc recvLine(c: var ClientConn, line: var string): bool =
  line.setLen(0)
  while true:
    var ch: char
    if not connReadByte(c, ch):
      return false
    if ch == '\n':
      return true
    if ch != '\r':
      line.add(ch)
      if line.len > 4096: return false

proc decodeB64Safe(s: string): string =
  try:
    result = decode(s.strip())
  except CatchableError:
    result = ""

proc checkAuth(server: SMTPServer, username,
            password: string, tlsActive: bool): bool =
  if server.authProvider != nil:
    let decision = server.authProvider(AuthRequest(
      username: username,
      password: password,
      remoteIp: "",
    ))
    return decision == authOk
  if server.authUsers.len > 0:
    return server.authUsers.hasKey(username) and server.authUsers[username] == password
  false

proc upgradeStartTls(c: var ClientConn, tlsCtx: SSL_CTX): bool =
  if tlsCtx == nil: return false
  let ssl = SSL_new(tlsCtx)
  if ssl == nil: return false
  if SSL_set_fd(ssl, c.fd) != 1:
    SSL_free(ssl)
    return false
  if SSL_accept(ssl) != 1:
    SSL_free(ssl)
    return false
  c.ssl = ssl
  c.tlsActive = true
  true

proc handleClient(sock: Socket, server: SMTPServer) =
  var conn = ClientConn(sock: sock, fd: SocketHandle(sock.getFd()), ssl: nil, tlsActive: false, inBuf: "")
  var st = SubmissionState(
    greeted: false, tlsActive: false, authenticated: false, authPhase: apNone
  )

  reply(conn, 220, "meowmail.local ESMTP ready")

  try:
    while true:
      var line = ""
      if not recvLine(conn, line): break
      line = line.strip()

      if st.authPhase == apUser:
        let u = decodeB64Safe(line)
        if u.len == 0:
          reply(conn, 535, "Authentication failed")
          st.authPhase = apNone
        else:
          st.authUser = u
          st.authPhase = apPass
          discard sendLine(conn, "334 UGFzc3dvcmQ6") # Password:
        continue
      elif st.authPhase == apPass:
        let p = decodeB64Safe(line)
        if checkAuth(server, st.authUser, p, st.tlsActive):
          st.authenticated = true
          reply(conn, 235, "Authentication successful")
        else:
          reply(conn, 535, "Authentication failed")
        st.authPhase = apNone
        st.authUser.setLen(0)
        continue
      if st.inData:
        if line == ".":
          let req = DeliveryRequest(
            mailFrom: st.mailFrom,
            rcptTo: st.rcptTo,
            data: st.dataLines.join("\r\n") & "\r\n",
            heloName: "submission"
          )
          spawn deliverInBackground(server.delivery, req)
          reply(conn, 250, "Message accepted for delivery")
          st.inData = false
          st.mailFrom.setLen(0)
          st.rcptTo.setLen(0)
          st.dataLines.setLen(0)
        else:
          st.dataLines.add(if line.len > 0 and line[0] == '.': line[1..^1] else: line)
        continue
      let p = line.split(' ', maxsplit = 1)
      let cmd = parseEnum[SMTPCommand](p[0].toUpperAscii(), SMTPCommand.smtpUnknownCmd)
      let arg = if p.len > 1: p[1].strip() else: ""
      case cmd
      of EHLO, HELO:
        st.greeted = true
        discard sendLine(conn, "250-meowmail.local Hello")
        discard sendLine(conn, "250-PIPELINING")
        discard sendLine(conn, "250-8BITMIME")
        if not st.tlsActive and server.tlsCtx != nil:
          discard sendLine(conn, "250-STARTTLS")
        if server.authProvider != nil or server.authUsers.len > 0:
          discard sendLine(conn, "250-AUTH LOGIN PLAIN")
        discard sendLine(conn, "250 HELP")

      of STARTTLS:
        if st.tlsActive:
          reply(conn, 503, "TLS already active")
        elif server.tlsCtx == nil:
          reply(conn, 454, "TLS not available")
        else:
          reply(conn, 220, "Ready to start TLS")
          if not upgradeStartTls(conn, server.tlsCtx):
            break
          st.tlsActive = true
          st.greeted = false
          st.authenticated = false
          st.authPhase = apNone
      of AUTH:
        if arg.len == 0:
          reply(conn, 501, "Syntax: AUTH mechanism")
        else:
          let ap = arg.split(' ')
          let mech = ap[0].toUpperAscii()
          if mech != "LOGIN":
            reply(conn, 504, "Unsupported auth mechanism")
          elif ap.len > 1:
            # AUTH LOGIN <base64-user>
            let u = decodeB64Safe(ap[1])
            if u.len == 0:
              reply(conn, 535, "Authentication failed")
            else:
              st.authUser = u
              st.authPhase = apPass
              discard sendLine(conn, "334 UGFzc3dvcmQ6")
          else:
            st.authPhase = apUser
            discard sendLine(conn, "334 VXNlcm5hbWU6") # Username:
      of MAIL:
        if not st.greeted:
          reply(conn, 503, "Send EHLO first")
        elif server.requireAuth and not st.authenticated:
          reply(conn, 530, "Authentication required")
        elif not arg.toUpperAscii().startsWith("FROM:"):
          reply(conn, 501, "Syntax: MAIL FROM:<address>")
        else:
          st.mailFrom = arg[5..^1].strip()
          st.rcptTo.setLen(0)
          reply(conn, 250, "OK")
      of RCPT:
        if st.mailFrom.len == 0:
          reply(conn, 503, "Need MAIL FROM first")
        elif not arg.toUpperAscii().startsWith("TO:"):
          reply(conn, 501, "Syntax: RCPT TO:<address>")
        else:
          st.rcptTo.add(arg[3..^1].strip())
          reply(conn, 250, "OK")
      of DATA:
        if st.rcptTo.len == 0:
          reply(conn, 503, "Need RCPT TO first")
        else:
          st.inData = true
          st.dataLines.setLen(0)
          reply(conn, 354, "End data with <CR><LF>.<CR><LF>")
      of RSET:
        st.mailFrom.setLen(0)
        st.rcptTo.setLen(0)
        st.inData = false
        st.dataLines.setLen(0)
        reply(conn, 250, "OK")
      of NOOP:
        reply(conn, 250, "OK")
      of QUIT:
        reply(conn, 221, "Bye")
        break
      else:
        reply(conn, 500, "Command unrecognized")
  except CatchableError:
    discard
  finally:
    if conn.ssl != nil:
      discard SSL_shutdown(conn.ssl)
      SSL_free(conn.ssl)
    conn.sock.close()

proc startSubmissionSocketServer*(server: SMTPServer, port = Port(587)) {.thread.} =
  ## Starts a separate socket server for handling SMTP submissions
  ## on the specified port (default 587). This allows the main SMTP server
  ## to focus on.
  var s = newSocket()
  s.setSockOpt(OptReuseAddr, true)
  s.bindAddr(port)
  s.listen()
  while true:
    var c = newSocket()
    s.accept(c)
    handleClient(c, server)