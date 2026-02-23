# MeowMail - A high-performance SMTP/IMAP server based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

import std/[posix, tables, strutils]
from std/net import Port, `$`

import libevent/bindings/[event, buffer, bufferevent,  http, listener]
import ./smtpauth, ./smtpserver

type
  IMAPCommand* = enum
    cmdUnknown = "UNKNOWN"
    cmdCapability = "CAPABILITY"
    cmdNoop = "NOOP"
    cmdLogout = "LOGOUT"
    cmdLogin = "LOGIN"
    cmdSelect = "SELECT"

  IMAPSession* = ref object
    ## Represents a single IMAP client session. This is stored in a
    ## thread-local table keyed by the bufferevent pointer.
    inbuf: string
      # Buffer for accumulating incoming data until we have complete lines.
    authenticated: bool
      # Whether the client has successfully authenticated.
      # Initially false until LOGIN command succeeds.
    username: string
      # The username of the authenticated client, if any.
    selectedMailbox: string
      # The currently selected mailbox, if any.
    quitting: bool
      # Set to true when the client issues a LOGOUT command,
      # indicating we should close the connection after responding.

  IMAPServer* = ref object
    base*: ptr event_base
      ## The LibEvent event base for this server. This is where all events are registered.
    listener*: ptr evconnlistener
      ## The LibEvent connection listener for accepting new IMAP client connections.
    port*: Port
      ## The port number the server is listening on.
    authUsers*: Table[string, string]
      # a simple in-memory table of username -> password for authentication.
      # todo implement AuthProvider support for IMAP as well, but for now this is sufficient for testing.
    authProvider*: AuthProvider

const
  MaxImapLineLen = 8192

var
  sessions {.threadvar.}: Table[uint, IMAPSession]
  sessionsReady {.threadvar.}: bool

proc ensureSessionsInit() =
  # Initialize the thread-local sessions table if it hasn't been initialized yet.
  if not sessionsReady:
    sessions = initTable[uint, IMAPSession]()
    sessionsReady = true

proc bevKey(bev: ptr bufferevent): uint {.inline.} =
  # Generate a unique key for the bufferevent pointer. We can use this to
  # store session data in a thread-local table
  cast[uint](bev)

proc checkAuth(server: SMTPServer, username,
              password: string, tlsActive: bool): bool =
  if server.authProvider != nil:
    let decision = server.authProvider(AuthRequest(
      username: username,
      password: password,
      remoteIp: "",
      mechanism: "LOGIN"
    ))
    return decision == authOk

proc imapWrite(bev: ptr bufferevent, s: string) =
  # Write a string to the client, followed by CRLF. This is a helper for sending IMAP responses
  discard bufferevent_write(bev, s.cstring, s.len.csize_t)

proc imapUntagged(bev: ptr bufferevent, s: string) =
  # Send an untagged response to the client (starts with "*"). This is a helper for sending IMAP responses
  imapWrite(bev, "* " & s & "\r\n")

proc imapTagged(bev: ptr bufferevent, tag, status, text: string) =
  # Send a tagged response to the client (starts with the command tag). This is a helper for sending IMAP responses
  imapWrite(bev, tag & " " & status & " " & text & "\r\n")

proc closeSession(bev: ptr bufferevent) =
  # Close the client session associated with this bufferevent.
  # This involves removing it from the sessions table and freeing the bufferevent.
  let k = bevKey(bev)
  if sessions.hasKey(k):
    sessions.del(k)
  bufferevent_free(bev)

proc onIMAPRead(bev: ptr bufferevent, ctx: pointer) {.cdecl.}
proc onIMAPEvent(bev: ptr bufferevent, events: cshort, ctx: pointer) {.cdecl.}

proc handleImapLine(bev: ptr bufferevent, server: IMAPServer, line: string) =
  # This is a very minimal IMAP command parser. It only supports a few basic commands
  if line.len == 0: return
  let p = line.splitWhitespace()
  if p.len < 2:
    imapTagged(bev, "*", "BAD", "Malformed command")
    return

  let tag = p[0]
  let cmd = parseEnum[IMAPCommand](p[1].toUpperAscii(), cmdUnknown)
  case cmd
  of cmdCapability:
    imapUntagged(bev, "CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN")
    imapTagged(bev, tag, "OK", "CAPABILITY completed")
  of cmdNoop:
    imapTagged(bev, tag, "OK", "NOOP completed")
  of cmdLogout:
    imapUntagged(bev, "BYE Logging out")
    imapTagged(bev, tag, "OK", "LOGOUT completed")
    let k = bevKey(bev)
    if sessions.hasKey(k): sessions[k].quitting = true
  of cmdLogin:
    # Minimal parser: LOGIN <user> <pass> (no quoted-string parsing yet)
    if p.len < 4:
      imapTagged(bev, tag, "BAD", "Usage: LOGIN <user> <pass>")
      return
    let user = p[2]
    let pass = p[3]
    echo pass
    let k = bevKey(bev)
    if not sessions.hasKey(k): return
    let s = sessions[k]
    if server.authUsers.hasKey(user) and server.authUsers[user] == pass:
      s.authenticated = true
      s.username = user
      imapTagged(bev, tag, "OK", "LOGIN completed")
    else:
      imapTagged(bev, tag, "NO", "Authentication failed")
  of cmdSelect:
    let k = bevKey(bev)
    if not sessions.hasKey(k): return
    let s = sessions[k]
    if not s.authenticated:
      imapTagged(bev, tag, "NO", "Authenticate first")
      return
    if p.len < 3:
      imapTagged(bev, tag, "BAD", "Usage: SELECT <mailbox>")
      return
    s.selectedMailbox = p[2]
    imapUntagged(bev, "FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)")
    imapUntagged(bev, "0 EXISTS")
    imapUntagged(bev, "0 RECENT")
    imapTagged(bev, tag, "OK", "[READ-WRITE] SELECT completed")
  else:
    imapTagged(bev, tag, "BAD", "Unsupported command")

proc onIMAPRead(bev: ptr bufferevent, ctx: pointer) {.cdecl.} =
  # This callback is called by LibEvent when there is data to read from the client.
  let server = cast[IMAPServer](ctx)
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

  if s.inbuf.find("\r\n") < 0 and s.inbuf.len > MaxImapLineLen:
    imapTagged(bev, "*", "BAD", "Line too long")
    closeSession(bev)
    return

  while true:
    let idx = s.inbuf.find("\r\n")
    if idx < 0: break
    let line = s.inbuf[0 ..< idx]
    if idx + 2 <= s.inbuf.high:
      s.inbuf = s.inbuf[idx + 2 .. ^1]
    else:
      s.inbuf.setLen(0)

    handleImapLine(bev, server, line)

    if not sessions.hasKey(k): break
    if sessions[k].quitting:
      closeSession(bev)
      break

proc onIMAPEvent(bev: ptr bufferevent, events: cshort, ctx: pointer) {.cdecl.} =
  # Handle connection close, errors, and timeouts. In any of these cases,
  # we want to clean up the session and free the bufferevent.
  if (events and BEV_EVENT_EOF) != 0 or
     (events and BEV_EVENT_ERROR) != 0 or
     (events and BEV_EVENT_TIMEOUT) != 0:
    closeSession(bev)

proc onIMAPConnection(listener: ptr evconnlistener, fd: cint,
                      sockAddr: ptr SockAddr, socklen: cint, ctx: pointer) {.cdecl.} =
  # This callback is called by LibEvent when a new client connects to the IMAP listener.
  ensureSessionsInit()
  let server = cast[IMAPServer](ctx)
  if server == nil or server.base == nil:
    discard close(fd)
    return

  let bev = bufferevent_socket_new(server.base, fd, BEV_OPT_CLOSE_ON_FREE)
  if bev == nil:
    discard close(fd)
    return

  let k = bevKey(bev)
  sessions[k] = IMAPSession()

  bufferevent_setcb(bev, onIMAPRead, nil, onIMAPEvent, ctx)
  discard bufferevent_enable(bev, EV_READ or EV_WRITE)
  imapUntagged(bev, "OK meowmail IMAP4rev1 ready")

proc newIMAPServer*(port: Port = Port(143)): IMAPServer =
  ## Creates a new IMAP server instance. You can optionally
  ## specify the port to listen on (default is 143).
  new(result)
  result.base = event_base_new()
  assert result.base != nil, "Failed to create event base"
  result.port = port
  result.authUsers = initTable[string, string]()
  result.authUsers["alice"] = "secret" # Example user for testing

  var sin: Sockaddr_in
  zeroMem(addr sin, sizeof(sin))
  sin.sin_family = AF_INET.TSa_Family
  sin.sin_port = htons(result.port.uint16)
  sin.sin_addr.s_addr = htonl(INADDR_ANY)

  let flags = LEV_OPT_REUSEABLE or LEV_OPT_CLOSE_ON_FREE
  result.listener = evconnlistener_new_bind(
    result.base,
    onIMAPConnection,
    cast[pointer](result),
    flags.cuint,
    -1,
    cast[ptr SockAddr](addr sin),
    sizeof(sin).cint
  )
  assert result.listener != nil, "Failed to bind IMAP listener"

proc start*(server: IMAPServer) =
  ## Starts the IMAP server event loop. This will block the current thread.
  assert server.base != nil
  assert server.listener != nil, "No IMAP listener configured"
  assert event_base_dispatch(server.base) > -1