## End-to-end IMAP server test: starts the server on a high port and drives a
## raw-socket client through auth, mailbox ops, fetch, search, store, append,
## copy/move, expunge and logout.

import std/[net, os, strutils, threadpool, tables, sequtils]
from std/net import Port
import powpow
import meowmail/imap/[imapserver, mailstore]

var failures = 0
proc check(cond: bool, msg: string) =
  if cond: echo "[OK] ", msg
  else:
    echo "[FAIL] ", msg
    inc failures

proc readReply(s: Socket, tag: string): seq[string] =
  while true:
    let line = s.recvLine()
    if line.len == 0: break
    result.add(line)
    if line.startsWith(tag & " "):
      break

proc cmd(s: Socket, tag, command: string): seq[string] =
  s.send(tag & " " & command & "\r\n")
  result = readReply(s, tag)

# unique ports to avoid clashes
let basePort = 4000 + (getCurrentProcessId() mod 500)
let smtpPort = Port(basePort)
let imapPort = Port(basePort + 1)

let base = getTempDir() / "mm-test-imap-" & $getCurrentProcessId()
removeDir(base)
let store = newMaildirStore(base, @["example.com"])
discard store.deliver("a@example.com", "alice@example.com",
  "From: A <a@example.com>\r\nTo: alice@example.com\r\nSubject: Test One\r\n\r\nHello body\r\n")
discard store.deliver("b@example.com", "alice@example.com",
  "From: B <b@example.com>\r\nTo: alice@example.com\r\nSubject: Second\r\n\r\nAnother\r\n")

let server = newIMAPServer(imapPort, store)
server.authUsers["alice"] = "secret"

proc runServer(srv: IMAPServer) {.thread.} =
  {.cast(gcsafe).}:
    srv.start()

var t: Thread[IMAPServer]
createThread(t, runServer, server)
sleep(300)

var s = newSocket()
s.connect("127.0.0.1", imapPort)

check(s.recvLine().startsWith("* OK"), "greeting")

var r = cmd(s, "c1", "CAPABILITY")
check(r[0].contains("UIDPLUS") and r[0].contains("IDLE"), "capabilities")
check(r[^1].startsWith("c1 OK"), "capability ok")

r = cmd(s, "c2", "LOGIN alice@example.com secret")
check(r[^1].startsWith("c2 OK"), "login")

r = cmd(s, "c3", "LIST \"\" \"*\"")
check(r[0].contains("INBOX"), "list inbox")

r = cmd(s, "c4", "SELECT INBOX")
check(r.anyIt(it.startsWith("* 2 ")), "2 messages")
check(r[^1].startsWith("c4 OK"), "select ok")

r = cmd(s, "c5", "FETCH 1:* (FLAGS UID ENVELOPE)")
check(r[0].startsWith("* 1 FETCH") and r[0].contains("ENVELOPE"), "fetch 1")
check(r[1].startsWith("* 2 FETCH"), "fetch 2")

r = cmd(s, "c6", "SEARCH SUBJECT \"Test\"")
check(r[0].contains("* SEARCH 1"), "search subject")

r = cmd(s, "c7", "STORE 1 +FLAGS (\\Seen)")
check(r[0].contains("\\Seen"), "store flags")

r = cmd(s, "c8", "FETCH 1 BODY.PEEK[TEXT]")
check(r.join(" ").contains("Hello body"), "fetch body text")

# COPY to a new mailbox
r = cmd(s, "c9", "CREATE Sent")
check(r[^1].startsWith("c9 OK"), "create Sent")
r = cmd(s, "c10", "COPY 1 Sent")
check(r[^1].startsWith("c10 OK"), "copy ok")
check(r[^1].contains("COPYUID"), "copyuid present")
r = cmd(s, "c11", "SELECT Sent")
check(r.anyIt(it.startsWith("* 1 ")), "sent has 1")
r = cmd(s, "c12", "FETCH 1 (FLAGS UID)")
check(r[0].contains("\\Seen"), "copy preserved \\Seen flag")

# MOVE back to INBOX
r = cmd(s, "c13", "MOVE 1 INBOX")
check(r[^1].startsWith("c13 OK"), "move ok")
check(r.anyIt(it.endsWith("EXPUNGE")), "move expunged source")
r = cmd(s, "c14", "SELECT INBOX")
check(r.anyIt(it.startsWith("* 3 ")), "inbox has 3 after move-back (2 originals + moved copy)")

# APPEND with literal
s.send("c15 APPEND INBOX (\\Seen) {5}\r\n")
let cont = s.recvLine()
check(cont.startsWith("+"), "append continuation")
s.send("hello\r\n")
r = readReply(s, "c15")
check(r[^1].startsWith("c15 OK") and r[^1].contains("APPENDUID"), "append ok")

# SUBSCRIBE + LSUB
r = cmd(s, "c16", "SUBSCRIBE Sent")
check(r[^1].startsWith("c16 OK"), "subscribe")
r = cmd(s, "c17", "LSUB \"\" \"*\"")
check(r[0].contains("Sent") and r[0].contains("\\Subscribed"), "lsub shows subscribed")

# EXPUNGE
r = cmd(s, "c18", "STORE 3 +FLAGS (\\Deleted)")
r = cmd(s, "c19", "EXPUNGE")
check(r.anyIt(it.endsWith("EXPUNGE")), "expunge happened")
check(r[^1].startsWith("c19 OK"), "expunge ok")

r = cmd(s, "c20", "LOGOUT")
check(r.anyIt(it.startsWith("* BYE")), "logout bye")
check(r[^1].startsWith("c20 OK"), "logout ok")

s.close()
server.loop.stop()
joinThread(t)

echo "failures=", failures
quit(if failures == 0: 0 else: 1)
