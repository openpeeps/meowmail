## Unit tests for the Maildir store and message parser backing the IMAP server.

import std/[os, strutils, tables]
import unittest
import meowmail/imap/[mailstore, msgparse]

suite "mailstore":
  var base: string
  var store: MaildirStore

  setup:
    base = getTempDir() / "mm-test-store-" & $getCurrentProcessId()
    removeDir(base)
    store = newMaildirStore(base, @["example.com"])

  teardown:
    removeDir(base)

  test "deliver + open + uid stability":
    check store.isLocal("alice@example.com")
    check not store.isLocal("alice@other.com")
    check store.deliver("a@example.com", "alice@example.com",
      "From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n")
    let mb = store.openMailbox("alice", "INBOX")
    check mb.messages.len == 1
    check mb.messages[0].uid == 1
    check mb.messages[0].recent
    let data = loadMessageData(mb, mb.messages[0])
    check data.contains("Return-Path: <a@example.com>")
    check data.contains("Delivered-To: alice@example.com")
    let mb2 = store.openMailbox("alice", "INBOX")
    check mb2.messages[0].uid == 1
    check mb2.uidvalidity == mb.uidvalidity

  test "flags persist across move new->cur":
    check store.deliver("a@example.com", "alice@example.com", "Subject: x\r\n\r\nb")
    let mb = store.openMailbox("alice", "INBOX")
    updateFlags(mb, mb.messages[0], {mfSeen, mfFlagged})
    check mb.messages[0].dir == "cur"
    check mfSeen in mb.messages[0].flags
    let mb2 = store.openMailbox("alice", "INBOX")
    check mb2.messages[0].flags == {mfSeen, mfFlagged}
    check not mb2.messages[0].recent

  test "mailbox CRUD":
    check store.createMailbox("alice", "Sent")
    check store.createMailbox("alice", "Archive/2025")
    check "Sent" in store.listMailboxes("alice")
    check "Archive/2025" in store.listMailboxes("alice")
    check store.renameMailbox("alice", "Archive/2025", "Archive/2026")
    check store.mailboxExists("alice", "Archive/2026")
    check store.deleteMailbox("alice", "Archive/2026")

  test "append assigns uid":
    check store.deliver("a@example.com", "alice@example.com", "Subject: a\r\n\r\nb")
    let res = store.appendMessage("alice", "INBOX", {mfSeen}, "Subject: appended\r\n\r\nc\r\n")
    check res.ok
    check res.uid == 2
    let mb = store.openMailbox("alice", "INBOX")
    check mb.messages.len == 2

  test "seq and uid set expansion":
    check store.deliver("a@example.com", "alice@example.com", "Subject: a\r\n\r\nb")
    check store.deliver("a@example.com", "alice@example.com", "Subject: b\r\n\r\nc")
    let mb = store.openMailbox("alice", "INBOX")
    check mb.seqSetToUids("1:*").len == 2
    check mb.uidSetToUids("2").len == 1

suite "msgparse":
  test "multipart envelope + bodystructure":
    let sample = "From: \"Alice A\" <alice@example.com>\r\n" &
      "To: bob@example.com\r\n" &
      "Subject: =?utf-8?B?SGVsbG8=?=\r\n" &
      "Date: Mon, 06 Jan 2026 12:00:00 +0100\r\n" &
      "Message-ID: <abc@example.com>\r\n" &
      "Content-Type: multipart/alternative; boundary=\"b1\"\r\n\r\n" &
      "--b1\r\nContent-Type: text/plain\r\n\r\nplain\r\n" &
      "--b1\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\nPGI+aGk8L2I+\r\n" &
      "--b1--\r\n"
    let parsed = parseMessage(sample)
    check parsed.envelope.subject == "Hello"
    check parsed.envelope.fromList.len == 1
    check parsed.envelope.fromList[0].name == "Alice A"
    check parsed.root.mainType == "multipart"
    check parsed.root.parts.len == 2
    let bs = renderBodyStructure(parsed.root, true)
    check bs.startsWith("((\"text\" \"plain\"")
    check textContent(parsed).contains("plain")
    check textContent(parsed).contains("hi")
