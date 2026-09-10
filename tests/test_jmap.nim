## End-to-end JMAP Core tests: session discovery, Core/echo, error handling.

import std/[unittest, os, strutils, httpclient, json, httpcore]
from std/net import Port
import powpow
import meowmail/jmap/[types, core]
import meowmail/jmap/server as jmapSrv
import meowmail/imap/mailstore

var failures = 0
proc check(cond: bool, msg: string) =
  if cond: echo "[OK] ", msg
  else:
    echo "[FAIL] ", msg
    inc failures

let basePort = 4200 + (getCurrentProcessId() mod 500)
let jmapPort = basePort

let base = getTempDir() / "mm-test-jmap-" & $getCurrentProcessId()
removeDir(base)
let store = newMaildirStore(base, @["example.com"])

# Deliver a message so the store has data
discard store.deliver("a@example.com", "alice@example.com",
  "From: A <a@example.com>\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello JMAP\r\n")

let jmapSvr = jmapSrv.newJMAPServer(store, "alice@example.com", "127.0.0.1", Port(jmapPort))

proc runServer(srv: JMAPServer) {.thread.} =
  {.cast(gcsafe).}:
    srv.start()

var t: Thread[JMAPServer]
createThread(t, runServer, jmapSvr)
sleep(300)

let baseUrl = "http://127.0.0.1:" & $jmapPort
var client = httpclient.newHttpClient()
client.headers = newHttpHeaders([("Content-Type", "application/json")])

proc postJMAP(body: string): (HttpCode, string) =
  ## Send a POST request and return (status, body) without raising on errors.
  let resp = client.request(baseUrl & "/jmap/api",
    httpMethod = HttpPost, body = body)
  (resp.code, resp.body)

# ── Test 1: Session discovery ────────────────────────────────────────────────

block:
  let resp = client.getContent(baseUrl & "/jmap/session")
  let sess = parseJson(resp)
  check sess["username"].getStr == "alice"
  check sess.hasKey("capabilities")
  check sess["capabilities"].hasKey("urn:ietf:params:jmap:core")
  check sess["capabilities"].hasKey("urn:ietf:params:jmap:mail")
  check sess["capabilities"].hasKey("urn:ietf:params:jmap:submission")
  check sess.hasKey("accounts")
  let accts = sess["accounts"]
  check accts.len == 1
  check sess["primaryAccounts"]["urn:ietf:params:jmap:mail"].getStr.len > 0
  check sess.hasKey("apiUrl")
  check sess.hasKey("state")
  echo "[OK] session discovery"

# ── Test 2: Well-known endpoint ──────────────────────────────────────────────

block:
  let resp = client.getContent(baseUrl & "/.well-known/jmap")
  let sess = parseJson(resp)
  check sess["username"].getStr == "alice"
  echo "[OK] /.well-known/jmap"

# ── Test 3: Core/echo ────────────────────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core"],
    "methodCalls": [
      ["Core/echo", {"foo": "bar", "num": 42}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  check respJson.hasKey("methodResponses")
  check respJson.hasKey("sessionState")
  let responses = respJson["methodResponses"]
  check responses.len == 1
  let first = responses[0]
  check first[0].getStr == "Core/echo"
  check first[1]["foo"].getStr == "bar"
  check first[1]["num"].getInt == 42
  check first[2].getStr == "c1"
  echo "[OK] Core/echo"

# ── Test 4: Unknown method ───────────────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core"],
    "methodCalls": [
      ["Fake/method", {}, "c2"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let first = respJson["methodResponses"][0]
  check first[0].getStr == "error"
  check first[1]["type"].getStr == "unknownMethod"
  check first[2].getStr == "c2"
  echo "[OK] unknown method error"

# ── Test 5: Multiple method calls ────────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core"],
    "methodCalls": [
      ["Core/echo", {"a": 1}, "c1"],
      ["Core/echo", {"b": 2}, "c2"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  check respJson["methodResponses"].len == 2
  check respJson["methodResponses"][0][0].getStr == "Core/echo"
  check respJson["methodResponses"][1][0].getStr == "Core/echo"
  check respJson["methodResponses"][0][1]["a"].getInt == 1
  check respJson["methodResponses"][1][1]["b"].getInt == 2
  echo "[OK] multiple method calls"

# ── Test 6: Mailbox/get — returns real data ──────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Mailbox/get", {"accountId": "u1", "ids": ["INBOX"]}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let first = respJson["methodResponses"][0]
  check first[0].getStr == "Mailbox/get"
  check first[1]["accountId"].getStr == "u1"
  check first[1]["list"].kind == JArray
  check first[1]["list"].len == 1
  check first[1]["list"][0]["name"].getStr == "INBOX"
  echo "[OK] Mailbox/get returns real data"

# ── Test 7: Unknown capability ───────────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:fake:capability"],
    "methodCalls": [
      ["Core/echo", {}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http400
  let respJson = parseJson(body)
  check respJson["type"].getStr.contains("unknownCapability")
  echo "[OK] unknown capability error"

# ── Test 8: Empty methodCalls ────────────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core"],
    "methodCalls": []
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http400
  let respJson = parseJson(body)
  check respJson["type"].getStr.contains("limit")
  echo "[OK] empty methodCalls error"

# ── Test 9: Invalid JSON body ────────────────────────────────────────────────

block:
  let (code, body) = postJMAP("{invalid json")
  check code == Http400
  let respJson = parseJson(body)
  check respJson["type"].getStr.contains("notJSON")
  echo "[OK] invalid JSON error"

# ── Test 10: Mailbox/get — list all ──────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Mailbox/get", {"accountId": "u1"}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let first = respJson["methodResponses"][0]
  check first[0].getStr == "Mailbox/get"
  let result = first[1]
  check result["accountId"].getStr == "u1"
  check result["list"].kind == JArray
  check result["list"].len >= 1  # at least INBOX
  # Verify INBOX is present
  var foundInbox = false
  for mb in result["list"].items:
    if mb["name"].getStr == "INBOX":
      foundInbox = true
      check mb["id"].getStr == "INBOX"
      check mb["role"].getStr == "inbox"
      check mb["totalEmails"].getInt >= 1
      check mb["myRights"]["mayReadItems"].getBool == true
  check foundInbox
  echo "[OK] Mailbox/get all"

# ── Test 11: Mailbox/get — specific IDs ──────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Mailbox/get", {"accountId": "u1", "ids": ["INBOX"]}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["list"].len == 1
  check result["list"][0]["name"].getStr == "INBOX"
  check result["notFound"].len == 0
  echo "[OK] Mailbox/get by ID"

# ── Test 12: Mailbox/get — not found ─────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Mailbox/get", {"accountId": "u1", "ids": ["NOPE"]}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["list"].len == 0
  check result["notFound"].len == 1
  check result["notFound"][0].getStr == "NOPE"
  echo "[OK] Mailbox/get not found"

# ── Test 13: Mailbox/set — create ────────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Mailbox/set", {
        "accountId": "u1",
        "create": {
          "crt1": {"name": "Test/Work"}
        }
      }, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["created"].hasKey("crt1")
  let newId = result["created"]["crt1"].getStr
  check newId == "Test/Work"
  echo "[OK] Mailbox/set create"

# ── Test 14: Mailbox/get — verify created mailbox ────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Mailbox/get", {"accountId": "u1", "ids": ["Test/Work"]}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["list"].len == 1
  check result["list"][0]["name"].getStr == "Test/Work"
  check result["list"][0]["totalEmails"].getInt == 0
  check result["list"][0]["parentId"].getStr == "Test"
  echo "[OK] Mailbox/get created"

# ── Test 15: Mailbox/query — filter by name ──────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Mailbox/query", {
        "accountId": "u1",
        "filter": {"name": "Test"},
        "calculateTotal": true
      }, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["ids"].kind == JArray
  check result["ids"].len >= 1
  check result["total"].getInt >= 1
  echo "[OK] Mailbox/query filter"

# ── Test 16: Mailbox/set — destroy ───────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Mailbox/set", {
        "accountId": "u1",
        "destroy": ["Test/Work"]
      }, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["destroyed"].len == 1
  check result["destroyed"][0].getStr == "Test/Work"
  echo "[OK] Mailbox/set destroy"

# ── Test 17: Mailbox/set — cannot destroy INBOX ──────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Mailbox/set", {
        "accountId": "u1",
        "destroy": ["INBOX"]
      }, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["destroyed"].len == 0
  check result.hasKey("notDestroyed")
  check result["notDestroyed"].hasKey("INBOX")
  echo "[OK] Mailbox/set cannot destroy INBOX"

# ── Test 18: Email/get — list all in INBOX ───────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/get", {"accountId": "u1", "mailboxId": "INBOX"}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let first = respJson["methodResponses"][0]
  check first[0].getStr == "Email/get"
  let result = first[1]
  check result["list"].kind == JArray
  check result["list"].len >= 1
  # Verify email structure
  let email = result["list"][0]
  check email.hasKey("id")
  check email.hasKey("mailboxIds")
  check email.hasKey("keywords")
  check email.hasKey("receivedAt")
  check email.hasKey("subject")
  check email.hasKey("from")
  check email.hasKey("to")
  check email.hasKey("headers")
  check email["headers"].kind == JArray
  echo "[OK] Email/get all in INBOX"

# ── Test 19: Email/get — specific ID ─────────────────────────────────────────

block:
  # First get all IDs
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/get", {"accountId": "u1", "mailboxId": "INBOX"}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  let respJson = parseJson(body)
  let allIds = respJson["methodResponses"][0][1]["list"]
  check allIds.len >= 1
  let firstId = allIds[0]["id"].getStr

  # Now fetch by specific ID
  let reqBody2 = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/get", {"accountId": "u1", "ids": [firstId]}, "c2"]
    ]
  }
  let (code2, body2) = postJMAP($reqBody2)
  check code2 == Http200
  let respJson2 = parseJson(body2)
  let result = respJson2["methodResponses"][0][1]
  check result["list"].len == 1
  check result["list"][0]["id"].getStr == firstId
  check result["notFound"].len == 0
  echo "[OK] Email/get by ID"

# ── Test 20: Email/get — not found ───────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/get", {"accountId": "u1", "ids": ["99999"]}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["list"].len == 0
  check result["notFound"].len == 1
  check result["notFound"][0].getStr == "99999"
  echo "[OK] Email/get not found"

# ── Test 21: Email/query — all emails ────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/query", {"accountId": "u1", "calculateTotal": true}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["ids"].kind == JArray
  check result["ids"].len >= 1
  check result["total"].getInt >= 1
  echo "[OK] Email/query all"

# ── Test 22: Email/query — filter by subject ─────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/query", {
        "accountId": "u1",
        "filter": {"subject": "Test"},
        "calculateTotal": true
      }, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["ids"].kind == JArray
  check result["total"].getInt >= 1
  echo "[OK] Email/query filter subject"

# ── Test 23: Email/set — create (append) ─────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/set", {
        "accountId": "u1",
        "create": {
          "crt1": {
            "mailboxIds": {"INBOX": true},
            "keywords": {"\\Seen": true},
            "blobId": "From: bob@example.com\r\nTo: alice@example.com\r\nSubject: JMAP Test\r\n\r\nHello from JMAP"
          }
        }
      }, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["created"].hasKey("crt1")
  let newId = result["created"]["crt1"].getStr
  check newId.len > 0
  echo "[OK] Email/set create"

# ── Test 24: Email/set — update keywords ─────────────────────────────────────

block:
  # First get an email ID
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/get", {"accountId": "u1", "mailboxId": "INBOX"}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  let respJson = parseJson(body)
  let allIds = respJson["methodResponses"][0][1]["list"]
  check allIds.len >= 1
  let emailId = allIds[0]["id"].getStr

  # Update keywords
  let reqBody2 = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/set", {
        "accountId": "u1",
        "update": {
          (emailId): {
            "keywords": {"\\Seen": true, "\\Flagged": true}
          }
        }
      }, "c2"]
    ]
  }
  let (code2, body2) = postJMAP($reqBody2)
  check code2 == Http200
  let respJson2 = parseJson(body2)
  let result = respJson2["methodResponses"][0][1]
  check result["updated"].len == 1
  echo "[OK] Email/set update keywords"

# ── Test 25: Email/set — destroy ─────────────────────────────────────────────

block:
  # Get the last email (the one we just created)
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/get", {"accountId": "u1", "mailboxId": "INBOX"}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  let respJson = parseJson(body)
  let allIds = respJson["methodResponses"][0][1]["list"]
  check allIds.len >= 1
  let emailId = allIds[^1]["id"].getStr

  # Destroy it
  let reqBody2 = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/set", {
        "accountId": "u1",
        "destroy": [emailId]
      }, "c2"]
    ]
  }
  let (code2, body2) = postJMAP($reqBody2)
  check code2 == Http200
  let respJson2 = parseJson(body2)
  let result = respJson2["methodResponses"][0][1]
  check result["destroyed"].len == 1
  check result["destroyed"][0].getStr == emailId
  echo "[OK] Email/set destroy"

# ── Test 26: Identity/get ────────────────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core"],
    "methodCalls": [
      ["Identity/get", {"accountId": "u1"}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let first = respJson["methodResponses"][0]
  check first[0].getStr == "Identity/get"
  let result = first[1]
  check result["list"].kind == JArray
  check result["list"].len == 1
  let identity = result["list"][0]
  check identity["id"].getStr == "id1"
  check identity["name"].getStr == "alice"
  check identity["email"].getStr.contains("@")
  check identity["mayDelete"].getBool == false
  echo "[OK] Identity/get"

# ── Test 27: Identity/get — specific ID ──────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core"],
    "methodCalls": [
      ["Identity/get", {"accountId": "u1", "ids": ["id1"]}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["list"].len == 1
  check result["notFound"].len == 0
  echo "[OK] Identity/get by ID"

# ── Test 28: Identity/get — not found ────────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core"],
    "methodCalls": [
      ["Identity/get", {"accountId": "u1", "ids": ["nope"]}, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["list"].len == 0
  check result["notFound"].len == 1
  echo "[OK] Identity/get not found"

# ── Test 29: EmailSubmission/set — create ────────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail",
              "urn:ietf:params:jmap:submission"],
    "methodCalls": [
      ["EmailSubmission/set", {
        "accountId": "u1",
        "create": {
          "crt1": {
            "identityId": "id1",
            "emailId": "1",
            "envelope": {
              "mailFrom": {"name": "Alice", "email": "alice@example.com"},
              "rcptTo": [{"name": "Bob", "email": "bob@example.com"}]
            }
          }
        }
      }, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let first = respJson["methodResponses"][0]
  check first[0].getStr == "EmailSubmission/set"
  let result = first[1]
  check result["created"].hasKey("crt1")
  check result["created"]["crt1"]["id"].getStr.len > 0
  check result["created"]["crt1"]["status"].getStr == "queued"
  echo "[OK] EmailSubmission/set create"

# ── Test 30: EmailSubmission/set — missing envelope ──────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission"],
    "methodCalls": [
      ["EmailSubmission/set", {
        "accountId": "u1",
        "create": {
          "crt1": {
            "identityId": "id1",
            "emailId": "1"
          }
        }
      }, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["notCreated"].hasKey("crt1")
  echo "[OK] EmailSubmission/set missing envelope"

# ── Test 31: EmailSubmission/set — destroy ───────────────────────────────────

block:
  let reqBody = %*{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission"],
    "methodCalls": [
      ["EmailSubmission/set", {
        "accountId": "u1",
        "destroy": ["fake-id"]
      }, "c1"]
    ]
  }
  let (code, body) = postJMAP($reqBody)
  check code == Http200
  let respJson = parseJson(body)
  let result = respJson["methodResponses"][0][1]
  check result["destroyed"].len == 1
  echo "[OK] EmailSubmission/set destroy"

# ── Cleanup ───────────────────────────────────────────────────────────────────

client.close()
jmapSvr.loop.stop()
joinThread(t)

echo "failures=", failures
quit(if failures == 0: 0 else: 1)
