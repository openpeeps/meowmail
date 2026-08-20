## MeowMail JMAP — Core methods and session discovery (RFC 8620 §2-4).

import std/[tables, strutils, options]
import openparser/json
import ../imap/mailstore
import ./types
import ./mailboxes
import ./emails
import ./submissions

type
  JMAPContext* = ref object
    ## Shared state for the JMAP server, passed to all method handlers.
    store*: MaildirStore
    state*: string                    ## Current session state string
    stateCounter*: int                ## Monotonic counter, incremented on writes
    username*: string                 ## Authenticated user's email/local-part
    accountId*: string                ## Single account ID (e.g. "u1")

proc newJMAPContext*(store: MaildirStore, username: string): JMAPContext =
  result = JMAPContext(
    store: store,
    state: "s-0",
    stateCounter: 0,
    username: username,
    accountId: "u1",
  )

proc bumpState*(ctx: JMAPContext) =
  ## Increment the state counter and update the state string.
  ## Call after any write operation (set, append, expunge).
  inc ctx.stateCounter
  ctx.state = "s-" & $ctx.stateCounter

# ── Session Object (RFC 8620 §2) ────────────────────────────────────────────

proc buildCoreCapability*(): JsonNode =
  ## Build the `urn:ietf:params:jmap:core` capability object.
  result = newJObject()
  result["maxSizeUpload"] = newJInt(50_000_000)
  result["maxConcurrentUpload"] = newJInt(4)
  result["maxSizeRequest"] = newJInt(10_000_000)
  result["maxConcurrentRequests"] = newJInt(8)
  result["maxCallsInRequest"] = newJInt(32)
  result["maxObjectsInGet"] = newJInt(500)
  result["maxObjectsInSet"] = newJInt(500)
  result["collationAlgorithms"] = %*["i;ascii-numeric", "i;ascii-casemap", "i;unicode-casemap"]

proc buildSession*(ctx: JMAPContext, host: string, port: int): JsonNode =
  ## Build the full JMAP Session Object (RFC 8620 §2).
  let accountId = ctx.accountId
  let capabilities = newJObject()
  capabilities["urn:ietf:params:jmap:core"] = buildCoreCapability()
  capabilities["urn:ietf:params:jmap:mail"] = newJObject()
  capabilities["urn:ietf:params:jmap:submission"] = newJObject()

  let accounts = newJObject()
  var acct = newJObject()
  acct["name"] = newJString(ctx.username)
  acct["isPersonal"] = newJBool(true)
  acct["isReadOnly"] = newJBool(false)
  var acctCaps = newJObject()
  acctCaps["urn:ietf:params:jmap:mail"] = newJObject()
  acctCaps["urn:ietf:params:jmap:submission"] = newJObject()
  acct["accountCapabilities"] = acctCaps
  accounts[accountId] = acct

  let primaryAccounts = newJObject()
  primaryAccounts["urn:ietf:params:jmap:mail"] = newJString(accountId)
  primaryAccounts["urn:ietf:params:jmap:submission"] = newJString(accountId)

  let base = "http://" & host & ":" & $port
  result = newJObject()
  result["capabilities"] = capabilities
  result["accounts"] = accounts
  result["primaryAccounts"] = primaryAccounts
  result["username"] = newJString(ctx.username)
  result["apiUrl"] = newJString(base & "/jmap/api")
  result["downloadUrl"] = newJString(base & "/jmap/download/{accountId}/{blobId}/{name}?type={type}")
  result["uploadUrl"] = newJString(base & "/jmap/upload/{accountId}/")
  result["eventSourceUrl"] = newJString(base & "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}")
  result["state"] = newJString(ctx.state)

# ── Core/echo (RFC 8620 §4) ─────────────────────────────────────────────────

proc handleCoreEcho*(args: JsonNode, callId: string): seq[JsonNode] =
  ## Core/echo: returns exactly the same arguments as the response.
  ## The server MUST validate the method name is exactly "Core/echo".
  ## RFC 8620 §4: "The server MUST do exactly the same as if the client
  ## had called the method with the same arguments."
  newJMAPOkResponse("Core/echo", args, callId)

# ── Method dispatch ──────────────────────────────────────────────────────────

proc handleMethod*(ctx: JMAPContext, methodName: string,
                   args: JsonNode, callId: string): seq[JsonNode] =
  ## Dispatch a single JMAP method call and return the response triple.
  case methodName
  of "Core/echo":
    handleCoreEcho(args, callId)
  of "Mailbox/get":
    handleMailboxGet(ctx.store, ctx.username, ctx.state, args, callId)
  of "Mailbox/set":
    let resp = handleMailboxSet(ctx.store, ctx.username, ctx.state, args, callId)
    # Update state if the set operation changed it
    if resp.len > 0 and resp[1].hasKey("newState"):
      let ns = resp[1]["newState"].getStr("")
      if ns.len > 0 and ns != ctx.state:
        ctx.state = ns
    resp
  of "Mailbox/query":
    handleMailboxQuery(ctx.store, ctx.username, ctx.state, args, callId)
  of "Email/get":
    handleEmailGet(ctx.store, ctx.username, ctx.state, args, callId)
  of "Email/set":
    let resp = handleEmailSet(ctx.store, ctx.username, ctx.state, args, callId)
    if resp.len > 0 and resp[1].hasKey("newState"):
      let ns = resp[1]["newState"].getStr("")
      if ns.len > 0 and ns != ctx.state:
        ctx.state = ns
    resp
  of "Email/query":
    handleEmailQuery(ctx.store, ctx.username, ctx.state, args, callId)
  of "Identity/get":
    handleIdentityGet(ctx.username, args, callId)
  of "EmailSubmission/set":
    handleEmailSubmissionSet(ctx.username, ctx.state, args, callId)
  else:
    newJMAPErrorResponse(callId, errUnknownMethod,
                         "Method not implemented: " & methodName)
