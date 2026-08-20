## MeowMail JMAP — Identity and EmailSubmission methods (RFC 8621 §7-8).
##
## Identity/get returns user identity information.
## EmailSubmission/set queues messages for SMTP delivery.

import std/[tables, strutils, options, times]
import openparser/json
import ../imap/mailstore
import ./types

# ── Identity/get (RFC 8621 §8.1) ────────────────────────────────────────────

proc handleIdentityGet*(username: string, args: JsonNode,
                        callId: string): seq[JsonNode] =
  let accountId = args.getOrDefault("accountId").getStr("")
  let requestedIds =
    if args.hasKey("ids") and args["ids"].kind == JArray and args["ids"].len > 0:
      var ids: seq[string]
      for item in args["ids"].items:
        ids.add(item.getStr(""))
      some(ids)
    else:
      none(seq[string])

  # MeowMail has a single identity per account: the user's email address
  let identityId = "id1"
  let email = username & "@meowmail.local"

  var list = newJArray()
  var notFound = newJArray()

  if requestedIds.isNone or identityId in requestedIds.get():
    var identity = newJObject()
    identity["id"] = newJString(identityId)
    identity["name"] = newJString(username)
    identity["email"] = newJString(email)
    identity["mayDelete"] = newJBool(false)

    # capabilities
    var caps = newJObject()
    caps["mayDelete"] = newJBool(false)
    identity["quotas"] = newJObject()  # empty quotas for now

    list.add(identity)
  elif requestedIds.isSome:
    notFound.add(newJString(identityId))

  var result = newJObject()
  result["accountId"] = newJString(accountId)
  result["list"] = list
  result["notFound"] = notFound
  newJMAPOkResponse("Identity/get", result, callId)

# ── EmailSubmission/set (RFC 8621 §7.3) ──────────────────────────────────────

proc handleEmailSubmissionSet*(username: string, state: string,
                               args: JsonNode, callId: string): seq[JsonNode] =
  let accountId = args.getOrDefault("accountId").getStr("")

  var created = newJObject()
  var destroyed = newJArray()
  var notCreated = newJObject()
  var notDestroyed = newJObject()
  var newState = state

  # Create — submit a message for delivery
  if args.hasKey("create") and args["create"].kind == JObject:
    for creationId, props in args["create"]:
      if props.kind != JObject:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "Properties must be an object"}
        continue

      # Validate required fields
      let envelope = props.getOrDefault("envelope")
      if envelope == nil or envelope.kind != JObject:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "envelope is required"}
        continue

      let mailFrom = envelope.getOrDefault("mailFrom")
      if mailFrom == nil or mailFrom.kind != JObject:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "envelope.mailFrom is required"}
        continue

      let emailAddr = mailFrom.getOrDefault("email").getStr("")
      if emailAddr.len == 0:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "envelope.mailFrom.email is required"}
        continue

      let rcptToArray = envelope.getOrDefault("rcptTo")
      if rcptToArray == nil or rcptToArray.kind != JArray or rcptToArray.len == 0:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "envelope.rcptTo must not be empty"}
        continue

      # Validate identityId
      let identityId = props.getOrDefault("identityId").getStr("")
      if identityId.len == 0:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "identityId is required"}
        continue

      # Validate emailId — the message to send
      let emailId = props.getOrDefault("emailId").getStr("")
      if emailId.len == 0:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "emailId is required"}
        continue

      # For now, store the submission as successful.
      # Actual SMTP delivery will be wired in a future iteration.
      let submissionId = "sub-" & $epochTime().int & "-" & $creationId
      created[creationId] = newJObject()
      created[creationId]["id"] = newJString(submissionId)
      created[creationId]["idempotencyKey"] = newJString(
        props.getOrDefault("idempotencyKey").getStr(""))
      created[creationId]["status"] = newJString("queued")
      newState = "s-" & $epochTime().int

  # Destroy — cancel a queued submission (not yet delivered)
  if args.hasKey("destroy") and args["destroy"].kind == JArray:
    for item in args["destroy"].items:
      let id = item.getStr("")
      # For now, treat all destroys as successful (no persistent queue yet)
      destroyed.add(newJString(id))
      newState = "s-" & $epochTime().int

  var result = newJObject()
  result["accountId"] = newJString(accountId)
  result["oldState"] = newJString(state)
  result["newState"] = newJString(newState)
  result["created"] = created
  result["updated"] = newJArray()
  result["destroyed"] = destroyed
  if notCreated.len > 0: result["notCreated"] = notCreated
  if notDestroyed.len > 0: result["notDestroyed"] = notDestroyed
  newJMAPOkResponse("EmailSubmission/set", result, callId)
