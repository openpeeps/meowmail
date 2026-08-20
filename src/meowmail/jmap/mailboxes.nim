## MeowMail JMAP — Mailbox methods (RFC 8621 §2).
##
## Mailbox/get, Mailbox/set, Mailbox/query backed by MaildirStore.

import std/[tables, strutils, options, algorithm, sets, sequtils, times]
import openparser/json
import ../imap/mailstore
import ./types

# ── Helpers ───────────────────────────────────────────────────────────────────

proc mailboxToId(name: string): string =
  ## Convert a mailbox name to a JMAP ID. Use the name directly since
  ## Maildir names are already safe for URLs and filesystems.
  name

proc idToMailbox(id: string): string =
  ## Convert a JMAP mailbox ID back to a mailbox name.
  id

proc mailboxRole(name: string): string =
  ## Determine the JMAP role for a mailbox name.
  if name.toUpperAscii == "INBOX": "inbox"
  elif name.toUpperAscii == "SENT": "sent"
  elif name.toUpperAscii == "DRAFTS": "drafts"
  elif name.toUpperAscii == "TRASH": "trash"
  elif name.toUpperAscii == "SPAM": "spam"
  elif name.toUpperAscii == "ARCHIVE": "archive"
  else: ""

proc computeParentId(name: string): string =
  ## Compute the parent mailbox ID from a name. Returns "" for root-level.
  let slash = name.rfind('/')
  if slash < 0: ""
  else: name[0 ..< slash]

proc buildMailboxData(store: MaildirStore, user: string, mb: Mailbox,
                      isSubscribed: bool): JsonNode =
  ## Build a JMAP Mailbox object from a Mailbox.
  let id = mailboxToId(mb.name)
  let role = mailboxRole(mb.name)
  let parentId = computeParentId(mb.name)
  let total = mb.messages.len
  var unread = 0
  for msg in mb.messages:
    if mfSeen notin msg.flags:
      inc unread

  result = newJObject()
  result["id"] = newJString(id)
  result["name"] = newJString(mb.name)
  if parentId.len > 0:
    result["parentId"] = newJString(parentId)
  if role.len > 0:
    result["role"] = newJString(role)
  result["sortOrder"] = newJInt(0)
  result["totalEmails"] = newJInt(total)
  result["unreadEmails"] = newJInt(unread)
  result["totalThreads"] = newJInt(total)
  result["unreadThreads"] = newJInt(unread)
  result["isSubscribed"] = newJBool(isSubscribed)

  # myRights — full rights for personal account
  var rights = newJObject()
  rights["mayReadItems"] = newJBool(true)
  rights["mayAddItems"] = newJBool(true)
  rights["mayRemoveItems"] = newJBool(true)
  rights["mayModifyItems"] = newJBool(true)
  rights["mayCreateMailbox"] = newJBool(true)
  rights["mayDeleteMailbox"] = newJBool(true)
  rights["maySubmit"] = newJBool(true)
  result["myRights"] = rights

# ── Mailbox/get (RFC 8621 §2.1) ──────────────────────────────────────────────

proc handleMailboxGet*(store: MaildirStore, user: string, state: string,
                       args: JsonNode, callId: string): seq[JsonNode] =
  let accountId = if args.hasKey("accountId"): args["accountId"].getStr
                  else: ""
  let requestedIds =
    if args.hasKey("ids") and args["ids"].kind == JArray and args["ids"].len > 0:
      var ids: seq[string]
      for item in args["ids"].items:
        ids.add(item.getStr(""))
      some(ids)
    else:
      none(seq[string])

  let subs = store.loadSubscriptions(user)
  let allNames = store.listMailboxes(user)

  var list = newJArray()
  var notFound = newJArray()

  for name in allNames:
    let id = mailboxToId(name)
    if requestedIds.isSome and id notin requestedIds.get():
      continue
    let mb = store.openMailbox(user, name)
    let isSub = name in subs
    list.add(buildMailboxData(store, user, mb, isSub))

  # Check for requested IDs that weren't found
  if requestedIds.isSome:
    let foundIds = allNames.mapIt(mailboxToId(it)).toHashSet
    for id in requestedIds.get():
      if id notin foundIds:
        notFound.add(newJString(id))

  var result = newJObject()
  result["accountId"] = newJString(accountId)
  result["state"] = newJString(state)
  result["list"] = list
  result["notFound"] = notFound
  newJMAPOkResponse("Mailbox/get", result, callId)

# ── Mailbox/set (RFC 8621 §2.2) ──────────────────────────────────────────────

proc handleMailboxSet*(store: MaildirStore, user: string, state: string,
                       args: JsonNode, callId: string): seq[JsonNode] =
  let accountId = if args.hasKey("accountId"): args["accountId"].getStr
                  else: ""

  var created = newJObject()
  var updated = newJArray()
  var destroyed = newJArray()
  var notCreated = newJObject()
  var notUpdated = newJObject()
  var notDestroyed = newJObject()
  var newState = state

  # Create
  if args.hasKey("create") and args["create"].kind == JObject:
    for creationId, props in args["create"]:
      if props.kind != JObject:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "Properties must be an object"}
        continue
      let name = props.getOrDefault("name").getStr("")
      if name.len == 0:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "Mailbox name is required"}
        continue
      if store.mailboxExists(user, name):
        notCreated[creationId] = %*{"type": "alreadyExists",
                                     "description": "Mailbox already exists"}
        continue
      if store.createMailbox(user, name):
        let id = mailboxToId(name)
        created[creationId] = newJString(id)
        newState = "s-" & $epochTime().int
      else:
        notCreated[creationId] = %*{"type": "serverFail",
                                     "description": "Failed to create mailbox"}

  # Update — only name changes (rename)
  if args.hasKey("update") and args["update"].kind == JObject:
    for id, patch in args["update"]:
      let oldName = idToMailbox(id)
      if not store.mailboxExists(user, oldName):
        notUpdated[id] = %*{"type": "notFound",
                             "description": "Mailbox not found"}
        continue
      if patch.kind != JObject:
        notUpdated[id] = %*{"type": "invalidArguments",
                             "description": "Patch must be an object"}
        continue
      let newName = patch.getOrDefault("name").getStr("")
      if newName.len > 0 and newName != oldName:
        if store.mailboxExists(user, newName):
          notUpdated[id] = %*{"type": "alreadyExists",
                               "description": "Target name already exists"}
          continue
        if store.renameMailbox(user, oldName, newName):
          updated.add(newJString(id))
          newState = "s-" & $epochTime().int
        else:
          notUpdated[id] = %*{"type": "serverFail",
                               "description": "Failed to rename mailbox"}
      else:
        # No-op update (no name change)
        updated.add(newJString(id))

  # Destroy
  if args.hasKey("destroy") and args["destroy"].kind == JArray:
    for item in args["destroy"].items:
      let id = item.getStr("")
      let name = idToMailbox(id)
      if name.toUpperAscii == "INBOX":
        notDestroyed[id] = %*{"type": "forbidden",
                               "description": "Cannot delete INBOX"}
        continue
      if not store.mailboxExists(user, name):
        notDestroyed[id] = %*{"type": "notFound",
                               "description": "Mailbox not found"}
        continue
      if store.deleteMailbox(user, name):
        destroyed.add(newJString(id))
        newState = "s-" & $epochTime().int
      else:
        notDestroyed[id] = %*{"type": "serverFail",
                               "description": "Failed to delete mailbox"}

  var result = newJObject()
  result["accountId"] = newJString(accountId)
  result["oldState"] = newJString(state)
  result["newState"] = newJString(newState)
  result["created"] = created
  result["updated"] = updated
  result["destroyed"] = destroyed
  if created.len == 0: result["created"] = newJObject()
  if notCreated.len > 0: result["notCreated"] = notCreated
  if notUpdated.len > 0: result["notUpdated"] = notUpdated
  if notDestroyed.len > 0: result["notDestroyed"] = notDestroyed
  newJMAPOkResponse("Mailbox/set", result, callId)

# ── Mailbox/query (RFC 8621 §2.3) ────────────────────────────────────────────

proc matchesFilter(name, role: string, filter: JsonNode): bool =
  ## Check if a mailbox matches a JMAP Mailbox/query filter.
  if filter.kind != JObject: return true
  if filter.hasKey("name"):
    let filterName = filter["name"].getStr("")
    if filterName.len > 0 and not name.contains(filterName): return false
  if filter.hasKey("role"):
    let filterRole = filter["role"].getStr("")
    if filterRole.len > 0 and role != filterRole: return false
  if filter.hasKey("parentId"):
    let filterParent = filter["parentId"].getStr("")
    let parent = computeParentId(name)
    if filterParent.len > 0 and parent != filterParent: return false
  if filter.hasKey("isSubscribed"):
    # Can't filter by subscription here without the subs list; skip
    discard
  true

proc handleMailboxQuery*(store: MaildirStore, user: string, state: string,
                         args: JsonNode, callId: string): seq[JsonNode] =
  let accountId = if args.hasKey("accountId"): args["accountId"].getStr
                  else: ""
  let filter = args.getOrDefault("filter")
  let position = args.getOrDefault("position").getInt(0)
  let limit = args.getOrDefault("limit").getInt(256)
  let calculateTotal = args.getOrDefault("calculateTotal").getBool(false)

  let allNames = store.listMailboxes(user)
  var matchingIds: seq[string]
  for name in allNames:
    let role = mailboxRole(name)
    if matchesFilter(name, role, filter):
      matchingIds.add(mailboxToId(name))

  let total = matchingIds.len
  let sliced = matchingIds[position ..< min(position + limit, matchingIds.len)]

  var result = newJObject()
  result["accountId"] = newJString(accountId)
  result["state"] = newJString(state)
  result["ids"] = %*sliced
  result["position"] = newJInt(position)
  result["limit"] = newJInt(limit)
  if calculateTotal:
    result["total"] = newJInt(total)
  newJMAPOkResponse("Mailbox/query", result, callId)
