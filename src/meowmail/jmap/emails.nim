## MeowMail JMAP — Email methods (RFC 8621 §4).
##
## Email/get, Email/set, Email/query backed by MaildirStore + msgparse.

import std/[tables, strutils, options, algorithm, times, sequtils, sets]
import openparser/json
import ../imap/mailstore
import ../imap/msgparse
import ./types

# ── Helpers ───────────────────────────────────────────────────────────────────

proc emailId(msg: MailMessage): string =
  ## JMAP email ID = string UID.
  $msg.uid

proc keywordsFromFlags(flags: set[MailFlag]): seq[string] =
  ## Convert Maildir flags to JMAP keywords.
  if mfSeen in flags: result.add("\\Seen")
  if mfAnswered in flags: result.add("\\Answered")
  if mfFlagged in flags: result.add("\\Flagged")
  if mfDraft in flags: result.add("\\Draft")
  if mfDeleted in flags: result.add("\\Deleted")

proc parseReceivedDate(s: string): string =
  ## Best-effort parse of an RFC 5322 date to JMAP UTCDate.
  try:
    let t = parseDateStr(s)
    if t.toUnix > 0:
      return format(t, "yyyy-MM-dd'T'HH:mm:ss") & "Z"
  except CatchableError:
    discard
  ""

proc envelopeAddressToJson(eaddr: EnvelopeAddress): JsonNode =
  result = newJObject()
  result["name"] = newJString(eaddr.name)
  result["email"] = newJString(eaddr.mailbox & "@" & eaddr.host)

proc addressListToJson(addrs: seq[EnvelopeAddress]): JsonNode =
  result = newJArray()
  for a in addrs:
    result.add(envelopeAddressToJson(a))

# ── Email/get (RFC 8621 §4.1) ────────────────────────────────────────────────

proc buildEmailObject(msg: MailMessage, mb: Mailbox, raw: string,
                      parsed: ParsedMessage,
                      props: seq[string]): JsonNode =
  ## Build a JMAP Email object from a MailMessage.
  let id = emailId(msg)
  let env = parsed.envelope
  let keywords = keywordsFromFlags(msg.flags)

  result = newJObject()
  result["id"] = newJString(id)

  # mailboxIds — this message belongs to one mailbox
  var mbIds = newJObject()
  mbIds[mb.name] = newJBool(true)
  result["mailboxIds"] = mbIds

  # keywords
  var kwObj = newJObject()
  for kw in keywords:
    kwObj[kw] = newJBool(true)
  result["keywords"] = kwObj

  # receivedAt
  let receivedAt = format(msg.internalDate, "yyyy-MM-dd'T'HH:mm:ss") & "Z"
  result["receivedAt"] = newJString(receivedAt)

  # size
  result["size"] = newJInt(raw.len)

  # Subject
  result["subject"] = newJString(env.subject)

  # sentAt — from the Date header
  let sentAt = parseReceivedDate(env.date)
  if sentAt.len > 0:
    result["sentAt"] = newJString(sentAt)
  else:
    result["sentAt"] = newJString(receivedAt)

  # Addresses
  result["from"] = addressListToJson(env.fromList)
  result["to"] = addressListToJson(env.to)
  result["cc"] = addressListToJson(env.cc)
  result["bcc"] = addressListToJson(env.bcc)
  result["replyTo"] = addressListToJson(env.replyTo)
  if env.inReplyTo.len > 0:
    result["inReplyTo"] = newJString(env.inReplyTo)

  # headers — all headers as [{name, value}]
  var headersArr = newJArray()
  for h in parsed.headers:
    var hdr = newJObject()
    hdr["name"] = newJString(h.name)
    hdr["value"] = newJString(h.value)
    headersArr.add(hdr)
  result["headers"] = headersArr

  # textBody / htmlBody — content type references
  var textParts = newJArray()
  var htmlParts = newJArray()
  proc collectParts(part: MimePart, path: string) =
    if part.mainType == "text" and part.subtype == "plain":
      textParts.add(newJString(path))
    elif part.mainType == "text" and part.subtype == "html":
      htmlParts.add(newJString(path))
    for i, sub in part.parts:
      collectParts(sub, path & "/" & $(i + 1))
  if parsed.root.parts.len > 0:
    for i, sub in parsed.root.parts:
      collectParts(sub, $(i + 1))
  else:
    collectParts(parsed.root, "1")
  result["textBody"] = textParts
  result["htmlBody"] = htmlParts

  # preview — first 256 chars of text content
  let preview = parsed.textContent()
  if preview.len > 0:
    result["preview"] = newJString(preview[0 ..< min(256, preview.len)])
  else:
    result["preview"] = newJString("")

proc handleEmailGet*(store: MaildirStore, user: string, state: string,
                     args: JsonNode, callId: string): seq[JsonNode] =
  let accountId = args.getOrDefault("accountId").getStr("")
  let mailboxId = args.getOrDefault("mailboxId").getStr("")
  let requestedIds =
    if args.hasKey("ids") and args["ids"].kind == JArray and args["ids"].len > 0:
      var ids: seq[string]
      for item in args["ids"].items:
        ids.add(item.getStr(""))
      some(ids)
    else:
      none(seq[string])

  var list = newJArray()
  var notFound = newJArray()

  # Determine which mailboxes to search
  var mailboxes: seq[string]
  if mailboxId.len > 0:
    mailboxes = @[mailboxId]
  else:
    mailboxes = store.listMailboxes(user)

  # If specific IDs requested, we need to find which mailbox each belongs to
  if requestedIds.isSome:
    let wantedIds = requestedIds.get().toHashSet
    var foundIds: HashSet[string]
    for mbName in mailboxes:
      let mb = store.openMailbox(user, mbName)
      for msg in mb.messages:
        let id = emailId(msg)
        if id in wantedIds:
          let raw = loadMessageData(mb, msg)
          if raw.len > 0:
            let parsed = parseMessage(raw)
            list.add(buildEmailObject(msg, mb, raw, parsed, @[]))
          foundIds.incl(id)
    for id in wantedIds:
      if id notin foundIds:
        notFound.add(newJString(id))
  else:
    # Return all messages in the specified mailboxes
    for mbName in mailboxes:
      let mb = store.openMailbox(user, mbName)
      for msg in mb.messages:
        let raw = loadMessageData(mb, msg)
        if raw.len > 0:
          let parsed = parseMessage(raw)
          list.add(buildEmailObject(msg, mb, raw, parsed, @[]))

  var result = newJObject()
  result["accountId"] = newJString(accountId)
  result["state"] = newJString(state)
  result["list"] = list
  result["notFound"] = notFound
  newJMAPOkResponse("Email/get", result, callId)

# ── Email/set (RFC 8621 §4.2) ────────────────────────────────────────────────

proc handleEmailSet*(store: MaildirStore, user: string, state: string,
                     args: JsonNode, callId: string): seq[JsonNode] =
  let accountId = args.getOrDefault("accountId").getStr("")

  var created = newJObject()
  var updated = newJArray()
  var destroyed = newJArray()
  var notCreated = newJObject()
  var notUpdated = newJObject()
  var notDestroyed = newJObject()
  var newState = state

  # Create — APPEND a message to a mailbox
  if args.hasKey("create") and args["create"].kind == JObject:
    for creationId, props in args["create"]:
      if props.kind != JObject:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "Properties must be an object"}
        continue
      let mbId = props.getOrDefault("mailboxIds")
      if mbId.kind != JObject or mbId.len == 0:
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "mailboxIds is required"}
        continue
      let mailboxName = mbId.keys.toSeq[0]
      let rawMsg = props.getOrDefault("blobId").getStr("")
      if rawMsg.len == 0:
        # Check for the message in keywords/headers — for now, require blobId
        notCreated[creationId] = %*{"type": "invalidArguments",
                                     "description": "blobId is required (raw RFC5322 message)"}
        continue
      # Parse keywords from the create request
      var flags: set[MailFlag]
      if props.hasKey("keywords") and props["keywords"].kind == JObject:
        for kw, _ in props["keywords"]:
          case kw
          of "\\Seen": flags.incl(mfSeen)
          of "\\Answered": flags.incl(mfAnswered)
          of "\\Flagged": flags.incl(mfFlagged)
          of "\\Draft": flags.incl(mfDraft)
          of "\\Deleted": flags.incl(mfDeleted)
          else: discard
      let res = store.appendMessage(user, mailboxName, flags, rawMsg)
      if res.ok:
        created[creationId] = newJString($res.uid)
        newState = "s-" & $epochTime().int
      else:
        notCreated[creationId] = %*{"type": "serverFail",
                                     "description": "Failed to append message"}

  # Update — change keywords (flags)
  if args.hasKey("update") and args["update"].kind == JObject:
    for id, patch in args["update"]:
      let uid = try: parseInt(id).uint32 except ValueError: 0
      if uid == 0:
        notUpdated[id] = %*{"type": "notFound", "description": "Invalid email ID"}
        continue
      # Find the message across all mailboxes
      var found = false
      for mbName in store.listMailboxes(user):
        let mb = store.openMailbox(user, mbName)
        let msg = mb.findMessageByUid(uid)
        if msg != nil:
          found = true
          if patch.kind == JObject and patch.hasKey("keywords"):
            var newFlags: set[MailFlag]
            let kw = patch["keywords"]
            if kw.kind == JObject:
              for k, _ in kw:
                case k
                of "\\Seen": newFlags.incl(mfSeen)
                of "\\Answered": newFlags.incl(mfAnswered)
                of "\\Flagged": newFlags.incl(mfFlagged)
                of "\\Draft": newFlags.incl(mfDraft)
                of "\\Deleted": newFlags.incl(mfDeleted)
                else: discard
            updateFlags(mb, msg, newFlags)
            updated.add(newJString(id))
            newState = "s-" & $epochTime().int
          break
      if not found:
        notUpdated[id] = %*{"type": "notFound", "description": "Email not found"}

  # Destroy — expunge messages
  if args.hasKey("destroy") and args["destroy"].kind == JArray:
    for item in args["destroy"].items:
      let id = item.getStr("")
      let uid = try: parseInt(id).uint32 except ValueError: 0
      if uid == 0:
        notDestroyed[id] = %*{"type": "notFound", "description": "Invalid email ID"}
        continue
      var found = false
      for mbName in store.listMailboxes(user):
        let mb = store.openMailbox(user, mbName)
        let msg = mb.findMessageByUid(uid)
        if msg != nil:
          found = true
          expungeMessage(mb, msg)
          destroyed.add(newJString(id))
          newState = "s-" & $epochTime().int
          break
      if not found:
        notDestroyed[id] = %*{"type": "notFound", "description": "Email not found"}

  var result = newJObject()
  result["accountId"] = newJString(accountId)
  result["oldState"] = newJString(state)
  result["newState"] = newJString(newState)
  result["created"] = created
  result["updated"] = updated
  result["destroyed"] = destroyed
  if notCreated.len > 0: result["notCreated"] = notCreated
  if notUpdated.len > 0: result["notUpdated"] = notUpdated
  if notDestroyed.len > 0: result["notDestroyed"] = notDestroyed
  newJMAPOkResponse("Email/set", result, callId)

# ── Email/query (RFC 8621 §4.3) ──────────────────────────────────────────────

proc matchesEmailFilter(msg: MailMessage, parsed: ParsedMessage,
                        filter: JsonNode): bool =
  ## Check if an email matches a JMAP Email/query filter.
  if filter == nil or filter.kind != JObject: return true
  if filter.hasKey("inMailbox"):
    # Handled at a higher level (filter by mailbox)
    discard
  if filter.hasKey("inMailboxOtherThan"):
    # Also handled at a higher level
    discard
  if filter.hasKey("unseen"):
    if filter["unseen"].getBool(false):
      if mfSeen in msg.flags: return false
  if filter.hasKey("seen"):
    if filter["seen"].getBool(false):
      if mfSeen notin msg.flags: return false
  if filter.hasKey("flagged"):
    if filter["flagged"].getBool(false):
      if mfFlagged notin msg.flags: return false
  if filter.hasKey("answered"):
    if filter["answered"].getBool(false):
      if mfAnswered notin msg.flags: return false
  if filter.hasKey("draft"):
    if filter["draft"].getBool(false):
      if mfDraft notin msg.flags: return false
  if filter.hasKey("subject"):
    let q = filter["subject"].getStr("").toLowerAscii
    if q.len > 0 and not parsed.envelope.subject.toLowerAscii.contains(q):
      return false
  if filter.hasKey("from"):
    let q = filter["from"].getStr("").toLowerAscii
    if q.len > 0:
      var found = false
      for a in parsed.envelope.fromList:
        if (a.mailbox & "@" & a.host).toLowerAscii.contains(q):
          found = true; break
      if not found: return false
  if filter.hasKey("to"):
    let q = filter["to"].getStr("").toLowerAscii
    if q.len > 0:
      var found = false
      for a in parsed.envelope.to:
        if (a.mailbox & "@" & a.host).toLowerAscii.contains(q):
          found = true; break
      if not found: return false
  true

proc sortEmails(msgs: seq[(MailMessage, ParsedMessage)],
                sort: JsonNode): seq[(MailMessage, ParsedMessage)] =
  ## Sort emails according to JMAP sort specification.
  result = msgs
  if sort == nil: return
  if sort.kind == JArray and sort.len > 0:
    let s = sort[0]
    let prop = s.getOrDefault("property").getStr("receivedAt")
    let asc = not s.getOrDefault("isAscending").getBool(false)
    result.sort(proc(a, b: (MailMessage, ParsedMessage)): int =
      case prop
      of "receivedAt":
        cmp(a[0].internalDate, b[0].internalDate) * (if asc: 1 else: -1)
      of "subject":
        cmp(a[1].envelope.subject, b[1].envelope.subject) * (if asc: 1 else: -1)
      of "size":
        cmp(a[0].size, b[0].size) * (if asc: 1 else: -1)
      else: 0
    )

proc handleEmailQuery*(store: MaildirStore, user: string, state: string,
                       args: JsonNode, callId: string): seq[JsonNode] =
  let accountId = args.getOrDefault("accountId").getStr("")
  let filter = args.getOrDefault("filter")
  let sort = args.getOrDefault("sort")
  let position = args.getOrDefault("position").getInt(0)
  let limit = args.getOrDefault("limit").getInt(256)
  let calculateTotal = args.getOrDefault("calculateTotal").getBool(false)

  # Collect all messages with parsed data
  var allMsgs: seq[(MailMessage, ParsedMessage, string)]  # msg, parsed, mailboxName
  for mbName in store.listMailboxes(user):
    let mb = store.openMailbox(user, mbName)
    for msg in mb.messages:
      let raw = loadMessageData(mb, msg)
      if raw.len > 0:
        let parsed = parseMessage(raw)
        allMsgs.add((msg, parsed, mbName))

  # Filter
  var filtered: seq[(MailMessage, ParsedMessage)]
  for (msg, parsed, mbName) in allMsgs:
    if matchesEmailFilter(msg, parsed, filter):
      filtered.add((msg, parsed))

  # Sort
  let sorted = sortEmails(filtered, sort)

  # Paginate
  let total = sorted.len
  let sliced = sorted[position ..< min(position + limit, sorted.len)]

  var ids = newJArray()
  for (msg, _) in sliced:
    ids.add(newJString(emailId(msg)))

  var result = newJObject()
  result["accountId"] = newJString(accountId)
  result["state"] = newJString(state)
  result["ids"] = ids
  result["position"] = newJInt(position)
  result["limit"] = newJInt(limit)
  if calculateTotal:
    result["total"] = newJInt(total)
  newJMAPOkResponse("Email/query", result, callId)
