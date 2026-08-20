# MeowMail - A high-performance SMTP/IMAP server based on powpow
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

## Maildir++ message store used by both the SMTP local-delivery path and the
## IMAP server.
##
## Layout (per user):
##
##   <base>/<user>/Maildir/{cur,new,tmp}                 INBOX
##   <base>/<user>/Maildir/.Folder/{cur,new,tmp}         subfolders (maildir++)
##   <base>/<user>/Maildir/.Folder.Sub/{cur,new,tmp}     nested folders
##
## Flags are stored in the `cur/` filename as `:2,` suffixes; messages in
## `new/` are un-seen and report \Recent. UID/UIDVALIDITY state is persisted
## per mailbox in `.uidlist` / `.uidvalidity` files so it survives restarts
## and is safe across the SMTP delivery threads and the IMAP loop.

import std/[os, times, tables, sets, strutils, sequtils, random, hashes, algorithm, atomics]

type
  MailFlag* = enum
    mfDraft    = 'D'
    mfDeleted  = 'T'
    mfAnswered = 'R'
    mfFlagged  = 'F'
    mfSeen     = 'S'

  MailMessage* = ref object
    uid*: uint32
      ## Stable message UID within the mailbox.
    seq*: int
      ## 1-based sequence number within the current mailbox snapshot.
    recent*: bool
      ## True while the message still lives in `new/`.
    flags*: set[MailFlag]
    fileName*: string
      ## Basename of the message file (may carry a `:2,` flag suffix).
    dir*: string
      ## `"cur"` or `"new"`.
    size*: int64
    internalDate*: Time
      ## Message received time (file mtime).

  Mailbox* = ref object
    name*: string
      ## IMAP mailbox name (`"INBOX"`, `"Sent"`, `"Archive/2024"`, ...).
    path*: string
      ## Absolute filesystem path of the maildir directory.
    uidvalidity*: uint32
    uidnext*: uint32
    messages*: seq[MailMessage]

  MaildirStore* = ref object
    base*: string
      ## Root directory containing one `Maildir` per user.
    localDomains*: HashSet[string]
      ## Domains treated as local (delivered into Maildir). Empty disables
      ## local delivery.

proc newMaildirStore*(base: string, localDomains: seq[string] = @[]): MaildirStore =
  ## Creates a Maildir store rooted at `base`.
  result = MaildirStore(base: base)
  for d in localDomains:
    result.localDomains.incl(d.toLowerAscii())

proc userMaildirPath*(store: MaildirStore, user: string): string =
  ## Absolute path of the user's INBOX maildir.
  store.base / user / "Maildir"

proc mailboxFsPath(store: MaildirStore, user, name: string): string =
  ## Map an IMAP mailbox name to its filesystem path.
  if name.len == 0 or name.toUpperAscii() == "INBOX":
    store.userMaildirPath(user)
  else:
    var p = store.userMaildirPath(user)
    for part in name.split('/'):
      if part.len > 0:
        p = p / ("." & part)
    p

proc mailboxNameFromPath(store: MaildirStore, user, path: string): string =
  ## Map a maildir++ filesystem path back to its IMAP mailbox name.
  let root = store.userMaildirPath(user)
  var rel = path
  if rel.startsWith(root & DirSep):
    rel = rel[root.len + 1 .. ^1]
  if rel == "":
    return "INBOX"
  var parts = rel.split(DirSep)
  for i in 0 ..< parts.len:
    if parts[i].len > 0 and parts[i][0] == '.':
      parts[i] = parts[i][1 .. ^1]
    else:
      parts[i] = ""
  parts.filterIt(it.len > 0).join("/")

proc ensureMaildirStructure(dir: string): bool =
  ## Create `{cur,new,tmp}` under `dir` if missing.
  try:
    for sub in ["cur", "new", "tmp"]:
      let p = dir / sub
      if not dirExists(p):
        createDir(p)
    true
  except CatchableError:
    false

proc ensureUserMaildir*(store: MaildirStore, user: string): bool =
  ## Ensure the user's INBOX maildir exists.
  let d = store.userMaildirPath(user)
  try:
    if not dirExists(d):
      createDir(d)
    ensureMaildirStructure(d)
  except CatchableError:
    false

proc loadSubscriptions*(store: MaildirStore, user: string): seq[string] =
  ## Load the user's subscribed mailbox list from `<user>/Maildir/subscriptions`.
  let p = store.userMaildirPath(user) / "subscriptions"
  if fileExists(p):
    for line in readFile(p).splitLines():
      let l = line.strip()
      if l.len > 0:
        result.add(l)

proc saveSubscriptions*(store: MaildirStore, user: string, subs: seq[string]) =
  ## Persist the user's subscribed mailbox list.
  try:
    discard existsOrCreateDir(store.userMaildirPath(user))
    writeFile(store.userMaildirPath(user) / "subscriptions",
              subs.join("\n") & (if subs.len > 0: "\n" else: ""))
  except CatchableError:
    discard

# ── UID / UIDVALIDITY persistence ─────────────────────────────────────────────

proc keyOf*(fileName: string): string =
  ## Stable key for a message file: the basename without any `:2,` suffix.
  let i = fileName.find(":2,")
  if i >= 0: fileName[0 ..< i] else: fileName

proc uidlistPath(mb: Mailbox): string = mb.path / ".uidlist"
proc uidvalPath(mb: Mailbox): string = mb.path / ".uidvalidity"

proc loadUidlist(mb: Mailbox): Table[string, uint32] =
  ## Load `<relative path> <uid>` lines from `.uidlist`.
  let p = mb.uidlistPath()
  if not fileExists(p): return
  try:
    for line in readFile(p).splitLines():
      let parts = line.splitWhitespace()
      if parts.len == 2:
        result[parts[0]] = parts[1].parseUInt().uint32
  except CatchableError:
    discard

proc saveUidlist(mb: Mailbox, mapping: Table[string, uint32]) =
  try:
    var lines = ""
    for k, v in mapping.pairs:
      lines.add($v & " " & k & "\n")
    writeFile(mb.uidlistPath(), lines)
  except CatchableError:
    discard

proc loadUidvalidity(mb: Mailbox): uint32 =
  let p = mb.uidvalPath()
  if not fileExists(p):
    result = uint32(epochTime().int64 and 0xFFFFFFFF) xor
             uint32(hash(mb.path) and 0xFFFFFFFF)
    if result == 0: result = 1
    try: writeFile(p, $result)
    except CatchableError: discard
  else:
    try: result = readFile(p).strip().parseUInt().uint32
    except CatchableError: result = 1

# ── Flag encoding ─────────────────────────────────────────────────────────────

proc flagSuffix(flags: set[MailFlag]): string =
  ## Encode flags into the maildir `:2,` suffix string.
  result = ":2,"
  for f in [mfDraft, mfDeleted, mfAnswered, mfFlagged, mfSeen]:
    if f in flags:
      result.add(char(f))

proc parseFlagSuffix(s: string): set[MailFlag] =
  ## Parse a `:2,DR` suffix (empty or missing suffix yields an empty set).
  var i = s.find(":2,")
  if i < 0: return
  i += 3
  while i < s.len:
    let f = s[i]
    case f
    of 'D': result.incl(mfDraft)
    of 'T': result.incl(mfDeleted)
    of 'R': result.incl(mfAnswered)
    of 'F': result.incl(mfFlagged)
    of 'S': result.incl(mfSeen)
    else: discard
    inc i

proc flagSetToImap*(flags: set[MailFlag]): string =
  ## Render flags as an IMAP flag list, e.g. `\Seen \Flagged`.
  result = ""
  for f in [mfSeen, mfAnswered, mfFlagged, mfDeleted, mfDraft]:
    if f in flags:
      case f
      of mfSeen: result.add("\\Seen ")
      of mfAnswered: result.add("\\Answered ")
      of mfFlagged: result.add("\\Flagged ")
      of mfDeleted: result.add("\\Deleted ")
      of mfDraft: result.add("\\Draft ")
      else: discard
  result = result.strip()

proc flagToMailFlag*(s: string): set[MailFlag] =
  ## Convert an IMAP flag keyword (`\Seen`, `\Flagged`, custom) to MailFlag set.
  case s.toUpperAscii()
  of "\\SEEN": {mfSeen}
  of "\\ANSWERED": {mfAnswered}
  of "\\FLAGGED": {mfFlagged}
  of "\\DELETED": {mfDeleted}
  of "\\DRAFT": {mfDraft}
  of "\\RECENT": {}
  else: {}

# ── Mailbox scanning ──────────────────────────────────────────────────────────

proc sortedFiles(dir: string): seq[string] =
  ## List regular files in `dir`, sorted by (mtime, name) — delivery order.
  if not dirExists(dir): return
  var entries: seq[(Time, string)] = @[]
  for kind, path in walkDir(dir):
    if kind == pcFile:
      let base = extractFilename(path)
      if base.startsWith("."): continue  # skip .uidlist etc.
      var t: Time
      try: t = getLastModificationTime(path)
      except CatchableError: t = fromUnix(0)
      entries.add((t, base))
  entries.sort(proc(a, b: (Time, string)): int =
    let c = cmp(a[0], b[0])
    if c != 0: c else: cmp(a[1], b[1]))
  for e in entries: result.add(e[1])

proc relPath(mb: Mailbox, dir, fileName: string): string =
  dir & "/" & fileName

proc openMailbox*(store: MaildirStore, user, name: string): Mailbox =
  ## Open (and create if needed) a mailbox and scan its contents, assigning
  ## stable UIDs from the persisted `.uidlist`.
  result = Mailbox(name: name, path: store.mailboxFsPath(user, name))
  if not dirExists(result.path):
    try: discard existsOrCreateDir(result.path)
    except CatchableError: return
  discard ensureMaildirStructure(result.path)
  result.uidvalidity = loadUidvalidity(result)

  var mapping = loadUidlist(result)
  var nextUid = 1'u32
  for v in mapping.values:
    if v >= nextUid: nextUid = v + 1
  result.uidnext = nextUid

  var changed = false
  for dir in ["new", "cur"]:
    for f in sortedFiles(result.path / dir):
      let msg = MailMessage(
        fileName: f,
        dir: dir,
        recent: (dir == "new"),
        flags: parseFlagSuffix(f),
        size: -1,
      )
      try: msg.internalDate = getLastModificationTime(result.path / dir / f)
      except CatchableError: msg.internalDate = fromUnix(0)
      try: msg.size = getFileSize(result.path / dir / f)
      except CatchableError: msg.size = 0

      let key = keyOf(f)
      var uid = mapping.getOrDefault(key)
      if uid == 0:
        uid = result.uidnext
        inc result.uidnext
        mapping[key] = uid
        changed = true
      msg.uid = uid
      result.messages.add(msg)

  result.messages.sort(proc(a, b: MailMessage): int = cmp(a.uid, b.uid))
  for i, m in result.messages:
    m.seq = i + 1
  if changed:
    saveUidlist(result, mapping)

proc msgAbsPath(mb: Mailbox, msg: MailMessage): string =
  mb.path / msg.dir / msg.fileName

proc loadMessageData*(mb: Mailbox, msg: MailMessage): string =
  ## Read the raw message file contents.
  let p = msgAbsPath(mb, msg)
  if fileExists(p):
    try: result = readFile(p)
    except CatchableError: discard

proc findMessageByUid*(mb: Mailbox, uid: uint32): MailMessage =
  for m in mb.messages:
    if m.uid == uid: return m
  nil

proc seqSetToUids*(mb: Mailbox, spec: string): seq[uint32] =
  ## Expand an IMAP sequence-set (`1:3,5,*`) into a sorted uid list.
  var wanted: seq[uint32]
  for part in spec.split(','):
    let p = part.strip()
    if p.len == 0: continue
    var lo, hi: int
    let colon = p.find(':')
    if colon < 0:
      if p == "*":
        lo = mb.messages.len; hi = mb.messages.len
      else:
        try: lo = parseInt(p) except ValueError: continue
        hi = lo
    else:
      try:
        lo = parseInt(p[0 ..< colon])
      except ValueError:
        if p[0 ..< colon] == "*": lo = mb.messages.len
        else: continue
      let r = p[colon + 1 .. ^1]
      try:
        hi = parseInt(r)
      except ValueError:
        if r == "*": hi = mb.messages.len
        else: continue
      if hi == 0: hi = mb.messages.len
    if lo <= 0: lo = 1
    if hi > mb.messages.len: hi = mb.messages.len
    for i in lo .. hi:
      if i >= 1 and i <= mb.messages.len:
        wanted.add(mb.messages[i - 1].uid)
  wanted

proc uidSetToUids*(mb: Mailbox, spec: string): seq[uint32] =
  ## Expand a UID sequence-set (`1:3,5,*`) into a sorted uid list.
  var wanted: seq[uint32]
  for part in spec.split(','):
    let p = part.strip()
    if p.len == 0: continue
    var lo, hi: uint32
    let colon = p.find(':')
    if colon < 0:
      if p == "*":
        lo = if mb.messages.len > 0: mb.messages[^1].uid else: 0
        hi = lo
      else:
        try: lo = parseUInt(p).uint32 except ValueError: continue
        hi = lo
    else:
      try: lo = parseUInt(p[0 ..< colon]).uint32
      except ValueError:
        if p[0 ..< colon] == "*": lo = if mb.messages.len > 0: mb.messages[^1].uid else: 0
        else: continue
      let r = p[colon + 1 .. ^1]
      try: hi = parseUInt(r).uint32
      except ValueError:
        if r == "*": hi = high(uint32)
        else: continue
    for m in mb.messages:
      if m.uid >= lo and m.uid <= hi:
        wanted.add(m.uid)
  wanted

# ── Flag / lifecycle operations ───────────────────────────────────────────────

proc moveToCur(mb: Mailbox, msg: MailMessage) =
  ## Move a message from `new/` to `cur/` (first time it is \Seen).
  if msg.dir == "cur": return
  let src = msgAbsPath(mb, msg)
  let dst = mb.path / "cur" / msg.fileName & flagSuffix(msg.flags)
  try: moveFile(src, dst)
  except CatchableError: return
  msg.dir = "cur"
  msg.fileName = extractFilename(dst)

proc updateFlags*(mb: Mailbox, msg: MailMessage, flags: set[MailFlag]) =
  ## Persist flag changes by renaming the message file with a new `:2,` suffix.
  let wasInNew = msg.dir == "new"
  msg.flags = flags
  if wasInNew and mfSeen in flags:
    moveToCur(mb, msg)
    return
  if wasInNew:
    return  # still in new/, no suffix yet
  let src = mb.path / "cur" / msg.fileName
  let base = msg.fileName
  let dotPos = base.rfind(":2,")
  let clean = if dotPos >= 0: base[0 ..< dotPos] else: base
  let dst = mb.path / "cur" / clean & flagSuffix(flags)
  try: moveFile(src, dst)
  except CatchableError: return
  msg.fileName = extractFilename(dst)

proc expungeMessage*(mb: Mailbox, msg: MailMessage) =
  ## Delete a message file and drop it from the snapshot.
  let p = msgAbsPath(mb, msg)
  try: removeFile(p)
  except CatchableError: discard
  let idx = mb.messages.find(msg)
  if idx >= 0:
    mb.messages.delete(idx)
    for i in 0 ..< mb.messages.len:
      mb.messages[i].seq = i + 1

proc persistUidChanges*(mb: Mailbox) =
  ## Rewrite `.uidlist` from the current snapshot (used after expunge so UIDs
  ## of remaining messages are stable).
  var mapping = initTable[string, uint32]()
  for m in mb.messages:
    mapping[keyOf(m.fileName)] = m.uid
  saveUidlist(mb, mapping)

# ── Mailbox CRUD (maildir++) ──────────────────────────────────────────────────

proc matchesImapPattern*(name, pattern: string): bool =
  ## Match a mailbox name against an IMAP LIST pattern (RFC 3501 §6.3.8).
  ## `*` matches zero or more characters (including `/`).
  ## `%` matches zero or more characters but NOT `/`.
  proc match(name, pattern: string, pi, ni: int): bool =
    var pi = pi
    var ni = ni
    while pi < pattern.len:
      case pattern[pi]
      of '*':
        inc pi
        if pi >= pattern.len: return true
        for s in ni..name.len:
          if match(name, pattern, pi, s): return true
        return false
      of '%':
        inc pi
        if pi >= pattern.len: return true
        for s in ni..name.len:
          if s > ni and name[s-1] == '/': break
          if match(name, pattern, pi, s): return true
        return false
      else:
        if ni >= name.len or name[ni] != pattern[pi]: return false
        inc pi
        inc ni
    ni >= name.len
  match(name, pattern, 0, 0)

proc listMailboxes*(store: MaildirStore, user: string): seq[string] =
  ## List all mailboxes for a user (including INBOX), depth-first.
  let root = store.userMaildirPath(user)
  if not dirExists(root): return @["INBOX"]
  result = @["INBOX"]
  var stack = @[(root, "")]
  while stack.len > 0:
    let (dir, prefix) = stack.pop()
    for kind, path in walkDir(dir):
      if kind != pcDir: continue
      let base = extractFilename(path)
      if base in ["cur", "new", "tmp"]: continue
      if base.startsWith("."):
        let name = prefix & base[1 .. ^1]
        result.add(name)
        stack.add((path, name & "/"))
  result.sort()

proc mailboxExists*(store: MaildirStore, user, name: string): bool =
  dirExists(store.mailboxFsPath(user, name))

proc createMailbox*(store: MaildirStore, user, name: string): bool =
  ## Create a mailbox (creating any missing parents). Returns false if the
  ## name is invalid or the mailbox already exists.
  if name.toUpperAscii() == "INBOX": return true
  if name.len == 0: return false
  var parent = "INBOX"
  for part in name.split('/'):
    if part.len == 0: return false
    parent = (if parent == "INBOX": part else: parent & "/" & part)
    if not store.mailboxExists(user, parent):
      discard ensureUserMaildir(store, user)
      let p = store.mailboxFsPath(user, parent)
      if not dirExists(p):
        try: discard existsOrCreateDir(p)
        except CatchableError: return false
      discard ensureMaildirStructure(p)
  true

proc deleteMailbox*(store: MaildirStore, user, name: string): bool =
  ## Delete a mailbox. Fails if it has subfolders.
  if name.toUpperAscii() == "INBOX": return false
  let p = store.mailboxFsPath(user, name)
  if not dirExists(p): return false
  var hasChildren = false
  for kind, path in walkDir(p):
    if kind == pcDir:
      let b = extractFilename(path)
      if b notin ["cur", "new", "tmp"]:
        hasChildren = true
        break
  if hasChildren: return false
  try:
    for sub in ["cur", "new", "tmp"]:
      for kind, path in walkDir(p / sub):
        if kind == pcFile: removeFile(path)
    removeDir(p)
    true
  except CatchableError:
    false

proc renameMailbox*(store: MaildirStore, user, fromName, toName: string): bool =
  ## Rename a mailbox (maildir++: renames subfolders under it too).
  if fromName.toUpperAscii() == "INBOX" or toName.toUpperAscii() == "INBOX":
    return false
  let src = store.mailboxFsPath(user, fromName)
  let dst = store.mailboxFsPath(user, toName)
  if not dirExists(src) or dirExists(dst): return false
  if not dirExists(store.mailboxFsPath(user, toName.parentDir())):
    if not store.createMailbox(user, toName.parentDir()):
      return false
  try:
    moveDir(src, dst)
    true
  except CatchableError:
    false

# ── Local delivery (SMTP → Maildir) ───────────────────────────────────────────

proc extractUser*(rcpt: string): string =
  ## `user@domain` (or `"Name" <user@domain>` / `<user@domain>`) → local part.
  var v = rcpt.strip()
  if v.len == 0: return
  if v[0] == '<' and v[^1] == '>':
    v = v[1 ..^ 2].strip()
  let lt = v.find('<')
  if lt >= 0:
    v = v[lt + 1 .. ^1]
    let gt = v.find('>')
    if gt >= 0: v = v[0 ..< gt]
  let at = v.rfind('@')
  if at < 0: return ""
  result = v[0 ..< at].strip()
  if result.len > 0 and result[0] == '"' and result[^1] == '"':
    result = result[1 ..^ 2]

proc extractDomain(rcpt: string): string =
  var v = rcpt.strip()
  if v.len == 0: return
  if v[0] == '<' and v[^1] == '>':
    v = v[1 ..^ 2].strip()
  let lt = v.find('<')
  if lt >= 0:
    v = v[lt + 1 .. ^1]
    let gt = v.find('>')
    if gt >= 0: v = v[0 ..< gt]
  let at = v.rfind('@')
  if at < 0 or at == v.high: return ""
  result = v[at + 1 .. ^1].strip().toLowerAscii()

proc isLocal*(store: MaildirStore, rcpt: string): bool =
  ## Whether a recipient address maps to a local user mailbox.
  if store.localDomains.len == 0: return false
  let domain = extractDomain(rcpt)
  if domain.len == 0: return false
  if domain notin store.localDomains: return false
  true

proc uniqueName(): string  # forward

proc appendMessage*(store: MaildirStore, user, mailbox: string, flags: set[MailFlag],
                    data: string, internalDate: times.Time = default(Time)): tuple[ok: bool, uid, uidvalidity: uint32] =
  ## Append a message to a mailbox (used by IMAP APPEND). Assigns a UID and
  ## returns it (plus the mailbox UIDVALIDITY) for APPENDUID responses.
  ## If `internalDate` is non-zero, it is used as the INTERNALDATE (file mtime).
  let mb = store.openMailbox(user, mailbox)
  if mb.messages.len == 0 and not store.mailboxExists(user, mailbox):
    return
  if not store.ensureUserMaildir(user):
    return
  let dir = mb.path
  let name = uniqueName()
  try:
    let filePath =
      if flags != {}:
        writeFile(dir / "cur" / name & flagSuffix(flags), data)
        dir / "cur" / name & flagSuffix(flags)
      else:
        writeFile(dir / "new" / name, data)
        dir / "new" / name
    if internalDate.toUnix > 0:
      setLastModificationTime(filePath, internalDate)
    let mb2 = store.openMailbox(user, mailbox)
    if mb2.messages.len > 0:
      result.ok = true
      result.uid = mb2.messages[^1].uid
      result.uidvalidity = mb2.uidvalidity
  except CatchableError:
    discard

var uniqueSeq {.global.}: Atomic[int]

proc uniqueName(): string =
  ## Generate a unique Maildir filename: `<epochMs>.<pid>.<seq>`. The counter
  ## is process-global and atomic so SMTP delivery threads and the IMAP loop
  ## never collide.
  uniqueSeq += 1
  let now = epochTime().int64
  result = $now & "." & $getCurrentProcessId() & "." & $uniqueSeq.load()

proc deliver*(store: MaildirStore, mailFrom, rcpt, data: string): bool =
  ## Deliver a message to a local recipient's INBOX Maildir.
  let user = extractUser(rcpt)
  if user.len == 0: return false
  if not store.ensureUserMaildir(user): return false
  let d = store.userMaildirPath(user)

  # Prepend envelope information (Return-Path + Delivered-To) as headers.
  var msg = data
  var hdr = ""
  if not msg.startsWith("Return-Path:"):
    hdr.add("Return-Path: <" & mailFrom.strip() & ">\r\n")
  if not msg.contains("\r\nDelivered-To:") and not msg.startsWith("Delivered-To:"):
    hdr.add("Delivered-To: " & rcpt.strip() & "\r\n")
  if hdr.len > 0:
    msg = hdr & msg

  let name = uniqueName()
  let tmpPath = d / "tmp" / name
  let newPath = d / "new" / name
  try:
    writeFile(tmpPath, msg)
    moveFile(tmpPath, newPath)
    true
  except CatchableError:
    false
