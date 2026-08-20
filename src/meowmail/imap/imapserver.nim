# MeowMail - A high-performance SMTP/IMAP server based on powpow
#
# (c) 2026 George Lemon | LGPLv3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

## A practical IMAP4rev1 server backed by a Maildir store.

import std/[tables, strutils, times, sets, sequtils, base64, algorithm]
from std/net import Port, `$`

import powpow
import ../smtp/smtpauth
import ./mailstore
import ./msgparse

const
  MaxImapLineLen = 16 * 1024 * 1024   # APPEND literals can be large

type
  ImapState* = enum
    stNotAuthenticated, stAuthenticated, stSelected

  AuthStep = enum
    apNone, apPlain, apLoginUser, apLoginPass

  IMAPSession* = ref object
    inbuf: string
    authenticated: bool
    username: string
    state: ImapState
    quitting: bool
    selectedMailbox: string
    mailbox: Mailbox
    readOnly: bool
    authStep: AuthStep
    authUser: string
    tlsActive: bool
    idling: bool
    idleTimer: TimerId
    # literal (APPEND) state
    literalExpected: int
    literalBuf: string
    pendingTokens: seq[string]
    appendMailbox: string
    appendFlags: set[MailFlag]
    appendDate: string
    parsedCache: Table[string, ParsedMessage]
      # Parsed-message cache keyed by `mailbox/keyOf(fileName)` so repeated
      # FETCH/SEARCH on the same messages don't re-read/re-parse the file.

  IMAPServer* = ref object
    loop*: Loop
    listener*: TcpServer
    port*: Port
    store*: MaildirStore
    authUsers*: Table[string, string]
    authProvider*: AuthProvider
    tlsCtx*: SslContext
    subscriptions*: Table[string, seq[string]]  # user -> subscribed mailboxes

proc checkAuth(server: IMAPServer, username, password: string): bool =
  if server.authProvider != nil:
    let decision = server.authProvider(AuthRequest(
      username: username,
      password: password,
      remoteIp: "",
      mechanism: "LOGIN"
    ))
    return decision == authOk
  if server.authUsers.hasKey(username) and server.authUsers[username] == password:
    return true
  # Accept the local part too (e.g. `alice` for `alice@example.com`).
  let local = extractUser(username)
  if local.len > 0 and local != username and
     server.authUsers.hasKey(local) and server.authUsers[local] == password:
    return true
  false

# ── low-level writers ─────────────────────────────────────────────────────────

proc imapWrite(conn: Connection, s: string) =
  discard conn.send(s & "\r\n")

proc imapUntagged(conn: Connection, s: string) =
  imapWrite(conn, "* " & s)

proc imapTagged(conn: Connection, tag, status, text: string) =
  imapWrite(conn, tag & " " & status & " " & text)

proc imapCont(conn: Connection, text: string) =
  imapWrite(conn, "+ " & text)

proc imapQuote(s: string): string =
  if s.len == 0: "\"\""
  else: "\"" & s.replace("\\", "\\\\").replace("\"", "\\\"") & "\""

# ── tokenizer ─────────────────────────────────────────────────────────────────

proc imapTokens(line: string): seq[string] =
  ## Tokenize an IMAP command line. Quoted strings are unquoted; `(`, `)`,
  ## `[`, `]` become standalone tokens. Literal references (`{n}`) are left
  ## as tokens.
  var cur = ""
  var inQuote = false
  var i = 0
  while i < line.len:
    let c = line[i]
    if inQuote:
      if c == '\\' and i + 1 < line.len:
        cur.add(line[i + 1])
        inc i
      elif c == '"':
        inQuote = false
      else:
        cur.add(c)
      inc i
      continue
    case c
    of '"':
      if cur.len > 0:
        result.add(cur)
        cur.setLen(0)
      inQuote = true
      inc i
    of ' ', '\t':
      if cur.len > 0:
        result.add(cur)
        cur.setLen(0)
      inc i
    of '(', ')', '[', ']':
      if cur.len > 0:
        result.add(cur)
        cur.setLen(0)
      result.add($c)
      inc i
    else:
      cur.add(c)
      inc i
  if cur.len > 0:
    result.add(cur)

proc isLiteralSpec(s: string): bool =
  s.len >= 3 and s[0] == '{' and s[^1] == '}' and s[1 .. ^2].allCharsInSet(Digits)

# ── flag helpers ──────────────────────────────────────────────────────────────

proc parseFlagList(tokens: seq[string], start: int,
                    flags: var set[MailFlag], next: var int) =
  ## Parse `(\Seen \Flagged)` or `\Seen \Flagged` into a flag set.
  flags = {}
  var i = start
  if i < tokens.len and tokens[i] == "(":
    inc i
    while i < tokens.len and tokens[i] != ")":
      case tokens[i].toUpperAscii()
      of "\\SEEN": flags.incl(mfSeen)
      of "\\ANSWERED": flags.incl(mfAnswered)
      of "\\FLAGGED": flags.incl(mfFlagged)
      of "\\DELETED": flags.incl(mfDeleted)
      of "\\DRAFT": flags.incl(mfDraft)
      else: discard
      inc i
    if i < tokens.len: inc i  # skip ")"
  else:
    while i < tokens.len:
      let t = tokens[i]
      if t == "(": break
      case t.toUpperAscii()
      of "\\SEEN": flags.incl(mfSeen)
      of "\\ANSWERED": flags.incl(mfAnswered)
      of "\\FLAGGED": flags.incl(mfFlagged)
      of "\\DELETED": flags.incl(mfDeleted)
      of "\\DRAFT": flags.incl(mfDraft)
      else: discard
      inc i
  next = i

# ── mailbox selection responses ───────────────────────────────────────────────

proc sendMailboxStatus(conn: Connection, tag: string, mb: Mailbox, readOnly: bool) =
  var exists = 0
  var recent = 0
  var unseen = 0
  var firstUnseen = 0
  for m in mb.messages:
    inc exists
    if m.recent: inc recent
    if mfSeen notin m.flags:
      inc unseen
      if firstUnseen == 0: firstUnseen = m.seq
  imapUntagged(conn, $exists & " EXISTS")
  imapUntagged(conn, $recent & " RECENT")
  if firstUnseen > 0:
    imapUntagged(conn, "OK [UNSEEN " & $firstUnseen & "] First unseen message")
  imapUntagged(conn, "OK [UIDVALIDITY " & $mb.uidvalidity & "] UIDs valid")
  imapUntagged(conn, "OK [UIDNEXT " & $mb.uidnext & "] Predicted next UID")
  imapUntagged(conn, "FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
  imapUntagged(conn, "OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted")
  if readOnly:
    imapTagged(conn, tag, "OK", "[READ-ONLY] SELECT completed")
  else:
    imapTagged(conn, tag, "OK", "[READ-WRITE] SELECT completed")

# ── FETCH section resolution ──────────────────────────────────────────────────

type
  SectionRef = object
    part: MimePart
    kind: string    # "", "HEADER", "TEXT", "MIME", "WHOLE"
    whole: bool     # empty section → whole message

proc resolveSection(parsed: ParsedMessage, section: string): SectionRef =
  ## Resolve a BODY[section] spec to a part + data kind.
  if section.len == 0:
    return SectionRef(part: parsed.root, kind: "WHOLE", whole: true)
  let s = section.toUpperAscii()
  if s == "HEADER":
    return SectionRef(part: parsed.root, kind: "HEADER")
  if s == "TEXT":
    return SectionRef(part: parsed.root, kind: "TEXT")
  # numeric part numbers
  var i = 0
  var cur: MimePart = parsed.root
  var isMime = false
  var nums: seq[int]
  var done = false
  var trailing = ""
  while i < s.len:
    if done: break
    if s[i] in {'0'..'9'}:
      var n = 0
      while i < s.len and s[i] in {'0'..'9'}:
        n = n * 10 + (ord(s[i]) - ord('0'))
        inc i
      nums.add(n)
    elif s[i] == '.':
      inc i
    elif s[i] == 'H':
      trailing = "HEADER"
      done = true
    elif s[i] == 'T':
      trailing = "TEXT"
      done = true
    elif s[i] == 'M':
      trailing = "MIME"
      isMime = true
      done = true
    else:
      done = true
  # walk parts
  for idx in nums:
    if cur.parts.len >= idx and idx >= 1:
      cur = cur.parts[idx - 1]
    else:
      cur = nil
      break
  if cur == nil:
    return SectionRef()
  if isMime:
    return SectionRef(part: cur, kind: "MIME")
  if trailing == "HEADER":
    return SectionRef(part: cur, kind: "HEADER")
  if trailing == "TEXT":
    return SectionRef(part: cur, kind: "TEXT")
  SectionRef(part: cur, kind: "WHOLE")

proc sectionData(parsed: ParsedMessage, sr: SectionRef): string =
  let raw = parsed.raw
  case sr.kind
  of "WHOLE":
    if sr.whole:
      raw
    else:
      raw[sr.part.headerOffset ..< sr.part.bodyOffset + sr.part.bodyLen]
  of "HEADER":
    raw[sr.part.headerOffset ..< sr.part.headerOffset + sr.part.headerLen]
  of "TEXT":
    raw[sr.part.bodyOffset ..< sr.part.bodyOffset + sr.part.bodyLen]
  of "MIME":
    raw[sr.part.headerOffset ..< sr.part.headerOffset + sr.part.headerLen]
  else:
    ""

# ── FETCH ─────────────────────────────────────────────────────────────────────

proc fetchItem(parsed: ParsedMessage, msg: MailMessage,
               item: string, section: string, partial: int): string =
  ## Build a single FETCH response item (no `* n FETCH (...)` wrapper).
  let base = item.toUpperAscii()
  case base
  of "FLAGS":
    "FLAGS (" & flagSetToImap(msg.flags) & ")"
  of "UID":
    "UID " & $msg.uid
  of "INTERNALDATE":
    let stamp = format(msg.internalDate, "ddd, dd MMM yyyy HH:mm:ss '+0000'")
    "INTERNALDATE \"" & stamp & "\""
  of "RFC822.SIZE":
    "RFC822.SIZE " & $msg.size
  of "ENVELOPE":
    "ENVELOPE " & renderEnvelope(parsed.envelope)
  of "BODYSTRUCTURE":
    "BODYSTRUCTURE " & renderBodyStructure(parsed.root, true)
  of "BODY":
    if section.len == 0:
      "BODY " & renderBodyStructure(parsed.root, false)
    else:
      let sr = resolveSection(parsed, section)
      if sr.part == nil:
        "BODY[" & section & "] NIL"
      else:
        var data = sectionData(parsed, sr)
        if partial >= 0:
          data = data[0 ..< min(partial, data.len)]
        let suffix = if partial >= 0: "<" & $partial & ">" else: ""
        "BODY[" & section & "]" & suffix & " {" & $data.len & "}\r\n" & data
  of "BODY.PEEK":
    let sr = resolveSection(parsed, section)
    if sr.part == nil:
      "BODY[" & section & "] NIL"
    else:
      var data = sectionData(parsed, sr)
      if partial >= 0:
        data = data[0 ..< min(partial, data.len)]
      let suffix = if partial >= 0: "<" & $partial & ">" else: ""
      "BODY[" & section & "]" & suffix & " {" & $data.len & "}\r\n" & data
  of "RFC822":
    let data = if partial >= 0:
      parsed.raw[0 ..< min(partial, parsed.raw.len)]
    else:
      parsed.raw
    "RFC822 {" & $data.len & "}\r\n" & data
  of "RFC822.HEADER":
    let data = parsed.raw[0 ..< parsed.headerEnd]
    "RFC822.HEADER {" & $data.len & "}\r\n" & data
  of "RFC822.TEXT":
    let data = parsed.raw[parsed.headerEnd .. ^1]
    "RFC822.TEXT {" & $data.len & "}\r\n" & data
  else:
    ""

proc getParsedMessage(server: IMAPServer, s: IMAPSession, msg: MailMessage): ParsedMessage  # forward

proc fetchSectionForItem(item: string): tuple[name, section: string, partial: int] =
  result.partial = -1
  let up = item.toUpperAscii()
  result.name = up
  if up.startsWith("BODY["):
    let close = item.find(']')
    if close > 5:
      result.section = item[5 ..< close]
      result.name = "BODY"
      # partial
      let lt = item.find('<', close)
      if lt >= 0:
        let gt = item.find('>', lt)
        if gt > lt:
          try: result.partial = parseInt(item[lt + 1 ..< gt])
          except ValueError: result.partial = -1
  elif up.startsWith("BODY.PEEK["):
    let close = item.find(']')
    if close > 10:
      result.section = item[10 ..< close]
      result.name = "BODY.PEEK"
      let lt = item.find('<', close)
      if lt >= 0:
        let gt = item.find('>', lt)
        if gt > lt:
          try: result.partial = parseInt(item[lt + 1 ..< gt])
          except ValueError: result.partial = -1

proc fetchMessage(conn: Connection, server: IMAPServer, s: IMAPSession,
                  msg: MailMessage, items: seq[string], uidMode: bool) =
  ## Send `* <seq> FETCH (...)` for one message.
  let parsed = getParsedMessage(server, s, msg)
  if parsed == nil:
    return
  var parts: seq[string]
  var bodyItems: seq[string]
  var peek = false
  for item in items:
    let up = item.toUpperAscii()
    if up == "ALL":
      bodyItems.add("FLAGS"); bodyItems.add("INTERNALDATE"); bodyItems.add("RFC822.SIZE"); bodyItems.add("ENVELOPE")
    elif up == "FAST":
      bodyItems.add("FLAGS"); bodyItems.add("INTERNALDATE"); bodyItems.add("RFC822.SIZE")
    elif up == "FULL":
      bodyItems.add("FLAGS"); bodyItems.add("INTERNALDATE"); bodyItems.add("RFC822.SIZE"); bodyItems.add("ENVELOPE"); bodyItems.add("BODY")
    else:
      bodyItems.add(item)
  for item in bodyItems:
    let f = fetchSectionForItem(item)
    if f.name == "BODY":
      peek = false
    elif f.name == "BODY.PEEK":
      peek = true
    let s = fetchItem(parsed, msg, f.name, f.section, f.partial)
    if s.len > 0:
      parts.add(s)
  if uidMode:
    parts.add("UID " & $msg.uid)
  imapWrite(conn, "* " & $msg.seq & " FETCH (" & parts.join(" ") & ")")
  # RFC 3501: BODY[...] (non-PEEK) implicitly sets \Seen
  if not peek:
    if mfSeen notin msg.flags:
      updateFlags(s.mailbox, msg, msg.flags + {mfSeen})

# ── STORE ─────────────────────────────────────────────────────────────────────

proc handleStore(conn: Connection, server: IMAPServer, s: IMAPSession,
                 tag: string, tokens: seq[string], uidMode: bool) =
  if s.state != stSelected:
    imapTagged(conn, tag, "BAD", "No mailbox selected")
    return
  if tokens.len < 3:
    imapTagged(conn, tag, "BAD", "Usage: STORE <set> <item> <flags>")
    return
  let seqSet = tokens[0]
  let item = tokens[1].toUpperAscii()
  var silent = false
  var mode = ""
  if item.startsWith("+FLAGS"):
    mode = "+"
  elif item.startsWith("-FLAGS"):
    mode = "-"
  elif item.startsWith("FLAGS"):
    mode = "="
  else:
    imapTagged(conn, tag, "BAD", "Unknown STORE item")
    return
  if item.endsWith(".SILENT"):
    silent = true
  var flags: set[MailFlag]
  var idx = 0
  parseFlagList(tokens, 2, flags, idx)
  var uids = if uidMode: s.mailbox.uidSetToUids(seqSet) else: s.mailbox.seqSetToUids(seqSet)
  for uid in uids:
    let msg = s.mailbox.findMessageByUid(uid)
    if msg == nil: continue
    var newFlags = msg.flags
    case mode
    of "+": newFlags = newFlags + flags
    of "-": newFlags = newFlags - flags
    else: newFlags = flags
    updateFlags(s.mailbox, msg, newFlags)
    if not silent:
      imapUntagged(conn, $msg.seq & " FETCH (FLAGS (" & flagSetToImap(newFlags) & "))")
  imapTagged(conn, tag, "OK", "STORE completed")

proc uidSetToString(uids: seq[uint32]): string =
  ## Render a sorted uid list as an IMAP sequence set (e.g. `1,3,5:7`).
  if uids.len == 0: return ""
  var parts: seq[string]
  var i = 0
  while i < uids.len:
    var j = i
    while j + 1 < uids.len and uids[j + 1] == uids[j] + 1:
      inc j
    if j == i:
      parts.add($uids[i])
    elif j == i + 1:
      parts.add($uids[i] & "," & $uids[j])
    else:
      parts.add($uids[i] & ":" & $uids[j])
    i = j + 1
  result = parts.join(",")

proc handleCopy(conn: Connection, server: IMAPServer, s: IMAPSession,
                tag: string, tokens: seq[string], move, uidMode: bool) =
  ## Handle COPY / MOVE (and their UID variants). Preserves message flags and
  ## reports the new UIDs via a UIDPLUS COPYUID response.
  if s.state != stSelected:
    imapTagged(conn, tag, "BAD", "No mailbox selected")
    return
  if tokens.len < 2:
    imapTagged(conn, tag, "BAD", "Usage: " & (if move: "MOVE" else: "COPY") & " <set> <mailbox>")
    return
  let seqSet = tokens[0]
  let dest = tokens[1]
  if not server.store.mailboxExists(s.username, dest):
    imapTagged(conn, tag, "NO", "No such mailbox")
    return
  var uids = if uidMode: s.mailbox.uidSetToUids(seqSet) else: s.mailbox.seqSetToUids(seqSet)
  var srcList: seq[uint32]
  var dstList: seq[uint32]
  var destValidity = 0'u32
  var copied: seq[MailMessage]
  for uid in uids:
    let msg = s.mailbox.findMessageByUid(uid)
    if msg == nil: continue
    let data = loadMessageData(s.mailbox, msg)
    if data.len == 0: continue
    let res = server.store.appendMessage(s.username, dest, msg.flags, data)
    if res.ok:
      srcList.add(uid)
      dstList.add(res.uid)
      destValidity = res.uidvalidity
      copied.add(msg)
  if move:
    for msg in copied:
      let seqNum = msg.seq
      expungeMessage(s.mailbox, msg)
      imapUntagged(conn, $seqNum & " EXPUNGE")
    persistUidChanges(s.mailbox)
  var extra = ""
  if srcList.len > 0:
    extra = "[COPYUID " & $destValidity & " " & uidSetToString(srcList) &
            " " & uidSetToString(dstList) & "] "
  imapTagged(conn, tag, "OK", extra & (if move: "MOVE" else: "COPY") & " completed")

# ── SEARCH ─────────────────────────────────────────────────────# ── SEARCH ────────────────────────────────────────────────────────────────────

type
  SearchKey* = enum
    skAll, skAnd, skOr, skNot,
    skAnswered, skBcc, skBefore, skBody, skCc, skDeleted, skDraft,
    skFlagged, skFrom, skHeader, skKeyword, skLarger, skNew, skOld,
    skOn, skRecent, skSeen, skSentBefore, skSentOn, skSentSince,
    skSince, skSmaller, skSubject, skText, skTo, skUid,
    skUnanswered, skUndeleted, skUndraft, skUnflagged, skUnkeyword, skUnseen

  SearchNode* = ref object
    key*: SearchKey
    str*: string
    date*: times.Time
    num*: int64
    uids*: seq[uint32]
    children*: seq[SearchNode]

proc isDateKey(k: SearchKey): bool =
  k in {skBefore, skOn, skSince, skSentBefore, skSentOn, skSentSince}

proc parseDateArg(s: string): times.Time =
  # dd-MMM-yyyy (e.g. 06-Jan-2026)
  var parts = s.strip().split('-')
  if parts.len != 3: return fromUnix(0)
  let months = ["jan", "feb", "mar", "apr", "may", "jun",
                "jul", "aug", "sep", "oct", "nov", "dec"]
  var mo = 0
  for i, m in months:
    if parts[1].toLowerAscii() == m:
      mo = i + 1
      break
  if mo == 0: return fromUnix(0)
  var d, y = 0
  try:
    d = parseInt(parts[0])
    y = parseInt(parts[2])
  except ValueError:
    return fromUnix(0)
  result = toTime(initDateTime(d, Month(mo), y, 0, 0, 0, utc()))

proc parseSearchOr(tokens: seq[string], i: var int): SearchNode  # forward
proc parseSearchNot(tokens: seq[string], i: var int): SearchNode  # forward

proc parseSearchKey(tokens: seq[string], i: var int): SearchNode =
  if i >= tokens.len: return
  let t = tokens[i].toUpperAscii()
  if tokens[i] == "(":
    inc i
    result = SearchNode(key: skAnd)
    while i < tokens.len and tokens[i] != ")":
      result.children.add(parseSearchOr(tokens, i))
    if i < tokens.len: inc i
    if result.children.len == 1:
      result = result.children[0]
    return
  result = SearchNode(key: skAll)
  case t
  of "ALL": inc i
  of "ANSWERED": result.key = skAnswered; inc i
  of "DELETED": result.key = skDeleted; inc i
  of "DRAFT": result.key = skDraft; inc i
  of "FLAGGED": result.key = skFlagged; inc i
  of "NEW": result.key = skNew; inc i
  of "OLD": result.key = skOld; inc i
  of "RECENT": result.key = skRecent; inc i
  of "SEEN": result.key = skSeen; inc i
  of "UNANSWERED": result.key = skUnanswered; inc i
  of "UNDELETED": result.key = skUndeleted; inc i
  of "UNDRAFT": result.key = skUndraft; inc i
  of "UNFLAGGED": result.key = skUnflagged; inc i
  of "UNSEEN": result.key = skUnseen; inc i
  of "BCC": result.key = skBcc; inc i; result.str = tokens[i].toLowerAscii(); inc i
  of "BODY": result.key = skBody; inc i; result.str = tokens[i].toLowerAscii(); inc i
  of "CC": result.key = skCc; inc i; result.str = tokens[i].toLowerAscii(); inc i
  of "FROM": result.key = skFrom; inc i; result.str = tokens[i].toLowerAscii(); inc i
  of "SUBJECT": result.key = skSubject; inc i; result.str = tokens[i].toLowerAscii(); inc i
  of "TEXT": result.key = skText; inc i; result.str = tokens[i].toLowerAscii(); inc i
  of "TO": result.key = skTo; inc i; result.str = tokens[i].toLowerAscii(); inc i
  of "KEYWORD":
    result.key = skKeyword; inc i
    result.str = tokens[i].toLowerAscii()
    if result.str == "\\seen": result.key = skSeen
    elif result.str == "\\flagged": result.key = skFlagged
    elif result.str == "\\answered": result.key = skAnswered
    elif result.str == "\\deleted": result.key = skDeleted
    elif result.str == "\\draft": result.key = skDraft
    inc i
  of "UNKEYWORD":
    result.key = skUnkeyword; inc i
    result.str = tokens[i].toLowerAscii()
    if result.str == "\\seen": result.key = skUnseen
    elif result.str == "\\flagged": result.key = skUnflagged
    elif result.str == "\\answered": result.key = skUnanswered
    elif result.str == "\\deleted": result.key = skUndeleted
    elif result.str == "\\draft": result.key = skUndraft
    inc i
  of "HEADER":
    result.key = skHeader; inc i
    result.str = tokens[i].toLowerAscii(); inc i
    result.str = result.str & "\x01" & tokens[i].toLowerAscii(); inc i
  of "LARGER":
    result.key = skLarger; inc i
    try: result.num = parseInt(tokens[i]).int64 except ValueError: result.num = -1
    inc i
  of "SMALLER":
    result.key = skSmaller; inc i
    try: result.num = parseInt(tokens[i]).int64 except ValueError: result.num = -1
    inc i
  of "UID":
    result.key = skUid; inc i
    result.uids = @[]
    inc i
  of "BEFORE": result.key = skBefore; inc i; result.date = parseDateArg(tokens[i]); inc i
  of "ON": result.key = skOn; inc i; result.date = parseDateArg(tokens[i]); inc i
  of "SINCE": result.key = skSince; inc i; result.date = parseDateArg(tokens[i]); inc i
  of "SENTBEFORE": result.key = skSentBefore; inc i; result.date = parseDateArg(tokens[i]); inc i
  of "SENTON": result.key = skSentOn; inc i; result.date = parseDateArg(tokens[i]); inc i
  of "SENTSINCE": result.key = skSentSince; inc i; result.date = parseDateArg(tokens[i]); inc i
  else: inc i

proc parseSearchNot(tokens: seq[string], i: var int): SearchNode =
  if i < tokens.len and tokens[i].toUpperAscii() == "NOT":
    inc i
    result = SearchNode(key: skNot)
    result.children.add(parseSearchNot(tokens, i))
  else:
    result = parseSearchKey(tokens, i)

proc parseSearchOr(tokens: seq[string], i: var int): SearchNode =
  if i < tokens.len and tokens[i].toUpperAscii() == "OR":
    inc i
    result = SearchNode(key: skOr)
    result.children.add(parseSearchNot(tokens, i))
    result.children.add(parseSearchNot(tokens, i))
  else:
    result = parseSearchNot(tokens, i)

proc parseSearch(tokens: seq[string]): SearchNode =
  var i = 0
  # optional CHARSET
  if tokens.len >= 2 and tokens[0].toUpperAscii() == "CHARSET":
    i = 2
  result = SearchNode(key: skAnd)
  while i < tokens.len:
    result.children.add(parseSearchOr(tokens, i))
  if result.children.len == 1:
    result = result.children[0]

proc dateOnly(t: times.Time): times.Time =
  let unix = t.toUnix()
  initTime((unix div 86400) * 86400, 0)

proc decodedHeaderSearch(parsed: ParsedMessage, name: string): string  # forward

proc evalSearch(node: SearchNode, parsed: ParsedMessage, msg: MailMessage): bool =
  case node.key
  of skAll: true
  of skAnd:
    for c in node.children:
      if not evalSearch(c, parsed, msg): return false
    true
  of skOr:
    for c in node.children:
      if evalSearch(c, parsed, msg): return true
    false
  of skNot:
    not evalSearch(node.children[0], parsed, msg)
  of skAnswered: mfAnswered in msg.flags
  of skDeleted: mfDeleted in msg.flags
  of skDraft: mfDraft in msg.flags
  of skFlagged: mfFlagged in msg.flags
  of skSeen: mfSeen in msg.flags
  of skRecent: msg.recent
  of skNew: msg.recent and (mfSeen notin msg.flags)
  of skOld: not msg.recent
  of skUnanswered: mfAnswered notin msg.flags
  of skUndeleted: mfDeleted notin msg.flags
  of skUndraft: mfDraft notin msg.flags
  of skUnflagged: mfFlagged notin msg.flags
  of skUnseen: mfSeen notin msg.flags
  of skUnkeyword: true
  of skKeyword: true
  of skLarger: msg.size > node.num
  of skSmaller: msg.size >= 0 and msg.size < node.num
  of skUid:
    msg.uid in node.uids
  of skBefore: dateOnly(msg.internalDate) < node.date
  of skOn: dateOnly(msg.internalDate) == node.date
  of skSince: dateOnly(msg.internalDate) >= node.date
  of skSentBefore: parsed.envelope.date.len > 0 and dateOnly(parseDateStr(parsed.envelope.date)) < node.date
  of skSentOn: parsed.envelope.date.len > 0 and dateOnly(parseDateStr(parsed.envelope.date)) == node.date
  of skSentSince: parsed.envelope.date.len > 0 and dateOnly(parseDateStr(parsed.envelope.date)) >= node.date
  of skBcc:
    node.str.len == 0 or decodedHeaderSearch(parsed, "Bcc").contains(node.str)
  of skCc:
    node.str.len == 0 or decodedHeaderSearch(parsed, "Cc").contains(node.str)
  of skFrom:
    node.str.len == 0 or decodedHeaderSearch(parsed, "From").contains(node.str)
  of skTo:
    node.str.len == 0 or decodedHeaderSearch(parsed, "To").contains(node.str)
  of skSubject:
    node.str.len == 0 or parsed.envelope.subject.toLowerAscii().contains(node.str)
  of skBody:
    node.str.len == 0 or textContent(parsed).toLowerAscii().contains(node.str)
  of skText:
    node.str.len == 0 or (textContent(parsed).toLowerAscii().contains(node.str) or
                          headerSearchText(parsed).toLowerAscii().contains(node.str))
  of skHeader:
    let parts = node.str.split('\x01')
    if parts.len == 2:
      decodedHeaderSearch(parsed, parts[0]).contains(parts[1])
    else:
      false

proc decodedHeaderSearch(parsed: ParsedMessage, name: string): string =
  var acc = ""
  for v in getAllHeaders(parsed.headers, name):
    acc.add(decodeMimeWords(v).toLowerAscii() & " ")
  acc

# ── IDLE ──────────────────────────────────────────────────────────────────────

proc cmpByUid(a, b: MailMessage): int {.noSideEffect, gcsafe.} = cmp(a.uid, b.uid)

proc rescanSelected(server: IMAPServer, s: IMAPSession): bool =
  ## Re-open the selected mailbox; returns true if the message count changed.
  if s.selectedMailbox.len == 0 or not s.authenticated: return false
  let old = s.mailbox.messages.len
  let prevRecent = s.mailbox.messages.filterIt(it.recent).len
  s.mailbox = server.store.openMailbox(s.username, s.selectedMailbox)
  s.mailbox.messages.sort(cmpByUid)
  for i, m in s.mailbox.messages:
    m.seq = i + 1
  let now = s.mailbox.messages.len
  let nowRecent = s.mailbox.messages.filterIt(it.recent).len
  now != old or nowRecent != prevRecent

proc startIdle(server: IMAPServer, conn: Connection, s: IMAPSession) =
  imapCont(conn, "idling")
  s.idling = true
  s.idleTimer = server.loop.addInterval(1000) do (id: int):
    let sess = cast[IMAPSession](conn.data)
    if sess == nil or not sess.idling:
      if sess != nil: sess.idling = false
      return
    if sess.selectedMailbox.len > 0:
      if rescanSelected(server, sess):
        imapUntagged(conn, $sess.mailbox.messages.len & " EXISTS")
        imapUntagged(conn, $sess.mailbox.messages.filterIt(it.recent).len & " RECENT")

proc endIdle(server: IMAPServer, conn: Connection, s: IMAPSession, tag: string) {.noinline.} =
  if s.idleTimer != TimerId(0):
    server.loop.cancelTimer(s.idleTimer)
    s.idleTimer = TimerId(0)
  s.idling = false
  if s.selectedMailbox.len > 0:
    if rescanSelected(server, s):
      imapUntagged(conn, $s.mailbox.messages.len & " EXISTS")
      imapUntagged(conn, $s.mailbox.messages.filterIt(it.recent).len & " RECENT")
  imapTagged(conn, tag, "OK", "IDLE terminated")

# ── command handlers ──────────────────────────────────────────────────────────

proc handleAuthCont(conn: Connection, server: IMAPServer, s: IMAPSession, line: string) {.noinline.} =
  case s.authStep
  of apPlain:
    s.authStep = apNone
    var decoded = ""
    try:
      decoded = decode(line)
    except CatchableError:
      imapTagged(conn, s.pendingTokens[0], "NO", "Invalid base64")
      return
    let parts = decoded.split('\0')
    if parts.len < 3:
      imapTagged(conn, s.pendingTokens[0], "NO", "Invalid credentials")
      return
    let user = parts[^2]
    let pass = parts[^1]
    if checkAuth(server, user, pass):
      s.authenticated = true
      s.username = extractUser(user)
      if s.username.len == 0:
        s.username = user
      s.state = stAuthenticated
      imapTagged(conn, s.pendingTokens[0], "OK", "AUTHENTICATE completed")
    else:
      imapTagged(conn, s.pendingTokens[0], "NO", "Authentication failed")
  of apLoginUser:
    s.authStep = apLoginPass
    s.authUser = line
    imapCont(conn, base64.encode("Password:"))
  of apLoginPass:
    s.authStep = apNone
    if checkAuth(server, s.authUser, line):
      s.authenticated = true
      s.username = extractUser(s.authUser)
      if s.username.len == 0:
        s.username = s.authUser
      s.state = stAuthenticated
      imapTagged(conn, s.pendingTokens[0], "OK", "AUTHENTICATE completed")
    else:
      imapTagged(conn, s.pendingTokens[0], "NO", "Authentication failed")
  of apNone:
    discard

proc handleSelect(conn: Connection, server: IMAPServer, s: IMAPSession,
                  tag: string, name: string, readOnly: bool) =
  if not s.authenticated:
    imapTagged(conn, tag, "NO", "Authenticate first")
    return
  if name.len == 0:
    imapTagged(conn, tag, "BAD", "Mailbox name required")
    return
  if not server.store.mailboxExists(s.username, name):
    imapTagged(conn, tag, "NO", "No such mailbox")
    return
  s.mailbox = server.store.openMailbox(s.username, name)
  s.mailbox.messages.sort(cmpByUid)
  for i, m in s.mailbox.messages:
    m.seq = i + 1
  s.selectedMailbox = name
  s.readOnly = readOnly
  s.state = stSelected
  s.parsedCache.clear()
  sendMailboxStatus(conn, tag, s.mailbox, readOnly)

proc handleList(conn: Connection, server: IMAPServer, s: IMAPSession,
                tag: string, tokens: seq[string], subscribed: bool) =
  if not s.authenticated:
    imapTagged(conn, tag, "NO", "Authenticate first")
    return
  var pattern = "*"
  if tokens.len >= 3:
    pattern = tokens[2]
  var all = server.store.listMailboxes(s.username)
  var subs = server.subscriptions.getOrDefault(s.username)
  if subscribed and subs.len == 0 and not server.subscriptions.hasKey(s.username):
    subs = server.store.loadSubscriptions(s.username)
  for name in all:
    if not matchesImapPattern(name, pattern): continue
    let hasChildren = all.anyIt(it.len > name.len and it.startsWith(name & "/"))
    var attrs: seq[string]
    if subscribed and name notin subs:
      continue
    if hasChildren:
      attrs.add("\\HasChildren")
    else:
      attrs.add("\\HasNoChildren")
    if subscribed and name in subs:
      attrs.add("\\Subscribed")
    imapUntagged(conn, "LIST (" & attrs.join(" ") & ") \"/\" " & imapQuote(name))
  imapTagged(conn, tag, "OK", (if subscribed: "LSUB" else: "LIST") & " completed")

proc handleSubscribe(conn: Connection, server: IMAPServer, s: IMAPSession,
                     tag: string, name: string, doSubscribe: bool) =
  if not s.authenticated:
    imapTagged(conn, tag, "NO", "Authenticate first")
    return
  var subs = server.subscriptions.getOrDefault(s.username)
  if subs.len == 0 and not server.subscriptions.hasKey(s.username):
    subs = server.store.loadSubscriptions(s.username)
  if doSubscribe:
    if name notin subs: subs.add(name)
  else:
    subs.keepItIf(it != name)
  server.subscriptions[s.username] = subs
  server.store.saveSubscriptions(s.username, subs)
  imapTagged(conn, tag, "OK", (if doSubscribe: "SUBSCRIBE" else: "UNSUBSCRIBE") & " completed")

proc handleFetch(conn: Connection, server: IMAPServer, s: IMAPSession,
                 tag: string, tokens: seq[string], uidMode: bool) =
  if s.state != stSelected:
    imapTagged(conn, tag, "BAD", "No mailbox selected")
    return
  if tokens.len < 2:
    imapTagged(conn, tag, "BAD", "Usage: FETCH <set> <items>")
    return
  let seqSet = tokens[0]
  var items: seq[string]
  var i = 1
  if i < tokens.len and tokens[i] == "(":
    inc i
    while i < tokens.len and tokens[i] != ")":
      var item = tokens[i]
      inc i
      if i < tokens.len and tokens[i] == "[":
        item.add("[")
        inc i
        while i < tokens.len and tokens[i] != "]":
          item.add(tokens[i])
          inc i
        if i < tokens.len: inc i
        item.add("]")
      if i < tokens.len and tokens[i].startsWith("<"):
        item.add(tokens[i])
        inc i
      items.add(item)
    inc i
  else:
    while i < tokens.len:
      var item = tokens[i]
      inc i
      if i < tokens.len and tokens[i] == "[":
        item.add("[")
        inc i
        while i < tokens.len and tokens[i] != "]":
          item.add(tokens[i])
          inc i
        if i < tokens.len: inc i
        item.add("]")
      if i < tokens.len and tokens[i].startsWith("<"):
        item.add(tokens[i])
        inc i
      items.add(item)
  var uids = if uidMode: s.mailbox.uidSetToUids(seqSet) else: s.mailbox.seqSetToUids(seqSet)
  for uid in uids:
    let msg = s.mailbox.findMessageByUid(uid)
    if msg != nil:
      fetchMessage(conn, server, s, msg, items, uidMode)
  imapTagged(conn, tag, "OK", (if uidMode: "UID " else: "") & "FETCH completed")

proc handleSearch(conn: Connection, server: IMAPServer, s: IMAPSession,
                  tag: string, tokens: seq[string], uidMode: bool) =
  if s.state != stSelected:
    imapTagged(conn, tag, "BAD", "No mailbox selected")
    return
  let node = parseSearch(tokens)
  var matches: seq[string]
  for m in s.mailbox.messages:
    let parsed = getParsedMessage(server, s, m)
    if parsed != nil and evalSearch(node, parsed, m):
      matches.add(if uidMode: $m.uid else: $m.seq)
  imapUntagged(conn, "SEARCH " & matches.join(" "))
  imapTagged(conn, tag, "OK", (if uidMode: "UID " else: "") & "SEARCH completed")

proc handleExpunge(conn: Connection, server: IMAPServer, s: IMAPSession,
                   tag: string, uidMode: bool, uidSet: string = "",
                   silent = false, okText = "EXPUNGE completed") =
  if s.state != stSelected:
    imapTagged(conn, tag, "BAD", "No mailbox selected")
    return
  var uidsToExpunge: seq[uint32]
  for m in s.mailbox.messages:
    if mfDeleted in m.flags:
      if uidMode:
        if uidSet.len == 0 or m.uid in s.mailbox.uidSetToUids(uidSet):
          uidsToExpunge.add(m.uid)
      else:
        uidsToExpunge.add(m.uid)
  for uid in uidsToExpunge:
    let msg = s.mailbox.findMessageByUid(uid)
    if msg == nil: continue
    let seqNum = msg.seq
    expungeMessage(s.mailbox, msg)
    if not silent:
      imapUntagged(conn, $seqNum & " EXPUNGE")
  persistUidChanges(s.mailbox)
  imapTagged(conn, tag, "OK", okText)

proc handleAppend(conn: Connection, server: IMAPServer, s: IMAPSession,
                  tag: string, mailbox: string, flags: set[MailFlag],
                  data: string, date: string = "") =
  if not s.authenticated:
    imapTagged(conn, tag, "NO", "Authenticate first")
    return
  if mailbox.len == 0:
    imapTagged(conn, tag, "BAD", "Mailbox name required")
    return
  var internalDate: times.Time
  if date.len > 0:
    try:
      internalDate = parseDateStr(date)
    except CatchableError:
      discard
  let res = server.store.appendMessage(s.username, mailbox, flags, data, internalDate)
  if res.ok:
    imapTagged(conn, tag, "OK", "[APPENDUID " & $res.uidvalidity & " " & $res.uid & "] APPEND completed")
  else:
    imapTagged(conn, tag, "NO", "APPEND failed")

proc handleCommand(conn: Connection, server: IMAPServer, s: IMAPSession,
                 line: string) {.noinline.} =
  let tokens = imapTokens(line)
  if tokens.len == 0: return
  let tag = tokens[0]
  let cmd = tokens[1].toUpperAscii()

  case cmd
  of "CAPABILITY":
    var caps = "IMAP4rev1 UIDPLUS IDLE MOVE CHILDREN NAMESPACE"
    if s.tlsActive:
      caps.add(" AUTH=PLAIN AUTH=LOGIN")
    else:
      caps.add(" STARTTLS AUTH=PLAIN AUTH=LOGIN")
    imapUntagged(conn, "CAPABILITY " & caps)
    imapTagged(conn, tag, "OK", "CAPABILITY completed")
  of "NOOP":
    if s.state == stSelected and s.selectedMailbox.len > 0:
      if rescanSelected(server, s):
        imapUntagged(conn, $s.mailbox.messages.len & " EXISTS")
        imapUntagged(conn, $s.mailbox.messages.filterIt(it.recent).len & " RECENT")
    imapTagged(conn, tag, "OK", "NOOP completed")
  of "LOGOUT":
    if s.idling:
      endIdle(server, conn, s, tag)
    imapUntagged(conn, "BYE Logging out")
    imapTagged(conn, tag, "OK", "LOGOUT completed")
    s.quitting = true
  of "STARTTLS":
    if s.tlsActive:
      imapTagged(conn, tag, "BAD", "TLS already active")
    elif server.tlsCtx == nil:
      imapTagged(conn, tag, "BAD", "TLS not available")
    elif s.authenticated:
      imapTagged(conn, tag, "BAD", "Already authenticated")
    else:
      imapTagged(conn, tag, "OK", "Begin TLS negotiation now")
      s.tlsActive = true
      s.inbuf.setLen(0)
      try:
        conn.wrapTls(server.tlsCtx)
        # RFC 3501 §6.2.1: re-advertise capabilities after TLS upgrade.
        imapUntagged(conn, "CAPABILITY IMAP4rev1 UIDPLUS IDLE MOVE CHILDREN NAMESPACE AUTH=PLAIN AUTH=LOGIN")
      except SslError:
        s.quitting = true
  of "LOGIN":
    if s.authenticated:
      imapTagged(conn, tag, "BAD", "Already authenticated")
    elif tokens.len < 4:
      imapTagged(conn, tag, "BAD", "Usage: LOGIN <user> <pass>")
    else:
      if checkAuth(server, tokens[2], tokens[3]):
        s.authenticated = true
        # Maildir directories are keyed by the local part of the address.
        s.username = extractUser(tokens[2])
        if s.username.len == 0:
          s.username = tokens[2]
        s.state = stAuthenticated
        imapTagged(conn, tag, "OK", "LOGIN completed")
      else:
        imapTagged(conn, tag, "NO", "Authentication failed")
  of "AUTHENTICATE":
    if s.authenticated:
      imapTagged(conn, tag, "BAD", "Already authenticated")
    elif tokens.len < 3:
      imapTagged(conn, tag, "BAD", "Usage: AUTHENTICATE <mech>")
    else:
      let mech = tokens[2].toUpperAscii()
      case mech
      of "PLAIN":
        s.authStep = apPlain
        s.pendingTokens = tokens
        imapCont(conn, "")
      of "LOGIN":
        s.authStep = apLoginUser
        s.pendingTokens = tokens
        imapCont(conn, base64.encode("Username:"))
      else:
        imapTagged(conn, tag, "NO", "Unsupported authentication mechanism")
  of "SELECT", "EXAMINE":
    if tokens.len < 3:
      imapTagged(conn, tag, "BAD", "Usage: " & cmd & " <mailbox>")
    else:
      handleSelect(conn, server, s, tag, tokens[2], cmd == "EXAMINE")
  of "LIST", "LSUB":
    handleList(conn, server, s, tag, tokens, cmd == "LSUB")
  of "CREATE":
    if not s.authenticated: imapTagged(conn, tag, "NO", "Authenticate first")
    elif tokens.len < 3: imapTagged(conn, tag, "BAD", "Usage: CREATE <mailbox>")
    elif server.store.createMailbox(s.username, tokens[2]):
      imapTagged(conn, tag, "OK", "CREATE completed")
    else:
      imapTagged(conn, tag, "NO", "CREATE failed")
  of "DELETE":
    if not s.authenticated: imapTagged(conn, tag, "NO", "Authenticate first")
    elif tokens.len < 3: imapTagged(conn, tag, "BAD", "Usage: DELETE <mailbox>")
    elif server.store.deleteMailbox(s.username, tokens[2]):
      imapTagged(conn, tag, "OK", "DELETE completed")
    else:
      imapTagged(conn, tag, "NO", "DELETE failed (INBOX or non-empty?)")
  of "RENAME":
    if not s.authenticated: imapTagged(conn, tag, "NO", "Authenticate first")
    elif tokens.len < 4: imapTagged(conn, tag, "BAD", "Usage: RENAME <old> <new>")
    elif server.store.renameMailbox(s.username, tokens[2], tokens[3]):
      imapTagged(conn, tag, "OK", "RENAME completed")
    else:
      imapTagged(conn, tag, "NO", "RENAME failed")
  of "SUBSCRIBE", "UNSUBSCRIBE":
    if tokens.len < 3:
      imapTagged(conn, tag, "BAD", "Usage: " & cmd & " <mailbox>")
    else:
      handleSubscribe(conn, server, s, tag, tokens[2], cmd == "SUBSCRIBE")
  of "STATUS":
    if not s.authenticated: imapTagged(conn, tag, "NO", "Authenticate first")
    elif tokens.len < 4: imapTagged(conn, tag, "BAD", "Usage: STATUS <mailbox> (items)")
    elif not server.store.mailboxExists(s.username, tokens[2]):
      imapTagged(conn, tag, "NO", "No such mailbox")
    else:
      let mb = server.store.openMailbox(s.username, tokens[2])
      var items: seq[string]
      var i = 3
      if i < tokens.len and tokens[i] == "(":
        inc i
        while i < tokens.len and tokens[i] != ")":
          items.add(tokens[i].toUpperAscii())
          inc i
      var parts: seq[string]
      for it in items:
        case it
        of "MESSAGES": parts.add("MESSAGES " & $mb.messages.len)
        of "RECENT": parts.add("RECENT " & $mb.messages.filterIt(it.recent).len)
        of "UNSEEN": parts.add("UNSEEN " & $mb.messages.filterIt(mfSeen notin it.flags).len)
        of "UIDNEXT": parts.add("UIDNEXT " & $mb.uidnext)
        of "UIDVALIDITY": parts.add("UIDVALIDITY " & $mb.uidvalidity)
        else: discard
      imapUntagged(conn, "STATUS " & imapQuote(tokens[2]) & " (" & parts.join(" ") & ")")
      imapTagged(conn, tag, "OK", "STATUS completed")
  of "FETCH":
    handleFetch(conn, server, s, tag, tokens[2 .. ^1], false)
  of "UID":
    if tokens.len >= 3:
      let sub = tokens[2].toUpperAscii()
      case sub
      of "FETCH": handleFetch(conn, server, s, tag, tokens[3 .. ^1], true)
      of "COPY": handleCopy(conn, server, s, tag, tokens[3 .. ^1], false, true)
      of "MOVE": handleCopy(conn, server, s, tag, tokens[3 .. ^1], true, true)
      of "STORE": handleStore(conn, server, s, tag, tokens[3 .. ^1], true)
      of "SEARCH": handleSearch(conn, server, s, tag, tokens[3 .. ^1], true)
      of "EXPUNGE":
        if tokens.len >= 4:
          handleExpunge(conn, server, s, tag, true, tokens[3])
        else:
          imapTagged(conn, tag, "BAD", "Usage: UID EXPUNGE <set>")
      else:
        imapTagged(conn, tag, "BAD", "Unknown UID command")
    else:
      imapTagged(conn, tag, "BAD", "Usage: UID <cmd>")
  of "COPY":
    handleCopy(conn, server, s, tag, tokens[2 .. ^1], false, false)
  of "MOVE":
    handleCopy(conn, server, s, tag, tokens[2 .. ^1], true, false)
  of "STORE":
    handleStore(conn, server, s, tag, tokens[2 .. ^1], false)
  of "SEARCH":
    handleSearch(conn, server, s, tag, tokens[2 .. ^1], false)
  of "EXPUNGE":
    handleExpunge(conn, server, s, tag, false)
  of "CLOSE":
    if s.state == stSelected:
      handleExpunge(conn, server, s, tag, false, silent = true, okText = "CLOSE completed")
    s.state = stAuthenticated
    s.selectedMailbox.setLen(0)
    s.mailbox = nil
  of "UNSELECT":
    s.state = stAuthenticated
    s.selectedMailbox.setLen(0)
    s.mailbox = nil
    imapTagged(conn, tag, "OK", "UNSELECT completed")
  of "CHECK":
    imapTagged(conn, tag, "OK", "CHECK completed")
  of "NAMESPACE":
    imapUntagged(conn, "NAMESPACE ((\"\" \"/\")) NIL NIL")
    imapTagged(conn, tag, "OK", "NAMESPACE completed")
  of "ID":
    imapUntagged(conn, "ID (\"name\" \"MeowMail\" \"version\" \"0.1.0\")")
    imapTagged(conn, tag, "OK", "ID completed")
  of "IDLE":
    if s.state != stSelected:
      imapTagged(conn, tag, "BAD", "No mailbox selected")
    else:
      startIdle(server, conn, s)
  of "APPEND":
    imapTagged(conn, tag, "BAD", "APPEND requires literal data")
  else:
    imapTagged(conn, tag, "BAD", "Unrecognized command: " & cmd)
proc beginAppend(conn: Connection, s: IMAPSession, tokens: seq[string]) {.noinline.} =
  s.literalBuf.setLen(0)
  var i = 2
  s.appendMailbox = if i < tokens.len: tokens[i] else: ""
  inc i
  s.appendFlags = {}
  if i < tokens.len and tokens[i] == "(":
    var appendFlags: set[MailFlag]
    parseFlagList(tokens, i, appendFlags, i)
    s.appendFlags = appendFlags
  if i < tokens.len and not isLiteralSpec(tokens[i]):
    s.appendDate = tokens[i]
    inc i
  s.pendingTokens = tokens
  s.literalExpected = 0
  if i < tokens.len and isLiteralSpec(tokens[i]):
    try: s.literalExpected = parseInt(tokens[i][1 .. ^2])
    except ValueError: s.literalExpected = 0
  imapCont(conn, "Ready for literal data")
proc finishAppend(conn: Connection, server: IMAPServer, s: IMAPSession) {.noinline.} =
  let tag = s.pendingTokens[0]
  let data = s.literalBuf
  s.literalBuf.setLen(0)
  handleAppend(conn, server, s, tag, s.appendMailbox, s.appendFlags, data, s.appendDate)

# ── input handling ────────────────────────────────────────────────────────────

proc handleData(server: IMAPServer, conn: Connection, s: IMAPSession, chunk: string) {.noinline.} =
  s.inbuf.add(chunk)
  if s.literalExpected > 0:
    let need = s.literalExpected - s.literalBuf.len
    if s.inbuf.len >= need:
      if need > 0:
        s.literalBuf.add(s.inbuf[0 ..< need])
        s.inbuf = s.inbuf[need .. ^1]
      s.literalExpected = 0
      if s.inbuf.startsWith("\r\n"):
        s.inbuf = s.inbuf[2 .. ^1]
      elif s.inbuf.startsWith("\n"):
        s.inbuf = s.inbuf[1 .. ^1]
      finishAppend(conn, server, s)
    return
  while true:
    let idx = s.inbuf.find("\r\n")
    if idx < 0:
      if s.inbuf.len > MaxImapLineLen:
        imapUntagged(conn, "BYE Line too long")
        imapTagged(conn, "*", "BAD", "Line too long")
        conn.closeAfterDrain()
      return
    let line = s.inbuf[0 ..< idx]
    s.inbuf = s.inbuf[idx + 2 .. ^1]
    if s.idling:
      if line.strip().toUpperAscii() == "DONE":
        endIdle(server, conn, s, s.pendingTokens[0])
    else:
      if s.authStep != apNone:
        handleAuthCont(conn, server, s, line)
      else:
        let tokens = imapTokens(line)
        if tokens.len > 0:
          if tokens[1].toUpperAscii() == "APPEND" and isLiteralSpec(tokens[^1]):
            beginAppend(conn, s, tokens)
          else:
            handleCommand(conn, server, s, line)
    if s.quitting or conn.state != Connected:
      return

proc getParsedMessage(server: IMAPServer, s: IMAPSession, msg: MailMessage): ParsedMessage =
  ## Load (and cache) a parsed message for the current session.
  let key = s.selectedMailbox & "/" & keyOf(msg.fileName)
  let cached = s.parsedCache.getOrDefault(key)
  if cached != nil:
    return cached
  let raw = loadMessageData(s.mailbox, msg)
  if raw.len == 0:
    return nil
  result = parseMessage(raw)
  s.parsedCache[key] = result

proc handleImapData(server: IMAPServer, conn: Connection, data: openArray[byte]) {.noinline.} =
  let s = cast[IMAPSession](conn.data)
  if s == nil or s.quitting: return
  var chunk = ""
  for b in data: chunk.add(char(b))
  handleData(server, conn, s, chunk)

proc handleAccept(server: IMAPServer, conn: Connection) =
  conn.data = cast[pointer](IMAPSession())
  imapUntagged(conn, "OK meowmail IMAP4rev1 ready")

proc handleClose(conn: Connection) =
  conn.data = nil

# ── server construction ───────────────────────────────────────────────────────

proc newIMAPServer*(port: Port = Port(143), store: MaildirStore = nil,
                    tlsCtx: SslContext = nil): IMAPServer =
  ## Creates an IMAP server bound to `port`, backed by `store`.
  new(result)
  result.loop = newLoop()
  result.port = port
  result.store = store
  result.tlsCtx = tlsCtx
  result.authUsers = initTable[string, string]()
  result.subscriptions = initTable[string, seq[string]]()

  let self = result
  result.listener = newTcpServer(result.loop,
    onData = proc(conn: Connection, data: openArray[byte]) =
      handleImapData(self, conn, data)
    ,
    onAccept = proc(conn: Connection) =
      handleAccept(self, conn)
    ,
    onClose = proc(conn: Connection) =
      handleClose(conn)
    ,
  )
  result.listener.listen("0.0.0.0", port.int)

proc start*(server: IMAPServer) =
  ## Starts the IMAP server event loop. This blocks the current thread.
  if server.loop == nil:
    raise newException(CatchableError, "IMAP server loop not initialized")
  if server.listener == nil:
    raise newException(CatchableError, "No IMAP listener configured")
  server.loop.run()
