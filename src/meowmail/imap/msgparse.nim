# MeowMail - A high-performance SMTP/IMAP server based on powpow
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

## RFC 5322 / RFC 2045-2047 message parsing used by the IMAP server to build
## ENVELOPE / BODYSTRUCTURE responses and to power SEARCH.
##
## The parser is intentionally pragmatic: it handles the common mail shapes
## (text/*, multipart/*, message/rfc822) and keeps byte offsets into the raw
## message so partial FETCH ranges can be served without re-parsing.

import std/[strutils, tables, sequtils, times, algorithm, base64]

type
  Header* = tuple[name, value: string]
  EnvelopeAddress* = object
    name*: string
    mailbox*: string
    host*: string

  Envelope* = object
    date*: string
    subject*: string
    fromList*: seq[EnvelopeAddress]
    sender*: seq[EnvelopeAddress]
    replyTo*: seq[EnvelopeAddress]
    to*: seq[EnvelopeAddress]
    cc*: seq[EnvelopeAddress]
    bcc*: seq[EnvelopeAddress]
    inReplyTo*: string
    messageId*: string

  MimePart* = ref object
    mainType*: string
    subtype*: string
    params*: seq[Header]
    contentId*: string
    description*: string
    encoding*: string
    disposition*: string
    fileName*: string
    headerOffset*: int
    headerLen*: int
    bodyOffset*: int
    bodyLen*: int
    lines*: int
    boundary*: string
    parts*: seq[MimePart]
    envelope*: Envelope
    headers*: seq[Header]

  ParsedMessage* = ref object
    raw*: string
    headerEnd*: int
    headers*: seq[Header]
    root*: MimePart
    envelope*: Envelope

proc parseHeaders(blk: string): seq[Header] =
  ## Parse a header block, unfolding continuation lines. Keys are lowercased.
  var lines = blk.split("\r\n")
  var i = 0
  while i < lines.len:
    var line = lines[i]
    if line.len == 0:
      inc i
      continue
    if line[0] in {' ', '\t'}:
      inc i
      continue
    let colon = line.find(':')
    if colon < 0:
      inc i
      continue
    let key = line[0 ..< colon].toLowerAscii()
    var value = line[colon + 1 .. ^1].strip()
    inc i
    # unfold continuation lines
    while i < lines.len and lines[i].len > 0 and lines[i][0] in {' ', '\t'}:
      value.add(" " & lines[i].strip())
      inc i
    result.add((key, value))

proc getHeader*(headers: seq[Header], name: string): string =
  ## First value for a (case-insensitive) header name.
  let n = name.toLowerAscii()
  for (k, v) in headers:
    if k == n:
      return v
  ""

proc getAllHeaders*(headers: seq[Header], name: string): seq[string] =
  let n = name.toLowerAscii()
  for (k, v) in headers:
    if k == n:
      result.add(v)

proc decodeQWord(s: string): string =
  ## Decode an RFC 2047 Q-encoded word (after the `Q` marker).
  var i = 0
  while i < s.len:
    let c = s[i]
    if c == '_':
      result.add(' ')
      inc i
    elif c == '=' and i + 2 < s.len:
      let hex = s[i + 1 .. i + 2]
      try: result.add(char(parseHexInt(hex)))
      except ValueError: result.add('=')
      i += 3
    else:
      result.add(c)
      inc i

proc decodeMimeWords*(s: string): string =
  ## Decode RFC 2047 encoded words (`=?charset?B|Q?data?=`) in a string.
  result = ""
  var i = 0
  while i < s.len:
    if s[i] == '=' and i + 2 < s.len and s[i + 1] == '?':
      let endPos = s.find("?=", i + 2)
      if endPos > 0:
        # find charset and encoding markers
        let inner = s[i + 2 ..< endPos]
        let parts = inner.split('?')
        if parts.len == 3 and parts[1].len == 1:
          let charset = parts[0]
          let enc = parts[1][0]
          let payload = parts[2]
          var decoded = ""
          if enc == 'B' or enc == 'b':
            try: decoded = decode(payload)
            except CatchableError: decoded = payload
          elif enc == 'Q' or enc == 'q':
            decoded = decodeQWord(payload)
          else:
            decoded = payload
          # Keep only UTF-8 (and ASCII) output; drop other charsets gracefully.
          if charset.toLowerAscii() in ["utf-8", "us-ascii", "ascii", ""]:
            result.add(decoded)
          else:
            result.add(payload)
          i = endPos + 2
          continue
    result.add(s[i])
    inc i

proc parseSingleAddress(s: string): EnvelopeAddress  # forward

proc parseAddressList*(s: string): seq[EnvelopeAddress] =
  ## Parse an RFC 5322 address list (no group expansion, addresses flattened).
  var cur = ""
  var inQuote = false
  var inAngle = false
  for c in s:
    case c
    of '"':
      inQuote = not inQuote
      cur.add(c)
    of '<':
      if not inQuote:
        inAngle = true
      cur.add(c)
    of '>':
      if not inQuote:
        inAngle = false
      cur.add(c)
    of ',':
      if not inQuote and not inAngle:
        cur = cur.strip()
        if cur.len > 0:
          result.add(parseSingleAddress(cur))
        cur.setLen(0)
      else:
        cur.add(c)
    else:
      cur.add(c)
  cur = cur.strip()
  if cur.len > 0:
    result.add(parseSingleAddress(cur))

proc parseSingleAddress(s: string): EnvelopeAddress =
  ## Parse `Display Name <user@host>` or `user@host` or `"Name" <...>`.
  var v = s.strip()
  if v.len == 0: return
  let lt = v.find('<')
  let gt = v.rfind('>')
  var addrPart = ""
  var namePart = ""
  if lt >= 0 and gt > lt:
    addrPart = v[lt + 1 ..< gt].strip()
    namePart = v[0 ..< lt].strip()
  else:
    addrPart = v
  if namePart.len >= 2 and namePart[0] == '"' and namePart[^1] == '"':
    namePart = namePart[1 ..^ 2]
  result.name = namePart
  let at = addrPart.rfind('@')
  if at < 0:
    result.mailbox = addrPart
  else:
    result.mailbox = addrPart[0 ..< at]
    result.host = addrPart[at + 1 .. ^1]

proc parseContentType(s: string): tuple[main, sub: string, params: seq[Header]] =
  ## Parse a Content-Type header into main/subtype and parameters.
  var parts = s.split(';')
  let t = parts[0].strip()
  let slash = t.find('/')
  if slash < 0:
    result.main = t.toLowerAscii()
    result.sub = ""
  else:
    result.main = t[0 ..< slash].toLowerAscii()
    result.sub = t[slash + 1 .. ^1].toLowerAscii()
  for i in 1 ..< parts.len:
    let p = parts[i].strip()
    let eq = p.find('=')
    if eq < 0: continue
    var key = p[0 ..< eq].strip().toLowerAscii()
    var val = p[eq + 1 .. ^1].strip()
    if val.len >= 2 and val[0] == '"' and val[^1] == '"':
      val = val[1 ..^ 2]
    result.params.add((key, val))

proc paramValue(params: seq[Header], name: string): string =
  for (k, v) in params:
    if k == name: return v
  ""

proc countLines(blk: string): int =
  result = 0
  for c in blk:
    if c == '\n': inc result

proc parseDateStr*(s: string): Time =
  ## Best-effort RFC 5322 date parse.
  let t = s.strip()
  if t.len == 0: return fromUnix(0)
  var fmt = "ddd, dd MMM yyyy HH:mm:ss zzz"
  try:
    result = parse(t, fmt).toTime()
  except CatchableError:
    try:
      result = parse(t, "ddd, dd MMM yyyy HH:mm:ss ZZZ").toTime()
    except CatchableError:
      try:
        result = parse(t, "dd MMM yyyy HH:mm:ss zzz").toTime()
      except CatchableError:
        result = fromUnix(0)

proc findSubMessageEnd(raw: string, start, boundEnd: int, boundary: string): int =
  ## Find the end of a part body: the start of the next `--boundary` line
  ## (or `--boundary--`), i.e. the index of the `-` that begins the delimiter.
  var searchFrom = start
  while true:
    let idx = raw.find("--" & boundary, searchFrom)
    if idx < 0: return boundEnd
    # must be at line start
    if idx > 0 and raw[idx - 1] == '\r':
      return idx - 1
    searchFrom = idx + 1

proc parseMessageInto(raw: string, start, len: int, headersOut: var seq[Header]): tuple[headerEnd, bodyOffset, bodyLen: int] =
  ## Locate the header/body boundary within `raw[start ..< start+len]`.
  var i = start
  let e = start + len
  while i < e - 1:
    if raw[i] == '\r' and raw[i + 1] == '\n':
      # blank line? header/body separator requires CRLFCRLF (possibly with
      # lone LFs tolerated).
      if i + 2 < e and raw[i + 2] == '\r' and i + 3 < e and raw[i + 3] == '\n':
        result.headerEnd = i
        result.bodyOffset = i + 4
        result.bodyLen = e - result.bodyOffset
        # headers block: [start, headerEnd)
        var blk = raw[start ..< i]
        if blk.len > 0 and blk[^1] == '\n':
          blk = blk[0 ..< blk.len - 1]
        headersOut = parseHeaders(blk)
        return
      # tolerate lone LF header separator
      if i + 2 < e and raw[i + 2] == '\n':
        result.headerEnd = i + 2
        result.bodyOffset = i + 3
        result.bodyLen = e - result.bodyOffset
        var blk = raw[start ..< i + 2]
        headersOut = parseHeaders(blk)
        return
    inc i
  # no separator found: all headers
  result.headerEnd = e
  result.bodyOffset = e
  result.bodyLen = 0
  var blk = raw[start ..< e]
  headersOut = parseHeaders(blk)

proc buildMimeTree(raw: string, part: MimePart)  # forward

proc parseMessage*(raw: string): ParsedMessage =
  ## Parse a raw RFC 5322 message.
  result = ParsedMessage(raw: raw)
  let sep = parseMessageInto(raw, 0, raw.len, result.headers)
  result.headerEnd = sep.headerEnd
  var root = MimePart(
    headerOffset: 0,
    headerLen: sep.headerEnd,
    bodyOffset: sep.bodyOffset,
    bodyLen: sep.bodyLen,
    headers: result.headers,
  )
  let ct = parseContentType(getHeader(result.headers, "Content-Type"))
  root.mainType = ct.main
  root.subtype = ct.sub
  root.params = ct.params
  root.boundary = paramValue(ct.params, "boundary")
  root.encoding = getHeader(result.headers, "Content-Transfer-Encoding").strip().toLowerAscii()
  root.contentId = getHeader(result.headers, "Content-ID").strip()
  root.description = getHeader(result.headers, "Content-Description").strip()
  root.disposition = getHeader(result.headers, "Content-Disposition").strip()
  root.fileName = ""
  let cd = root.disposition
  if cd.len > 0:
    let cdct = parseContentType(cd)
    root.fileName = paramValue(cdct.params, "filename")
  result.root = root

  # envelope from top-level headers
  result.envelope = Envelope(
    date: getHeader(result.headers, "Date"),
    subject: decodeMimeWords(getHeader(result.headers, "Subject")),
    fromList: parseAddressList(getHeader(result.headers, "From")),
    sender: parseAddressList(getHeader(result.headers, "Sender")),
    replyTo: parseAddressList(getHeader(result.headers, "Reply-To")),
    to: parseAddressList(getHeader(result.headers, "To")),
    cc: parseAddressList(getHeader(result.headers, "Cc")),
    bcc: parseAddressList(getHeader(result.headers, "Bcc")),
    inReplyTo: getHeader(result.headers, "In-Reply-To"),
    messageId: getHeader(result.headers, "Message-ID"),
  )
  root.envelope = result.envelope

  buildMimeTree(raw, root)

proc findBoundary(raw: string, fromPos, bodyEnd: int, boundary: string): int =
  ## Find the next `--boundary` that starts at the beginning of a line.
  var i = fromPos
  while i <= bodyEnd:
    let idx = raw.find("--" & boundary, i)
    if idx < 0 or idx > bodyEnd: return -1
    if idx == 0 or raw[idx - 1] == '\n':
      return idx
    i = idx + 1
  -1

proc buildMimeTree(raw: string, part: MimePart) =
  ## Recursively build the MIME part tree, computing offsets and sub-parts.
  if part.mainType == "multipart" and part.boundary.len > 0:
    part.parts = @[]
    var searchFrom = part.bodyOffset
    let bodyEnd = part.bodyOffset + part.bodyLen
    let delim = "--" & part.boundary
    var firstBoundary = findBoundary(raw, part.bodyOffset, bodyEnd, part.boundary)
    if firstBoundary < 0:
      return
    var pos = firstBoundary + delim.len
    if pos < raw.len and raw[pos] == '-':
      return  # closing delimiter immediately
    while pos < raw.len and raw[pos] notin {'\r', '\n'}:
      inc pos
    if pos < raw.len and raw[pos] == '\r': inc pos
    if pos < raw.len and raw[pos] == '\n': inc pos

    while pos <= bodyEnd:
      let nextB = findBoundary(raw, pos, bodyEnd, part.boundary)
      if nextB < 0:
        break
      var partEnd = nextB
      # trim trailing CRLF before the next boundary
      while partEnd > pos and (raw[partEnd - 1] == '\r' or raw[partEnd - 1] == '\n'):
        dec partEnd
      if partEnd > pos:
        let sub = MimePart(headerOffset: pos)
        var hdrs: seq[Header]
        let sep2 = parseMessageInto(raw, pos, partEnd - pos, hdrs)
        sub.headerLen = sep2.headerEnd - pos
        sub.bodyOffset = sep2.bodyOffset
        sub.bodyLen = sep2.bodyLen
        sub.headers = hdrs
        let ctsub = parseContentType(getHeader(hdrs, "Content-Type"))
        sub.mainType = ctsub.main
        sub.subtype = ctsub.sub
        sub.params = ctsub.params
        sub.boundary = paramValue(ctsub.params, "boundary")
        sub.encoding = getHeader(hdrs, "Content-Transfer-Encoding").strip().toLowerAscii()
        sub.contentId = getHeader(hdrs, "Content-ID").strip()
        sub.description = getHeader(hdrs, "Content-Description").strip()
        sub.disposition = getHeader(hdrs, "Content-Disposition").strip()
        let cdsub = parseContentType(sub.disposition)
        sub.fileName = paramValue(cdsub.params, "filename")
        if sub.fileName.len == 0:
          sub.fileName = paramValue(ctsub.params, "name")
        if sub.mainType == "text":
          sub.lines = countLines(raw[sub.bodyOffset ..< sub.bodyOffset + sub.bodyLen])
        if sub.mainType == "message" and sub.subtype == "rfc822":
          sub.envelope = Envelope(
            date: getHeader(hdrs, "Date"),
            subject: decodeMimeWords(getHeader(hdrs, "Subject")),
            fromList: parseAddressList(getHeader(hdrs, "From")),
            sender: parseAddressList(getHeader(hdrs, "Sender")),
            replyTo: parseAddressList(getHeader(hdrs, "Reply-To")),
            to: parseAddressList(getHeader(hdrs, "To")),
            cc: parseAddressList(getHeader(hdrs, "Cc")),
            bcc: parseAddressList(getHeader(hdrs, "Bcc")),
            inReplyTo: getHeader(hdrs, "In-Reply-To"),
            messageId: getHeader(hdrs, "Message-ID"),
          )
          # parse the encapsulated message so BODYSTRUCTURE can render it
          var innerHeaders: seq[Header]
          let innerSep = parseMessageInto(raw, sub.bodyOffset, sub.bodyLen, innerHeaders)
          var inner = MimePart(
            headerOffset: sub.bodyOffset,
            headerLen: innerSep.headerEnd - sub.bodyOffset,
            bodyOffset: innerSep.bodyOffset,
            bodyLen: innerSep.bodyLen,
            headers: innerHeaders,
          )
          let innerCt = parseContentType(getHeader(innerHeaders, "Content-Type"))
          inner.mainType = innerCt.main
          inner.subtype = innerCt.sub
          inner.params = innerCt.params
          inner.boundary = paramValue(innerCt.params, "boundary")
          inner.encoding = getHeader(innerHeaders, "Content-Transfer-Encoding").strip().toLowerAscii()
          inner.envelope = Envelope(
            date: getHeader(innerHeaders, "Date"),
            subject: decodeMimeWords(getHeader(innerHeaders, "Subject")),
            fromList: parseAddressList(getHeader(innerHeaders, "From")),
            to: parseAddressList(getHeader(innerHeaders, "To")),
            cc: parseAddressList(getHeader(innerHeaders, "Cc")),
            messageId: getHeader(innerHeaders, "Message-ID"),
          )
          buildMimeTree(raw, inner)
          sub.parts = @[inner]
        part.parts.add(sub)
        buildMimeTree(raw, sub)
      # advance past the boundary we just consumed
      pos = nextB + delim.len
      if pos < raw.len and raw[pos] == '-':
        break  # closing delimiter
      while pos < raw.len and raw[pos] notin {'\r', '\n'}:
        inc pos
      if pos < raw.len and raw[pos] == '\r': inc pos
      if pos < raw.len and raw[pos] == '\n': inc pos
    return
  # count lines for text parts
  if part.mainType == "text":
    part.lines = countLines(raw[part.bodyOffset ..< part.bodyOffset + part.bodyLen])

proc renderEnvelope*(env: Envelope): string =
  ## Render an ENVELOPE response.
  proc q(s: string): string =
    if s.len == 0: "NIL" else: "\"" & s.replace("\\", "\\\\").replace("\"", "\\\"") & "\""
  proc addrs(list: seq[EnvelopeAddress]): string =
    if list.len == 0: return "NIL"
    var items: seq[string]
    for a in list:
      items.add("(" & q(a.name) & " NIL " & q(a.mailbox) & " " & q(a.host) & ")")
    "(" & items.join(" ") & ")"
  result = "(" & q(env.date) & " " & q(env.subject) & " " &
    addrs(env.fromList) & " " & addrs(env.sender) & " " & addrs(env.replyTo) & " " &
    addrs(env.to) & " " & addrs(env.cc) & " " & addrs(env.bcc) & " " &
    q(env.inReplyTo) & " " & q(env.messageId) & ")"

proc renderBodyStructure*(part: MimePart, extensions: bool): string =
  ## Render BODYSTRUCTURE (extensions=true) or BODY (extensions=false).
  proc q(s: string): string =
    if s.len == 0: "NIL" else: "\"" & s.replace("\\", "\\\\").replace("\"", "\\\"") & "\""
  proc params(p: seq[Header]): string =
    if p.len == 0: return "NIL"
    var items: seq[string]
    for (k, v) in p:
      items.add(q(k) & " " & q(v))
    "(" & items.join(" ") & ")"
  if part.mainType == "multipart":
    var items: seq[string]
    for p in part.parts:
      items.add(renderBodyStructure(p, extensions))
    items.add(q(part.subtype))
    items.add(params(part.params))
    if extensions:
      items.add(q(part.disposition))
      items.add(q(part.contentId))
      items.add(q(part.description))
    return "(" & items.join(" ") & ")"
  if part.mainType == "message" and part.subtype == "rfc822":
    var items: seq[string] = @[]
    items.add(q(part.mainType))
    items.add(q(part.subtype))
    items.add(params(part.params))
    items.add(q(part.contentId))
    items.add(q(part.description))
    items.add(q(part.encoding))
    items.add($part.bodyLen)
    items.add(renderEnvelope(part.envelope))
    # the encapsulated message is rendered as its top-level structure
    if part.parts.len > 0:
      items.add(renderBodyStructure(part.parts[0], extensions))
    else:
      items.add("NIL")
    if extensions:
      items.add($part.lines)
    return "(" & items.join(" ") & ")"
  var items: seq[string] = @[]
  items.add(q(part.mainType))
  items.add(q(part.subtype))
  items.add(params(part.params))
  items.add(q(part.contentId))
  items.add(q(part.description))
  items.add(q(part.encoding))
  items.add($part.bodyLen)
  if extensions:
    if part.mainType == "text":
      items.add($part.lines)
    items.add(q(part.disposition))
    items.add(q(part.fileName))
    items.add("NIL")  # md5
    items.add("NIL")  # enveloNIL
  result = "(" & items.join(" ") & ")"

proc textContent*(parsed: ParsedMessage): string =
  ## Return the decoded text of the leaf text parts (for SEARCH TEXT/BODY).
  var acc = ""
  proc walk(part: MimePart, acc: var string) =
    if part.mainType == "text":
      let raw = parsed.raw[part.bodyOffset ..< part.bodyOffset + part.bodyLen]
      case part.encoding
      of "base64":
        try: acc.add(decode(raw.replace("\r\n", "").replace("\n", "")))
        except CatchableError: acc.add(raw)
      of "quoted-printable":
        var i = 0
        while i < raw.len:
          if raw[i] == '=' and i + 2 < raw.len and
             raw[i + 1] in {'0'..'9', 'a'..'f', 'A'..'F'} and
             raw[i + 2] in {'0'..'9', 'a'..'f', 'A'..'F'}:
            try: acc.add(char(parseHexInt(raw[i + 1 .. i + 2])))
            except ValueError: acc.add('=')
            i += 3
          elif raw[i] == '=' and i + 1 < raw.len and raw[i + 1] == '\n':
            i += 2
          else:
            acc.add(raw[i])
            inc i
      else:
        acc.add(raw)
    elif part.mainType == "multipart":
      for p in part.parts:
        walk(p, acc)
  walk(parsed.root, acc)
  acc

proc headerSearchText*(parsed: ParsedMessage): string =
  ## Concatenated header values useful for SEARCH FROM/TO/CC/SUBJECT/BCC.
  for name in ["From", "To", "Cc", "Bcc", "Subject"]:
    for v in getAllHeaders(parsed.headers, name):
      result.add(decodeMimeWords(v) & " ")
