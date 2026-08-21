# MeowMail - A high-performance SMTP based on powpow
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

## RFC 5321 §4.1.2 mailbox parser.
##
## Parses and validates SMTP MAIL FROM / RCPT TO addresses into their
## component parts. Handles angle-addr, quoted local-parts, address-literals,
## null sender `<>`, and enforces the length limits from RFC 5321 §4.5.3.1.
##
## This is a pure, stateless module with no I/O — safe to use from any thread
## and trivially unit-testable.

import std/[strutils]

const
  MaxLocalPartLen* = 64
  MaxDomainLen* = 255
  MaxPathLen* = 256

type
  MailboxKind* = enum
    mkNull,          ## `<>` — null sender (bounces)
    mkLocal,         ## `postmaster` — bare local name, no domain
    mkStandard,      ## `user@domain`
    mkLiteral,       ## `user@[127.0.0.1]`

  Mailbox* = object
    localPart*: string
    domain*: string
    kind*: MailboxKind
    error*: string     ## non-empty when validation fails

# ── Character classification (RFC 5321 §4.1.2) ───────────────────────────────

proc isAtext(ch: char): bool =
  ## ATEXT = ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" /
  ##         "*" / "+" / "-" / "/" / "=" / "?" / "^" / "_" / "`" /
  ##         "{" / "|" / "}" / "~"
  case ch
  of 'A'..'Z', 'a'..'z', '0'..'9':
    true
  of '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?',
     '^', '_', '`', '{', '|', '}', '~':
    true
  else:
    false

proc parseDotString(s: string; start: int; limit: int; local: var string): int =
  ## Parse a dot-atom (`Atom *("." Atom)`). Returns position after the last
  ## consumed character, or -1 on error. Appends the raw value to `local`.
  var pos = start
  while pos < s.len:
    if s[pos] == '.':
      # dot must not be first or last, and not doubled
      if pos == start or (pos + 1 < s.len and s[pos + 1] == '.'):
        return -1
      local.add('.')
      inc pos
      # must be followed by another atom
      if pos >= s.len or not s[pos].isAtext:
        return -1
    elif s[pos].isAtext:
      local.add(s[pos])
      inc pos
    else:
      break
  if local.len == 0 or local.len > limit:
    return -1
  # must not end with a dot
  if local[^1] == '.':
    return -1
  pos

proc parseQuotedString(s: string; start: int; limit: int; local: var string): int =
  ## Parse a quoted-string (`" *([\\] qcontent) "`). Returns position after
  ## the closing quote, or -1 on error. Appends the raw (unescaped) value to
  ## `local`.
  var pos = start
  if pos >= s.len or s[pos] != '"':
    return -1
  inc pos  # skip opening quote
  local.add('"')
  while pos < s.len:
    let ch = s[pos]
    if ch == '"':
      local.add('"')
      inc pos
      if local.len - 2 > limit:  # -2 for the surrounding quotes
        return -1
      return pos
    elif ch == '\\':
      inc pos
      if pos >= s.len:
        return -1
      local.add(s[pos])
      inc pos
    elif ch.int in 32..33 or ch.int in 35..91 or ch.int in 93..126:
      local.add(ch)
      inc pos
    else:
      return -1
  return -1  # no closing quote

proc parseDomain(s: string; start: int; limit: int; domain: var string): int =
  ## Parse a domain name (labels separated by dots). Returns position after
  ## the last consumed character, or -1 on error.
  var pos = start
  var labelLen = 0
  var totalLen = 0
  while pos < s.len:
    let ch = s[pos]
    if ch == '.':
      if labelLen == 0:
        return -1  # empty label
      domain.add('.')
      inc pos
      labelLen = 0
      inc totalLen
    elif ch.isAtext:
      domain.add(ch)
      inc pos
      inc labelLen
      inc totalLen
      if totalLen > limit:
        return -1
    else:
      break
  if labelLen == 0:
    return -1  # trailing dot or empty domain
  # Labels must not start or end with hyphens (RFC 952)
  # — relaxed here for compatibility; strict check is optional
  pos

proc parseAddressLiteral(s: string; start: int; domain: var string): int =
  ## Parse `[ IPv4-address ]` or `[ IPv6-address ]`. Returns position after
  ## the closing bracket, or -1 on error.
  var pos = start
  if pos >= s.len or s[pos] != '[':
    return -1
  inc pos  # skip '['
  domain.add('[')
  while pos < s.len and s[pos] != ']':
    domain.add(s[pos])
    inc pos
  if pos >= s.len:
    return -1  # no closing bracket
  domain.add(']')
  inc pos  # skip ']'
  # Minimal validation: at least one character inside brackets
  if domain.len <= 2:
    return -1
  pos

# ── Main parser ──────────────────────────────────────────────────────────────

proc parseMailbox*(s: string): Mailbox =
  ## Parse an SMTP mailbox address per RFC 5321 §4.1.2.
  ##
  ## Accepts:
  ## - `<>` — null sender
  ## - `<local@domain>` — standard mailbox
  ## - `<"quoted local"@domain>` — quoted local-part
  ## - `<local@[127.0.0.1]>` — address-literal domain
  ## - `<postmaster>` — bare local name (RFC 5321 §4.1.4)
  ## - Bare forms without angle brackets (common extension)
  ##
  ## Returns a `Mailbox` with `kind` set and `error` non-empty on failure.
  result = Mailbox(kind: mkNull)

  var s = s.strip()
  if s.len == 0:
    result.error = "empty address"
    return result

  # Strip angle brackets if present
  var hasAngle = false
  if s[0] == '<' and s[^1] == '>':
    s = s[1..^2].strip()
    hasAngle = true

  # Null sender: <>
  if s.len == 0:
    result.kind = mkNull
    return result

  # Find the @ — may be inside quotes
  var atPos = -1
  var inQuotes = false
  var i = 0
  if s.len > 0 and s[0] == '"':
    inQuotes = true
    i = 1
    while i < s.len:
      if s[i] == '\\':
        inc i  # skip escaped char
      elif s[i] == '"':
        inQuotes = false
        inc i
        break
      inc i
    # Reject unclosed quotes
    if inQuotes:
      result.error = "unclosed quoted string"
      return result
    # After closing quote, look for @
    if i < s.len and s[i] == '@':
      atPos = i

  if not inQuotes and atPos < 0:
    # Not quoted — scan for @
    i = 0
    while i < s.len:
      if s[i] == '@' and (i == 0 or s[i - 1] != '\\'):
        atPos = i
        break
      inc i

  if atPos < 0:
    # No @ — bare local name (e.g. "postmaster")
    if s.len > MaxLocalPartLen:
      result.error = "local-part exceeds " & $MaxLocalPartLen & " octets"
      return result
    result.localPart = s
    result.kind = mkLocal
    return result

  # Parse local-part
  var localPart = ""
  let localStart = 0
  var pos: int
  if s[localStart] == '"':
    pos = parseQuotedString(s, localStart, MaxLocalPartLen, localPart)
  else:
    pos = parseDotString(s, localStart, MaxLocalPartLen, localPart)

  if pos < 0:
    result.error = "invalid local-part"
    return result

  # Skip the @
  if pos >= s.len or s[pos] != '@':
    result.error = "missing '@'"
    return result
  inc pos

  # Parse domain
  var domain = ""
  if pos < s.len and s[pos] == '[':
    pos = parseAddressLiteral(s, pos, domain)
    if pos < 0:
      result.error = "invalid address-literal"
      return result
    result.kind = mkLiteral
  else:
    pos = parseDomain(s, pos, MaxDomainLen, domain)
    if pos < 0:
      result.error = "invalid domain"
      return result
    result.kind = mkStandard

  # Check there's nothing after the domain (trailing garbage)
  if pos < s.len:
    result.error = "unexpected trailing characters"
    return result

  # Check total path length
  let totalLen = localPart.len + 1 + domain.len  # local + @ + domain
  if totalLen > MaxPathLen:
    result.error = "path exceeds " & $MaxPathLen & " octets"
    return result

  result.localPart = localPart
  result.domain = domain

# ── Convenience helpers ──────────────────────────────────────────────────────

proc isNullSender*(m: Mailbox): bool {.inline.} =
  m.kind == mkNull

proc hasValidSyntax*(m: Mailbox): bool {.inline.} =
  m.error.len == 0

proc isDomainValid*(m: Mailbox): bool {.inline.} =
  ## Whether the domain part is non-empty and syntactically valid.
  m.hasValidSyntax and m.domain.len > 0 and m.kind in {mkStandard, mkLiteral}
