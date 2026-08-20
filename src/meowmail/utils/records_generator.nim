import std/[strutils, sequtils, options]

## This module provides utility functions for generating DNS records related to email authentication,
## such as SPF, DKIM, and DMARC records. These functions can be used to create properly formatted
## DNS TXT records for configuring email servers and improving email deliverability.

type
  DmarcPolicy* = enum
    ## Represents the DMARC policy to be applied to messages that fail DMARC checks.
    dpNone = "none"
    dpQuarantine = "quarantine"
    dpReject = "reject"

proc splitDnsTxt*(value: string; chunkSize = 255): seq[string] =
  ## Split a TXT value into <=255-byte chunks for zone files.
  if chunkSize <= 0:
    return @[value]
  var i = 0
  while i < value.len:
    let j = min(i + chunkSize, value.len)
    result.add value[i ..< j]
    i = j

proc buildSpfTxt*(
  ip4: seq[string] = @[],
  ip6: seq[string] = @[],
  includes: seq[string] = @[],
  mx = true,
  a = false,
  existsRules: seq[string] = @[],
  redirect: string = "",
  allQualifier = "~all"   # "+all", "-all", "~all", "?all"
): string =
  ## Builds an SPF record string based on the provided parameters
  ##  - `ip4`: A sequence of IPv4 addresses or CIDR blocks to include in the SPF record.
  ##  - `ip6`: A sequence of IPv6 addresses or CIDR blocks to include in the SPF record.
  ##  - `includes`: A sequence of domain names to include in the SPF record using the "include:" mechanism.
  ##  - `mx`: A boolean flag indicating whether to include the "mx" mechanism in the SPF record (default: true).
  ##  - `a`: A boolean flag indicating whether to include the "a" mechanism in the SPF record (default: false).
  ##  - `existsRules`: A sequence of domain names to include in the SPF record using the "exists:" mechanism.
  ##  - `redirect`: A domain name to use in the "redirect=" modifier of the SPF record (default: empty string, meaning no redirect).
  ##  - `allQualifier`: A string representing the qualifier to use for the "all" mechanism in the SPF record (default: "~all"). Valid values
  ##    include "+all" (pass), "-all" (fail), "~all" (softfail), and "?all" (neutral).
  var parts = @["v=spf1"]
  if mx: parts.add "mx"
  if a: parts.add "a"
  for x in ip4: parts.add "ip4:" & x.strip()
  for x in ip6: parts.add "ip6:" & x.strip()
  for x in includes: parts.add "include:" & x.strip()
  for x in existsRules: parts.add "exists:" & x.strip()
  if redirect.len > 0:
    parts.add "redirect=" & redirect.strip()
  parts.add allQualifier.strip()
  result = parts.join(" ")

proc dkimRecordName*(selector, domain: string): string =
  selector.strip().toLowerAscii() & "._domainkey." & domain.strip().toLowerAscii()

proc normalizePemPublicKeyToB64*(pem: string): string =
  ## Converts PEM public key text into DKIM DNS p= value.
  for line in pem.splitLines():
    let s = line.strip()
    if s.len == 0: continue
    if s.startsWith("-----BEGIN"): continue
    if s.startsWith("-----END"): continue
    result.add s

proc buildDkimTxt*(
  publicKeyB64: string,
  keyType = "rsa",
  hashAlgos: seq[string] = @["sha256"],
  serviceType = "email",   # email or *
  notes = ""
): string =
  ## Builds a DKIM record string based on the provided parameters.
  var parts = @[
    "v=DKIM1",
    "k=" & keyType.strip(),
    "h=" & hashAlgos.mapIt(it.strip()).join(":"),
    "s=" & serviceType.strip(),
    "p=" & publicKeyB64.strip()
  ]
  if notes.len > 0:
    parts.add "n=" & notes
  result = parts.join("; ")

proc buildDmarcTxt*(
  policy: DmarcPolicy,
  rua: seq[string] = @[],
  ruf: seq[string] = @[],
  pct = 100,
  adkim = "r",      # r|s
  aspf = "r",       # r|s
  sp: Option[DmarcPolicy] = none(DmarcPolicy),
  fo = "0",         # 0|1|d|s or colon-combined
  rf = "afrf",      # report format(s)
  ri = 86400
): string =
  ## Builds a DMARC record string based on the provided parameters.
  var parts = @[
    "v=DMARC1",
    "p=" & $policy
  ]

  if sp.isSome:
    parts.add "sp=" & $sp.get()

  if rua.len > 0:
    parts.add "rua=" & rua.mapIt("mailto:" & it.strip()).join(",")

  if ruf.len > 0:
    parts.add "ruf=" & ruf.mapIt("mailto:" & it.strip()).join(",")

  parts.add "adkim=" & adkim.strip().toLowerAscii()
  parts.add "aspf=" & aspf.strip().toLowerAscii()
  parts.add "pct=" & $max(0, min(100, pct))
  parts.add "fo=" & fo.strip()
  parts.add "rf=" & rf.strip()
  parts.add "ri=" & $max(0, ri)

  result = parts.join("; ")