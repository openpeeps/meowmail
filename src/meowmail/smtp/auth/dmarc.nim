## MeowMail — Inbound DMARC evaluation (RFC 7489).
##
## Native policy evaluator used for inbound mail: it parses the `_dmarc`
## TXT record, checks SPF/DKIM alignment against the From domain, applies
## sampling (pct=) and returns the disposition. Outbound preflight keeps
## using libopendmarc (`dmarc_preflight.nim`); this module is for reporting
## and enforcing policy on received messages.

import std/[strutils, random]

type
  DmarcPolicy* = enum
    dpNone        ## p=none: report only
    dpQuarantine  ## p=quarantine
    dpReject      ## p=reject
    dpAbsent      ## no usable record

  DmarcRecord* = object
    policy*: DmarcPolicy
    subPolicy*: DmarcPolicy  ## sp=, falls back to p= when absent
    hasSubPolicy*: bool
    pct*: int                ## sampling percentage, 0..100
    adkim*: char             ## 'r' or 's'
    aspf*: char              ## 'r' or 's'
    rua*: string
    ruf*: string

  DmarcOutcome* = object
    aligned*: bool     ## SPF or DKIM (or both) aligned and passing
    spfAligned*: bool
    dkimAligned*: bool
    policy*: DmarcPolicy   ## effective policy (sp= when subdomain + present)
    sampled*: bool     ## pct= sampling selected this message
    enforced*: bool    ## policy applies (aligned == false and sampled)
    detail*: string

proc selectDmarcRecord*(records: seq[string]): string =
  ## Pick the `v=DMARC1` record out of a set of TXT strings.
  for r in records:
    if r.strip().toLowerAscii.startsWith("v=dmarc1"):
      return r
  ""

proc parseDmarcPolicy*(s: string): tuple[ok: bool, p: DmarcPolicy] =
  case s.strip().toLowerAscii
  of "none": (true, dpNone)
  of "quarantine": (true, dpQuarantine)
  of "reject": (true, dpReject)
  else: (false, dpAbsent)

proc dmarcPolicyStr*(p: DmarcPolicy): string =
  ## Wire string for a policy ("none", "quarantine", "reject", "absent").
  case p
  of dpNone: "none"
  of dpQuarantine: "quarantine"
  of dpReject: "reject"
  of dpAbsent: "absent"

proc parseDmarcRecord*(record: string): tuple[ok: bool, rec: DmarcRecord, err: string] =
  ## Parse a `v=DMARC1` TXT record. Unknown tags are ignored per RFC 7489 §6.3.
  var rec = DmarcRecord(policy: dpAbsent, subPolicy: dpAbsent,
                        pct: 100, adkim: 'r', aspf: 'r')
  var seenV = false
  for part in record.split(';'):
    let kv = part.strip().split('=', 1)
    if kv.len != 2: continue
    let key = kv[0].strip().toLowerAscii
    let val = kv[1].strip()
    case key
    of "v":
      if not val.toLowerAscii.startsWith("dmarc1"):
        return (false, rec, "unsupported version: " & val)
      seenV = true
    of "p":
      let (ok, p) = parseDmarcPolicy(val)
      if not ok: return (false, rec, "invalid p=: " & val)
      rec.policy = p
    of "sp":
      let (ok, p) = parseDmarcPolicy(val)
      if not ok: return (false, rec, "invalid sp=: " & val)
      rec.subPolicy = p
      rec.hasSubPolicy = true
    of "pct":
      try:
        rec.pct = parseInt(val)
      except ValueError:
        return (false, rec, "invalid pct=: " & val)
      if rec.pct < 0 or rec.pct > 100:
        return (false, rec, "pct out of range: " & val)
    of "adkim":
      let v = val.toLowerAscii
      if v notin ["r", "s"]: return (false, rec, "invalid adkim=: " & val)
      rec.adkim = v[0]
    of "aspf":
      let v = val.toLowerAscii
      if v notin ["r", "s"]: return (false, rec, "invalid aspf=: " & val)
      rec.aspf = v[0]
    of "rua": rec.rua = val
    of "ruf": rec.ruf = val
    else: discard
  if not seenV:
    return (false, rec, "missing v=DMARC1")
  if rec.policy == dpAbsent:
    return (false, rec, "missing p=")
  (true, rec, "")

proc domainsAlign*(a, b: string, strict: bool): bool =
  ## Alignment check (RFC 7489 §3.1): strict requires an exact match,
  ## relaxed allows subdomains of the same organizational domain. Without a
  ## Public Suffix List the relaxed check is approximated as exact-or-subdomain.
  let x = a.strip().toLowerAscii.strip(chars = {'.'})
  let y = b.strip().toLowerAscii.strip(chars = {'.'})
  if x.len == 0 or y.len == 0: return false
  if x == y: return true
  if strict: return false
  x.endsWith("." & y) or y.endsWith("." & x)

proc evaluateDmarc*(fromDomain: string, record: string,
                    envelopeFromDomain: string, spfPass: bool,
                    dkimPassDomains: seq[string],
                    isSubdomain = false, pctRoll = -1): DmarcOutcome =
  ## Evaluate DMARC for a message. `pctRoll` forces the sampling roll
  ## (0..99) for deterministic tests; -1 rolls randomly.
  result = DmarcOutcome(policy: dpAbsent)
  if fromDomain.len == 0:
    result.detail = "no From domain"
    return
  if record.strip().len == 0:
    result.detail = "no DMARC record"
    return
  let (ok, rec, err) = parseDmarcRecord(record)
  if not ok:
    result.detail = "invalid record: " & err
    return
  result.spfAligned = spfPass and domainsAlign(envelopeFromDomain, fromDomain,
                                              rec.aspf == 's')
  result.dkimAligned = false
  for d in dkimPassDomains:
    if domainsAlign(d, fromDomain, rec.adkim == 's'):
      result.dkimAligned = true
      break
  result.aligned = result.spfAligned or result.dkimAligned
  result.policy = if isSubdomain and rec.hasSubPolicy: rec.subPolicy
                  else: rec.policy
  let roll = if pctRoll >= 0: pctRoll else: rand(99)
  result.sampled = roll < rec.pct
  result.enforced = not result.aligned and result.sampled
  if result.aligned:
    result.detail = "spf_aligned=" & $result.spfAligned &
                    " dkim_aligned=" & $result.dkimAligned
  elif not result.sampled:
    result.detail = "not sampled (pct=" & $rec.pct & ")"
  else:
    result.detail = "policy=" & dmarcPolicyStr(result.policy)
