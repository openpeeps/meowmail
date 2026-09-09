## MeowMail — Inbound email authentication (SPF, DKIM, DMARC).
##
## Verifies incoming messages and adds Authentication-Results header.
## SPF checks the connecting IP against the sender's DNS record.
## DKIM verifies cryptographic signatures.
## DMARC checks alignment between SPF and DKIM results.

import std/strutils
import pkg/spf
import ../smtpdelivery
import ../../imap/msgparse
import ../dkim
import ./dmarc
import ../mxprovider

type
  AuthResult* = enum
    arPass, arFail, arSoftFail, arNeutral, arNone, arTempError, arPermError

  AuthHeader* = object
    spf*: AuthResult
    spfDetail*: string       ## e.g. "smtp.mailfrom=alice@example.com"
    dkim*: AuthResult
    dkimDetail*: string      ## e.g. "header.d=example.com"
    dkimDomains*: seq[string] ## domains of passing signatures (for DMARC)
    dmarc*: AuthResult
    dmarcDetail*: string
    dmarcReject*: bool       ## DMARC p=reject applied and enforcement on
    combined*: string        ## Full Authentication-Results header value

  DkimKeyLookup* = proc(domain, selector: string): string {.closure, gcsafe.}
    ## Returns the selected `v=DKIM1` TXT record ("" when unavailable).

proc authResultStr(r: AuthResult): string =
  case r
  of arPass: "pass"
  of arFail: "fail"
  of arSoftFail: "softfail"
  of arNeutral: "neutral"
  of arNone: "none"
  of arTempError: "temperror"
  of arPermError: "permerror"

# ── SPF verification ──────────────────────────────────────────────────────────

proc verifySpf*(spfServerPtr: pointer, clientIp, heloDomain, mailFrom: string): (AuthResult, string) =
  ## Verify the connecting IP against the sender's SPF record.
  ## Returns (result, detail string).
  if spfServerPtr == nil:
    return (arTempError, "SPF server not initialized")
  if clientIp.len == 0:
    return (arPermError, "no client IP")

  let envFrom = mailFrom.strip()
  if envFrom.len == 0:
    return (arPermError, "empty MAIL FROM")

  let spfServer = cast[SPF_server](spfServerPtr)
  let q = SPF_request_new(spfServer)
  if q == nil:
    return (arTempError, "SPF request creation failed")
  defer:
    SPF_request_free(q)

  if clientIp.contains(":"):
    if SPF_request_set_ipv6_str(q, clientIp) != SPF_E_SUCCESS:
      return (arTempError, "invalid IPv6 address")
  else:
    if SPF_request_set_ipv4_str(q, clientIp) != SPF_E_SUCCESS:
      return (arTempError, "invalid IPv4 address")

  if SPF_request_set_helo_dom(q, heloDomain) != SPF_E_SUCCESS:
    return (arTempError, "invalid HELO domain")
  if SPF_request_set_env_from(q, envFrom) != 0:
    return (arPermError, "invalid MAIL FROM domain")

  var resp: SPF_response = nil
  try:
    resp = SPF_response_new(q)
    if resp == nil:
      return (arTempError, "SPF response allocation failed")

    let err = SPF_request_query_mailfrom(q, addr resp)
    if err != SPF_E_SUCCESS:
      return (arTempError, "SPF query failed: " & $err)

    let result = SPF_response_result(resp)
    let detail = "smtp.mailfrom=" & envFrom

    case result
    of SPF_RESULT_PASS:
      return (arPass, detail)
    of SPF_RESULT_FAIL:
      return (arFail, detail)
    of SPF_RESULT_SOFTFAIL:
      return (arSoftFail, detail)
    of SPF_RESULT_NEUTRAL:
      return (arNone, detail)
    of SPF_RESULT_NONE:
      return (arNone, detail)
    of SPF_RESULT_PERMERROR, SPF_RESULT_INVALID:
      return (arPermError, detail)
    of SPF_RESULT_TEMPERROR:
      return (arTempError, detail)
    else:
      return (arTempError, "unknown SPF result: " & $result)
  finally:
    if resp != nil: SPF_response_free(resp)

# ── DKIM verification (RFC 6376) ──────────────────────────────────────────────

proc defaultDkimKeyLookup(domain, selector: string): string {.gcsafe.} =
  ## Fetch the `v=DKIM1` key record via powpow's TXT resolver.
  selectDkimKeyRecord(resolveTxtRecords(selector & "._domainkey." & domain))

proc defaultDmarcFetch(domain: string): string {.gcsafe.} =
  ## Fetch the `v=DMARC1` record via powpow's TXT resolver.
  selectDmarcRecord(resolveTxtRecords("_dmarc." & domain))

proc verifyDkim*(headers: seq[Header], body: string,
                 keyLookup: DkimKeyLookup = nil,
                 rawHeaderBlock: string = ""): (AuthResult, seq[string], string) =
  ## Cryptographically verify DKIM signature(s) in the message headers.
  ## Returns (result, passing domains, detail string).
  ##
  ## The raw header block is preferred: `simple` canonicalization is only
  ## byte-exact when the original wire bytes are available. Without it the
  ## fields are rebuilt from parsed headers, which is exact for `relaxed`
  ## but best-effort for `simple`.
  let lookup: DkimKeyLookup = if keyLookup != nil: keyLookup else: defaultDkimKeyLookup
  var fields: seq[RawHeaderField]
  if rawHeaderBlock.len > 0:
    fields = splitRawHeaders(rawHeaderBlock)
  else:
    for h in headers:
      fields.add(RawHeaderField(name: h.name, raw: h.name & ": " & h.value))
  var sigIdxs: seq[int]
  for i, f in fields:
    if f.name.toLowerAscii == "dkim-signature":
      sigIdxs.add(i)
  if sigIdxs.len == 0:
    return (arNone, @[], "no signature")

  var passDomains: seq[string]
  var firstDetail = ""
  var sawTemp = false
  var tempDetail = ""
  var sawFail = false
  var failDetail = ""
  var sawPerm = false
  var permDetail = ""
  for sigIdx in sigIdxs:
    let value = fields[sigIdx].raw.split(":", 1)[^1]
    let (tok, tags, terr) = parseDkimSigTags(value)
    if not tok:
      sawPerm = true
      if permDetail.len == 0: permDetail = terr
      continue
    let record = lookup(tags.domain, tags.selector)
    if record.len == 0:
      sawTemp = true
      if tempDetail.len == 0:
        tempDetail = "header.d=" & tags.domain & "; key unavailable"
      continue
    let (kok, pubkeyDer, kerr) = parseDkimKeyRecord(record)
    if not kok:
      sawFail = true
      if failDetail.len == 0:
        failDetail = "header.d=" & tags.domain & "; " & kerr
      continue
    let (valid, domain, verr) = verifyDkimSignature(fields, sigIdx, body, pubkeyDer)
    if valid:
      if domain notin passDomains:
        passDomains.add(domain)
      if firstDetail.len == 0:
        firstDetail = "header.d=" & domain
    else:
      sawFail = true
      if failDetail.len == 0:
        failDetail = "header.d=" & domain & "; " & verr
  if passDomains.len > 0:
    return (arPass, passDomains, firstDetail)
  if sawFail:
    return (arFail, @[], failDetail)
  if sawTemp:
    return (arTempError, @[], tempDetail)
  if sawPerm:
    return (arPermError, @[], permDetail)
  (arNone, @[], "no signature")

# ── Combined authentication ───────────────────────────────────────────────────

proc extractHeaderDomain(headers: seq[Header], name: string): string =
  ## Extract the domain of the last address in a header such as From:.
  var value = ""
  for h in headers:
    if h.name.toLowerAscii == name.toLowerAscii:
      value = h.value
  if value.len == 0: return ""
  let addrPart = value.strip().strip(chars = {'<', '>'})
  let at = addrPart.rfind('@')
  if at > 0:
    result = addrPart[at + 1 .. ^1].strip(chars = {'>', ' '}).toLowerAscii()

proc extractEnvelopeDomain(envSender: string): string =
  ## Domain of the envelope sender ("" for null path or malformed).
  var v = envSender.strip()
  if v.len == 0 or v == "<>": return ""
  v = v.strip(chars = {'<', '>'})
  let at = v.rfind('@')
  if at < 0 or at == v.high: return ""
  v[at + 1 .. ^1].strip().toLowerAscii()

proc authenticateMessage*(spfServerPtr: pointer, clientIp, heloDomain: string,
                          headers: seq[Header], body: string,
                          envelopeFrom: string = "",
                          rawHeaderBlock: string = "",
                          keyLookup: DkimKeyLookup = nil,
                          dmarcFetch: DmarcRecordLookup = nil,
                          dmarcMode = "report",
                          authHost = "meowmail.local",
                          verifyDkimSigs = true): AuthHeader =
  ## Run all authentication checks on an incoming message and build
  ## the Authentication-Results header value.
  ##
  ## SPF is evaluated against the envelope sender (RFC 7208), falling back to
  ## the From: domain only when the envelope is unavailable. DKIM signatures
  ## are cryptographically verified (RFC 6376) and DMARC is evaluated
  ## (RFC 7489) with SPF/DKIM alignment. `dmarcMode` controls enforcement:
  ## "report" never rejects, "quarantine" accepts and reports, "reject"
  ## marks `dmarcReject` when a `p=reject` policy applies so the caller can
  ## refuse the message.

  # Envelope sender for SPF (strip angle brackets / null path)
  var envSender = envelopeFrom.strip()
  if envSender.len > 0 and envSender != "<>":
    envSender = envSender.strip(chars = {'<', '>'})
  else:
    envSender = ""
  let envDomain = extractEnvelopeDomain(envSender)

  let fromDomain = extractHeaderDomain(headers, "from")

  # Run SPF against the envelope identity
  let spfIdentity = if envSender.len > 0: envSender else: fromDomain
  let (spfResult, spfDetail) = verifySpf(spfServerPtr, clientIp, heloDomain, spfIdentity)

  # Run DKIM (cryptographic verification, unless disabled)
  var dkimResult = arNone
  var dkimDomains: seq[string]
  var dkimDetail = ""
  if verifyDkimSigs:
    (dkimResult, dkimDomains, dkimDetail) =
      verifyDkim(headers, body, keyLookup, rawHeaderBlock)

  # Run DMARC (alignment of SPF/DKIM against the From domain)
  var dmarcResult = arNone
  var dmarcDetail = ""
  var dmarcReject = false
  if fromDomain.len > 0:
    let fetch: DmarcRecordLookup = if dmarcFetch != nil: dmarcFetch else: defaultDmarcFetch
    let record = fetch(fromDomain)
    if record.strip().len == 0:
      dmarcDetail = "no DMARC record"
    else:
      let outcome = evaluateDmarc(fromDomain, record, envDomain,
                                  spfResult == arPass, dkimDomains)
      if outcome.policy == dpAbsent:
        dmarcDetail = outcome.detail
      elif outcome.aligned:
        dmarcResult = arPass
        dmarcDetail = outcome.detail
      else:
        dmarcDetail = outcome.detail
        if outcome.enforced:
          dmarcResult = arFail
          if outcome.policy == dpReject and dmarcMode == "reject":
            dmarcReject = true
        else:
          # Fail without enforcement (p=none, or not sampled): report only.
          dmarcResult = if outcome.policy == dpNone: arNone else: arFail

  var results: seq[string]
  if spfIdentity.len > 0:
    results.add("spf=" & authResultStr(spfResult) & " (" & spfDetail & ")")
  case dkimResult
  of arNone:
    discard # no signature present; omit from header like most MTAs
  else:
    results.add("dkim=" & authResultStr(dkimResult) & " (" & dkimDetail & ")")
  case dmarcResult
  of arNone:
    if dmarcDetail.len > 0 and dmarcDetail != "no DMARC record":
      results.add("dmarc=none (" & dmarcDetail & ")")
    else:
      discard
  else:
    results.add("dmarc=" & authResultStr(dmarcResult) & " (" & dmarcDetail & ")")

  AuthHeader(
    spf: spfResult,
    spfDetail: spfDetail,
    dkim: dkimResult,
    dkimDetail: dkimDetail,
    dkimDomains: dkimDomains,
    dmarc: dmarcResult,
    dmarcDetail: dmarcDetail,
    dmarcReject: dmarcReject,
    combined: "Authentication-Results: " & authHost & ";\r\n\t" & results.join(";\r\n\t"),
  )

proc renderAuthHeader*(auth: AuthHeader): string =
  ## Render the Authentication-Results header.
  auth.combined
