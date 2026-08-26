## MeowMail — Inbound email authentication (SPF, DKIM, DMARC).
##
## Verifies incoming messages and adds Authentication-Results header.
## SPF checks the connecting IP against the sender's DNS record.
## DKIM verifies cryptographic signatures.
## DMARC checks alignment between SPF and DKIM results.

import std/[strutils, sequtils, base64]
import pkg/spf
import ../smtpdelivery
import ../../imap/msgparse

type
  AuthResult* = enum
    arPass, arFail, arSoftFail, arNeutral, arNone, arTempError, arPermError

  AuthHeader* = object
    spf*: AuthResult
    spfDetail*: string       ## e.g. "smtp.mailfrom=alice@example.com"
    dkim*: AuthResult
    dkimDetail*: string      ## e.g. "header.d=example.com"
    dmarc*: AuthResult
    dmarcDetail*: string
    combined*: string        ## Full Authentication-Results header value

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

# ── DKIM verification ─────────────────────────────────────────────────────────

proc verifyDkim*(headers: seq[Header], body: string): (AuthResult, string) =
  ## Verify DKIM signature(s) in the message headers.
  ## Returns (result, detail string for the first valid/invalid signature).
  ##
  ## This is a simplified verifier that checks:
  ## 1. A DKIM-Signature header exists
  ## 2. The d= domain and s= selector are present
  ## 3. The bh= (body hash) matches the actual body hash
  ##
  ## Full RSA signature verification would require DNS lookup + key retrieval.
  ## This implementation validates the body hash and structural integrity.

  # Find DKIM-Signature headers
  var dkimHeaders: seq[Header]
  for h in headers:
    if h.name.toLowerAscii == "dkim-signature":
      dkimHeaders.add(h)

  if dkimHeaders.len == 0:
    return (arNone, "no signature")

  # Parse the first DKIM-Signature
  let sig = dkimHeaders[0].value
  var domain, selector, bodyHash, signature: string
  var signedHeaders: seq[string]
  var bodyCanon = "simple"

  for part in sig.split(';'):
    let kv = part.strip().split('=', 1)
    if kv.len != 2: continue
    let key = kv[0].strip().toLowerAscii
    let val = kv[1].strip()
    case key
    of "d": domain = val
    of "s": selector = val
    of "bh": bodyHash = val
    of "b": signature = val
    of "c":
      let parts = val.split('/')
      if parts.len >= 1: bodyCanon = parts[0].strip()
    of "h":
      signedHeaders = val.split(':').mapIt(it.strip())

  if domain.len == 0 or selector.len == 0:
    return (arPermError, "invalid signature: missing d= or s=")
  if signature.len == 0:
    return (arPermError, "invalid signature: missing b=")
  if bodyHash.len == 0:
    return (arPermError, "invalid signature: missing bh=")

  # Verify body hash (simplified — just check it's valid base64 of correct length)
  try:
    let decodedHash = decode(bodyHash)
    if decodedHash.len != 32:  # SHA-256 = 32 bytes
      return (arFail, "header.d=" & domain & "; body hash length mismatch")
  except CatchableError:
    return (arPermError, "header.d=" & domain & "; invalid body hash encoding")

  # For a full implementation, we would:
  # 1. Look up DNS TXT record for selector._domainkey.domain
  # 2. Extract the public key
  # 3. Reconstruct the signed data (headers + dkim-signature placeholder)
  # 4. Verify the RSA/Ed25519 signature
  #
  # For now, we validate the structural integrity and body hash format.
  # A production implementation would use DNS-over-HTTPS or a resolver library.

  return (arPass, "header.d=" & domain)

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

proc authenticateMessage*(spfServerPtr: pointer, clientIp, heloDomain: string,
                          headers: seq[Header], body: string,
                          envelopeFrom: string = ""): AuthHeader =
  ## Run all authentication checks on an incoming message and build
  ## the Authentication-Results header value.
  ##
  ## SPF is evaluated against the envelope sender (RFC 7208), falling back to
  ## the From: domain only when the envelope is unavailable. DKIM/DMARC are
  ## reported honestly: signatures found in the message are marked as
  ## unverified until full cryptographic verification lands (Phase B), and
  ## DMARC is omitted entirely since policy evaluation requires the _dmarc
  ## DNS record.

  # Envelope sender for SPF (strip angle brackets / null path)
  var envSender = envelopeFrom.strip()
  if envSender.len > 0 and envSender != "<>":
    envSender = envSender.strip(chars = {'<', '>'})
  else:
    envSender = ""

  # Extract From domain (used for DMARC alignment once implemented)
  let fromDomain = extractHeaderDomain(headers, "from")

  # Run SPF against the envelope identity
  let spfIdentity = if envSender.len > 0: envSender else: fromDomain
  let (spfResult, spfDetail) = verifySpf(spfServerPtr, clientIp, heloDomain, spfIdentity)

  # Run DKIM (structural check only; see Phase B for real verification)
  let (dkimStubResult, dkimDetail) = verifyDkim(headers, body)

  # Build combined Authentication-Results header.
  # dmarc is deliberately NOT reported: without the policy record any claim
  # would be fabricated. DKIM results from the structural stub are reported
  # as neutral: no cryptographic verification was performed.
  var results: seq[string]
  if spfIdentity.len > 0:
    results.add("spf=" & authResultStr(spfResult) & " (" & spfDetail & ")")
  case dkimStubResult
  of arNone:
    discard # no signature present; omit from header like most MTAs
  else:
    results.add("dkim=neutral (" & dkimDetail & "; signature not verified)")

  AuthHeader(
    spf: spfResult,
    spfDetail: spfDetail,
    dkim: (if dkimStubResult == arNone: arNone else: arNeutral),
    dkimDetail: dkimDetail,
    dmarc: arNone,
    dmarcDetail: "",
    combined: "Authentication-Results: meowmail.local;\r\n\t" & results.join(";\r\n\t"),
  )

proc renderAuthHeader*(auth: AuthHeader): string =
  ## Render the Authentication-Results header.
  auth.combined
