import std/strutils
import pkg/spf
import ../smtpdelivery

type
  SpfPreflightResult* = object
    ## Raw SPF preflight outcome. `pass` is true only on SPF_RESULT_PASS;
    ## `tempError` marks DNS/transient failures (retry later); anything else
    ## (fail, softfail, permerror, invalid, empty sender) is a hard fail.
    ## `raw` carries the libspf2 result code so callers needing the legacy
    ## verdict mapping (neutral/none -> tempfail) can reproduce it exactly.
    pass*: bool
    tempError*: bool
    raw*: SPF_result_t
    domain*: string
    detail*: string

proc extractSpfDomain*(mailFrom: string): string =
  ## Envelope sender domain, "" for null path or malformed addresses.
  var v = mailFrom.strip()
  if v.len == 0 or v == "<>": return ""
  v = v.strip(chars = {'<', '>'})
  let at = v.rfind('@')
  if at < 0 or at == v.high: return ""
  v[at + 1 .. ^1].strip().toLowerAscii()

proc querySpfRaw*(spfServerPtr: pointer, spfClientIp, spfHeloDomain,
                  mailFrom: string): SpfPreflightResult =
  ## Evaluate SPF for an outbound envelope sender without collapsing the
  ## result to a delivery verdict, so DMARC alignment can consume it.
  ## Angle brackets are stripped: libspf2 expects a bare address and fails
  ## bracketed senders with SPF_E_NOT_SPF.
  var envFrom = mailFrom.strip().strip(chars = {'<', '>'})
  if envFrom.len == 0:
    return SpfPreflightResult(pass: false, detail: "empty MAIL FROM")
  if spfServerPtr == nil:
    return SpfPreflightResult(tempError: true, detail: "SPF server not initialized")
  let spfServer = cast[SPF_server](spfServerPtr)
  let q = SPF_request_new(spfServer)
  if q == nil:
    return SpfPreflightResult(tempError: true, detail: "SPF request creation failed")
  var resp: SPF_response = nil
  try:
    if spfClientIp.contains(":"):
      if SPF_request_set_ipv6_str(q, spfClientIp) != SPF_E_SUCCESS:
        return SpfPreflightResult(tempError: true, detail: "invalid IPv6 address")
    else:
      if SPF_request_set_ipv4_str(q, spfClientIp) != SPF_E_SUCCESS:
        return SpfPreflightResult(tempError: true, detail: "invalid IPv4 address")
    if SPF_request_set_helo_dom(q, spfHeloDomain) != SPF_E_SUCCESS:
      return SpfPreflightResult(tempError: true, detail: "invalid HELO domain")
    if SPF_request_set_env_from(q, envFrom) != 0:
      return SpfPreflightResult(detail: "invalid MAIL FROM domain")
    resp = SPF_response_new(q)
    if resp == nil:
      return SpfPreflightResult(tempError: true, detail: "SPF response allocation failed")
    let err = SPF_request_query_mailfrom(q, addr resp)
    if err != SPF_E_SUCCESS:
      return SpfPreflightResult(tempError: true, detail: "SPF query failed: " & $err)
    let detail = "smtp.mailfrom=" & envFrom
    let res = SPF_response_result(resp)
    case res
    of SPF_RESULT_PASS:
      SpfPreflightResult(pass: true, raw: res,
                         domain: extractSpfDomain(envFrom), detail: detail)
    of SPF_RESULT_TEMPERROR:
      SpfPreflightResult(tempError: true, raw: res, detail: detail)
    else:
      SpfPreflightResult(raw: res, domain: extractSpfDomain(envFrom),
                         detail: detail)
  finally:
    if resp != nil: SPF_response_free(resp)
    SPF_request_free(q)

proc runSpfPreflight*(enforce: bool, spfServerPtr: pointer,
            spfClientIp: string, spfHeloDomain: string, mailFrom: string): DeliveryDecision =
  ## Performs an SPF preflight check for the given delivery request using the provided configuration.
  ## Verdict mapping is unchanged from the original implementation.
  if not enforce: return ddOk
  if spfServerPtr == nil: return ddTempFail
  if mailFrom.strip().len == 0: return ddPermFail

  let r = querySpfRaw(spfServerPtr, spfClientIp, spfHeloDomain, mailFrom)
  case r.raw
  of SPF_RESULT_PASS: ddOk
  of SPF_RESULT_FAIL, SPF_RESULT_SOFTFAIL, SPF_RESULT_PERMERROR, SPF_RESULT_INVALID: ddPermFail
  else: ddTempFail