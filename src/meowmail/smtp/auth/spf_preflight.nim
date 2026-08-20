import std/strutils
import pkg/spf
import ../smtpdelivery

proc runSpfPreflight*(enforce: bool, spfServerPtr: pointer,
            spfClientIp: string, spfHeloDomain: string, mailFrom: string): DeliveryDecision =
  ## Performs an SPF preflight check for the given delivery request using the provided configuration.
  if not enforce: return ddOk
  if spfServerPtr == nil: return ddTempFail

  let envFrom = mailFrom.strip()
  if envFrom.len == 0: return ddPermFail

  let spfServer = cast[SPF_server](spfServerPtr)
  let q = SPF_request_new(spfServer)
  if q == nil: return ddTempFail

  var resp: SPF_response = nil
  try:
    if spfClientIp.contains(":"):
      if SPF_request_set_ipv6_str(q, spfClientIp) != SPF_E_SUCCESS: return ddTempFail
    else:
      if SPF_request_set_ipv4_str(q, spfClientIp) != SPF_E_SUCCESS: return ddTempFail

    if SPF_request_set_helo_dom(q, spfHeloDomain) != SPF_E_SUCCESS: return ddTempFail
    if SPF_request_set_env_from(q, envFrom) != 0: return ddPermFail

    resp = SPF_response_new(q)
    if resp == nil: return ddTempFail

    let err = SPF_request_query_mailfrom(q, addr resp)
    if err != SPF_E_SUCCESS: return ddTempFail

    case SPF_response_result(resp)
    of SPF_RESULT_PASS: ddOk
    of SPF_RESULT_FAIL, SPF_RESULT_SOFTFAIL, SPF_RESULT_PERMERROR, SPF_RESULT_INVALID: ddPermFail
    else: ddTempFail
  finally:
    if resp != nil: SPF_response_free(resp)
    SPF_request_free(q)