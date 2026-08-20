import std/strutils
import pkg/opendmarc
import ../smtpdelivery

proc runDmarcPreflight*(enforce: bool, fromDomain: string, record: string): DeliveryDecision =
  ## Performs a DMARC preflight check for the given delivery request using the provided configuration.
  if not enforce: return ddOk
  if fromDomain.len == 0: return ddPermFail
  if record.strip().len == 0: return ddOk

  var ip4: array[4, uint8] = [127'u8, 0'u8, 0'u8, 1'u8]
  let ctx = opendmarc_policy_connect_init(
    cast[ptr uint8](ip4[0].addr),
    DMARC_POLICY_IP_TYPE_IPV4.cint
  )
  if ctx == nil: return ddTempFail
  defer:
    discard opendmarc_policy_connect_shutdown(ctx)

  let rc = opendmarc_policy_parse_dmarc(
    ctx,
    cast[ptr uint8](fromDomain.cstring),
    cast[ptr uint8](record.cstring)
  )
  if rc != DMARC_PARSE_OKAY: return ddPermFail

  case opendmarc_get_policy_to_enforce(ctx)
  of DMARC_POLICY_NONE, DMARC_POLICY_ABSENT: ddOk
  of DMARC_POLICY_QUARANTINE, DMARC_POLICY_REJECT: ddPermFail
  else: ddTempFail
