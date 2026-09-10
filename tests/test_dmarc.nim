## DMARC evaluation tests (RFC 7489).
##
## Covers record parsing, alignment (strict/relaxed), policy application,
## sampling (pct=) and record selection, all offline with stub data.

when defined(macosx):
  # spf chain (via mxprovider) needs arpa/nameser.h before the spf
  # package's forced "-include spf.h". Must precede imports.
  {.passC: "-include arpa/nameser.h".}

import std/[strutils, unittest]

import pkg/spf
import meowmail/smtp/smtpdelivery
import meowmail/smtp/auth/dmarc
import meowmail/smtp/auth/spf_preflight
import meowmail/smtp/mxprovider

suite "DMARC record parsing":
  test "valid record parses":
    let (ok, rec, err) = parseDmarcRecord(
      "v=DMARC1; p=reject; rua=mailto:d@example.com")
    check ok
    check err == ""
    check rec.policy == dpReject
    check rec.pct == 100
    check rec.adkim == 'r'
    check rec.aspf == 'r'

  test "full record with sp and strict alignment":
    let (ok, rec, _) = parseDmarcRecord(
      "v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=s; " &
      "rua=mailto:a@x.com; ruf=mailto:f@x.com")
    check ok
    check rec.policy == dpQuarantine
    check rec.subPolicy == dpReject
    check rec.hasSubPolicy
    check rec.pct == 50
    check rec.adkim == 's'
    check rec.aspf == 's'

  test "missing v fails":
    let (ok, _, err) = parseDmarcRecord("p=reject")
    check not ok
    check err.len > 0

  test "missing p fails":
    let (ok, _, _) = parseDmarcRecord("v=DMARC1; rua=mailto:a@x.com")
    check not ok

  test "bad policy fails":
    let (ok, _, _) = parseDmarcRecord("v=DMARC1; p=block")
    check not ok

  test "pct out of range fails":
    let (ok, _, _) = parseDmarcRecord("v=DMARC1; p=none; pct=101")
    check not ok

  test "unknown tags are ignored":
    let (ok, rec, _) = parseDmarcRecord("v=DMARC1; p=none; foobar=baz")
    check ok
    check rec.policy == dpNone

  test "record selection picks v=DMARC1":
    check selectDmarcRecord(@["some random txt", "v=DMARC1; p=reject"]) ==
      "v=DMARC1; p=reject"
    check selectDmarcRecord(@["nothing here"]) == ""

suite "DMARC alignment":
  test "strict requires exact match":
    check domainsAlign("example.com", "example.com", true)
    check not domainsAlign("mail.example.com", "example.com", true)

  test "relaxed allows subdomains":
    check domainsAlign("mail.example.com", "example.com", false)
    check domainsAlign("example.com", "mail.example.com", false)
    check not domainsAlign("example.com", "other.com", false)

  test "empty domains never align":
    check not domainsAlign("", "example.com", false)
    check not domainsAlign("example.com", "", false)

suite "DMARC evaluation":
  test "spf alignment passes":
    let o = evaluateDmarc("example.com", "v=DMARC1; p=reject",
                          "example.com", true, @[], pctRoll = 0)
    check o.aligned
    check o.spfAligned
    check not o.enforced
    check o.policy == dpReject

  test "dkim alignment passes":
    let o = evaluateDmarc("example.com", "v=DMARC1; p=reject",
                          "evil.com", false, @["example.com"], pctRoll = 0)
    check o.aligned
    check o.dkimAligned
    check not o.enforced

  test "misaligned fail with reject is enforced":
    let o = evaluateDmarc("example.com", "v=DMARC1; p=reject",
                          "evil.com", false, @[], pctRoll = 0)
    check not o.aligned
    check o.enforced
    check o.policy == dpReject

  test "p=none never enforces":
    let o = evaluateDmarc("example.com", "v=DMARC1; p=none",
                          "evil.com", false, @[], pctRoll = 0)
    check not o.aligned
    check o.policy == dpNone

  test "pct sampling skips when roll exceeds pct":
    let o = evaluateDmarc("example.com", "v=DMARC1; p=reject; pct=10",
                          "evil.com", false, @[], pctRoll = 50)
    check not o.aligned
    check not o.sampled
    check not o.enforced

  test "sp applies to subdomains":
    let o = evaluateDmarc("mail.example.com",
                          "v=DMARC1; p=reject; sp=none",
                          "evil.com", false, @[],
                          isSubdomain = true, pctRoll = 0)
    check o.policy == dpNone

  test "p applies without subdomain flag":
    let o = evaluateDmarc("mail.example.com",
                          "v=DMARC1; p=reject; sp=none",
                          "evil.com", false, @[],
                          isSubdomain = false, pctRoll = 0)
    check o.policy == dpReject

  test "no record means absent":
    let o = evaluateDmarc("example.com", "", "example.com", true, @[])
    check o.policy == dpAbsent
    check not o.aligned

  test "strict aspf blocks subdomain spf":
    let o = evaluateDmarc("example.com", "v=DMARC1; p=reject; aspf=s",
                          "mail.example.com", true, @[], pctRoll = 0)
    check not o.spfAligned
    check not o.aligned
    check o.enforced

proc spfRes(pass, temp: bool, domain: string,
            raw = SPF_RESULT_PASS): SpfPreflightResult =
  SpfPreflightResult(pass: pass, tempError: temp, raw: raw, domain: domain,
                     detail: "smtp.mailfrom=test")

suite "DMARC joint preflight decision":
  const rejectRec = "v=DMARC1; p=reject"

  test "spf-aligned send passes":
    check decideJointDmarc("example.com", rejectRec, "example.com",
      spfRes(true, false, "example.com"), @[], false) == ddOk

  test "spf fail with aligned dkim passes (no false refusal)":
    check decideJointDmarc("example.com", rejectRec, "evil.com",
      spfRes(false, false, "evil.com"), @["example.com"], false) == ddOk

  test "spoofed p=reject is refused":
    check decideJointDmarc("example.com", rejectRec, "evil.com",
      spfRes(false, false, "evil.com"), @[], false) == ddPermFail

  test "spoofed p=quarantine is refused":
    check decideJointDmarc("example.com", "v=DMARC1; p=quarantine",
      "evil.com", spfRes(false, false, "evil.com"), @[], false) == ddPermFail

  test "p=none never refuses":
    check decideJointDmarc("example.com", "v=DMARC1; p=none",
      "evil.com", spfRes(false, false, "evil.com"), @[], false) == ddOk

  test "no record passes":
    check decideJointDmarc("example.com", "",
      "example.com", spfRes(true, false, "example.com"), @[], false) == ddOk

  test "empty from domain is refused":
    check decideJointDmarc("", rejectRec,
      "", spfRes(false, false, ""), @[], false) == ddPermFail

  test "spf temp error defers":
    check decideJointDmarc("example.com", rejectRec, "example.com",
      spfRes(false, true, "", SPF_RESULT_TEMPERROR), @[], false) == ddTempFail

  test "dkim key trouble defers instead of refusing":
    check decideJointDmarc("example.com", rejectRec, "evil.com",
      spfRes(false, false, "evil.com"), @[], true) == ddTempFail

  test "unparsable record is treated as absent":
    check decideJointDmarc("example.com", "v=DMARC1; p=bogus",
      "evil.com", spfRes(false, false, "evil.com"), @[], false) == ddOk

  test "pct=0 never enforces":
    check decideJointDmarc("example.com", "v=DMARC1; p=reject; pct=0",
      "evil.com", spfRes(false, false, "evil.com"), @[], false) == ddOk
