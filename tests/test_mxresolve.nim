## MX resolution outcome tests (Phase C1).
##
## Covers the pure DNS-answer classifier: NXDOMAIN vs transient errors,
## null MX (RFC 7505), genuine no-MX (RFC 5321 section 5.1), and the
## empty-domain guard. All offline, no network I/O.

when defined(macosx):
  # spf chain (via mxprovider) needs arpa/nameser.h before the spf
  # package's forced "-include spf.h". Must precede imports.
  {.passC: "-include arpa/nameser.h".}

import std/[unittest]

import meowmail/smtp/mxprovider

suite "classifyMxAnswer":
  test "NXDOMAIN error maps to mrsNxDomain":
    check classifyMxAnswer("DNS: host not found: no-such.example", @[]) ==
      mrsNxDomain

  test "SERVFAIL maps to mrsTempError":
    check classifyMxAnswer(
      "DNS: query failed (rcode 2): example.com", @[]) == mrsTempError

  test "timeout maps to mrsTempError":
    check classifyMxAnswer(
      "DNS: timed out resolving example.com", @[]) == mrsTempError

  test "truncated response maps to mrsTempError":
    check classifyMxAnswer(
      "DNS: truncated response for example.com (TCP fallback not implemented)",
      @[]) == mrsTempError

  test "empty answer with no error is NODATA":
    check classifyMxAnswer("", @[]) == mrsNoData

  test "lone dot exchange is null MX":
    check classifyMxAnswer("", @[MXHost(preference: 0, host: ".")]) ==
      mrsNullMx

  test "normal MX hosts are usable":
    check classifyMxAnswer("", @[
      MXHost(preference: 10, host: "mx1.example.com"),
      MXHost(preference: 20, host: "mx2.example.com"),
    ]) == mrsOk

  test "dot host alongside real hosts is not null MX":
    check classifyMxAnswer("", @[
      MXHost(preference: 0, host: "."),
      MXHost(preference: 10, host: "mx.example.com"),
    ]) == mrsOk

suite "resolveMxOutcome guards":
  test "empty domain is a temp error without network I/O":
    let r = resolveMxOutcome("", 5, 1000)
    check r.status == mrsTempError
    check r.hosts.len == 0

  test "legacy wrapper returns empty for empty domain":
    check resolveMxHosts("", 5).len == 0

suite "tlsHostSkipped":
  test "exact hostname matches":
    check tlsHostSkipped(@["mx.broken.example"], "mx.broken.example")

  test "match is case-insensitive and ignores trailing dots":
    check tlsHostSkipped(@["MX.Broken.Example."], "mx.broken.example.")
    check tlsHostSkipped(@["mx.broken.example"], "MX.BROKEN.EXAMPLE")

  test "other hosts are not skipped":
    check not tlsHostSkipped(@["mx.broken.example"], "mx.ok.example")
    check not tlsHostSkipped(@[], "mx.broken.example")

  test "subdomains do not match the parent entry":
    check not tlsHostSkipped(@["example.com"], "mx.example.com")
