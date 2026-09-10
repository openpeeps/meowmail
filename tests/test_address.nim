## tests/test_address.nim — RFC 5321 mailbox parser tests.
##
## Compile/run with: `clue build tests/test_address.nim && ./test_address`

import std/[unittest, strutils]
import ../src/meowmail/smtp/address

test "null sender <>":
  let m = parseMailbox("<>")
  check m.kind == mkNull
  check m.isNullSender()
  check m.hasValidSyntax()

test "null sender with spaces":
  let m = parseMailbox("  <>  ")
  check m.kind == mkNull
  check m.hasValidSyntax()

test "bare local name (postmaster)":
  let m = parseMailbox("postmaster")
  check m.kind == mkLocal
  check m.localPart == "postmaster"
  check m.domain.len == 0
  check m.hasValidSyntax()

test "standard mailbox":
  let m = parseMailbox("<user@example.com>")
  check m.kind == mkStandard
  check m.localPart == "user"
  check m.domain == "example.com"
  check m.hasValidSyntax()
  check m.isDomainValid()

test "standard mailbox without angle brackets":
  let m = parseMailbox("user@example.com")
  check m.kind == mkStandard
  check m.localPart == "user"
  check m.domain == "example.com"
  check m.hasValidSyntax()

test "quoted local-part":
  let m = parseMailbox("<\"john.doe\"@example.com>")
  check m.kind == mkStandard
  check m.localPart == "\"john.doe\""
  check m.domain == "example.com"
  check m.hasValidSyntax()

test "quoted local-part with special chars":
  let m = parseMailbox("<\"john doe\"@example.com>")
  check m.kind == mkStandard
  check m.localPart == "\"john doe\""
  check m.domain == "example.com"
  check m.hasValidSyntax()

test "quoted local-part with escaped quote":
  let m = parseMailbox("<\"john\\\"doe\"@example.com>")
  check m.kind == mkStandard
  check m.localPart == "\"john\"doe\""  # raw form with surrounding quotes
  check m.domain == "example.com"
  check m.hasValidSyntax()

test "dot-atom local-part":
  let m = parseMailbox("<a.b.c@example.com>")
  check m.kind == mkStandard
  check m.localPart == "a.b.c"
  check m.domain == "example.com"
  check m.hasValidSyntax()

test "address-literal domain":
  let m = parseMailbox("<user@[192.168.1.1]>")
  check m.kind == mkLiteral
  check m.localPart == "user"
  check m.domain == "[192.168.1.1]"
  check m.hasValidSyntax()
  check m.isDomainValid()

test "IPv6 address-literal":
  let m = parseMailbox("<user@[IPv6:::1]>")
  check m.kind == mkLiteral
  check m.localPart == "user"
  check m.domain == "[IPv6:::1]"
  check m.hasValidSyntax()

test "empty address":
  let m = parseMailbox("")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "missing domain":
  let m = parseMailbox("user@")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "missing local-part":
  let m = parseMailbox("@example.com")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "double dot in local-part":
  let m = parseMailbox("<a..b@example.com>")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "leading dot in local-part":
  let m = parseMailbox("<.user@example.com>")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "trailing dot in local-part":
  let m = parseMailbox("<user.@example.com>")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "unclosed angle bracket":
  let m = parseMailbox("<user@example.com")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "unclosed quotes":
  let m = parseMailbox("<\"user@example.com>")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "empty domain label":
  let m = parseMailbox("<user@.example.com>")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "trailing dot in domain":
  let m = parseMailbox("<user@example.com.>")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "address-literal missing bracket":
  let m = parseMailbox("<user@[192.168.1.1>")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "address-literal empty":
  let m = parseMailbox("<user@[]>")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "local-part length limit":
  let longLocal = 'a'.repeat(65)
  let m = parseMailbox("<" & longLocal & "@example.com>")
  check m.error.len > 0
  check not m.hasValidSyntax()

test "domain length limit":
  let longLabel = 'a'.repeat(85)
  let longDomain = longLabel & "." & longLabel & "." & longLabel
  let m = parseMailbox("<user@" & longDomain & ">")
  check m.error.len > 0
  check not m.hasValidSyntax()
