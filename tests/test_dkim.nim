## DKIM signing tests (RFC 6376).
##
## Covers canonicalization vectors plus full sign -> verify round-trips.
## The verifier side is implemented here independently of the signer, using
## OpenSSL EVP verify APIs, so a broken signer cannot self-confirm.

when defined(macosx):
  # spf2 headers require arpa/nameser.h (ns_type) before the spf package's
  # forced "-include spf.h". Must precede imports: import statements collect
  # dependency pragmas first (same workaround as src/meowmail.nim).
  {.passC: "-include arpa/nameser.h".}

import std/[os, osproc, strutils, base64, tables, unittest]

import meowmail/smtp/dkim
import meowmail/smtp/auth/inbound
import meowmail/imap/msgparse

# ── OpenSSL verify bindings (independent of the dkim module internals) ───────

{.passL: "-lssl -lcrypto".}

type
  EVP_MD = pointer
  EVP_MD_CTX = pointer
  EVP_PKEY = pointer
  BIO = pointer

proc EVP_sha256(): EVP_MD {.importc, header: "<openssl/evp.h>".}
proc EVP_MD_CTX_new(): EVP_MD_CTX {.importc, header: "<openssl/evp.h>".}
proc EVP_MD_CTX_free(ctx: EVP_MD_CTX) {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestInit(ctx: EVP_MD_CTX, mdType: EVP_MD): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestUpdate(ctx: EVP_MD_CTX, d: pointer, cnt: csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestFinal(ctx: EVP_MD_CTX, md: ptr UncheckedArray[byte], s: var cuint): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestVerifyInit(ctx: EVP_MD_CTX, pctx: pointer, mdType: EVP_MD,
                          e: pointer, pkey: EVP_PKEY): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestVerifyUpdate(ctx: EVP_MD_CTX, d: pointer, cnt: csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestVerifyFinal(ctx: EVP_MD_CTX, sig: ptr UncheckedArray[byte], s: csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc BIO_new_mem_buf(data: pointer, len: cint): BIO {.importc, header: "<openssl/bio.h>".}
proc BIO_free(bio: BIO): cint {.importc, header: "<openssl/bio.h>".}
proc PEM_read_bio_PrivateKey(bio: BIO, x: pointer, cb: pointer, u: pointer): EVP_PKEY {.importc, header: "<openssl/pem.h>".}

proc loadTestKey(path: string): EVP_PKEY =
  let pem = readFile(path)
  let bio = BIO_new_mem_buf(unsafeAddr pem[0], pem.len.cint)
  if bio == nil: return nil
  result = PEM_read_bio_PrivateKey(bio, nil, nil, nil)
  discard BIO_free(bio)

# ── Minimal DKIM verifier (test-side) ────────────────────────────────────────

type ParsedSig = object
  headerCanon: string
  bodyCanon: string
  hNames: seq[string]
  bhB64: string
  sigB64: string
  tagsWithoutB: string   # value with b= emptied, exactly as rendered

proc sha256Raw(data: string): string =
  let ctx = EVP_MD_CTX_new()
  if ctx == nil: return ""
  discard EVP_DigestInit(ctx, EVP_sha256())
  if data.len > 0:
    discard EVP_DigestUpdate(ctx, unsafeAddr data[0], data.len.csize_t)
  var hash: array[32, byte]
  var hashLen: cuint
  discard EVP_DigestFinal(ctx, cast[ptr UncheckedArray[byte]](addr hash[0]), hashLen)
  EVP_MD_CTX_free(ctx)
  result = newString(32)
  copyMem(addr result[0], addr hash[0], 32)

proc parseSigHeader(fieldRaw: string): ParsedSig =
  # fieldRaw looks like "DKIM-Signature: v=1; ...; b=<base64>"
  for part in fieldRaw.split(';'):
    let t = part.strip()
    let eq = t.find('=')
    if eq <= 0: continue
    let k = t[0 ..< eq].strip().toLowerAscii()
    let v = t[eq + 1 .. ^1]
    case k
    of "c":
      let parts = v.split('/')
      result.headerCanon = parts[0].strip()
      result.bodyCanon = parts[^1].strip()
    of "h":
      for n in v.split(':'):
        result.hNames.add(n.strip().toLowerAscii())
    of "bh":
      result.bhB64 = v.replace(" ", "")
    of "b":
      result.sigB64 = v.replace(" ", "")
    else:
      discard
  # Rebuild "value with empty b=" by truncating at the final "; b=" marker,
  # preserving the original spacing byte-for-byte (leading space included).
  let colon = fieldRaw.find(':')
  let bIdx = fieldRaw.rfind("; b=")
  result.tagsWithoutB = fieldRaw[colon + 1 ..< bIdx + 3] & "="

proc verifyDkimMessage(msg, keyPath: string): bool =
  ## Verify the first DKIM-Signature in `msg`. Returns false on any mismatch,
  ## mirroring what an external verifier would do.
  let sep = msg.find("\r\n\r\n")
  if sep < 0: return false
  let headerBlock = msg[0 ..< sep]
  let bodyPart = msg[sep + 4 .. ^1]

  let fields = splitRawHeaders(headerBlock)
  var sigIdx = -1
  for i, f in fields:
    if f.name.toLowerAscii() == "dkim-signature":
      sigIdx = i
      break
  if sigIdx < 0: return false

  let parsed = parseSigHeader(fields[sigIdx].raw)

  # Rebuild signed data
  let selected = selectSignedHeaders(fields, parsed.hNames)
  var dataToSign = ""
  for i in selected:
    if parsed.headerCanon == "relaxed":
      dataToSign.add(relaxedHeaderValue(fields[i]) & "\r\n")
    else:
      dataToSign.add(canonHeaderSimple(fields[i]))

  if parsed.headerCanon == "relaxed":
    # RFC 6376 §3.4.2: WSP around the colon is deleted
    dataToSign.add("dkim-signature:" &
                   relaxWsp(parsed.tagsWithoutB).strip(chars = {' ', '\t'}))
  else:
    dataToSign.add("DKIM-Signature:" & parsed.tagsWithoutB)

  # bh= must match the canonicalized body (this is what catches body tampering)
  let canonBody = if parsed.bodyCanon == "relaxed": relaxedCanonBody(bodyPart)
                  else: simpleCanonBody(bodyPart)
  let expectedBh = encode(sha256Raw(canonBody))
  if expectedBh != parsed.bhB64:
    return false

  # Verify signature over dataToSign
  let pkey = loadTestKey(keyPath)
  if pkey == nil: return false
  defer: discard # key owned by OpenSSL; process-lifetime test, no free needed

  let sigBytes = decode(parsed.sigB64)
  let ctx = EVP_MD_CTX_new()
  if ctx == nil: return false
  defer: EVP_MD_CTX_free(ctx)
  if EVP_DigestVerifyInit(ctx, nil, EVP_sha256(), nil, pkey) != 1:
    return false
  if dataToSign.len > 0:
    if EVP_DigestVerifyUpdate(ctx, unsafeAddr dataToSign[0], dataToSign.len.csize_t) != 1:
      return false
  else:
    if EVP_DigestVerifyUpdate(ctx, nil, 0.csize_t) != 1:
      return false
  let rc = EVP_DigestVerifyFinal(ctx, cast[ptr UncheckedArray[byte]](addr sigBytes[0]),
                                 sigBytes.len.csize_t)
  result = rc == 1

# ── Test message fixtures ────────────────────────────────────────────────────

const SampleMsg =
  "From: George Lemon <george@example.com>\r\n" &
  "To: Anna <anna@example.org>\r\n" &
  "Subject: Hello   there\r\n" &
  "Date: Wed, 26 Aug 2026 10:00:00 GMT\r\n" &
  "Message-ID: <abc@example.com>\r\n" &
  "X-Unsigned-Header: not covered\r\n" &
  "\r\n" &
  "Hi,\r\n" &
  "\r\n" &
  "This is the   body.  \r\n" &
  "\r\n"

const FoldedMsg =
  "From: George Lemon <george@example.com>\r\n" &
  "To: Anna\r\n <anna@example.org>, Bob <bob@example.net>\r\n" &
  "Subject: Folded subject line\r\n" &
  "Date: Wed, 26 Aug 2026 10:00:00 GMT\r\n" &
  "\r\n" &
  "folded body\r\n"

const DupSubjectMsg =
  "Subject: first instance\r\n" &
  "From: george@example.com\r\n" &
  "Subject: second instance\r\n" &
  "Date: Wed, 26 Aug 2026 10:00:00 GMT\r\n" &
  "\r\n" &
  "dup body\r\n"

# ── Tests ────────────────────────────────────────────────────────────────────

suite "DKIM canonicalization":

  test "relaxed header canon matches RFC 6376 A.2 example":
    let fields = splitRawHeaders(
      "From: Joe SixPack <joe@football.example.com>")
    check relaxedHeaderValue(fields[0]) ==
      "from:Joe SixPack <joe@football.example.com>"

  test "relaxed header canon unfolds and collapses WSP":
    let fields = splitRawHeaders(
      "Subject: Is that your handbag?\r\n\tAnna")
    check relaxedHeaderValue(fields[0]) ==
      "subject:Is that your handbag? Anna"

  test "relaxed header canon lowercases only the name":
    let fields = splitRawHeaders("SUBJECT:   MiXeD CaSe VALUE")
    check relaxedHeaderValue(fields[0]) == "subject:MiXeD CaSe VALUE"

  test "simple header canon preserves raw bytes":
    let raw = "SUBJECT :  spaced name"
    let fields = splitRawHeaders(raw)
    check canonHeaderSimple(fields[0]) == raw & "\r\n"

  test "simple body canon reduces trailing empty lines to one CRLF":
    check simpleCanonBody("X\r\n\r\n\r\n") == "X\r\n"
    check simpleCanonBody("") == "\r\n"
    check simpleCanonBody("X") == "X\r\n"

  test "relaxed body canon keeps internal empty lines":
    check relaxedCanonBody("Hi,\r\n\r\nWe lost.\r\n\r\n") ==
      "Hi,\r\n\r\nWe lost.\r\n"
    check relaxedCanonBody("") == ""

  test "relaxed body canon strips trailing WSP per line":
    check relaxedCanonBody("trailing  \tspaces  \r\n") == "trailing spaces\r\n"

  test "splitRawHeaders handles folded headers":
    let fields = splitRawHeaders(FoldedMsg[0 ..< FoldedMsg.find("\r\n\r\n")])
    check fields.len == 4
    check fields[1].raw == "To: Anna\r\n <anna@example.org>, Bob <bob@example.net>"

suite "DKIM sign -> external verify":
  var keyPath = getTempDir() / "meowmail-test-dkim.key"
  var keyReady = false

  test "generate test RSA key":
    when defined(windows):
      skip()
    else:
      let cmd = "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out " & keyPath & " 2>/dev/null"
      let (outp, code) = execCmdEx(cmd)
      discard outp
      keyReady = code == 0 and fileExists(keyPath)
      check keyReady

  test "sign relaxed/relaxed verifies":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    let signed = signMessage(key, SampleMsg)
    check signed != SampleMsg
    check verifyDkimMessage(signed, keyPath)

  test "sign simple/simple verifies":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    key.headerCanon = "simple"
    key.bodyCanon = "simple"
    let signed = signMessage(key, SampleMsg)
    check verifyDkimMessage(signed, keyPath)

  test "signature covers folded headers":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    let signed = signMessage(key, FoldedMsg)
    check verifyDkimMessage(signed, keyPath)

  test "repeated headers signed bottom-up":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    let signed = signMessage(key, DupSubjectMsg)
    check verifyDkimMessage(signed, keyPath)

  test "tampered body fails verification":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    var signed = signMessage(key, SampleMsg)
    signed = signed.replace("This is the   body.", "Tampered body!")
    check not verifyDkimMessage(signed, keyPath)

  test "tampered signed header fails verification":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    var signed = signMessage(key, SampleMsg)
    signed = signed.replace("Hello   there", "Evil rewrite")
    check not verifyDkimMessage(signed, keyPath)

  test "RSA-4096 keys work (buffer sized via EVP_PKEY_size)":
    require(keyReady)
    let bigKey = getTempDir() / "meowmail-test-dkim4096.key"
    let cmd = "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out " & bigKey & " 2>/dev/null"
    let (_, code) = execCmdEx(cmd)
    if code != 0:
      skip()
    else:
      let key = newDkimKey("example.com", "big", bigKey)
      let signed = signMessage(key, SampleMsg)
      check verifyDkimMessage(signed, bigKey)

# ── Module verifier (dkim.verifyDkimSignature via auth/inbound) ───────────────

proc splitTestMsg(msg: string): tuple[rawHeaders: string, headers: seq[Header], body: string] =
  let sep = msg.find("\r\n\r\n")
  let hb = msg[0 ..< sep]
  result = (hb, @[], msg[sep + 4 .. ^1])
  for line in hb.split("\r\n"):
    if line.len == 0: continue
    if line[0] in {' ', '\t'}:
      if result.headers.len > 0:
        result.headers[^1].value &= " " & line.strip()
      continue
    let colon = line.find(':')
    if colon > 0:
      result.headers.add((name: line[0 ..< colon],
                          value: line[colon + 1 .. ^1].strip()))

proc keyRecordFor(keyPath, domain, selector: string): string =
  let key = newDkimKey(domain, selector, keyPath)
  "v=DKIM1; k=rsa; p=" & encode(publicKeyDer(key))

var stubKeyRecord {.threadvar.}: string

proc stubLookup(d, s: string): string {.gcsafe.} = stubKeyRecord

suite "DKIM verify (module)":
  var keyPath = getTempDir() / "meowmail-test-dkim.key"
  var keyReady = fileExists(keyPath)

  test "roundtrip relaxed/relaxed verifies with stub DNS":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    let signed = signMessage(key, SampleMsg)
    let (hb, headers, body) = splitTestMsg(signed)
    let record = keyRecordFor(keyPath, "example.com", "test")
    stubKeyRecord = record
    let (res, domains, _) = verifyDkim(headers, body, stubLookup, hb)
    check res == arPass
    check domains == @["example.com"]

  test "roundtrip simple/simple verifies with stub DNS":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    key.headerCanon = "simple"
    key.bodyCanon = "simple"
    let signed = signMessage(key, SampleMsg)
    let (hb, headers, body) = splitTestMsg(signed)
    let record = keyRecordFor(keyPath, "example.com", "test")
    stubKeyRecord = record
    let (res, domains, _) = verifyDkim(headers, body, stubLookup, hb)
    check res == arPass
    check domains == @["example.com"]

  test "tampered body fails module verification":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    var signed = signMessage(key, SampleMsg)
    signed = signed.replace("This is the   body.", "Tampered body!")
    let (hb, headers, body) = splitTestMsg(signed)
    let record = keyRecordFor(keyPath, "example.com", "test")
    stubKeyRecord = record
    let (res, _, _) = verifyDkim(headers, body, stubLookup, hb)
    check res == arFail

  test "tampered signed header fails module verification":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    var signed = signMessage(key, SampleMsg)
    signed = signed.replace("Hello   there", "Evil rewrite")
    let (hb, headers, body) = splitTestMsg(signed)
    let record = keyRecordFor(keyPath, "example.com", "test")
    stubKeyRecord = record
    let (res, _, _) = verifyDkim(headers, body, stubLookup, hb)
    check res == arFail

  test "wrong key fails module verification":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    let signed = signMessage(key, SampleMsg)
    let (hb, headers, body) = splitTestMsg(signed)
    let otherKey = getTempDir() / "meowmail-test-dkim-other.key"
    let cmd = "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out " & otherKey & " 2>/dev/null"
    let (_, code) = execCmdEx(cmd)
    require(code == 0)
    let record = keyRecordFor(otherKey, "example.com", "test")
    stubKeyRecord = record
    let (res, _, _) = verifyDkim(headers, body, stubLookup, hb)
    check res == arFail

  test "missing key record is a temp error":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    let signed = signMessage(key, SampleMsg)
    let (hb, headers, body) = splitTestMsg(signed)
    stubKeyRecord = ""
    let (res, _, _) = verifyDkim(headers, body, stubLookup, hb)
    check res == arTempError

  test "revoked key (empty p=) fails":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    let signed = signMessage(key, SampleMsg)
    let (hb, headers, body) = splitTestMsg(signed)
    stubKeyRecord = "v=DKIM1; k=rsa; p="
    let (res, _, _) = verifyDkim(headers, body, stubLookup, hb)
    check res == arFail

  test "unsigned message reports none":
    let (hb, headers, body) = splitTestMsg(SampleMsg)
    stubKeyRecord = ""
    let (res, domains, _) = verifyDkim(headers, body, stubLookup, hb)
    check res == arNone
    check domains.len == 0
  test "sig tag parser rejects bad algorithm and version":
    let (_, _, err1) = parseDkimSigTags("v=1; a=rsa-sha1; d=x.com; s=y; h=from; bh=QQ==; b=QQ==")
    check err1.len > 0
    let (_, _, err2) = parseDkimSigTags("v=2; a=rsa-sha256; d=x.com; s=y; h=from; bh=QQ==; b=QQ==")
    check err2.len > 0
    let (ok3, tags3, _) = parseDkimSigTags(
      "v=1; a=rsa-sha256; c=relaxed/simple; d=example.com; s=test; h=from:to; bh=QQ==; b=QQ==")
    check ok3
    check tags3.domain == "example.com"
    check tags3.headerCanon == "relaxed"
    check tags3.bodyCanon == "simple"

suite "DKIM verify raw message (preflight path)":
  var keyPath = getTempDir() / "meowmail-test-dkim.key"
  var keyReady = fileExists(keyPath)

  test "signed message verifies from raw bytes":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    let signed = signMessage(key, SampleMsg)
    stubKeyRecord = keyRecordFor(keyPath, "example.com", "test")
    let (pass, domains, tempErr, _) = verifyDkimData(signed, stubLookup)
    check pass
    check domains == @["example.com"]
    check not tempErr

  test "tampered raw message fails definitively":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    var signed = signMessage(key, SampleMsg)
    signed = signed.replace("This is the   body.", "Tampered body!")
    stubKeyRecord = keyRecordFor(keyPath, "example.com", "test")
    let (pass, _, tempErr, _) = verifyDkimData(signed, stubLookup)
    check not pass
    check not tempErr

  test "unavailable key defers instead of failing":
    require(keyReady)
    let key = newDkimKey("example.com", "test", keyPath)
    let signed = signMessage(key, SampleMsg)
    stubKeyRecord = ""
    let (pass, _, tempErr, _) = verifyDkimData(signed, stubLookup)
    check not pass
    check tempErr

  test "unsigned raw message has no signatures":
    let (pass, domains, tempErr, detail) = verifyDkimData(SampleMsg, stubLookup)
    check not pass
    check domains.len == 0
    check not tempErr
    check detail == "no signature"
