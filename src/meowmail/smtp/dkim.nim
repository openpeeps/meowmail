## MeowMail — DKIM signing for outbound messages (RFC 6376).
##
## Signs the From, To, Subject, Date, and Message-ID headers using
## RSA-SHA256 and appends a DKIM-Signature header.

import std/[strutils, times, base64, os, tables]
import ../imap/msgparse

type
  DkimKey* = ref object
    domain*: string
    selector*: string
    privateKey*: pointer  # EVP_PKEY*
    bodyLength*: int      # l= tag, 0 = sign entire body
    headerCanon*: string  # "simple" or "relaxed"
    bodyCanon*: string    # "simple" or "relaxed"

  DkimSignature* = object
    headerCanon*: string   # "simple" or "relaxed"
    bodyCanon*: string     # "simple" or "relaxed"
    domain*: string
    selector*: string
    signedHeaders*: seq[string]
    bodyHash*: string      # base64-encoded body hash
    signature*: string     # base64-encoded signature

# ── OpenSSL bindings ──────────────────────────────────────────────────────────

{.passL: "-lssl -lcrypto".}

type
  EVP_MD = pointer
  EVP_MD_CTX = pointer
  EVP_PKEY = pointer
  BIO = pointer
  PKCS8_PRIV_KEY_INFO = pointer

proc EVP_sha256(): EVP_MD {.importc, header: "<openssl/evp.h>".}
proc EVP_sha1(): EVP_MD {.importc, header: "<openssl/evp.h>".}

proc EVP_MD_CTX_new(): EVP_MD_CTX {.importc, header: "<openssl/evp.h>".}
proc EVP_MD_CTX_free(ctx: EVP_MD_CTX) {.importc, header: "<openssl/evp.h>".}

proc EVP_DigestInit(ctx: EVP_MD_CTX, mdType: EVP_MD): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestUpdate(ctx: EVP_MD_CTX, d: pointer, cnt: csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestFinal(ctx: EVP_MD_CTX, md: ptr UncheckedArray[byte], s: var cuint): cint {.importc, header: "<openssl/evp.h>".}

proc EVP_SignInit(ctx: EVP_MD_CTX, mdType: EVP_MD): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_SignUpdate(ctx: EVP_MD_CTX, d: pointer, cnt: csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_SignFinal(ctx: EVP_MD_CTX, sig: ptr UncheckedArray[byte], s: var cuint, pkey: EVP_PKEY): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_size(pkey: EVP_PKEY): cint {.importc, header: "<openssl/evp.h>".}

proc EVP_DigestVerifyInit(ctx: EVP_MD_CTX, pctx: pointer, mdType: EVP_MD,
                          engine: pointer, pkey: EVP_PKEY): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestVerifyFinal(ctx: EVP_MD_CTX, sig: pointer,
                           siglen: csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc d2i_PUBKEY(a: pointer, pp: ptr pointer, length: clong): EVP_PKEY {.importc, header: "<openssl/x509.h>".}

proc BIO_new_mem_buf(data: pointer, len: cint): BIO {.importc, header: "<openssl/bio.h>".}
proc BIO_free(bio: BIO): cint {.importc, header: "<openssl/bio.h>".}

proc PEM_read_bio_PrivateKey(bio: BIO, x: pointer, cb: pointer, u: pointer): EVP_PKEY {.importc, header: "<openssl/pem.h>".}
proc EVP_PKEY_free(pkey: EVP_PKEY) {.importc, header: "<openssl/evp.h>".}
proc i2d_PUBKEY(x: EVP_PKEY, outp: ptr pointer): cint {.importc, header: "<openssl/evp.h>".}
proc OPENSSL_free(p: pointer) {.importc, header: "<openssl/crypto.h>".}

# ── Hashing / RSA ─────────────────────────────────────────────────────────────

proc sha256(data: string): string =
  ## Compute SHA-256 hash of data, return raw bytes as string.
  let ctx = EVP_MD_CTX_new()
  if ctx == nil: return ""
  discard EVP_DigestInit(ctx, EVP_sha256())
  if data.len > 0:
    discard EVP_DigestUpdate(ctx, unsafeAddr data[0], data.len.csize_t)
  else:
    discard EVP_DigestUpdate(ctx, nil, 0.csize_t)
  var hash: array[32, byte]
  var hashLen: cuint
  discard EVP_DigestFinal(ctx, cast[ptr UncheckedArray[byte]](addr hash[0]), hashLen)
  EVP_MD_CTX_free(ctx)
  result = newString(32)
  copyMem(addr result[0], addr hash[0], 32)

proc rsaSign(data: string, pkey: EVP_PKEY): string =
  ## Sign data with RSA-SHA256, return raw signature bytes.
  let ctx = EVP_MD_CTX_new()
  if ctx == nil: return ""
  discard EVP_SignInit(ctx, EVP_sha256())
  if data.len > 0:
    discard EVP_SignUpdate(ctx, unsafeAddr data[0], data.len.csize_t)
  # Size the buffer from the key so RSA-3072/4096 keys work too.
  let maxLen = int(EVP_PKEY_size(pkey))
  if maxLen <= 0:
    EVP_MD_CTX_free(ctx)
    return ""
  var sig = newSeq[byte](maxLen)
  var sigLen: cuint
  if EVP_SignFinal(ctx, cast[ptr UncheckedArray[byte]](addr sig[0]), sigLen, pkey) != 1:
    EVP_MD_CTX_free(ctx)
    return ""
  EVP_MD_CTX_free(ctx)
  result = newString(sigLen)
  copyMem(addr result[0], addr sig[0], sigLen.int)

proc loadPrivateKey(pemData: string): EVP_PKEY =
  ## Load a PEM-encoded private key. Returns nil on failure.
  let bio = BIO_new_mem_buf(unsafeAddr pemData[0], pemData.len.cint)
  if bio == nil: return nil
  result = PEM_read_bio_PrivateKey(bio, nil, nil, nil)
  discard BIO_free(bio)

# ── Canonicalization (RFC 6376 §3.4) ─────────────────────────────────────────

type
  RawHeaderField* = object
    ## A single header field exactly as it appears on the wire, including any
    ## folded continuation lines (CRLF + WSP preserved).
    name*: string   # field name as written (original case)
    raw*: string    # complete field text, no trailing CRLF

proc splitRawHeaders*(headerBlock: string): seq[RawHeaderField] =
  ## Split a raw header block (fields separated by CRLF, folding allowed)
  ## into individual fields while preserving their original bytes.
  var curName = ""
  var curRaw = ""
  for line in headerBlock.split("\r\n"):
    if line.len == 0: continue
    if line[0] in {' ', '\t'}:
      if curRaw.len > 0:
        curRaw.add("\r\n")
        curRaw.add(line)
      continue
    if curRaw.len > 0:
      result.add(RawHeaderField(name: curName, raw: curRaw))
    let colon = line.find(':')
    if colon > 0:
      curName = line[0 ..< colon]
      curRaw = line
    else:
      curName = ""
      curRaw = line
  if curRaw.len > 0:
    result.add(RawHeaderField(name: curName, raw: curRaw))

proc relaxWsp*(s: string): string =
  ## Reduce every run of WSP to a single SP. Trailing WSP disappears because
  ## a run at the end is never flushed; leading WSP becomes a single SP.
  var inWs = false
  for ch in s:
    if ch == ' ' or ch == '\t':
      inWs = true
    else:
      if inWs:
        result.add(' ')
        inWs = false
      result.add(ch)

proc relaxedHeaderValue*(field: RawHeaderField): string =
  ## RFC 6376 §3.4.2 relaxed header canonicalization for a single field:
  ## lowercase name, unfold, collapse WSP runs, trim WSP around the colon.
  let colon = field.raw.find(':')
  let value = if colon >= 0: field.raw[colon + 1 .. ^1] else: ""
  let unfolded = value.replace("\r\n", "")
  result = field.name.toLowerAscii() & ":" & relaxWsp(unfolded).strip(chars = {' ', '\t'})

proc canonHeaderSimple*(field: RawHeaderField): string =
  ## RFC 6376 §3.4.1 simple header canonicalization: exact bytes plus CRLF.
  field.raw & "\r\n"

proc selectSignedHeaders*(fields: seq[RawHeaderField],
                         names: seq[string]): seq[int] =
  ## Resolve `names` (h= tag order) into field indexes. Repeated headers are
  ## consumed bottom-up as required by RFC 6376 §5.4; names with no remaining
  ## instance contribute nothing (signing a non-existent header is legal).
  var used = initTable[string, int]()
  for n in names:
    let ln = n.toLowerAscii()
    let skip = used.getOrDefault(ln, 0)
    var seen = 0
    for i in countdown(fields.high, 0):
      if fields[i].name.toLowerAscii() != ln: continue
      if seen < skip:
        inc seen
        continue
      result.add(i)
      used[ln] = skip + 1
      break

proc simpleCanonBody*(body: string): string =
  ## RFC 6376 §3.4.3 simple body canonicalization: ensure one terminating
  ## CRLF and reduce all trailing empty lines to it.
  var b = body
  if not b.endsWith("\r\n"):
    b.add("\r\n")
  while b.endsWith("\r\n\r\n"):
    b.setLen(b.len - 2)
  b

proc relaxedCanonBody*(body: string): string =
  ## RFC 6376 §3.4.2 relaxed body canonicalization: strip trailing WSP per
  ## line, reduce WSP runs to single SP, drop trailing empty lines (internal
  ## empty lines are preserved). An empty body stays empty; otherwise output
  ## always ends with CRLF.
  var lines = body.split("\r\n")
  while lines.len > 0 and lines[^1].len == 0:
    discard lines.pop()
  for line in lines:
    result.add(relaxWsp(line) & "\r\n")

# ── Public API ────────────────────────────────────────────────────────────────

proc newDkimKeyFromPem*(domain, selector, pemData: string): DkimKey =
  ## Build a DkimKey from PEM text. Raises IOError when the key is invalid.
  let pkey = loadPrivateKey(pemData)
  if pkey == nil:
    raise newException(IOError, "Failed to load DKIM private key")
  result = DkimKey(
    domain: domain,
    selector: selector,
    privateKey: pkey,
    bodyLength: 0,
    headerCanon: "relaxed",
    bodyCanon: "relaxed",
  )

proc newDkimKey*(domain, selector, pemKeyFile: string): DkimKey =
  ## Load a DKIM private key from a PEM file. Defaults to relaxed/relaxed
  ## canonicalization, which survives in-transit header reformatting.
  let pemData = readFile(pemKeyFile)
  result = newDkimKeyFromPem(domain, selector, pemData)

proc publicKeyDer*(key: DkimKey): string =
  ## DER-encoded SubjectPublicKeyInfo for the key (for DNS TXT publishing).
  if key.privateKey == nil: return ""
  var p: pointer
  let n = i2d_PUBKEY(cast[EVP_PKEY](key.privateKey), addr p)
  if n <= 0 or p == nil: return ""
  result = newString(n)
  copyMem(addr result[0], p, n)
  OPENSSL_free(p)

proc dkimTxtRecord*(key: DkimKey): string =
  ## Render the DNS TXT record publishing this key's public half:
  ## `<selector>._domainkey.<domain> IN TXT "v=DKIM1; k=rsa; p=..."`
  let der = publicKeyDer(key)
  if der.len == 0: return ""
  let p = encode(der)
  result = key.selector & "._domainkey." & key.domain &
           " IN TXT \"v=DKIM1; k=rsa; p=" & p & "\""

const DefaultSignHeaders* = @["from", "to", "subject", "date", "message-id"]

proc sigTagString(key: DkimKey, hValue, bodyHash: string): string =
  ## The DKIM-Signature tag list with an empty b= value. This exact string is
  ## used both for the signed placeholder and for the rendered header, so a
  ## verifier reconstructing the header minus b= hashes the same bytes.
  "v=1; a=rsa-sha256; d=" & key.domain &
  "; s=" & key.selector &
  "; c=" & key.headerCanon & "/" & key.bodyCanon &
  "; h=" & hValue &
  "; bh=" & bodyHash &
  "; b="

proc signMessage*(key: DkimKey, rawMessage: string,
                  signHeaders: seq[string] = DefaultSignHeaders): string =
  ## Sign a complete raw RFC 5322 message per RFC 6376 and return it with a
  ## DKIM-Signature header inserted after the existing headers.
  ##
  ## Correctness notes:
  ## - bh= is computed over the canonicalized (not raw) body.
  ## - Signed headers are taken from the original byte stream; repeated
  ##   instances are consumed bottom-up.
  ## - The data hash covers canonicalized selected headers plus the signature
  ##   header with an empty b= and NO trailing CRLF (RFC 6376 §3.7).
  let sep = rawMessage.find("\r\n\r\n")
  if sep < 0:
    return rawMessage  # no headers found, return as-is

  let headerBlock = rawMessage[0 ..< sep]
  let bodyPart = rawMessage[sep + 4 .. ^1]
  let fields = splitRawHeaders(headerBlock)

  # Body hash over the canonicalized body
  let canonBody = if key.bodyCanon == "relaxed": relaxedCanonBody(bodyPart)
                  else: simpleCanonBody(bodyPart)
  let bodyHash = sha256(canonBody)
  if bodyHash.len != 32:
    raise newException(IOError, "SHA-256 hashing failed")
  let bhB64 = encode(bodyHash)

  # Canonicalized selected headers, bottom-up instances per RFC 6376 §5.4
  let selected = selectSignedHeaders(fields, signHeaders)
  var dataToSign = ""
  for i in selected:
    if key.headerCanon == "relaxed":
      dataToSign.add(relaxedHeaderValue(fields[i]) & "\r\n")
    else:
      dataToSign.add(canonHeaderSimple(fields[i]))

  # Signature header placeholder (empty b=), without trailing CRLF
  let tags = sigTagString(key, signHeaders.join(":"), bhB64)
  if key.headerCanon == "relaxed":
    dataToSign.add("dkim-signature:" & relaxWsp(tags))
  else:
    dataToSign.add("DKIM-Signature: " & tags)

  let sig = rsaSign(dataToSign, cast[EVP_PKEY](key.privateKey))
  if sig.len == 0:
    raise newException(IOError, "RSA signing failed")

  let sigHeader = "DKIM-Signature: " & tags & encode(sig)

  # Insert DKIM-Signature after the last header
  result = headerBlock & "\r\n" & sigHeader & "\r\n\r\n" & bodyPart

# ── Verification (RFC 6376 §3.7, §6.1) ───────────────────────────────────────

type
  DkimSigTags* = object
    version*: string
    algo*: string
    headerCanon*: string
    bodyCanon*: string
    domain*: string
    selector*: string
    signedHeaders*: seq[string]
    bodyHashB64*: string
    sigB64*: string
    bodyLength*: int     # l= tag, -1 = absent
    timestamp*: int64    # t= tag, 0 = absent
    expiry*: int64       # x= tag, 0 = absent
    query*: string       # q= tag, "" = default dns/txt

proc parseDkimSigTags*(value: string): tuple[ok: bool, tags: DkimSigTags, err: string] =
  ## Parse a DKIM-Signature header value into its tags. The b= signature
  ## value is base64 (no semicolons), so splitting on ";" is safe.
  var tags = DkimSigTags(headerCanon: "simple", bodyCanon: "simple", bodyLength: -1)
  for part in value.split(';'):
    let kv = part.strip().split('=', 1)
    if kv.len != 2: continue
    let key = kv[0].strip().toLowerAscii
    let val = kv[1].strip()
    case key
    of "v": tags.version = val
    of "a": tags.algo = val.toLowerAscii
    of "c":
      let parts = val.split('/')
      tags.headerCanon = parts[0].strip().toLowerAscii
      tags.bodyCanon = if parts.len > 1: parts[^1].strip().toLowerAscii
                       else: parts[0].strip().toLowerAscii
    of "d": tags.domain = val.toLowerAscii
    of "s": tags.selector = val
    of "h":
      tags.signedHeaders = @[]
      for n in val.split(':'):
        let hn = n.strip()
        if hn.len > 0: tags.signedHeaders.add(hn)
    of "bh": tags.bodyHashB64 = val.replace(" ", "").replace("\t", "")
    of "b": tags.sigB64 = val.replace(" ", "").replace("\t", "")
    of "l":
      try: tags.bodyLength = parseInt(val)
      except ValueError: return (false, tags, "invalid l= tag")
    of "t":
      try: tags.timestamp = parseBiggestInt(val)
      except ValueError: return (false, tags, "invalid t= tag")
    of "x":
      try: tags.expiry = parseBiggestInt(val)
      except ValueError: return (false, tags, "invalid x= tag")
    of "q": tags.query = val.toLowerAscii
    else: discard
  if tags.version != "1":
    return (false, tags, "unsupported version: " & tags.version)
  if tags.algo != "rsa-sha256":
    return (false, tags, "unsupported algorithm: " & tags.algo)
  if tags.headerCanon notin ["simple", "relaxed"]:
    return (false, tags, "unsupported header canonicalization: " & tags.headerCanon)
  if tags.bodyCanon notin ["simple", "relaxed"]:
    return (false, tags, "unsupported body canonicalization: " & tags.bodyCanon)
  if tags.query.len > 0 and tags.query != "dns/txt":
    return (false, tags, "unsupported query method: " & tags.query)
  if tags.domain.len == 0 or tags.selector.len == 0:
    return (false, tags, "missing d= or s=")
  if tags.bodyHashB64.len == 0:
    return (false, tags, "missing bh=")
  if tags.sigB64.len == 0:
    return (false, tags, "missing b=")
  if tags.signedHeaders.len == 0:
    return (false, tags, "missing h=")
  if tags.expiry > 0 and getTime().toUnix() > tags.expiry:
    return (false, tags, "signature expired")
  (true, tags, "")

proc selectDkimKeyRecord*(records: seq[string]): string =
  ## Pick the `v=DKIM1` key record out of a set of TXT strings.
  for r in records:
    if r.strip().toLowerAscii.startsWith("v=dkim1"):
      return r
  ""

proc parseDkimKeyRecord*(record: string): tuple[ok: bool, pubkeyDer: string, err: string] =
  ## Extract the DER public key from a `v=DKIM1` TXT record.
  var keyType = "rsa"
  var pubB64 = ""
  for part in record.split(';'):
    let kv = part.strip().split('=', 1)
    if kv.len != 2: continue
    case kv[0].strip().toLowerAscii
    of "k": keyType = kv[1].strip().toLowerAscii
    of "p": pubB64 = kv[1].strip().replace(" ", "").replace("\t", "")
    else: discard
  if keyType != "rsa":
    return (false, "", "unsupported key type: " & keyType)
  if pubB64.len == 0:
    return (false, "", "key revoked (empty p=)")
  try:
    let der = decode(pubB64)
    if der.len == 0:
      return (false, "", "empty public key")
    (true, der, "")
  except CatchableError:
    (false, "", "invalid base64 in p=")

proc loadPublicKeyDer*(der: string): EVP_PKEY =
  ## Load a DER SubjectPublicKeyInfo into an EVP_PKEY. Caller must free with
  ## EVP_PKEY_free. Returns nil on failure.
  if der.len == 0: return nil
  var p = unsafeAddr der[0]
  result = d2i_PUBKEY(nil, cast[ptr pointer](addr p), der.len.clong)

proc rsaVerify*(data, sigBytes: string, pkey: EVP_PKEY): bool =
  ## Verify RSA-SHA256 `sigBytes` over `data`. Returns false on any failure.
  if pkey == nil or sigBytes.len == 0: return false
  let ctx = EVP_MD_CTX_new()
  if ctx == nil: return false
  try:
    if EVP_DigestVerifyInit(ctx, nil, EVP_sha256(), nil, pkey) != 1:
      return false
    if data.len > 0:
      if EVP_DigestUpdate(ctx, unsafeAddr data[0], data.len.csize_t) != 1:
        return false
    else:
      if EVP_DigestUpdate(ctx, nil, 0.csize_t) != 1:
        return false
    EVP_DigestVerifyFinal(ctx, unsafeAddr sigBytes[0],
                           sigBytes.len.csize_t) == 1
  finally:
    EVP_MD_CTX_free(ctx)

proc stripSigValue(raw: string): string =
  ## Remove the b= signature value from a raw DKIM-Signature field, keeping
  ## every other byte intact (RFC 6376 §3.7: verify the header with an
  ## empty b= value). Tag values are base64 (no semicolons), so splitting
  ## the field on ";" locates tag boundaries exactly.
  var pos = 0
  while true:
    let semi = raw.find(';', pos)
    let segEnd = if semi < 0: raw.len else: semi
    let eq = raw.find('=', pos)
    if eq >= 0 and eq < segEnd and raw[pos ..< eq].strip().toLowerAscii == "b":
      return raw[0 ..< eq + 1]
    if semi < 0:
      return raw
    pos = semi + 1

proc verifyDkimSignature*(fields: seq[RawHeaderField], sigIdx: int, body: string,
                          pubkeyDer: string): tuple[valid: bool, domain, err: string] =
  ## Verify the DKIM-Signature at `fields[sigIdx]` against `body` using the
  ## DER public key. Reconstructs the signed data per RFC 6376 §3.7: selected
  ## headers bottom-up (excluding the other signatures) plus the signature
  ## header itself with an empty b= and no trailing CRLF.
  if sigIdx < 0 or sigIdx > fields.high:
    return (false, "", "signature index out of range")
  let (ok, tags, perr) = parseDkimSigTags(fields[sigIdx].raw.split(":", 1)[^1])
  if not ok:
    return (false, "", perr)
  # Body hash over the canonicalized body (l= truncates to a prefix).
  let canonBody = if tags.bodyCanon == "relaxed": relaxedCanonBody(body)
                  else: simpleCanonBody(body)
  let hashedBody = if tags.bodyLength >= 0: canonBody[0 ..< min(tags.bodyLength, canonBody.len)]
                   else: canonBody
  let bh = sha256(hashedBody)
  var claimedBh: string
  try:
    claimedBh = decode(tags.bodyHashB64)
  except CatchableError:
    return (false, tags.domain, "invalid bh encoding")
  if claimedBh != bh:
    return (false, tags.domain, "body hash mismatch")
  # Signed headers: bottom-up instances, ignoring the other signatures. The
  # signature under test is appended last with an empty b=.
  var pool: seq[RawHeaderField]
  for i, f in fields:
    if i != sigIdx and f.name.toLowerAscii != "dkim-signature":
      pool.add(f)
  let selected = selectSignedHeaders(pool, tags.signedHeaders)
  var data = ""
  # Map pool indexes back: selectSignedHeaders returns pool positions, and
  # pool preserves field order, so index directly into pool.
  for i in selected:
    if tags.headerCanon == "relaxed":
      data.add(relaxedHeaderValue(pool[i]) & "\r\n")
    else:
      data.add(canonHeaderSimple(pool[i]))
  let placeholder = stripSigValue(fields[sigIdx].raw)
  # No trailing CRLF on the signature header (RFC 6376 §3.7), matching the
  # signer which appends the placeholder without one.
  if tags.headerCanon == "relaxed":
    data.add(relaxedHeaderValue(RawHeaderField(name: "dkim-signature", raw: placeholder)))
  else:
    data.add(placeholder)
  var sigBytes: string
  try:
    sigBytes = decode(tags.sigB64)
  except CatchableError:
    return (false, tags.domain, "invalid b encoding")
  let pkey = loadPublicKeyDer(pubkeyDer)
  if pkey == nil:
    return (false, tags.domain, "invalid public key")
  try:
    if rsaVerify(data, sigBytes, pkey):
      (true, tags.domain, "")
    else:
      (false, tags.domain, "signature mismatch")
  finally:
    EVP_PKEY_free(pkey)

proc destroy*(key: DkimKey) =
  ## Free the private key resources.
  if key.privateKey != nil:
    EVP_PKEY_free(cast[EVP_PKEY](key.privateKey))
    key.privateKey = nil
