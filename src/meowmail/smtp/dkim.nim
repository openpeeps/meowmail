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
  RawHeaderField = object
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

proc destroy*(key: DkimKey) =
  ## Free the private key resources.
  if key.privateKey != nil:
    EVP_PKEY_free(cast[EVP_PKEY](key.privateKey))
    key.privateKey = nil
