## MeowMail — DKIM signing for outbound messages (RFC 6376).
##
## Signs the From, To, Subject, Date, and Message-ID headers using
## RSA-SHA256 and appends a DKIM-Signature header.

import std/[strutils, times, base64, os]
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

proc BIO_new_mem_buf(data: pointer, len: cint): BIO {.importc, header: "<openssl/bio.h>".}
proc BIO_free(bio: BIO): cint {.importc, header: "<openssl/bio.h>".}

proc PEM_read_bio_PrivateKey(bio: BIO, x: pointer, cb: pointer, u: pointer): EVP_PKEY {.importc, header: "<openssl/pem.h>".}
proc EVP_PKEY_free(pkey: EVP_PKEY) {.importc, header: "<openssl/evp.h>".}

# ── Helpers ───────────────────────────────────────────────────────────────────

proc sha256(data: string): string =
  ## Compute SHA-256 hash of data, return raw bytes as string.
  let ctx = EVP_MD_CTX_new()
  if ctx == nil: return ""
  discard EVP_DigestInit(ctx, EVP_sha256())
  discard EVP_DigestUpdate(ctx, unsafeAddr data[0], data.len.csize_t)
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
  discard EVP_SignUpdate(ctx, unsafeAddr data[0], data.len.csize_t)
  var sig: array[256, byte]  # max RSA-2048 signature size
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

proc relaxedHeaderCanon(headers: seq[Header], names: seq[string]): string =
  ## Produce the relaxed-canonical form of the signed headers (RFC 6376 §5.4.2).
  ## Headers are lowercased, whitespace folded, and trimmed.
  var lowerNames: seq[string]
  for n in names:
    lowerNames.add(n.toLowerAscii)
  for h in headers:
    let hName = h.name.toLowerAscii
    if hName in lowerNames:
      let val = h.value.strip().toLowerAscii
      result.add(hName & ":" & val & "\r\n")

proc simpleHeaderCanon(headers: seq[Header], names: seq[string]): string =
  ## Produce the simple-canonical form of the signed headers (RFC 6376 §5.4.1).
  var lowerNames: seq[string]
  for n in names:
    lowerNames.add(n.toLowerAscii)
  for h in headers:
    let hName = h.name.toLowerAscii
    if hName in lowerNames:
      result.add(h.name & ":" & h.value & "\r\n")

proc relaxedBodyCanon(body: string): string =
  ## Produce the relaxed-canonical form of the body (RFC 6376 §5.3.2).
  ## Trailing whitespace removed, empty lines collapsed.
  var lines = body.split("\r\n")
  # Remove trailing empty lines
  while lines.len > 0 and lines[^1].strip().len == 0:
    lines.del(lines.len - 1)
  for line in lines:
    result.add(line.strip(trailing = true) & "\r\n")
  if result.len == 0:
    result = "\r\n"

proc simpleBodyCanon(body: string): string =
  ## Produce the simple-canonical form of the body (RFC 6376 §5.3.1).
  body

# ── Public API ────────────────────────────────────────────────────────────────

proc newDkimKey*(domain, selector, pemKeyFile: string): DkimKey =
  ## Load a DKIM private key from a PEM file.
  let pemData = readFile(pemKeyFile)
  let pkey = loadPrivateKey(pemData)
  if pkey == nil:
    raise newException(IOError, "Failed to load DKIM private key from " & pemKeyFile)
  result = DkimKey(
    domain: domain,
    selector: selector,
    privateKey: pkey,
    bodyLength: 0,
    headerCanon: "simple",
    bodyCanon: "simple",
  )

proc signDkim*(key: DkimKey, headers: seq[Header], body: string,
               signHeaders: seq[string] = @["from", "to", "subject", "date", "message-id"]): DkimSignature =
  ## Sign a message's headers and body, producing a DKIM-Signature.
  let bodyHash = sha256(body)
  if bodyHash.len == 0:
    raise newException(IOError, "SHA-256 hashing failed")

  # Build the signed headers string for the DKIM-Signature h= tag
  var hValue = signHeaders.join(":")

  # Compute the data to sign: header canonicalization + dkim-signature placeholder
  let sigName = "dkim-signature"
  var dataToSign: string
  if key.headerCanon == "relaxed":
    dataToSign = relaxedHeaderCanon(headers, signHeaders)
  else:
    dataToSign = simpleHeaderCanon(headers, signHeaders)
  # Add the DKIM-Signature header with empty b= tag
  dataToSign.add(sigName & ": v=1; a=rsa-sha256; d=" & key.domain &
                  "; s=" & key.selector & "; c=" & key.headerCanon & "/" & key.bodyCanon &
                  "; h=" & hValue & "; bh=" & encode(bodyHash) &
                  "; b=;\r\n")

  # Sign the data
  let sig = rsaSign(dataToSign, key.privateKey)
  if sig.len == 0:
    raise newException(IOError, "RSA signing failed")

  result = DkimSignature(
    headerCanon: "simple",
    bodyCanon: "simple",
    domain: key.domain,
    selector: key.selector,
    signedHeaders: signHeaders,
    bodyHash: encode(bodyHash),
    signature: encode(sig),
  )

proc renderDkimSignature*(sig: DkimSignature): string =
  ## Render the DKIM-Signature header value.
  result = "DKIM-Signature: v=1; a=rsa-sha256; d=" & sig.domain &
           "; s=" & sig.selector & "; c=" & sig.headerCanon & "/" & sig.bodyCanon &
           "; h=" & sig.signedHeaders.join(":") &
           "; bh=" & sig.bodyHash & "; b=" & sig.signature

proc signMessage*(key: DkimKey, rawMessage: string): string =
  ## Sign a complete raw RFC 5322 message. Returns the message with
  ## DKIM-Signature header appended after the existing headers.
  let sep = rawMessage.find("\r\n\r\n")
  if sep < 0:
    return rawMessage  # no headers found, return as-is

  let headerBlock = rawMessage[0 ..< sep]
  let bodyPart = rawMessage[sep + 4 .. ^1]

  # Parse headers
  var headers: seq[Header]
  for line in headerBlock.split("\r\n"):
    if line.len == 0: continue
    if line[0] in {' ', '\t'}:
      # continuation line — append to previous header value
      if headers.len > 0:
        headers[^1].value &= " " & line.strip()
      continue
    let colon = line.find(':')
    if colon > 0:
      headers.add((name: line[0 ..< colon], value: line[colon + 1 .. ^1].strip()))

  let sig = signDkim(key, headers, bodyPart)
  let sigHeader = renderDkimSignature(sig)

  # Insert DKIM-Signature after the last header
  result = headerBlock & "\r\n" & sigHeader & "\r\n\r\n" & bodyPart

proc destroy*(key: DkimKey) =
  ## Free the private key resources.
  if key.privateKey != nil:
    EVP_PKEY_free(cast[EVP_PKEY](key.privateKey))
    key.privateKey = nil
