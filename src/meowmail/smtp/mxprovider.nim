# MeowMail - A high-performance SMTP based on powpow
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

import std/[strutils, sequtils, osproc, algorithm]
import ./auth/[spf_preflight, dmarc_preflight]

## This module implements an MX delivery provider for MeowMail that delivers
## messages directly to recipient domains by resolving their MX records and
## performing SMTP transactions using powpow's non-blocking TCP/TLS client.
## It includes configuration options for timeouts, STARTTLS requirements,
## and debugging.
##
## The provider is designed to be suitable for production use but can also be
## used for testing with local domains and custom MX records.
##
## Each delivery runs in a spawned thread with its own powpow event loop; the
## SMTP dialog is driven by the loop until a final delivery decision is made.

import powpow
import ./smtpdelivery

{.warning: "MXProvider is still in early development and may have limitations and edge cases that are not yet handled. Don't use this in production".}

type
  MXHost* = object
    ## Represents an MX host with its preference value and hostname.
    preference*: int
      ## The preference value of the MX host, where lower values indicate higher priority.
    host*: string
      ## The hostname of the MX server to which mail should be delivered.

  DmarcRecordLookup* = proc(domain: string): string {.gcsafe.}

  MXProviderConfig* = object
    heloName*: string = "localhost"
      ## The HELO/EHLO name to use when connecting to MX hosts.
      ## This can be configured to improve compatibility with
      ## certain mail servers that expect a valid domain name
    connectTimeoutMs*: int = 7000
      ## The timeout in milliseconds for establishing a connection
      ## to an MX host.
    commandTimeoutMs*: int = 10000
      ## The timeout in milliseconds for waiting for responses
      ## to SMTP commands during the delivery process.
    requireStartTls*: bool
      ## Whether to require STARTTLS support from MX hosts. If set to true,
      ## the provider will only attempt delivery to MX hosts that advertise
      ## STARTTLS in their EHLO response and will upgrade the connection to
      ## TLS before sending mail.
    maxMxHostsPerDomain*: int = 5
      ## The maximum number of MX hosts to consider for each
      ## recipient domain.
    debug*: bool = false
      ## Whether to enable debug logging for the MX provider.

    # SPF preflight (optional)
    enforceSpf*: bool = false
    spfServer*: pointer = nil
    spfClientIp*: string = "127.0.0.1"
    spfHeloDomain*: string = "localhost"

    # DMARC preflight (optional)
    enforceDmarc*: bool = false
    dmarcLookup*: DmarcRecordLookup = nil

proc initMXProviderConfig*(
  heloName: string,
  connectTimeoutMs: int = 7000,
  commandTimeoutMs: int = 10000,
  requireStartTls: bool = false,
  maxMxHostsPerDomain: int = 5,
  debug: bool = false,
  enforceSpf: bool = false,
  spfServer: pointer = nil,
  spfClientIp: string = "127.0.0.1",
  spfHeloDomain: string = "localhost",
  enforceDmarc: bool = false,
  dmarcLookup: DmarcRecordLookup = nil
): MXProviderConfig =
  ## Initializes an `MXProviderConfig` object with the specified parameters.
  MXProviderConfig(
    heloName: heloName,
    connectTimeoutMs: connectTimeoutMs,
    commandTimeoutMs: commandTimeoutMs,
    requireStartTls: requireStartTls,
    maxMxHostsPerDomain: maxMxHostsPerDomain,
    debug: debug,
    enforceSpf: enforceSpf,
    spfServer: spfServer,
    spfClientIp: spfClientIp,
    spfHeloDomain: spfHeloDomain,
    enforceDmarc: enforceDmarc,
    dmarcLookup: dmarcLookup
  )

proc extractMailFromDomain(path: string): string =
  # Extracts the domain part from the MAIL FROM address. This is used for DMARC checks.
  var v = path.strip()
  if v.len == 0: return
  if v[0] == '<' and v[^1] == '>':
    v = v[1..^2].strip()
  let atPos = v.rfind('@')
  if atPos < 0 or atPos == v.high: return
  result = v[atPos + 1 .. ^1].strip().toLowerAscii()

proc runSpfPreflight(req: DeliveryRequest, cfg: MXProviderConfig): DeliveryDecision =
  spf_preflight.runSpfPreflight(
    cfg.enforceSpf, cfg.spfServer, cfg.spfClientIp, cfg.spfHeloDomain, req.mailFrom
  )

proc runDmarcPreflight(req: DeliveryRequest, cfg: MXProviderConfig): DeliveryDecision =
  if not cfg.enforceDmarc: return ddOk
  if cfg.dmarcLookup.isNil: return ddTempFail

  let fromDomain = extractMailFromDomain(req.mailFrom)
  let rec = if fromDomain.len == 0: "" else: cfg.dmarcLookup(fromDomain)
  dmarc_preflight.runDmarcPreflight(cfg.enforceDmarc, fromDomain, rec)

proc extractRcptDomain(rcpt: string): string =
  # Extracts the domain part from a recipient email address.
  var v = rcpt.strip()
  if v.len == 0: return

  # support "<user@domain>"
  if v[0] == '<' and v[^1] == '>':
    v = v[1..^2].strip()

  let atPos = v.rfind('@')
  if atPos < 0 or atPos == v.high: return
  result = v[atPos + 1 .. ^1].strip().toLowerAscii()

proc parseMxLine(line: string): MXHost =
  # dig +short MX google.com
  let parts = line.splitWhitespace()
  if parts.len < 2:
    return MXHost(preference: high(int))

  var host = parts[1].strip()
  if host.endsWith("."):
    host.setLen(host.len - 1)

  var pref = high(int)
  try:
    pref = parseInt(parts[0])
  except ValueError:
    pref = high(int)

  result.preference = pref
  result.host = host.toLowerAscii()

proc resolveMxHosts*(domain: string, maxHosts = 5): seq[MXHost] =
  ## Temporary resolver via `dig` (available on macOS by default).
  ## Later replace with c-ares / native DNS.
  let (outp, exitCode) = execCmdEx("dig +short MX " & domain)
  if exitCode == 0:
    for raw in outp.splitLines():
      let line = raw.strip()
      if line.len == 0: continue
      let mx = parseMxLine(line)
      if mx.host.len > 0:
        result.add(mx)

  result.sort(proc(a, b: MXHost): int = cmp(a.preference, b.preference))

  # RFC behavior: if no MX, try the domain itself.
  if result.len == 0 and domain.len > 0:
    result.add(MXHost(preference: 0, host: domain.toLowerAscii()))

  if result.len > maxHosts and maxHosts > 0:
    result.setLen(maxHosts)

type
  MxTxnState = enum
    msBanner, msEhlo, msHelo, msStartTls, msMailFrom,
    msRcpt, msDataCmd, msDataBody, msDone

  MxTxn = ref object
    loop: Loop
      # The powpow event loop driving this transaction.
    conn: Connection
      # The SMTP connection to the MX host.
    tlsCtx: SslContext
      # Client-side TLS context, used when STARTTLS is required.
    req: DeliveryRequest
      # The delivery request being processed.
    cfg: MXProviderConfig
      # The configuration settings for the MX provider.
    state: MxTxnState
      # The current state of the SMTP transaction.
    done: bool
      # Whether the transaction is complete and a delivery decision has been made.
    decision: DeliveryDecision
      # The delivery decision for this transaction, set when
      # the transaction is complete.
    inbuf: string
      # A buffer for accumulating incoming data until complete lines arrive.
    replyCode: int
      # The SMTP reply code from the server, used to guide the transaction flow.
    replyLines: seq[string]
      # The lines of the SMTP reply, used for processing multi-line replies
      # and extracting capabilities.
    usedHeloFallback: bool
      # Whether a HELO fallback was already attempted after an EHLO failure.
    sawStartTlsCap: bool
      # Whether the STARTTLS capability was advertised in the EHLO response.
    tlsEstablished: bool
      # Whether the connection was already upgraded to TLS (avoids re-offering
      # STARTTLS after the re-EHLO).
    rcptIdx: int
      # The index of the current recipient being processed.
    acceptedRcpt: int
      # The count of recipients accepted by the server so far.
    sawTempRcpt: bool
      # Whether any recipients were temporarily rejected.
    sawPermRcpt: bool
      # Whether any recipients were permanently rejected.

proc classifyReply(code: int): DeliveryDecision =
  if code >= 500 and code < 600: return ddPermFail
  if code >= 400 and code < 500: return ddTempFail
  ddTempFail

proc setDone(txn: MxTxn, d: DeliveryDecision): DeliveryDecision {.discardable.} =
  if txn.done: return
  txn.done = true
  txn.decision = d
  txn.state = msDone
  if txn.conn != nil:
    txn.conn.close()
  if txn.loop != nil:
    txn.loop.stop()
  txn.decision

proc smtpWriteLine(txn: MxTxn, line: string): bool =
  if txn.cfg.debug:
    echo "[mx] > ", line
  if txn.conn == nil: return false
  let s = line & "\r\n"
  result = txn.conn.send(s) == s.len

proc envelopePath(path: string): string =
  var a = path.strip()
  if a.len == 0: return "<>"
  if a[0] == '<' and a[^1] == '>': return a
  "<" & a & ">"

proc sendDataBlock(txn: MxTxn, data: string): bool =
  var normalized = data.replace("\r\n", "\n").replace("\r", "\n")
  for line in normalized.split('\n'):
    let outLine = if line.len > 0 and line[0] == '.': "." & line else: line
    let wire = outLine & "\r\n"
    if txn.conn == nil or txn.conn.send(wire) != wire.len:
      return false
  let dot = ".\r\n"
  txn.conn != nil and txn.conn.send(dot) == dot.len

proc updateStartTlsCapability(txn: MxTxn) =
  txn.sawStartTlsCap = false
  for l in txn.replyLines:
    if l.len >= 4 and l[0].isDigit and l[1].isDigit and l[2].isDigit:
      let cap = l[4 .. ^1].strip().toUpperAscii()
      if cap.startsWith("STARTTLS"):
        txn.sawStartTlsCap = true
        return

proc sendNextRcpt(txn: MxTxn): bool =
  if txn.rcptIdx >= txn.req.rcptTo.len:
    return false
  let ok = smtpWriteLine(txn, "RCPT TO:" & envelopePath(txn.req.rcptTo[txn.rcptIdx]))
  if ok:
    txn.state = msRcpt
  ok

proc startTlsUpgrade(txn: MxTxn) =
  # Upgrade the connection to TLS (STARTTLS). The queued EHLO is flushed once
  # the handshake completes, then the transaction resumes from the msEhlo
  # state with tlsEstablished set.
  if txn.tlsCtx == nil:
    setDone(txn, ddTempFail)
    return
  txn.tlsEstablished = true
  try:
    txn.conn.wrapTls(txn.tlsCtx)
  except SslError:
    setDone(txn, ddTempFail)
    return
  let helo = (if txn.cfg.heloName.len > 0: txn.cfg.heloName else: "localhost")
  if not smtpWriteLine(txn, "EHLO " & helo):
    setDone(txn, ddTempFail)
    return
  txn.state = msEhlo

proc handleReply(txn: MxTxn, code: int): DeliveryDecision {.discardable.} =
  case txn.state
  of msBanner:
    if code div 100 == 2:
      let helo = (if txn.cfg.heloName.len > 0: txn.cfg.heloName else: "localhost")
      if not smtpWriteLine(txn, "EHLO " & helo):
        return setDone(txn, ddTempFail)
      txn.state = msEhlo
    else:
      setDone(txn, classifyReply(code))

  of msEhlo:
    if code div 100 == 2:
      updateStartTlsCapability(txn)
      if txn.cfg.requireStartTls and not txn.tlsEstablished:
        if not txn.sawStartTlsCap:
          return setDone(txn, ddPermFail)
        if not smtpWriteLine(txn, "STARTTLS"):
          return setDone(txn, ddTempFail)
        txn.state = msStartTls
      else:
        if not smtpWriteLine(txn, "MAIL FROM:" & envelopePath(txn.req.mailFrom)):
          return setDone(txn, ddTempFail)
        txn.state = msMailFrom
    elif not txn.usedHeloFallback:
      txn.usedHeloFallback = true
      let helo = (if txn.cfg.heloName.len > 0: txn.cfg.heloName else: "localhost")
      if not smtpWriteLine(txn, "HELO " & helo):
        return setDone(txn, ddTempFail)
      txn.state = msHelo
    else:
      setDone(txn, classifyReply(code))

  of msHelo:
    if code div 100 == 2:
      if txn.cfg.requireStartTls:
        return setDone(txn, ddPermFail)
      if not smtpWriteLine(txn, "MAIL FROM:" & envelopePath(txn.req.mailFrom)):
        return setDone(txn, ddTempFail)
      txn.state = msMailFrom
    else:
      setDone(txn, classifyReply(code))

  of msStartTls:
    # STARTTLS accepted: upgrade the connection to TLS and re-EHLO.
    if code div 100 == 2:
      startTlsUpgrade(txn)
    else:
      setDone(txn, classifyReply(code))

  of msMailFrom:
    if code div 100 != 2:
      return setDone(txn, classifyReply(code))
    if txn.req.rcptTo.len == 0:
      return setDone(txn, ddPermFail)
    txn.rcptIdx = 0
    if not sendNextRcpt(txn):
      return setDone(txn, ddPermFail)

  of msRcpt:
    case code div 100
    of 2: inc txn.acceptedRcpt
    of 4: txn.sawTempRcpt = true
    of 5: txn.sawPermRcpt = true
    else: txn.sawTempRcpt = true

    inc txn.rcptIdx
    if txn.rcptIdx < txn.req.rcptTo.len:
      if not sendNextRcpt(txn):
        return setDone(txn, ddTempFail)
    else:
      if txn.acceptedRcpt == 0:
        if txn.sawPermRcpt: return setDone(txn, ddPermFail)
        return setDone(txn, ddTempFail)
      if not smtpWriteLine(txn, "DATA"):
        return setDone(txn, ddTempFail)
      txn.state = msDataCmd

  of msDataCmd:
    if code != 354:
      return setDone(txn, classifyReply(code))
    if not sendDataBlock(txn, txn.req.data):
      return setDone(txn, ddTempFail)
    txn.state = msDataBody

  of msDataBody:
    if code div 100 == 2:
      discard smtpWriteLine(txn, "QUIT")
      setDone(txn, ddOk)
    else:
      setDone(txn, classifyReply(code))

  of msDone:
    discard

proc processReplyLine(txn: MxTxn, line: string): DeliveryDecision {.discardable.} =
  if txn.cfg.debug:
    echo "[mx] < ", line

  if line.len < 3:
    return setDone(txn, ddTempFail)

  var code = 0
  try:
    code = parseInt(line[0..2])
  except ValueError:
    return setDone(txn, ddTempFail)

  let sep = if line.len > 3: line[3] else: ' '
  if txn.replyCode == 0:
    txn.replyCode = code
  txn.replyLines.add(line)

  if sep == '-':
    return txn.decision

  # FINAL line of multiline reply:
  let finalCode = txn.replyCode
  let savedLines = txn.replyLines   # keep lines for handler (EHLO capability parsing)
  txn.replyCode = 0
  txn.replyLines = savedLines
  let d = handleReply(txn, finalCode)

  # clear only after handler consumed them
  txn.replyLines.setLen(0)
  d

proc onMxData(conn: Connection, data: openArray[byte]) =
  let txn = cast[MxTxn](conn.data)
  if txn == nil or txn.done: return

  txn.inbuf.add(cast[string](@data))

  while true:
    let idx = txn.inbuf.find("\r\n")
    if idx < 0: break
    let line = txn.inbuf[0 ..< idx]
    if idx + 2 <= txn.inbuf.high:
      txn.inbuf = txn.inbuf[idx + 2 .. ^1]
    else:
      txn.inbuf.setLen(0)
    processReplyLine(txn, line)
    if txn.done: break

proc onMxClose(conn: Connection) =
  let txn = cast[MxTxn](conn.data)
  if txn != nil and not txn.done:
    setDone(txn, ddTempFail)

proc mxLog(cfg: MXProviderConfig, msg: string) =
  if cfg.debug:
    echo "[mx] ", msg

proc deliverToMxHost(req: DeliveryRequest,
        mxHost: MXHost, cfg: MXProviderConfig): DeliveryDecision {.gcsafe.} =
  # Delivers the email to a specific MX host by performing an SMTP
  # transaction using a dedicated powpow event loop.
  #
  # The powpow client API is not (statically) GC-safe, but the transaction
  # runs entirely in a dedicated delivery thread with its own event loop and
  # never touches shared mutable state, so the cast boundary is sound.
  {.cast(gcsafe).}:
    mxLog(cfg, "try host=" & mxHost.host & " pref=" & $mxHost.preference)
    let loop = newLoop()

    var txn = MxTxn(
      loop: loop,
      req: req,
      cfg: cfg,
      decision: ddTempFail
    )

    if cfg.requireStartTls:
      try:
        txn.tlsCtx = newClientTlsContext()
      except SslError:
        loop.close()
        return ddTempFail

    # Total transaction timeout (connection + entire SMTP dialog) to ensure we
    # don't get stuck on slow/unresponsive hosts.
    discard loop.addTimer(max(5000, cfg.connectTimeoutMs + cfg.commandTimeoutMs * 8)) do (id: int):
      setDone(txn, ddTempFail)

    try:
      loop.connect(mxHost.host, 25,
        onConnect = proc(conn: Connection) =
          txn.conn = conn
          conn.data = cast[pointer](txn)
          # The banner is sent by the server unprompted.
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          onMxData(conn, data)
        ,
        onClose = proc(conn: Connection) =
          onMxClose(conn)
        ,
      )
    except NetError:
      loop.close()
      return ddTempFail

    loop.run()

    if not txn.done:
      txn.decision = ddTempFail

    loop.close()
    result = txn.decision

proc deliverToDomain(req: DeliveryRequest, domain: string,
                cfg: MXProviderConfig): DeliveryDecision =
  # Delivers the email to a domain by resolving its MX hosts and attempting
  # delivery to each until one succeeds or all fail.
  let mxHosts = resolveMxHosts(domain, cfg.maxMxHostsPerDomain)
  if mxHosts.len == 0:
    return ddTempFail

  var sawTempFail = false
  var sawPermFail = false
  for mx in mxHosts:
    let d = deliverToMxHost(req, mx, cfg)
    case d
    of ddOk:
      return ddOk
    of ddPermFail:
      sawPermFail = true
    of ddTempFail:
      sawTempFail = true

  if sawTempFail: return ddTempFail
  if sawPermFail: return ddPermFail
  ddTempFail

proc newMXProvider*(cfg = MXProviderConfig(), performSpfPreflight = true, performDmarcPreflight = true): DeliveryProvider =
  ## Creates a new MX delivery provider with the specified configuration. The returned
  ## provider will attempt to deliver messages directly to recipient domains by resolving
  ## their MX records and performing SMTP transactions.
  result = proc(req: DeliveryRequest): DeliveryDecision {.gcsafe.} =
    if req.rcptTo.len == 0:
      return ddPermFail

    # when enabled, perform SPF and DMARC preflight checks before attempting
    # delivery to MX hosts.
    if performSpfPreflight:
      let spfDecision = runSpfPreflight(req, cfg)
      if spfDecision != ddOk:
        return spfDecision

    if performDmarcPreflight:
      let dmarcDecision = runDmarcPreflight(req, cfg)
      if dmarcDecision != ddOk:
        return dmarcDecision

    # Validate recipients and collect unique domains.
    var domains: seq[string] = @[]
    for rcpt in req.rcptTo:
      let domain = extractRcptDomain(rcpt)
      if domain.len == 0:
        return ddPermFail
      if domain notin domains:
        domains.add(domain)

    # Deliver once per domain with only that domain's recipients.
    for domain in domains:
      var domainReq = req
      domainReq.rcptTo = req.rcptTo.filterIt(extractRcptDomain(it) == domain)

      let d = deliverToDomain(domainReq, domain, cfg)
      if d != ddOk:
        return d
    ddOk
