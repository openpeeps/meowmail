# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail
import std/[strutils, sequtils, osproc, algorithm]
from std/nativesockets import Domain

import libevent/bindings/[event, buffer, bufferevent]
import ./smtpdelivery

type
  MXHost* = object
    ## Represents an MX host with its preference value and hostname.
    preference*: int
      ## The preference value of the MX host, where lower values indicate higher priority.
    host*: string
      ## The hostname of the MX server to which mail should be delivered.

  MXProviderConfig* = object
    heloName*: string = "localhost"
      ## The HELO/EHLO name to use when connecting to MX hosts. This can be configured
      ## to improve compatibility with certain mail servers that expect a valid domain name.
    connectTimeoutMs*: int = 7000
      ## The timeout in milliseconds for establishing a connection to an MX host. If the connection
    commandTimeoutMs*: int = 10000
      ## The timeout in milliseconds for waiting for responses to SMTP commands during the delivery process.
    requireStartTls*: bool
      ## Whether to require STARTTLS support from MX hosts. If set to true, the provider will only attempt
      ## delivery to MX hosts that advertise STARTTLS in their EHLO response. This can improve security
      ## but may reduce deliverability if some recipient domains do not support STARTTLS.
    maxMxHostsPerDomain*: int = 5
      ## The maximum number of MX hosts to consider for each recipient domain. This limits the number of
      ## connection attempts and can help avoid long delays when a domain has many MX records.
    debug*: bool = false
      ## Whether to enable debug logging for the MX provider. When enabled, the provider will log detailed

proc initMXProviderConfig*(
  heloName: string,
  connectTimeoutMs: int = 7000,
  commandTimeoutMs: int = 10000,
  requireStartTls: bool = false,
  maxMxHostsPerDomain: int = 5,
  debug: bool = false
): MXProviderConfig =
  ## Initializes an `MXProviderConfig` object with the specified parameters
  ## This function provides a convenient way to create a configuration object for
  ## the MX provider with custom settings.
  MXProviderConfig(
    heloName: heloName,
    connectTimeoutMs: connectTimeoutMs,
    commandTimeoutMs: commandTimeoutMs,
    requireStartTls: requireStartTls,
    maxMxHostsPerDomain: maxMxHostsPerDomain

  )

proc extractRcptDomain(rcpt: string): string =
  # Extracts the domain part from a recipient email address. This is used to determine
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
    msBanner, msEhlo, msHelo, msStartTls, msMailFrom, msRcpt, msDataCmd, msDataBody, msDone

  MxTxn = ref object
    base: ptr event_base
    bev: ptr bufferevent
    req: DeliveryRequest
    cfg: MXProviderConfig
    state: MxTxnState
    done: bool
    decision: DeliveryDecision
    inbuf: string
    replyCode: int
    replyLines: seq[string]
    usedHeloFallback: bool
    sawStartTlsCap: bool
    rcptIdx: int
    acceptedRcpt: int
    sawTempRcpt: bool
    sawPermRcpt: bool

proc classifyReply(code: int): DeliveryDecision =
  if code >= 500 and code < 600: return ddPermFail
  if code >= 400 and code < 500: return ddTempFail
  ddTempFail

proc setDone(txn: MxTxn, d: DeliveryDecision): DeliveryDecision {.discardable.} =
  if txn.done: return
  txn.done = true
  txn.decision = d
  txn.state = msDone
  if txn.base != nil:
    discard event_base_loopbreak(txn.base)
  txn.decision

proc smtpWriteLine(txn: MxTxn, line: string): bool =
  if txn.cfg.debug:
    echo "[mx] > ", line
  let s = line & "\r\n"
  bufferevent_write(txn.bev, s.cstring, s.len.csize_t) == 0

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
    if bufferevent_write(txn.bev, wire.cstring, wire.len.csize_t) != 0:
      return false
  bufferevent_write(txn.bev, ".\r\n".cstring, 3.csize_t) == 0

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
      if txn.cfg.requireStartTls:
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
    # STARTTLS command accepted, but TLS socket upgrade is intentionally not wired in this step.
    # Treat as temporary failure so caller can retry another MX / later.
    if code div 100 == 2:
      setDone(txn, ddTempFail)
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

proc onMxRead(bev: ptr bufferevent, ctx: pointer) {.cdecl.} =
  let txn = cast[MxTxn](ctx)
  if txn == nil or txn.done: return

  let input = bufferevent_get_input(bev)
  let n = evbuffer_get_length(input).int
  if n <= 0: return

  var chunk = newString(n)
  let got = evbuffer_remove(input, addr(chunk[0]), n.csize_t)
  if got <= 0: return
  if got < n: chunk.setLen(got)

  txn.inbuf.add(chunk)

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

proc mxLog(cfg: MXProviderConfig, msg: string) =
  if cfg.debug:
    echo "[mx] ", msg

proc onMxEvent(bev: ptr bufferevent, events: cshort, ctx: pointer) {.cdecl.} =
  let txn = cast[MxTxn](ctx)
  if txn == nil or txn.done: return

  if (events and BEV_EVENT_CONNECTED) != 0:
    if txn.cfg.debug: echo "[mx] event: connected"
    return

  if (events and BEV_EVENT_TIMEOUT) != 0:
    if txn.cfg.debug: echo "[mx] event: timeout state=", txn.state
    setDone(txn, ddTempFail)
    return

  if (events and BEV_EVENT_ERROR) != 0:
    if txn.cfg.debug: echo "[mx] event: error state=", txn.state
    setDone(txn, ddTempFail)
    return

  if (events and BEV_EVENT_EOF) != 0:
    if txn.cfg.debug: echo "[mx] event: eof state=", txn.state
    setDone(txn, ddTempFail)

proc deliverToMxHost(req: DeliveryRequest,
        mxHost: MXHost, cfg: MXProviderConfig): DeliveryDecision =
  # Delivers the email to a specific MX host by performing an SMTP transaction using libevent.
  mxLog(cfg, "try host=" & mxHost.host & " pref=" & $mxHost.preference)
  let base = event_base_new()
  if base == nil:
    return ddTempFail

  let bev = bufferevent_socket_new(base, -1, (BEV_OPT_CLOSE_ON_FREE or BEV_OPT_DEFER_CALLBACKS).cint)
  if bev == nil:
    event_base_free(base)
    return ddTempFail

  # apply libevent read/write timeouts
  var rwTv: Timeval
  rwTv.tv_sec = (max(1000, cfg.commandTimeoutMs) div 1000).clong
  rwTv.tv_usec = ((max(1000, cfg.commandTimeoutMs) mod 1000) * 1000).clong
  discard bufferevent_set_timeouts(bev, addr rwTv, addr rwTv)

  var txn = MxTxn(base: base, bev: bev,
            req: req, cfg: cfg, decision: ddTempFail)
  bufferevent_setcb(bev, onMxRead, nil, onMxEvent, cast[pointer](txn))
  discard bufferevent_enable(bev, EV_READ or EV_WRITE)
  # Total transaction timeout (connection + entire SMTP dialog) to ensure we
  # don't get stuck on slow/unresponsive hosts.
  var tv: Timeval
  let totalMs = max(5000, cfg.connectTimeoutMs + cfg.commandTimeoutMs * 8)
  tv.tv_sec = (totalMs div 1000).clong
  tv.tv_usec = ((totalMs mod 1000) * 1000).clong
  discard event_base_loopexit(base, addr tv)

  let rc = bufferevent_socket_connect_hostname(
    bev,
    nil, # no evdns_base yet
    AF_UNSPEC.cint,
    mxHost.host.cstring,
    25.cint
  )
  if rc != 0:
    bufferevent_free(bev)
    event_base_free(base)
    return ddTempFail

  discard event_base_dispatch(base)

  if not txn.done:
    txn.decision = ddTempFail

  bufferevent_free(bev)
  event_base_free(base)
  txn.decision

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

proc newMXProvider*(cfg = MXProviderConfig()): DeliveryProvider =
  ## Creates a new MX delivery provider with the specified configuration. The returned
  ## provider will attempt to deliver messages directly to recipient domains by resolving
  ## their MX records and performing SMTP transactions.
  ## 
  ## This provider is suitable for production use
  ## but can also be used for testing with local domains and custom MX records
  result = proc(req: DeliveryRequest): DeliveryDecision {.gcsafe.} =
    if req.rcptTo.len == 0:
      return ddPermFail

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
