# MeowMail - A high-performance SMTP based on powpow
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

import std/[strutils, sequtils, algorithm]
import ./auth/spf_preflight
import ./auth/dmarc
import ./dkim

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
import ../utils/logger
import ./smtpdelivery

{.warning: "MXProvider is still in early development and may have limitations and edge cases that are not yet handled. Don't use this in production".}

type
  MXHost* = object
    ## Represents an MX host with its preference value and hostname.
    preference*: int
      ## The preference value of the MX host, where lower values indicate higher priority.
    host*: string
      ## The hostname of the MX server to which mail should be delivered.

  DmarcRecordLookup* = proc(domain: string): string {.closure, gcsafe.}

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
    startTlsOpportunistic*: bool = true
      ## Offer STARTTLS whenever the peer advertises it, even when
      ## `requireStartTls` is false. The upgrade is verified (chain against
      ## the system CA store plus hostname check); if it fails, delivery
      ## falls back to plaintext once rather than losing the message.
      ## This protects against passive observers only. Active downgrade
      ## protection needs MTA-STS or DANE (future work).
    tlsSkipDomains*: seq[string] = @[]
      ## MX hostnames that never get a STARTTLS upgrade, in either mode.
      ## Explicit admin exception for broken peers. Matched case-insensitively
      ## with trailing dots ignored.
    maxMxHostsPerDomain*: int = 5
      ## The maximum number of MX hosts to consider for each
      ## recipient domain.
    dnsTimeoutMs*: int = 8000
      ## Upper bound in milliseconds for the blocking DNS wrappers
      ## (`resolveMxOutcome`, `resolveTxtRecords`). Powpow resolves
      ## asynchronously on a throwaway loop; the watchdog stops the loop
      ## so unresolvable domains fail fast instead of stalling the
      ## delivery thread.
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
    dkimLookup*: DkimKeyLookup = nil
      ## Key lookup for outbound DKIM verification. Nil uses powpow's TXT
      ## resolver; tests inject stub records.

proc initMXProviderConfig*(
  heloName: string,
  connectTimeoutMs: int = 7000,
  commandTimeoutMs: int = 10000,
  requireStartTls: bool = false,
  startTlsOpportunistic: bool = true,
  tlsSkipDomains: seq[string] = @[],
  maxMxHostsPerDomain: int = 5,
  dnsTimeoutMs: int = 8000,
  debug: bool = false,
  enforceSpf: bool = false,
  spfServer: pointer = nil,
  spfClientIp: string = "127.0.0.1",
  spfHeloDomain: string = "localhost",
  enforceDmarc: bool = false,
  dmarcLookup: DmarcRecordLookup = nil,
  dkimLookup: DkimKeyLookup = nil
): MXProviderConfig =
  ## Initializes an `MXProviderConfig` object with the specified parameters.
  MXProviderConfig(
    heloName: heloName,
    connectTimeoutMs: connectTimeoutMs,
    commandTimeoutMs: commandTimeoutMs,
    requireStartTls: requireStartTls,
    startTlsOpportunistic: startTlsOpportunistic,
    tlsSkipDomains: tlsSkipDomains,
    maxMxHostsPerDomain: maxMxHostsPerDomain,
    dnsTimeoutMs: dnsTimeoutMs,
    debug: debug,
    enforceSpf: enforceSpf,
    spfServer: spfServer,
    spfClientIp: spfClientIp,
    spfHeloDomain: spfHeloDomain,
    enforceDmarc: enforceDmarc,
    dmarcLookup: dmarcLookup,
    dkimLookup: dkimLookup
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

type
  MxResolveStatus* = enum
    mrsOk        ## Usable MX hosts found.
    mrsNoData    ## Name exists but publishes no MX (RFC 5321 section 5.1
                 ## address fallback applies).
    mrsNxDomain  ## Name does not exist: permanent failure, no fallback.
    mrsNullMx    ## Null MX (RFC 7505): the domain accepts no mail, permanent.
    mrsTempError ## DNS failure or timeout: defer, retry later.

  MxResolveResult* = object
    status*: MxResolveStatus
    hosts*: seq[MXHost]

func classifyMxAnswer*(err: string, hosts: seq[MXHost]): MxResolveStatus =
  ## Pure mapping from a powpow MX answer to a delivery-grade status.
  ## NXDOMAIN arrives as `"DNS: host not found: ..."` (rcode 3, including
  ## negative-cache hits); every other non-empty `err` (SERVFAIL, timeout,
  ## truncation, resolver failure) is transient. A lone `.` exchange is a
  ## null MX per RFC 7505. Unit-testable without network I/O.
  if err.len > 0:
    if "host not found:" in err: mrsNxDomain
    else: mrsTempError
  elif hosts.len == 0: mrsNoData
  elif hosts.len == 1 and hosts[0].host.strip() in [".", ""]: mrsNullMx
  else: mrsOk

proc resolveMxOutcome*(domain: string, maxHosts = 5,
                       dnsTimeoutMs = 8000): MxResolveResult {.gcsafe.} =
  ## Resolve MX records for `domain` with a bounded wait. Unlike the legacy
  ## wrapper below, NXDOMAIN and null MX are reported distinctly from transient
  ## failures so callers can fail fast instead of attempting delivery to a host
  ## that does not exist. On genuine NOERROR-with-no-MX the result keeps the
  ## RFC 5321 section 5.1 fallback (the domain itself) with status `mrsNoData`.
  if domain.len == 0:
    return MxResolveResult(status: mrsTempError)
  {.cast(gcsafe).}:
    let loop = newLoop()
    var done = false
    var timedOut = false
    var found: seq[MXHost]
    var answerErr = ""
    loop.resolveMxAsync(domain) do (records: seq[MxRecord]; err: string):
      if err.len == 0:
        for r in records:
          found.add(MXHost(preference: r.pref, host: r.exchange))
      else:
        answerErr = err
      done = true
      loop.stop()
    discard loop.addTimer(dnsTimeoutMs) do (tid: int):
      if not done:
        timedOut = true
        done = true
        loop.stop()
    if not done:
      loop.run()
    loop.close()
    if timedOut:
      return MxResolveResult(status: mrsTempError)
    found.sort(proc(a, b: MXHost): int = cmp(a.preference, b.preference))
    if found.len > maxHosts and maxHosts > 0:
      found.setLen(maxHosts)
    let status = classifyMxAnswer(answerErr, found)
    if status == mrsNoData:
      found = @[MXHost(preference: 0, host: domain.toLowerAscii())]
    MxResolveResult(status: status, hosts: found)

proc resolveMxHosts*(domain: string, maxHosts = 5): seq[MXHost] {.gcsafe.} =
  ## Legacy wrapper: usable hosts, or empty when the domain has no usable
  ## mail exchanger (NXDOMAIN, null MX) or resolution failed transiently.
  ## Genuine no-MX answers keep the RFC 5321 fallback to the domain itself.
  let r = resolveMxOutcome(domain, maxHosts)
  case r.status
  of mrsOk, mrsNoData: r.hosts
  else: @[]

proc resolveTxtRecords*(hostname: string, dnsTimeoutMs = 8000): seq[string] {.gcsafe.} =
  ## Resolve TXT records for `hostname` using powpow's native async DNS resolver.
  ## Returns the raw TXT data strings (one per record). Empty seq on NODATA.
  ## The watchdog bounds the throwaway loop so a wedged resolver cannot stall
  ## the caller past `dnsTimeoutMs`.
  if hostname.len == 0: return
  {.cast(gcsafe).}:
    let loop = newLoop()
    var done = false
    var timedOut = false
    var results: seq[string]
    loop.resolveTxtAsync(hostname) do (records: seq[TxtRecord]; err: string):
      if err.len == 0:
        for r in records:
          results.add(r.data)
      done = true
      loop.stop()
    discard loop.addTimer(dnsTimeoutMs) do (tid: int):
      if not done:
        timedOut = true
        done = true
        loop.stop()
    if not done:
      loop.run()
    loop.close()
    if timedOut: return @[]
    results

proc defaultDkimLookup(domain, selector: string): string {.gcsafe.} =
  ## Fetch the `v=DKIM1` key record via powpow's TXT resolver.
  selectDkimKeyRecord(resolveTxtRecords(selector & "._domainkey." & domain))

proc decideJointDmarc*(fromDomain, record, envDomain: string,
                       spf: SpfPreflightResult,
                       dkimDomains: seq[string],
                       dkimTempError: bool): DeliveryDecision =
  ## Pure joint DMARC verdict for outbound preflight (no I/O; unit-testable).
  ## Sampling is forced on (`pctRoll = 0`): senders do not get to deliver a
  ## fraction of spoofed mail. Inconclusive DNS (SPF/DKIM temp errors) defers
  ## instead of refusing so legitimate mail is never bounced on resolver
  ## trouble; unparsable records are treated as absent (receivers agree).
  if fromDomain.len == 0: return ddPermFail
  if record.strip().len == 0: return ddOk
  if spf.tempError: return ddTempFail
  let outcome = evaluateDmarc(fromDomain, record, envDomain, spf.pass,
                              dkimDomains, pctRoll = 0)
  if outcome.policy == dpAbsent: return ddOk
  if outcome.policy == dpNone: return ddOk
  if outcome.aligned: return ddOk
  if not outcome.enforced: return ddOk
  if dkimTempError: return ddTempFail
  ddPermFail

proc runDmarcPreflight(req: DeliveryRequest, cfg: MXProviderConfig): DeliveryDecision =
  if not cfg.enforceDmarc: return ddOk
  if cfg.dmarcLookup.isNil: return ddTempFail

  let fromDomain = extractMailFromDomain(req.mailFrom)
  if fromDomain.len == 0: return ddPermFail
  let rec = cfg.dmarcLookup(fromDomain)
  if rec.strip().len == 0: return ddOk

  # SPF disposition for the envelope sender (raw: pass/fail/defer).
  let spf = querySpfRaw(cfg.spfServer, cfg.spfClientIp, cfg.spfHeloDomain,
                        req.mailFrom)
  if spf.tempError: return ddTempFail

  # DKIM signatures already on the message (ours and/or the author's).
  let lookup: DkimKeyLookup =
    if cfg.dkimLookup != nil: cfg.dkimLookup else: defaultDkimLookup
  let dkim = verifyDkimData(req.data, lookup)

  decideJointDmarc(fromDomain, rec, spf.domain, spf, dkim.domains,
                   dkim.tempError)

func tlsHostSkipped*(skipDomains: seq[string], host: string): bool =
  ## Pure matcher for `tlsSkipDomains`: case-insensitive, trailing dots
  ## ignored on both sides. Unit-testable without network I/O.
  let h = host.strip().strip(chars = {'.'}).toLowerAscii()
  for s in skipDomains:
    if h == s.strip().strip(chars = {'.'}).toLowerAscii():
      return true
  false

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
      # Client-side TLS context, created on demand when an upgrade starts.
    mxHost: string
      # The MX hostname under delivery (SNI + hostname verification).
    allowStartTls: bool
      # False on the plaintext retry after a failed opportunistic upgrade.
    opportunistic: bool
      # This attempt may try STARTTLS but must fall back to plaintext
      # instead of failing when the upgrade does not complete.
    tlsUpgradePending: bool
      # Upgrade started, no post-upgrade application data seen yet. A close
      # in this window means the handshake failed.
    downgraded: bool
      # Opportunistic upgrade failed; the caller retries plaintext once.
    tlsNote: string
      # Per-host TLS outcome for debug logging.
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
    cmdGen: int
      # Generation counter for the per-stage idle timer. Each arm bumps it
      # so stale timers no-op instead of needing cancellation.

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

proc armReplyTimer(txn: MxTxn) =
  ## (Re)arm the per-stage idle timer: if the peer sends nothing for
  ## `commandTimeoutMs` the host attempt fails transiently and delivery moves
  ## to the next MX instead of holding the delivery thread. Called when the
  ## connection opens (banner wait) and on every inbound chunk, so any server
  ## activity resets the deadline. Stale timers compare generations and no-op.
  if txn.loop == nil: return
  inc txn.cmdGen
  let t = txn
  let gen = t.cmdGen
  discard t.loop.addTimer(t.cfg.commandTimeoutMs) do (id: int):
    if not t.done and t.cmdGen == gen:
      discard setDone(t, ddTempFail)

proc smtpWriteLine(txn: MxTxn, line: string): bool =
  if txn.cfg.debug and logitGlobal != nil:
    logitGlobal.debug("[mx] > " & line)
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

proc downgradeOrTempFail(txn: MxTxn) =
  ## An upgrade that never completed. Opportunistic attempts signal a
  ## plaintext retry; strict attempts fail the host transiently.
  if txn.opportunistic:
    txn.tlsNote = "upgrade failed, downgraded to plaintext"
    txn.downgraded = true
  discard setDone(txn, ddTempFail)

proc startTlsUpgrade(txn: MxTxn) =
  # Upgrade the connection to TLS (STARTTLS). The context verifies the chain
  # against the system CA store; passing the MX hostname adds SNI plus the
  # hostname check. The queued EHLO is flushed once the handshake completes,
  # then the transaction resumes from the msEhlo state with tlsEstablished
  # set. Plaintext written meanwhile is buffered by powpow, never sent raw.
  if txn.tlsCtx == nil:
    try:
      txn.tlsCtx = newClientTlsContext()
    except SslError:
      downgradeOrTempFail(txn)
      return
  txn.tlsEstablished = true
  txn.tlsUpgradePending = true
  try:
    txn.conn.wrapTls(txn.tlsCtx, txn.mxHost)
  except SslError:
    downgradeOrTempFail(txn)
    return
  let helo = (if txn.cfg.heloName.len > 0: txn.cfg.heloName else: "localhost")
  if not smtpWriteLine(txn, "EHLO " & helo):
    downgradeOrTempFail(txn)
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
      if not txn.tlsEstablished and txn.allowStartTls and
         not tlsHostSkipped(txn.cfg.tlsSkipDomains, txn.mxHost):
        if txn.cfg.requireStartTls or
           (txn.cfg.startTlsOpportunistic and txn.sawStartTlsCap):
          if not txn.sawStartTlsCap:
            # Reachable in required mode only: opportunistic never offers
            # without the capability.
            txn.tlsNote = "peer does not advertise STARTTLS"
            return setDone(txn, ddPermFail)
          if not smtpWriteLine(txn, "STARTTLS"):
            return setDone(txn, ddTempFail)
          txn.state = msStartTls
          return
        elif txn.sawStartTlsCap:
          txn.tlsNote = "STARTTLS offered but policy is plaintext"
      elif tlsHostSkipped(txn.cfg.tlsSkipDomains, txn.mxHost):
        txn.tlsNote = "host in tls_skip_domains"
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
  if txn.cfg.debug and logitGlobal != nil:
    logitGlobal.debug("[mx] < " & line)

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

  armReplyTimer(txn)
  if txn.tlsUpgradePending:
    # Application data after an upgrade means the handshake completed
    # (powpow feeds handshake bytes to the handshake driver, never to
    # onData), so the peer certificate verified against mxHost.
    txn.tlsUpgradePending = false
    txn.tlsNote = "verified"
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
    if txn.tlsUpgradePending and txn.opportunistic:
      # The handshake never completed: signal a plaintext retry instead of
      # failing the host. Strict attempts keep the transient failure.
      txn.tlsNote = "upgrade failed, downgraded to plaintext"
      txn.downgraded = true
    setDone(txn, ddTempFail)

proc mxLog(cfg: MXProviderConfig, msg: string) =
  if cfg.debug and logitGlobal != nil:
    logitGlobal.debug("[mx] " & msg)

proc deliverToMxHost(req: DeliveryRequest,
        mxHost: MXHost, cfg: MXProviderConfig,
        allowStartTls = true): DeliveryDecision {.gcsafe.} =
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
      mxHost: mxHost.host,
      allowStartTls: allowStartTls,
      opportunistic: allowStartTls and not cfg.requireStartTls and
        cfg.startTlsOpportunistic and
        not tlsHostSkipped(cfg.tlsSkipDomains, mxHost.host),
      decision: ddTempFail
    )

    # Total transaction timeout (connection + entire SMTP dialog) to ensure we
    # don't get stuck on slow/unresponsive hosts.
    discard loop.addTimer(max(5000, cfg.connectTimeoutMs + cfg.commandTimeoutMs * 8)) do (id: int):
      setDone(txn, ddTempFail)

    try:
      # Happy Eyeballs racing across the MX host's addresses; connect-level
      # failures report via onError so dead hosts fail over fast instead of
      # burning the total transaction timer.
      loop.connectHe(mxHost.host, 25,
        onConnect = proc(conn: Connection) =
          txn.conn = conn
          conn.data = cast[pointer](txn)
          # The banner is sent by the server unprompted.
          armReplyTimer(txn)
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          onMxData(conn, data)
        ,
        onClose = proc(conn: Connection) =
          onMxClose(conn)
        ,
        onError = proc(err: string) =
          mxLog(cfg, "connect failed host=" & mxHost.host & ": " & err)
          discard setDone(txn, ddTempFail)
        ,
      )
    except NetError:
      loop.close()
      return ddTempFail

    loop.run()

    if not txn.done:
      txn.decision = ddTempFail

    let tlsInfo =
      if txn.downgraded: "tls=downgraded"
      elif txn.tlsEstablished: "tls=verified"
      elif tlsHostSkipped(cfg.tlsSkipDomains, mxHost.host): "tls=skipped"
      else: "tls=plaintext" & (if txn.tlsNote.len > 0: " (" & txn.tlsNote & ")" else: "")
    mxLog(cfg, "result host=" & mxHost.host & " " & tlsInfo &
      " decision=" & $txn.decision)

    # A failed opportunistic upgrade retries the same host in plaintext once.
    # The retry is a fresh connection; allowStartTls=false blocks any further
    # upgrade or downgrade signalling for it.
    if txn.downgraded and allowStartTls:
      mxLog(cfg, "retry plaintext host=" & mxHost.host)
      loop.close()
      return deliverToMxHost(req, mxHost, cfg, false)

    loop.close()
    result = txn.decision

proc deliverToDomain(req: DeliveryRequest, domain: string,
                cfg: MXProviderConfig): DeliveryDecision =
  # Delivers the email to a domain by resolving its MX hosts and attempting
  # delivery to each until one succeeds or all fail. NXDOMAIN and null MX
  # fail permanently without any connect attempt; transient DNS trouble
  # defers so the queue can retry.
  let resolved = resolveMxOutcome(domain, cfg.maxMxHostsPerDomain,
                                  cfg.dnsTimeoutMs)
  case resolved.status
  of mrsNxDomain, mrsNullMx:
    return ddPermFail
  of mrsTempError:
    return ddTempFail
  of mrsOk, mrsNoData:
    discard
  let mxHosts = resolved.hosts
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
  result = proc(req: DeliveryRequest): DeliveryOutcome {.gcsafe.} =
    if req.rcptTo.len == 0:
      return okOutcome(ddPermFail)

    # When DMARC enforcement is active its joint evaluation owns the SPF
    # verdict: a standalone SPF short-circuit here would refuse SPF-fail +
    # DKIM-pass mail that DMARC explicitly allows.
    if performDmarcPreflight and cfg.enforceDmarc:
      let dmarcDecision = runDmarcPreflight(req, cfg)
      if dmarcDecision != ddOk:
        return okOutcome(dmarcDecision)
    elif performSpfPreflight:
      let spfDecision = runSpfPreflight(req, cfg)
      if spfDecision != ddOk:
        return okOutcome(spfDecision)

    # Validate recipients and collect unique domains.
    var domains: seq[string] = @[]
    for rcpt in req.rcptTo:
      let domain = extractRcptDomain(rcpt)
      if domain.len == 0:
        return okOutcome(ddPermFail)
      if domain notin domains:
        domains.add(domain)

    # Deliver once per domain with only that domain's recipients.
    for domain in domains:
      var domainReq = req
      domainReq.rcptTo = req.rcptTo.filterIt(extractRcptDomain(it) == domain)

      let d = deliverToDomain(domainReq, domain, cfg)
      if d != ddOk:
        return okOutcome(d)
    okOutcome(ddOk)
