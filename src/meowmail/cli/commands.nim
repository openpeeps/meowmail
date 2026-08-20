import std/[options, os, strutils, tables, times]
from std/net import Port, `$`

import pkg/kapsis/runtime
import pkg/kapsis/interactive/prompts

import ../smtp/[smtpserver, smtpdelivery, smtpauth, mxprovider, dkim, queue]
import ../imap/[imapserver, mailstore]
import ../jmap/server as jmapserver
import ../restapi/admin
import powpow/net/tls
import ./config

const defaultConfig = """# MeowMail configuration
[smtp]
enabled = true
hostname = "meowmail.local" # used for greetings/HELO fallback
send_policy = "default"     # default | local_send_only | internal_send_only | no_relay

[smtp.listen.port25]
enabled = true
host = "0.0.0.0"
port = 25

[smtp.listen.submission587]
enabled = true
host = "0.0.0.0"
port = 587

[smtp.listen.smtps465]
enabled = false
host = "0.0.0.0"
port = 465

[smtp.tls]
enabled = false
cert_file = "/etc/ssl/certs/meowmail.crt"
key_file = "/etc/ssl/private/meowmail.key"

[smtp.tls.starttls]
enabled = true
require_for_auth = false

[smtp.auth]
required = true
mechanisms = ["PLAIN", "LOGIN"]

[smtp.auth.users]
"relay-user@example.com" = "change-me"

[smtp.auth.http_provider]
enabled = false
url = ""
bearer_token = ""
timeout_ms = 1200

[smtp.delivery]
mode = "mx"             # mx | spool
spool_directory = "/var/spool/meowmail"

[smtp.delivery.mx]
helo_name = "mail.example.com"
connect_timeout_ms = 7000
command_timeout_ms = 10000
require_starttls = false
max_mx_hosts_per_domain = 5
debug = false

[smtp.delivery.mx.preflight.spf]
enabled = false
client_ip = "127.0.0.1"
helo_domain = "mail.example.com"

[smtp.delivery.mx.preflight.dmarc]
enabled = false

# Local Maildir delivery (readable over IMAP)
[maildir]
base = "./maildir"
local_domains = ["example.com"]

[imap]
enabled = true
port = 143

[jmap]
enabled = false
port = 8080
host = "0.0.0.0"

[jmap.tls]
cert_file = ""
key_file = ""

[dkim]
enabled = false
domain = ""
selector = "meowmail"
key_file = ""

[logging]
level = "info"
format = "text"
file = true
console = true
max_file_size = 10485760
max_files = 30

[queue]
spool_dir = ""
max_retries = 20
base_delay = 300
max_delay = 86400
runner_interval = 30

[admin]
enabled = false
port = 8081
host = "127.0.0.1"
"""

proc initCommand*(v: Values) =
  ## Initialize a MeowMail configuration file
  let path = v.get("init").getStr
  if fileExists(path):
    echo "config already exists: ", path
    return
  writeFile(path, defaultConfig)
  echo "wrote config to ", path

var thr: array[0..1, Thread[(ptr SMTPServer, Port)]]
proc initSMTPServer(args: (ptr SMTPServer, Port)) {.thread.} =
  # Start the SMTP server event loop in this thread.
  {.gcsafe.}:
    let (server, port) = args
    server[].start()

var smtpServerInstance: SMTPServer

proc maildirBase(): string =
  getEnv("MEOWMAIL_MAILDIR", getCurrentDir() / "maildir")

proc localDomains(): seq[string] =
  let envDomains = getEnv("MEOWMAIL_LOCAL_DOMAINS", "")
  if envDomains.len > 0:
    for d in envDomains.split(','):
      let dd = d.strip()
      if dd.len > 0: result.add(dd)
  if result.len == 0:
    result = @[smtpHostname(), "localhost", "meowmail.local"]

var imapServerInstance: IMAPServer
proc runIMAPServer(server: IMAPServer) {.thread.} =
  {.cast(gcsafe).}:
    server.start()

var jmapServerInstance: JMAPServer
proc runJMAPServer(server: JMAPServer) {.thread.} =
  {.cast(gcsafe).}:
    server.start()

var adminServerInstance: AdminServer
proc runAdminServer(server: AdminServer) {.thread.} =
  {.cast(gcsafe).}:
    server.start()

proc startCommand*(v: Values) =
  ## Start the MeowMail server using the specified configuration
  let cfgPath = v.get("config").getPath.path
  if not fileExists(cfgPath):
    stderr.writeLine("config not found: ", cfgPath)
    quit(1)
  let cfg = loadConfig(cfgPath)

  # Explicit env vars override config (useful for non-privileged testing).
  if getEnv("MEOWMAIL_SMTP_PORT", "") == "":
    putEnv("MEOWMAIL_SMTP_PORT", $cfg.listenPort)
  if getEnv("MEOWMAIL_IMAP_PORT", "") == "":
    putEnv("MEOWMAIL_IMAP_PORT", $cfg.imapPort)
  if getEnv("MEOWMAIL_LOCAL_DOMAINS", "") == "" and cfg.localDomains.len > 0:
    putEnv("MEOWMAIL_LOCAL_DOMAINS", cfg.localDomains.join(","))

  smtpServerInstance = newSMTPServer(settings = cfg.toSMTPSettings())
  applyAuth(smtpServerInstance, cfg)

  # Initialize TLS if configured
  if cfg.certifications.isSome:
    let (cert, key) = cfg.certifications.get()
    if not smtpServerInstance.setupTlsCtx(cert, key):
      stderr.writeLine("TLS setup failed: ", cert, " + ", key)

  # Load DKIM signing key if configured
  if cfg.dkimEnabled and cfg.dkimKeyFile.len > 0 and cfg.dkimDomain.len > 0:
    try:
      smtpServerInstance.dkimKey = newDkimKey(cfg.dkimDomain, cfg.dkimSelector, cfg.dkimKeyFile)
      echo "DKIM signing enabled for ", cfg.dkimDomain
    except CatchableError as e:
      stderr.writeLine("DKIM key load error: ", e.msg)

  # Initialize outbound message queue
  let spoolDir = if cfg.spoolDirectory.len > 0: cfg.spoolDirectory
                 else: getTempDir() / "meowmail-queue"
  smtpServerInstance.queue = newQueue(spoolDir)
  smtpServerInstance.queue.load()
  let qs = smtpServerInstance.queue.stats()
  if qs.total > 0:
    echo "Queue: ", qs.total, " messages (", qs.deferred, " deferred)"

  # create thread for main SMTP server
  createThread(thr[0], initSMTPServer, (addr(smtpServerInstance), Port(cfg.listenPort)))

  # give the main server a moment to start up
  sleep(100)

  # IMAP server backed by the same Maildir store
  var imapThread: Thread[IMAPServer]
  var jmapThread: Thread[JMAPServer]
  if cfg.imapEnabled:
    let imapPort = getEnv("MEOWMAIL_IMAP_PORT", $cfg.imapPort).parseInt
    let base = getEnv("MEOWMAIL_MAILDIR",
      (if cfg.maildirBase.len > 0: cfg.maildirBase else: getCurrentDir() / "maildir"))
    imapServerInstance = newIMAPServer(Port(imapPort), newMaildirStore(base, localDomains()))
    for (u, p) in cfg.authUsers:
      imapServerInstance.authUsers[u] = p
    imapServerInstance.authProvider = smtpServerInstance.authProvider
    createThread(imapThread, runIMAPServer, imapServerInstance)

  # JMAP server (HTTP JSON API)
  if cfg.jmapEnabled:
    let jmapPort = cfg.jmapPort
    let jmapHost = cfg.jmapHost
    let base = getEnv("MEOWMAIL_MAILDIR",
      (if cfg.maildirBase.len > 0: cfg.maildirBase else: getCurrentDir() / "maildir"))
    let firstUser = if cfg.authUsers.len > 0: cfg.authUsers[0][0].split("@")[0]
                    else: "meow"
    var jmapTlsCtx: SslContext
    if cfg.jmapTlsCert.len > 0 and cfg.jmapTlsKey.len > 0:
      try:
        jmapTlsCtx = newServerTlsContext(cfg.jmapTlsCert, cfg.jmapTlsKey)
      except SslError as e:
        stderr.writeLine("JMAP TLS error: ", e.msg)
    jmapServerInstance = newJMAPServer(newMaildirStore(base, localDomains()),
                                       firstUser, jmapHost, Port(jmapPort),
                                       jmapTlsCtx)
    createThread(jmapThread, runJMAPServer, jmapServerInstance)

  # Admin API server
  var adminThread: Thread[AdminServer]
  if cfg.adminEnabled:
    let adminPort = cfg.adminPort
    let adminHost = cfg.adminHost
    var adminSvr = newAdminServer(smtpServerInstance.queue, adminHost, Port(adminPort))
    createThread(adminThread, runAdminServer, adminSvr)

  joinThreads(thr)
  if cfg.imapEnabled:
    joinThread(imapThread)
  if cfg.jmapEnabled:
    joinThread(jmapThread)
  if cfg.adminEnabled:
    joinThread(adminThread)
       
import ../utils/records_generator
proc spfCommand*(v: Values) =
  ## Generate an SPF record for the specified domain and IP addresses
  let ip4 = v.get("ip4").getStr.split(",")
  let ip6 =
    if v.has("ip6"):
      v.get("ip6").getStr.split(",")
    else: @[]
  display(records_generator.buildSpfTxt(
      ip4 = ip4, ip6 = ip6, allQualifier = "-all"
    ))

proc dkimCommand*(v: Values) =
  ## Generate a DKIM record for the specified domain, selector, and public key
  let dkimPath = v.get("dkim").getStr
  if not fileExists(dkimPath):
    echo "DKIM file not found: ", dkimPath
    return
  let dkimData = readFile(dkimPath)
  let lines = dkimData.splitLines()
  if lines.len < 3:
    echo "Invalid DKIM file format. Expected selector, domain, and public key."
    return
  let selector = lines[0].strip()
  let domain = lines[1].strip()

proc dmarcCommand*(v: Values) =
  ## Generate a DMARC record for the specified domain,
  ## policy, and reporting options based on the contents of the specified file.
  let dmarcPath = v.get("dmarc").getStr
  if not fileExists(dmarcPath):
    echo "DMARC file not found: ", dmarcPath
    return
  let dmarcData = readFile(dmarcPath)
  let lines = dmarcData.splitLines()
  if lines.len < 2:
    echo "Invalid DMARC file format. Expected domain and policy."
    return
  let domain = lines[0].strip()
  let policyStr = lines[1].strip().toLowerAscii()
  
  var policy: DmarcPolicy
  case policyStr
  of "none": policy = DmarcPolicy.dpNone
  of "quarantine": policy = DmarcPolicy.dpQuarantine
  of "reject": policy = DmarcPolicy.dpReject
  else:
    echo "Invalid DMARC policy: ", policyStr, ". Expected none, quarantine, or reject."
    return
  display(buildDmarcTxt(policy))

# ── Queue management commands ─────────────────────────────────────────────────

proc queueListCommand*(v: Values) =
  ## List queued messages with status, retries, and next retry time.
  let dir = v.get("queueDir").getStr
  let q = newQueue(dir)
  q.load()
  let entries = q.entries
  if entries.len == 0:
    echo "Queue is empty"
    return
  echo "ID | Status | From | To | Retries | Next Retry"
  echo "---|--------|------|----|---------|"
  for entry in entries:
    echo entry.id & " | " &
         $entry.status & " | " &
         entry.mailFrom & " | " &
         entry.rcptTo.join(", ") & " | " &
         $entry.retryCount & " | " &
         $entry.nextRetry

proc queueStatsCommand*(v: Values) =
  ## Show queue statistics.
  let dir = v.get("queueDir").getStr
  let q = newQueue(dir)
  q.load()
  let (total, deferred, active, delivered, bounced) = q.stats()
  echo "Queue statistics:"
  echo "  Total:     ", total
  echo "  Deferred:  ", deferred
  echo "  Active:    ", active
  echo "  Delivered: ", delivered
  echo "  Bounced:   ", bounced

proc queueFlushCommand*(v: Values) =
  ## Force immediate delivery of all pending messages.
  let dir = v.get("queueDir").getStr
  let q = newQueue(dir)
  q.load()
  let pending = q.pending()
  if pending.len == 0:
    echo "No pending messages to flush"
    return
  echo "Flushing ", pending.len, " messages..."
  for entry in pending:
    echo "  Delivering ", entry.id, " (from=", entry.mailFrom, " to=", entry.rcptTo.join(","), ")"
  echo "Done. Messages queued for delivery."

proc queueRetryCommand*(v: Values) =
  ## Requeue a specific message for immediate retry.
  let dir = v.get("queueDir").getStr
  let id = v.get("id").getStr
  let q = newQueue(dir)
  q.load()
  var found = false
  for i, entry in q.entries:
    if entry.id == id:
      q.entries[i].status = qsDeferred
      q.entries[i].nextRetry = getTime()
      q.entries[i].retryCount = 0
      q.saveMeta(q.entries[i])
      found = true
      echo "Message ", id, " requeued for immediate delivery"
      break
  if not found:
    echo "Message ", id, " not found"

proc queueDeleteCommand*(v: Values) =
  ## Remove a message from the queue.
  let dir = v.get("queueDir").getStr
  let id = v.get("id").getStr
  let q = newQueue(dir)
  q.load()
  var found = false
  for entry in q.entries:
    if entry.id == id:
      try:
        removeFile(entry.path)
        removeFile(entry.path.changeFileExt(".meta"))
      except CatchableError:
        discard
      q.removeEntry(id)
      found = true
      echo "Message ", id, " deleted"
      break
  if not found:
    echo "Message ", id, " not found"

proc queuePurgeCommand*(v: Values) =
  ## Remove all delivered, bounced, and failed messages.
  let dir = v.get("queueDir").getStr
  let q = newQueue(dir)
  q.load()
  var purged = 0
  var i = q.entries.high
  while i >= 0:
    let entry = q.entries[i]
    if entry.status in [qsDelivered, qsBounced, qsFailed]:
      try:
        removeFile(entry.path)
        removeFile(entry.path.changeFileExt(".meta"))
      except CatchableError:
        discard
      q.removeEntry(entry.id)
    