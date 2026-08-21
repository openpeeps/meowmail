# MeowMail - A high-performance SMTP/IMAP server based on powpow
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

## Loads `meowmail.config.toml` into server settings.

import std/[os, strutils, options, sequtils, tables]
import pkg/openparser/toml

import ../smtp/[smtpserver, smtpauth, mxprovider]

type
  MeowMailConfig* = object
    hostname*: string
    listenPort*: int
    enablePort25*, enablePort587*, enablePort465*: bool
    certifications*: Option[(string, string)]
    requireTlsForAuth*: bool
    requireAuth*: bool
    authUsers*: seq[(string, string)]
    authUrl*, authToken*: string
    authTimeoutMs*: int
    sendPolicy*: string
    deliveryMode*: string
    spoolDirectory*: string
    mxCfg*: MXProviderConfig
    maildirBase*: string
    localDomains*: seq[string]
    imapEnabled*: bool
    imapPort*: int
    jmapEnabled*: bool
    jmapPort*: int
    jmapHost*: string
    jmapTlsCert*: string
    jmapTlsKey*: string
    dkimEnabled*: bool
    dkimDomain*: string
    dkimSelector*: string
    dkimKeyFile*: string
    adminEnabled*: bool
    adminPort*: int
    adminHost*: string
    queueSpoolDir*: string
    queueMaxRetries*: int
    queueBaseDelay*: int
    queueMaxDelay*: int
    queueRunnerInterval*: int
    checkSenderDomain*: bool
    checkRcptDomain*: bool
    msgPerHour*: int
    msgPerDay*: int
    userMsgPerHour*: int
    userMsgPerDay*: int
    smtpCommandsLog*: bool

proc loadConfig*(path: string): MeowMailConfig =
  ## Parse a `meowmail.config.toml` file.
  let doc = parseTOML(readFile(path))
  template boolOf(key: string, default = false): bool =
    let n = doc.get(key)
    if n == nil: default else: n.getBool()
  template strOf(key: string, default = ""): string =
    let n = doc.get(key)
    if n == nil: default else: n.getStr()
  template intOf(key: string, default = 0): int =
    let n = doc.get(key)
    if n == nil: default else: int(n.getInt())
  template arrOf(key: string): seq[string] =
    let n = doc.get(key)
    if n == nil or n.kind != tvkArray: @[]
    else: n.getArray().mapIt(it.getStr())

  result.hostname = strOf("smtp.hostname")
  result.listenPort = intOf("smtp.listen.port25.port", 25)
  result.enablePort25 = boolOf("smtp.listen.port25.enabled", true)
  result.enablePort587 = boolOf("smtp.listen.submission587.enabled", true)
  result.enablePort465 = boolOf("smtp.listen.smtps465.enabled", false)

  if boolOf("smtp.tls.enabled", false):
    let cert = strOf("smtp.tls.cert_file")
    let key = strOf("smtp.tls.key_file")
    if cert.len > 0 and key.len > 0:
      result.certifications = some((cert, key))
  result.requireTlsForAuth = boolOf("smtp.tls.starttls.require_for_auth")
  result.requireAuth = boolOf("smtp.auth.required")

  let usersNode = doc.get("smtp.auth.users")
  if usersNode != nil and usersNode.kind == tvkTable:
    for k, v in usersNode.getObject():
      result.authUsers.add((k, v.getStr()))
  if boolOf("smtp.auth.http_provider.enabled", false):
    result.authUrl = strOf("smtp.auth.http_provider.url")
    result.authToken = strOf("smtp.auth.http_provider.bearer_token")
    result.authTimeoutMs = intOf("smtp.auth.http_provider.timeout_ms", 1200)

  result.sendPolicy = strOf("smtp.send_policy", "default")
  result.deliveryMode = strOf("smtp.delivery.mode", "mx")
  result.spoolDirectory = strOf("smtp.delivery.spool_directory")

  result.mxCfg = initMXProviderConfig(
    heloName = strOf("smtp.delivery.mx.helo_name", "localhost"),
    connectTimeoutMs = intOf("smtp.delivery.mx.connect_timeout_ms", 7000),
    commandTimeoutMs = intOf("smtp.delivery.mx.command_timeout_ms", 10000),
    requireStartTls = boolOf("smtp.delivery.mx.require_starttls"),
    maxMxHostsPerDomain = intOf("smtp.delivery.mx.max_mx_hosts_per_domain", 5),
    debug = boolOf("smtp.delivery.mx.debug"),
    enforceSpf = boolOf("smtp.delivery.mx.preflight.spf.enabled"),
    spfClientIp = strOf("smtp.delivery.mx.preflight.spf.client_ip", "127.0.0.1"),
    spfHeloDomain = strOf("smtp.delivery.mx.preflight.spf.helo_domain", "localhost"),
    enforceDmarc = boolOf("smtp.delivery.mx.preflight.dmarc.enabled"),
  )

  result.maildirBase = strOf("maildir.base")
  result.localDomains = arrOf("maildir.local_domains")
  result.imapEnabled = boolOf("imap.enabled", true)
  result.imapPort = intOf("imap.port", 143)
  result.jmapEnabled = boolOf("jmap.enabled", false)
  result.jmapPort = intOf("jmap.port", 8080)
  result.jmapHost = strOf("jmap.host", "0.0.0.0")
  result.jmapTlsCert = strOf("jmap.tls.cert_file")
  result.jmapTlsKey = strOf("jmap.tls.key_file")
  result.dkimEnabled = boolOf("dkim.enabled", false)
  result.dkimDomain = strOf("dkim.domain")
  result.dkimSelector = strOf("dkim.selector", "meowmail")
  result.dkimKeyFile = strOf("dkim.key_file")
  result.adminEnabled = boolOf("admin.enabled", false)
  result.adminPort = intOf("admin.port", 8081)
  result.adminHost = strOf("admin.host", "127.0.0.1")
  result.queueSpoolDir = strOf("queue.spool_dir")
  result.queueMaxRetries = intOf("queue.max_retries", 20)
  result.queueBaseDelay = intOf("queue.base_delay", 300)
  result.queueMaxDelay = intOf("queue.max_delay", 86400)
  result.queueRunnerInterval = intOf("queue.runner_interval", 30)
  result.checkSenderDomain = boolOf("smtp.validation.check_sender_domain")
  result.checkRcptDomain = boolOf("smtp.validation.check_rcpt_domain")
  result.msgPerHour = intOf("smtp.limits.messages_per_hour", 100)
  result.msgPerDay = intOf("smtp.limits.messages_per_day", 1000)
  result.userMsgPerHour = intOf("smtp.limits.user_messages_per_hour")
  result.userMsgPerDay = intOf("smtp.limits.user_messages_per_day")
  result.smtpCommandsLog = boolOf("logging.smtp_commands")

proc toSMTPSettings*(cfg: MeowMailConfig): SMTPSettings =
  ## Convert a parsed config into `SMTPSettings`.
  let policy =
    case cfg.sendPolicy
    of "local_send_only": spLocalSendOnly
    of "internal_send_only": spInternalSendOnly
    of "no_relay": spNoRelay
    else: spDefault
  result = SMTPSettings(
    sendPolicy: policy,
    enablePort25: cfg.enablePort25,
    enablePort587: cfg.enablePort587,
    enablePort465: cfg.enablePort465,
    certifications: cfg.certifications,
    spoolDirectory: (if cfg.spoolDirectory.len > 0: some(cfg.spoolDirectory) else: none(string)),
    enableMxDelivery: (cfg.deliveryMode == "mx"),
    mxConfig: cfg.mxCfg,
    maildirBase: (if cfg.maildirBase.len > 0: some(cfg.maildirBase) else: none(string)),
    localDomains: cfg.localDomains,
    checkSenderDomain: cfg.checkSenderDomain,
    checkRcptDomain: cfg.checkRcptDomain,
    msgPerHour: cfg.msgPerHour,
    msgPerDay: cfg.msgPerDay,
    userMsgPerHour: cfg.userMsgPerHour,
    userMsgPerDay: cfg.userMsgPerDay,
    smtpCommandsLog: cfg.smtpCommandsLog,
  )

proc applyAuth*(server: SMTPServer, cfg: MeowMailConfig) =
  ## Apply configured local users + HTTP auth provider to a server.
  for (u, p) in cfg.authUsers:
    server.authUsers[u] = p
  if cfg.authUrl.len > 0:
    server.authProvider = newHTTPAuthProvider(cfg.authUrl, cfg.authToken, cfg.authTimeoutMs)
  server.requireAuth = cfg.requireAuth
  server.requireTlsForAuth = cfg.requireTlsForAuth
