## MeowMail — SMTP rate limiting and connection hardening.
##
## Per-IP connection limits, brute-force auth protection, and
## configurable SMTP server limits.

import std/[tables, times, strutils, sequtils]
import ../utils/logger

type
  SmtpRateLimit* = ref object
    ## Per-IP connection rate limiter.
    connectionLimiter*: ConnectionLimiter
    authLimiter*: AuthLimiter

  ConnectionLimiter* = ref object
    ## Limits concurrent connections per IP and connection rate.
    maxConcurrent*: int            ## Max simultaneous connections per IP
    maxConnectionsPerMinute*: int  ## Max new connections per minute per IP
    concurrent: Table[string, int] ## IP -> current connection count
    connecting: Table[string, int] ## IP -> connections in last minute

  AuthLimiter* = ref object
    ## Throttles failed authentication attempts.
    maxFailedAttempts*: int        ## Max failed attempts before lockout
    lockoutDurationMs*: int        ## Lockout duration in milliseconds
    failedAttempts: Table[string, seq[int64]]  ## IP -> list of failure timestamps
    lockouts: Table[string, int64]  ## IP -> lockout expiry timestamp

  SmtpLimits* = object
    ## Configurable SMTP server limits.
    maxRecipients*: int            ## Max RCPT TO per session
    maxMessageSize*: int           ## Max message size in bytes
    maxLineLength*: int            ## Max command line length
    maxConnectionsPerIp*: int      ## Max concurrent connections per IP
    maxConnectionsPerMinute*: int  ## Max new connections per minute per IP
    maxAuthFailed*: int            ## Max failed auth before lockout
    authLockoutMs*: int            ## Auth lockout duration in milliseconds

const
  DefaultSmtpLimits* = SmtpLimits(
    maxRecipients: 100,
    maxMessageSize: 52428800,  # 50 MB
    maxLineLength: 1024 * 1024,  # 1 MB
    maxConnectionsPerIp: 20,
    maxConnectionsPerMinute: 60,
    maxAuthFailed: 5,
    authLockoutMs: 300_000,  # 5 minutes
  )

# ── Connection Limiter ────────────────────────────────────────────────────────

proc newConnectionLimiter*(maxConcurrent = 20,
                           maxPerMinute = 60): ConnectionLimiter =
  result = ConnectionLimiter(
    maxConcurrent: maxConcurrent,
    maxConnectionsPerMinute: maxPerMinute,
    concurrent: initTable[string, int](64),
    connecting: initTable[string, int](64),
  )

proc allowConnection*(limiter: ConnectionLimiter, ip: string): bool =
  ## Check if a new connection from this IP is allowed.
  if ip.len == 0: return true
  let current = limiter.concurrent.getOrDefault(ip, 0)
  if current >= limiter.maxConcurrent:
    return false
  let recent = limiter.connecting.getOrDefault(ip, 0)
  if recent >= limiter.maxConnectionsPerMinute:
    return false
  true

proc trackConnect*(limiter: ConnectionLimiter, ip: string) =
  ## Record a new connection from this IP.
  if ip.len == 0: return
  limiter.concurrent[ip] = limiter.concurrent.getOrDefault(ip, 0) + 1
  limiter.connecting[ip] = limiter.connecting.getOrDefault(ip, 0) + 1

proc trackDisconnect*(limiter: ConnectionLimiter, ip: string) =
  ## Record a disconnection from this IP.
  if ip.len == 0: return
  let current = limiter.concurrent.getOrDefault(ip, 0)
  if current > 1:
    limiter.concurrent[ip] = current - 1
  else:
    limiter.concurrent.del(ip)

proc cleanup*(limiter: ConnectionLimiter) =
  ## Reset the per-minute counters. Call every 60 seconds.
  limiter.connecting.clear()

# ── Auth Limiter ──────────────────────────────────────────────────────────────

proc newAuthLimiter*(maxFailed = 5,
                     lockoutMs = 300_000): AuthLimiter =
  result = AuthLimiter(
    maxFailedAttempts: maxFailed,
    lockoutDurationMs: lockoutMs,
    failedAttempts: initTable[string, seq[int64]](64),
    lockouts: initTable[string, int64](64),
  )

proc isLockedOut*(limiter: AuthLimiter, ip: string): bool =
  ## Check if this IP is currently locked out.
  if ip.len == 0: return false
  let lockoutExpiry = limiter.lockouts.getOrDefault(ip, 0.int64)
  if lockoutExpiry > 0:
    let now = int64(epochTime() * 1000)
    if now < lockoutExpiry:
      return true
    # Lockout expired, clean up
    limiter.lockouts.del(ip)
  false

proc recordFailure*(limiter: AuthLimiter, ip: string) =
  ## Record a failed authentication attempt. May trigger lockout.
  if ip.len == 0: return
  let now = int64(epochTime() * 1000)
  var attempts = limiter.failedAttempts.getOrDefault(ip, @[])
  # Keep only failures within the lockout window
  let windowStart = now - limiter.lockoutDurationMs.int64
  attempts.keepItIf(it > windowStart)
  attempts.add(now)
  limiter.failedAttempts[ip] = attempts

  if attempts.len >= limiter.maxFailedAttempts:
    limiter.lockouts[ip] = now + limiter.lockoutDurationMs.int64

proc recordSuccess*(limiter: AuthLimiter, ip: string) =
  ## Clear failed attempts on successful authentication.
  if ip.len == 0: return
  limiter.failedAttempts.del(ip)
  limiter.lockouts.del(ip)

# ── Composite Rate Limiter ────────────────────────────────────────────────────

proc newSmtpRateLimit*(limits: SmtpLimits = DefaultSmtpLimits): SmtpRateLimit =
  result = SmtpRateLimit(
    connectionLimiter: newConnectionLimiter(
      limits.maxConnectionsPerIp, limits.maxConnectionsPerMinute),
    authLimiter: newAuthLimiter(
      limits.maxAuthFailed, limits.authLockoutMs),
  )

proc allowConnection*(rl: SmtpRateLimit, ip: string): bool =
  rl.connectionLimiter.allowConnection(ip)

proc trackConnect*(rl: SmtpRateLimit, ip: string) =
  rl.connectionLimiter.trackConnect(ip)

proc trackDisconnect*(rl: SmtpRateLimit, ip: string) =
  rl.connectionLimiter.trackDisconnect(ip)

proc isLockedOut*(rl: SmtpRateLimit, ip: string): bool =
  rl.authLimiter.isLockedOut(ip)

proc recordAuthFailure*(rl: SmtpRateLimit, ip: string) =
  rl.authLimiter.recordFailure(ip)

proc recordAuthSuccess*(rl: SmtpRateLimit, ip: string) =
  rl.authLimiter.recordSuccess(ip)

proc cleanup*(rl: SmtpRateLimit) =
  rl.connectionLimiter.cleanup()
