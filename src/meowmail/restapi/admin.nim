## MeowMail — Admin HTTP API for queue inspection, health, and metrics.
##
## Serves on a separate port (default 8081) with JSON responses.

import std/[json, strutils, times, options, tables, httpcore]
from std/net import Port, `$`

import powpow
import ../smtp/queue

type
  AdminFlushProc* = proc(): int {.gcsafe.}
    ## Forces immediate delivery of pending queue entries; returns the number
    ## attempted. Injected by the caller that owns the delivery provider.

  AdminServer* = ref object
    loop*: Loop
    http*: HttpServer
    host*: string
    port*: Port
    queue*: Queue
    flushProc*: AdminFlushProc
      ## Optional callback performing a real queue flush. When nil the flush
      ## endpoint reports the pending count only.
    startTime*: times.Time

proc sendJson(res: HttpResponse, code: HttpCode, payload: JsonNode) =
  res.header("Content-Type", "application/json; charset=utf-8")
     .status(code)
     .send($payload)

proc sendProblem(res: HttpResponse, code: HttpCode, detail: string) =
  let payload = %*{"status": code.int, "detail": detail}
  res.header("Content-Type", "application/problem+json; charset=utf-8")
     .status(code)
     .send($payload)

# ── Handlers ──────────────────────────────────────────────────────────────────

proc handleAdminRequest(server: AdminServer, req: HttpRequest, res: HttpResponse) =
  let uri = req.getPath()
  let cmd = req.getMethod()

  # Health check
  if cmd == HttpGet and uri == "/admin/health":
    let uptime = (getTime() - server.startTime).inSeconds
    let payload = %*{
      "status": "ok",
      "version": "0.1.0",
      "uptime_seconds": uptime,
    }
    sendJson(res, Http200, payload)
    return

  # Queue stats
  if cmd == HttpGet and uri == "/admin/queue":
    let (total, deferred, active, delivered, bounced) = server.queue.stats()
    let payload = %*{
      "total": total,
      "deferred": deferred,
      "active": active,
      "delivered": delivered,
      "bounced": bounced,
    }
    sendJson(res, Http200, payload)
    return

  # Queue flush
  if cmd == HttpPost and uri == "/admin/queue/flush":
    var payload = %*{"status": "ok"}
    if server.flushProc != nil:
      try:
        payload["flushed"] = %server.flushProc()
      except CatchableError as e:
        payload["error"] = %e.msg
        sendJson(res, Http500, payload)
        return
    else:
      let pending = server.queue.pending()
      payload["flushed"] = %0
      payload["pending"] = %pending.len
      payload["detail"] = %"no delivery provider attached; nothing was attempted"
    sendJson(res, Http200, payload)
    return

  # Queue entry detail
  if cmd == HttpGet and uri.startsWith("/admin/queue/"):
    let entryId = uri[15 .. ^1]
    let entry = server.queue.getEntry(entryId)
    if entry.id.len == 0:
      sendProblem(res, Http404, "Queue entry not found: " & entryId)
      return
    let payload = %*{
      "id": entry.id,
      "mail_from": entry.mailFrom,
      "rcpt_to": entry.rcptTo,
      "status": $entry.status,
      "retry_count": entry.retryCount,
      "next_retry": $entry.nextRetry,
      "last_error": entry.lastError,
    }
    sendJson(res, Http200, payload)
    return

  # Metrics (JSON format)
  if cmd == HttpGet and uri == "/admin/metrics":
    let (total, deferred, active, delivered, bounced) = server.queue.stats()
    let uptime = (getTime() - server.startTime).inSeconds
    let payload = %*{
      "uptime_seconds": uptime,
      "queue": {
        "total": total,
        "deferred": deferred,
        "active": active,
        "delivered": delivered,
        "bounced": bounced,
      },
      "version": "0.1.0",
    }
    sendJson(res, Http200, payload)
    return

  sendProblem(res, Http404, "Not Found")

# ── Server lifecycle ──────────────────────────────────────────────────────────

proc newAdminServer*(queue: Queue, host = "127.0.0.1",
                     port: Port = Port(8081)): AdminServer =
  ## Create a new admin HTTP server.
  new(result)
  result.loop = newLoop()
  result.http = newHttpServer(result.loop)
  result.host = host
  result.port = port
  result.queue = queue
  result.startTime = getTime()

  let server = result
  result.http.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.cast(gcsafe).}:
      handleAdminRequest(server, req, res)
  result.http.listen(host, port.int)

proc start*(server: AdminServer) =
  ## Start the admin event loop (blocking).
  assert server.loop != nil
  assert server.http != nil
  server.loop.run()
