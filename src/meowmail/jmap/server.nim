## MeowMail JMAP — HTTP server, request parsing, and method dispatch.
##
## Routes:
##   GET  /.well-known/jmap   → Session Object
##   GET  /jmap/session       → Session Object
##   POST /jmap/api           → JMAP API method calls

import std/[json, strutils, tables, options]
import std/httpcore
from std/net import Port, `$`

import powpow
import ../imap/mailstore
import ./types
import ./core

proc extractLocalPart(email: string): string =
  ## Extract the local part from an email address for use as the mailstore user.
  let at = email.rfind('@')
  if at > 0: email[0 ..< at]
  else: email

type
  JMAPServer* = ref object
    loop*: Loop
    http*: HttpServer
    host*: string
    port*: Port
    ctx*: JMAPContext

# ── Response helpers ──────────────────────────────────────────────────────────

proc sendJson(res: HttpResponse, code: HttpCode, payload: JsonNode) =
  res.header("Content-Type", "application/json; charset=utf-8")
     .header("Cache-Control", "no-cache, no-store, must-revalidate")
     .status(code)
     .send($payload)

proc sendProblemDetails(res: HttpResponse, code: HttpCode, problem: JsonNode) =
  ## Send an RFC 7807 problem details response (request-level error).
  res.header("Content-Type", "application/problem+json; charset=utf-8")
     .status(code)
     .send($problem)

# ── Request parsing (RFC 8620 §3.3) ─────────────────────────────────────────

proc parseMethodCall(call: JsonNode): (string, JsonNode, string) =
  ## Parse a JMAP positional invocation: [name, args, callId].
  ## Returns (methodName, args, callId).
  if call.kind != JArray or call.len < 3:
    raise newException(ValueError, "Method call must be [name, args, callId]")
  let name = call[0].getStr("")
  let args = if call[1].kind == JObject: call[1] else: newJObject()
  let callId = call[2].getStr("")
  (name, args, callId)

# ── API request processor (RFC 8620 §3.3-3.4) ────────────────────────────────

proc processApi(ctx: JMAPContext, reqJson: JsonNode): JsonNode =
  ## Process a JMAP Request object and return a JMAP Response object.
  if reqJson.kind != JObject:
    return newJMAPRequestLevelError(
      "urn:ietf:params:jmap:error:notRequest", 400,
      "Request must be a JSON object")

  # Validate 'using' array (optional)
  if reqJson.hasKey("using"):
    let caps = reqJson["using"]
    if caps.kind != JArray:
      return newJMAPRequestLevelError(
        "urn:ietf:params:jmap:error:notRequest", 400,
        "'using' must be an array of capability URNs")
    # Check for unknown capabilities
    for cap in caps.items:
      let capStr = cap.getStr("")
      if capStr != "urn:ietf:params:jmap:core" and
         capStr != "urn:ietf:params:jmap:mail" and
         capStr != "urn:ietf:params:jmap:submission":
        return newJMAPRequestLevelError(
          "urn:ietf:params:jmap:error:unknownCapability", 400,
          "Unknown capability: " & capStr)

  # Validate 'methodCalls' array
  if not reqJson.hasKey("methodCalls") or reqJson["methodCalls"].kind != JArray:
    return newJMAPRequestLevelError(
      "urn:ietf:params:jmap:error:notRequest", 400,
      "Request must contain 'methodCalls' array")
  let methodCalls = reqJson["methodCalls"]
  if methodCalls.len == 0:
    return newJMAPRequestLevelError(
      "urn:ietf:params:jmap:error:limit", 400,
      "methodCalls must not be empty")

  # Process each method call sequentially
  var responses = newJArray()
  for call in methodCalls.items:
    try:
      let (methodName, args, callId) = parseMethodCall(call)
      if methodName.len == 0:
        let errResp = newJMAPErrorResponse(callId, errInvalidArguments,
                                           "Method name must not be empty")
        var errArr = newJArray()
        for item in errResp: errArr.add(item)
        responses.add(errArr)
        continue
      let response = ctx.handleMethod(methodName, args, callId)
      var respArr = newJArray()
      for item in response:
        respArr.add(item)
      responses.add(respArr)
    except ValueError as e:
      let errResp = newJMAPErrorResponse("*", errInvalidArguments, e.msg)
      var errArr = newJArray()
      for item in errResp: errArr.add(item)
      responses.add(errArr)

  # Build the Response object
  result = newJObject()
  result["methodResponses"] = responses
  result["sessionState"] = newJString(ctx.state)

# ── HTTP handler ──────────────────────────────────────────────────────────────

proc onHttpRequest(ctx: JMAPContext, host: string, port: int,
                   req: HttpRequest, res: HttpResponse) =
  let uri = req.getPath()
  let cmd = req.getMethod()

  # Session discovery (RFC 8620 §2.2)
  if cmd == HttpGet and (uri == "/.well-known/jmap" or uri == "/jmap/session"):
    sendJson(res, Http200, buildSession(ctx, host, port))
    return

  # JMAP API endpoint (RFC 8620 §3.1)
  if cmd == HttpPost and uri == "/jmap/api":
    let body = req.getBodyString()
    if body.len == 0:
      sendProblemDetails(res, Http400,
        newJMAPRequestLevelError("urn:ietf:params:jmap:error:notJSON", 400,
                                 "Empty request body"))
      return
    try:
      let reqJson = parseJson(body)
      let resp = processApi(ctx, reqJson)
      # Request-level errors have a 'type' key at the top level
      if resp.hasKey("type"):
        sendProblemDetails(res, Http400, resp)
      else:
        sendJson(res, Http200, resp)
    except JsonParsingError:
      sendProblemDetails(res, Http400,
        newJMAPRequestLevelError("urn:ietf:params:jmap:error:notJSON", 400,
                                 "Request body is not valid JSON"))
    except CatchableError as e:
      sendProblemDetails(res, Http500,
        newJMAPRequestLevelError("urn:ietf:params:jmap:error:serverFail", 500,
                                 e.msg))
    return

  sendProblemDetails(res, Http404,
    newJMAPRequestLevelError("urn:ietf:params:jmap:error:unknownMethod", 404,
                             "Not Found"))

# ── Server lifecycle ──────────────────────────────────────────────────────────

proc newJMAPServer*(store: MaildirStore, username: string,
                    host = "0.0.0.0", port: Port = Port(8080),
                    tlsCtx: SslContext = nil): JMAPServer =
  ## Create a new JMAP server backed by the given MaildirStore.
  ## If `tlsCtx` is provided, all connections are wrapped in TLS (implicit HTTPS).
  new(result)
  result.loop = newLoop()
  result.http = newHttpServer(result.loop)
  result.host = host
  result.port = port
  result.ctx = newJMAPContext(store, extractLocalPart(username))

  if tlsCtx != nil:
    result.http.sslCtx = tlsCtx

  let ctx = result.ctx
  let h = host
  let p = port.int
  result.http.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.cast(gcsafe).}:
      onHttpRequest(ctx, h, p, req, res)
  result.http.listen(host, port.int)

proc start*(server: JMAPServer) =
  ## Start the JMAP event loop (blocking).
  assert server.loop != nil
  assert server.http != nil
  server.loop.run()
