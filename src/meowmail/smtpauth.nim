# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail
import std/[httpclient, json]

## This module defines a framework-agnostic authentication system for the SMTP server.
## 
## It includes types for representing authentication requests and decisions,
## as well as an example implementation of an `AuthProvider` that makes HTTP requests
## to an external service for authentication. This allows for flexible integration with various 
## authentication backends without coupling the SMTP server to a specific authentication mechanism.

type
  AuthProgress* = enum
    ## Tracks the current step in an ongoing
    ## authentication process. This is used to manage
    apNone, apPlain, apLoginUser, apLoginPass

  AuthDecision* = enum
    ## Represents the possible outcomes of an
    ## authentication attempt. This is used by the
    authInvalid, authOk, authFailure

  AuthRequest* = object
    username*: string
      ## The username provided by the client during authentication.
    password*: string
      ## The password provided by the client during authentication.
    mechanism*: string
      ## The authentication mechanism being used (e.g., "PLAIN", "LOGIN").
    remoteIp*: string
      ## The IP address of the client attempting to authenticate.
    heloName*: string
      ## The HELO/EHLO name provided by the client, which may be useful for
      ## logging or authentication decisions.

  AuthProvider* = proc(req: AuthRequest): AuthDecision {.gcsafe.}
    ## A callback type for providing authentication decisions. The server will call

proc newHTTPAuthProvider*(url: string, bearerToken = "", timeoutMs = 1200): AuthProvider =
  ## Creates an `AuthProvider` that makes an HTTP POST request to the specified URL
  ## with the authentication details in JSON format.
  ## 
  ## The server is expected to respond
  ## with a JSON object containing an "ok" field indicating success. 
  ## 
  ## POST url with JSON: {"username":"...","password":"...","mechanism":"...","remoteIp":"...","heloName":"..."}
  ## Expected:
  ##   200 + {"ok":true} => authOk
  ##   401/403           => authInvalid
  ##   timeout/5xx/etc   => authFailure
  var client = newHttpClient(timeout = timeoutMs)
  result = proc(req: AuthRequest): AuthDecision {.gcsafe.} =
    try:
      var headers = newHttpHeaders()
      headers["Content-Type"] = "application/json"
      if bearerToken.len > 0:
        headers["Authorization"] = "Bearer " & bearerToken

      let payload = %*{
        "username": req.username,
        "password": req.password,
        "mechanism": req.mechanism,
        "remoteIp": req.remoteIp,
        "heloName": req.heloName
      }

      let resp = client.request(url, httpMethod = HttpPost, headers = headers, body = $payload)
      let code = resp.code.int

      if code == 200:
        try:
          let node = parseJson(resp.body)
          if node.kind == JObject and node.hasKey("ok") and node["ok"].getBool(false):
            return authOk
          return authInvalid
        except CatchableError:
          return authFailure
      elif code == 401 or code == 403:
        return authInvalid
      elif code >= 500:
        return authFailure
      else:
        return authInvalid
    except CatchableError:
      return authFailure
