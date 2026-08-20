## MeowMail JMAP — Type definitions for JMAP Core (RFC 8620) and Mail (RFC 8621).
##
## All types use openparser's serialization hooks. The top-level request/response
## envelope uses JsonNode for JMAP's positional `[name, args, callId]` array
## format; per-method args/results are typed Nim objects.

import std/[tables, options]
import openparser/json

type
  # ── Request / Response envelope ───────────────────────────────────────────

  JMAPRequest* = object
    `using`*: seq[string]                   ## Capability URNs the client uses
    methodCalls*: seq[seq[JsonNode]]        ## [[name, args, callId], ...]
    createdIds*: Option[Table[string, string]]

  JMAPResponse* = object
    methodResponses*: seq[seq[JsonNode]]    ## [[name, result, callId], ...]
    sessionState*: string
    createdIds*: Option[Table[string, string]]

  # ── JMAP error types (RFC 8620 §3.6) ──────────────────────────────────────

  JMAPErrorType* = enum
    errServerUnavailable = "serverUnavailable"
    errServerFail = "serverFail"
    errServerPartialFail = "serverPartialFail"
    errUnknownMethod = "unknownMethod"
    errInvalidArguments = "invalidArguments"
    errInvalidResultReference = "invalidResultReference"
    errForbidden = "forbidden"
    errAccountNotFound = "accountNotFound"
    errAccountNotSupportedByMethod = "accountNotSupportedByMethod"
    errAccountReadOnly = "accountReadOnly"
    errNotFound = "notFound"
    errAlreadyExists = "alreadyExists"
    errOverQuota = "overQuota"
    errRateLimit = "rateLimit"
    errSyntaxError = "syntaxError"
    errRequestTooLarge = "requestTooLarge"
    errInvalidType = "invalidType"
    errTooManyObjects = "tooManyObjects"
    errValueDoesNotExist = "valueDoesNotExist"

  JMAPError* = object
    ## A method-level error response.
    `type`*: JMAPErrorType
    description*: Option[string]

  # ── Session Object (RFC 8620 §2) ──────────────────────────────────────────

  JMAPSession* = object
    capabilities*: JsonNode
    accounts*: Table[string, JMAPAccount]
    primaryAccounts*: Table[string, string]
    username*: string
    apiUrl*: string
    downloadUrl*: string
    uploadUrl*: string
    eventSourceUrl*: string
    state*: string

  JMAPAccount* = object
    name*: string
    isPersonal*: bool
    isReadOnly*: bool
    accountCapabilities*: JsonNode

  # ── Core capability (RFC 8620 §2) ─────────────────────────────────────────

  CoreCapability* = object
    maxSizeUpload*: int
    maxConcurrentUpload*: int
    maxSizeRequest*: int
    maxConcurrentRequests*: int
    maxCallsInRequest*: int
    maxObjectsInGet*: int
    maxObjectsInSet*: int
    collationAlgorithms*: seq[string]

  # ── Core/echo (RFC 8620 §4) ───────────────────────────────────────────────

  Core_echoArgs* = object
    ## Echo arguments — any key/value pairs.
    ## We keep this as raw JsonNode since the spec says echo back everything.
    discard

  # ── Mailbox types (RFC 8621 §2) — stubs for Phase 2 ──────────────────────

  Mailbox_getArgs* = object
    accountId*: string
    ids*: seq[string]
    properties*: seq[string]

  Mailbox_getResponse* = object
    accountId*: string
    state*: string
    list*: seq[JsonNode]      ## Will be seq[MailboxData] in Phase 2
    notFound*: seq[string]

  # ── Helpers ────────────────────────────────────────────────────────────────

proc newJMAPError*(errType: JMAPErrorType, desc: string = ""): seq[JsonNode] =
  ## Build a method-level error response: ["error", {type, description?}, callId].
  ## callId is filled in by the caller.
  var errObj = newJObject()
  errObj["type"] = newJString($errType)
  if desc.len > 0:
    errObj["description"] = newJString(desc)
  result = @[newJString("error"), errObj]

proc newJMAPErrorResponse*(callId: string, errType: JMAPErrorType,
                           desc: string = ""): seq[JsonNode] =
  ## Build a complete method-level error response with callId.
  var errObj = newJObject()
  errObj["type"] = newJString($errType)
  if desc.len > 0:
    errObj["description"] = newJString(desc)
  result = @[newJString("error"), errObj, newJString(callId)]

proc newJMAPOkResponse*(methodName: string, payload: JsonNode,
                        callId: string): seq[JsonNode] =
  ## Build a successful method response: [methodName, result, callId].
  result = @[newJString(methodName), payload, newJString(callId)]

proc newJMAPRequestLevelError*(errType: string, status: int,
                               detail: string): JsonNode =
  ## Build a request-level error (RFC 8620 §3.6.1) as a JSON problem details object.
  result = newJObject()
  result["type"] = newJString(errType)
  result["status"] = newJInt(status)
  result["detail"] = newJString(detail)
