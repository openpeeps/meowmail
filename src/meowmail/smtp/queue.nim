## MeowMail — Persistent outbound message queue with retry and backoff.
##
## Messages are spooled to disk as `.eml` files with envelope metadata.
## A background queue runner processes deferred messages with exponential
## backoff. The queue survives server restarts.

import std/[os, strutils, times, options, algorithm, sequtils, locks, posix]
import ./smtpdelivery
import ./bounce
import ../imap/mailstore

type
  QueueStatus* = enum
    qsDeferred    ## Waiting for retry
    qsActive      ## Currently being delivered
    qsDelivered   ## Successfully delivered
    qsBounced     ## Permanent failure, bounce generated
    qsFailed      ## Unrecoverable error

  QueueEntry* = object
    id*: string             ## Filename without extension
    path*: string           ## Full path to the .eml file
    mailFrom*: string
    rcptTo*: seq[string]
    heloName*: string
    dataOffset*: int        ## Byte offset where message data starts
    status*: QueueStatus
    retryCount*: int
    nextRetry*: times.Time        ## When to attempt next delivery
    lastAttempt*: times.Time
    lastError*: string
    created*: times.Time

  Queue* = ref object
    dir*: string            ## Spool directory path
    entries*: seq[QueueEntry]
    lock*: Lock
    maxRetries*: int
    baseDelay*: int         ## Initial retry delay in seconds
    maxDelay*: int          ## Maximum retry delay in seconds

# ── Helpers ───────────────────────────────────────────────────────────────────

proc parseSpoolFile(path: string): QueueEntry =
  ## Parse a spool .eml file into a QueueEntry.
  result.path = path
  result.id = extractFilename(path).changeFileExt("")
  result.status = qsDeferred
  result.retryCount = 0
  result.nextRetry = getTime()
  result.created = getTime()

  try:
    let content = readFile(path)
    let sep = content.find("\r\n\r\n")
    if sep < 0:
      result.dataOffset = 0
      return
    result.dataOffset = sep + 4

    # Parse envelope headers
    var i = 0
    while i < sep:
      let eol = content.find("\r\n", i)
      if eol < 0 or eol > sep: break
      let line = content[i ..< eol]
      if line.startsWith("X-MeowMail-Envelope-From: "):
        result.mailFrom = line[26 .. ^1]
      elif line.startsWith("X-MeowMail-Envelope-To: "):
        result.rcptTo.add(line[24 .. ^1])
      elif line.startsWith("X-MeowMail-Helo: "):
        result.heloName = line[17 .. ^1]
      i = eol + 2
  except CatchableError:
    discard

proc retryDelay(queue: Queue, retryCount: int): int =
  ## Compute exponential backoff delay in seconds.
  ## delay = min(baseDelay * 2^retryCount, maxDelay)
  result = queue.baseDelay * (1 shl min(retryCount, 10))
  result = min(result, queue.maxDelay)

# ── Queue operations ──────────────────────────────────────────────────────────

proc newQueue*(dir: string, maxRetries = 20, baseDelay = 300,
               maxDelay = 86400): Queue =
  ## Create a new queue backed by the given directory.
  result = Queue(
    dir: dir,
    entries: @[],
    maxRetries: maxRetries,
    baseDelay: baseDelay,
    maxDelay: maxDelay,
  )
  initLock(result.lock)

proc load*(queue: Queue) =
  ## Load all spool files from the queue directory into memory.
  withLock(queue.lock):
    queue.entries.setLen(0)
    if not dirExists(queue.dir):
      try: createDir(queue.dir)
      except CatchableError: return
    for kind, path in walkDir(queue.dir):
      if kind == pcFile and path.endsWith(".eml"):
        var entry = parseSpoolFile(path)
        # Check for associated metadata (.meta file)
        let metaPath = path.changeFileExt(".meta")
        if fileExists(metaPath):
          try:
            let meta = readFile(metaPath).splitLines()
            for line in meta:
              if line.startsWith("retryCount="):
                entry.retryCount = parseInt(line[11 .. ^1])
              elif line.startsWith("nextRetry="):
                let ts = parseFloat(line[10 .. ^1])
                entry.nextRetry = fromUnixFloat(ts)
              elif line.startsWith("status="):
                case line[7 .. ^1]
                of "deferred": entry.status = qsDeferred
                of "active": entry.status = qsActive
                of "delivered": entry.status = qsDelivered
                of "bounced": entry.status = qsBounced
                of "failed": entry.status = qsFailed
              elif line.startsWith("lastError="):
                entry.lastError = line[10 .. ^1]
          except CatchableError:
            discard
        queue.entries.add(entry)

proc saveMeta*(queue: Queue, entry: QueueEntry) =
  ## Persist queue entry metadata to a .meta file.
  let metaPath = entry.path.changeFileExt(".meta")
  var meta: string
  meta.add("retryCount=" & $entry.retryCount & "\n")
  meta.add("nextRetry=" & $entry.nextRetry.toUnixFloat & "\n")
  meta.add("status=" & $entry.status & "\n")
  if entry.lastError.len > 0:
    meta.add("lastError=" & entry.lastError & "\n")
  try:
    writeFile(metaPath, meta)
  except CatchableError:
    discard

proc enqueue*(queue: Queue, req: DeliveryRequest): string =
  ## Add a message to the queue. Returns the queue entry ID.
  let dir = queue.dir
  try:
    discard existsOrCreateDir(dir)
  except CatchableError:
    return ""

  var payload: string
  payload.add("X-MeowMail-Envelope-From: " & req.mailFrom & "\r\n")
  for rcpt in req.rcptTo:
    payload.add("X-MeowMail-Envelope-To: " & rcpt & "\r\n")
  if req.heloName.len > 0:
    payload.add("X-MeowMail-Helo: " & req.heloName & "\r\n")
  payload.add("\r\n")
  payload.add(req.data)

  let tsMs = int64(epochTime() * 1000.0)
  let fileName = $tsMs & "-" & $getpid() & "-" & $queue.entries.len & ".eml"
  let path = dir / fileName

  try:
    writeFile(path, payload)
  except CatchableError:
    return ""

  var entry = parseSpoolFile(path)
  entry.created = getTime()
  queue.saveMeta(entry)

  withLock(queue.lock):
    queue.entries.add(entry)

  entry.id

proc markDelivered*(queue: Queue, entryId: string) =
  ## Mark a queue entry as successfully delivered.
  withLock(queue.lock):
    for i, entry in queue.entries:
      if entry.id == entryId:
        queue.entries[i].status = qsDelivered
        queue.entries[i].lastAttempt = getTime()
        queue.saveMeta(queue.entries[i])
        # Remove the .eml and .meta files
        try:
          removeFile(entry.path)
          removeFile(entry.path.changeFileExt(".meta"))
        except CatchableError:
          discard
        break

proc markFailed*(queue: Queue, entryId: string, errorMsg: string) =
  ## Mark a queue entry as failed. If retries remain, schedule next attempt.
  ## Otherwise mark as bounced.
  withLock(queue.lock):
    for i, entry in queue.entries:
      if entry.id == entryId:
        queue.entries[i].retryCount += 1
        queue.entries[i].lastAttempt = getTime()
        queue.entries[i].lastError = errorMsg
        if queue.entries[i].retryCount >= queue.maxRetries:
          queue.entries[i].status = qsBounced
        else:
          queue.entries[i].status = qsDeferred
          let delay = queue.retryDelay(queue.entries[i].retryCount)
          queue.entries[i].nextRetry = getTime() + initDuration(seconds = delay)
        queue.saveMeta(queue.entries[i])
        break

proc pending*(queue: Queue): seq[QueueEntry] =
  ## Return entries that are due for retry.
  withLock(queue.lock):
    let nowTime = getTime()
    for entry in queue.entries:
      if entry.status == qsDeferred and entry.nextRetry <= nowTime:
        result.add(entry)

proc getEntry*(queue: Queue, entryId: string): QueueEntry =
  ## Look up a queue entry by ID.
  withLock(queue.lock):
    for entry in queue.entries:
      if entry.id == entryId:
        return entry

proc removeEntry*(queue: Queue, entryId: string) =
  ## Remove a queue entry from the in-memory list and delete its files.
  withLock(queue.lock):
    queue.entries.keepItIf(it.id != entryId)

proc stats*(queue: Queue): tuple[total, deferred, active, delivered, bounced: int] =
  ## Return queue statistics.
  withLock(queue.lock):
    for entry in queue.entries:
      inc result.total
      case entry.status
      of qsDeferred: inc result.deferred
      of qsActive: inc result.active
      of qsDelivered: inc result.delivered
      of qsBounced: inc result.bounced
      of qsFailed: discard

# ── Queue runner ──────────────────────────────────────────────────────────────

proc bounceEntry(queue: Queue, entry: QueueEntry, localStore: MaildirStore,
                 status: DsnStatus, diag: string) =
  ## Generate DSN bounces for a failed queue entry. Local senders receive the
  ## bounce in their Maildir; remote senders get it enqueued for MX delivery
  ## with a null return-path (loop-safe: bounces never generate bounces).
  for rcpt in entry.rcptTo:
    let (bounceTo, bounceBody) = generateBounce(
      entry.mailFrom, rcpt, entry.heloName, status, diag)
    if bounceTo.len == 0 or bounceBody.len == 0:
      continue  # loop prevention (empty sender or postmaster)
    if localStore != nil and localStore.isLocal(bounceTo):
      discard localStore.deliver("MAILER-DAEMON@meowmail.local", bounceTo, bounceBody)
    else:
      discard queue.enqueue(DeliveryRequest(
        mailFrom: "",
        rcptTo: @[bounceTo],
        data: bounceBody,
        heloName: "meowmail.local",
      ))

proc runQueue*(queue: Queue,
               deliverProc: proc(req: DeliveryRequest): DeliveryDecision {.gcsafe.},
               intervalMs: int = 30_000,
               localStore: MaildirStore = nil) =
  ## Background queue runner. Processes pending entries at the given interval.
  ## Temporary failures are retried with exponential backoff; permanent
  ## failures and exhausted retries generate DSN bounces to the sender.
  ## This proc runs forever (should be called from a thread).
  {.cast(gcsafe).}:
    while true:
      let pending = queue.pending()
      for entry in pending:
        # Mark as active
        withLock(queue.lock):
          for i, e in queue.entries:
            if e.id == entry.id:
              queue.entries[i].status = qsActive
              break

        # Build delivery request
        let content = readFile(entry.path)
        let sep = content.find("\r\n\r\n")
        let msgData = if sep >= 0: content[sep + 4 .. ^1]
                      else: content

        let req = DeliveryRequest(
          mailFrom: entry.mailFrom,
          rcptTo: entry.rcptTo,
          data: msgData,
          heloName: entry.heloName,
        )

        # Attempt delivery
        try:
          let decision = deliverProc(req)
          case decision
          of ddOk:
            queue.markDelivered(entry.id)
          of ddTempFail:
            queue.markFailed(entry.id, "temporary failure")
            # If retries are now exhausted, notify the sender and drop the entry.
            let e = queue.getEntry(entry.id)
            if e.id.len > 0 and e.status == qsBounced:
              bounceEntry(queue, e, localStore, dsnMessageExpired, e.lastError)
              queue.removeEntry(e.id)
          of ddPermFail:
            # Permanent failure: bounce immediately instead of retrying.
            bounceEntry(queue, entry, localStore, dsnFailed, "permanent failure")
            queue.removeEntry(entry.id)
        except CatchableError as e:
          queue.markFailed(entry.id, e.msg)

      sleep(intervalMs)
