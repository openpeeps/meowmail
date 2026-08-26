## MeowMail — Persistent outbound message queue with retry and backoff.
##
## Messages are spooled to disk as `.eml` files with envelope metadata.
## A background queue runner processes deferred messages with exponential
## backoff. The queue survives server restarts.

import std/[os, strutils, times, options, algorithm, sequtils, locks, posix]
import pkg/flysystem
import ./smtpdelivery
import ./bounce
import ../imap/mailstore
import ../utils/logger

type
  QueueStatus* = enum
    qsDeferred    ## Waiting for retry
    qsActive      ## Currently being delivered
    qsDelivered   ## Successfully delivered
    qsBounced     ## Permanent failure, bounce generated
    qsFailed      ## Unrecoverable error

  QueueEntry* = object
    id*: string             ## Filename without extension
    path*: string           ## Spool file path, relative to the queue root
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
    store*: StorageDriver   ## Flysystem-backed spool storage (atomic writes)
    entries*: seq[QueueEntry]
    lock*: Lock
    nameSeq: uint64         ## Filename sequence counter (guarded by lock)
    maxRetries*: int
    baseDelay*: int         ## Initial retry delay in seconds
    maxDelay*: int          ## Maximum retry delay in seconds

# ── Helpers ───────────────────────────────────────────────────────────────────

# Flysystem drivers are dispatched through methods the effect system cannot
# prove GC-safe. The LocalDriver used here is stateless after construction
# (immutable root, no shared mutable state), so the cast boundary below is
# sound; spool operations run on delivery threads and the queue runner.
proc stRead(store: StorageDriver, path: string): string =
  {.cast(gcsafe).}:
    result = store.read(path)

proc stWrite(store: StorageDriver, path, content: string) =
  {.cast(gcsafe).}:
    store.write(path, content)

proc stDelete(store: StorageDriver, path: string) =
  {.cast(gcsafe).}:
    store.delete(path)

proc stExists(store: StorageDriver, path: string): bool =
  {.cast(gcsafe).}:
    result = store.exists(path)

proc stSearch(store: StorageDriver, pattern: string): seq[string] =
  {.cast(gcsafe).}:
    result = store.search(pattern)

proc parseSpoolFile(store: StorageDriver, path: string): QueueEntry =
  ## Parse a spool .eml file into a QueueEntry. `path` is relative to the
  ## storage root.
  result.path = path
  result.id = extractFilename(path).changeFileExt("")
  result.status = qsDeferred
  result.retryCount = 0
  result.nextRetry = getTime()
  result.created = getTime()

  try:
    let content = stRead(store, path)
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
  ## Create a new queue backed by the given directory. Spool I/O goes through
  ## a flysystem LocalDriver rooted at `dir` (atomic writes, traversal-safe
  ## paths). The root directory is created if missing.
  result = Queue(
    dir: dir,
    store: newLocalDriver(dir),
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
    for relPath in stSearch(queue.store, "*.eml"):
      var entry = parseSpoolFile(queue.store, relPath)
      # Check for associated metadata (.meta file)
      let metaPath = relPath.changeFileExt(".meta")
      if stExists(queue.store, metaPath):
        try:
          let meta = stRead(queue.store, metaPath).splitLines()
          for line in meta:
            if line.startsWith("retryCount="):
              entry.retryCount = parseInt(line[11 .. ^1])
            elif line.startsWith("nextRetry="):
              let ts = parseFloat(line[10 .. ^1])
              entry.nextRetry = fromUnixFloat(ts)
            elif line.startsWith("status="):
              # Meta files historically contained either bare words
              # ("deferred") or Nim enum names ("qsDeferred"); accept both.
              var st = line[7 .. ^1].toLowerAscii()
              if st.startsWith("qs"):
                st = st[2 .. ^1]
              case st
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
  ## Persist queue entry metadata to a .meta file (atomic write).
  let metaPath = entry.path.changeFileExt(".meta")
  var meta: string
  meta.add("retryCount=" & $entry.retryCount & "\n")
  meta.add("nextRetry=" & $entry.nextRetry.toUnixFloat & "\n")
  meta.add("status=" & $entry.status & "\n")
  if entry.lastError.len > 0:
    meta.add("lastError=" & entry.lastError & "\n")
  try:
    stWrite(queue.store, metaPath, meta)
  except CatchableError:
    discard

proc deleteEntryFiles*(queue: Queue, entry: QueueEntry) =
  ## Delete the spool file and its metadata file. Missing files are ignored.
  try:
    if stExists(queue.store, entry.path):
      stDelete(queue.store, entry.path)
    let metaPath = entry.path.changeFileExt(".meta")
    if stExists(queue.store, metaPath):
      stDelete(queue.store, metaPath)
  except CatchableError:
    discard

proc enqueue*(queue: Queue, req: DeliveryRequest): string =
  ## Add a message to the queue. Returns the queue entry ID.
  # Build the spool payload before touching shared state.
  var payload: string
  payload.add("X-MeowMail-Envelope-From: " & req.mailFrom & "\r\n")
  for rcpt in req.rcptTo:
    payload.add("X-MeowMail-Envelope-To: " & rcpt & "\r\n")
  if req.heloName.len > 0:
    payload.add("X-MeowMail-Helo: " & req.heloName & "\r\n")
  payload.add("\r\n")
  payload.add(req.data)

  var fileName: string
  withLock(queue.lock):
    inc queue.nameSeq
    let tsMs = int64(epochTime() * 1000.0)
    fileName = $tsMs & "-" & $getpid() & "-" & $queue.nameSeq & ".eml"

  let path = fileName
  try:
    # Atomic write via flysystem (temp file + rename in the same directory).
    stWrite(queue.store, path, payload)
  except CatchableError:
    return ""

  var entry = parseSpoolFile(queue.store, path)
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
        queue.deleteEntryFiles(queue.entries[i])
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

proc routeBounce*(localStore: MaildirStore, q: Queue, envelopeFrom, rcpt, helo: string,
                  status: DsnStatus, diag: string = ""): bool =
  ## Generate a DSN bounce for one recipient and route it to the original
  ## sender: local senders receive it in their Maildir, remote senders get it
  ## enqueued with a null return-path (loop-safe: bounces never bounce).
  let (bounceTo, bounceBody) = generateBounce(envelopeFrom, rcpt, helo, status, diag)
  if bounceTo.len == 0 or bounceBody.len == 0:
    return false  # loop prevention (empty sender or postmaster)
  if localStore != nil and localStore.isLocal(bounceTo):
    result = localStore.deliver("MAILER-DAEMON@meowmail.local", bounceTo, bounceBody)
  elif q != nil:
    let id = q.enqueue(DeliveryRequest(
      mailFrom: "",
      rcptTo: @[bounceTo],
      data: bounceBody,
      heloName: "meowmail.local",
    ))
    result = id.len > 0

proc bounceEntry(queue: Queue, entry: QueueEntry, localStore: MaildirStore,
                 status: DsnStatus, diag: string) =
  ## Generate DSN bounces for every recipient of a failed queue entry.
  for rcpt in entry.rcptTo:
    discard routeBounce(localStore, queue, entry.mailFrom, rcpt,
                        entry.heloName, status, diag)

proc attemptEntry*(queue: Queue, entryId: string,
                   deliverProc: proc(req: DeliveryRequest): DeliveryOutcome {.gcsafe.},
                   localStore: MaildirStore): bool =
  ## Attempt one delivery of the queue entry with the given id. Handles
  ## partial acceptance (bounce permanent rejections, requeue temporary ones),
  ## retry scheduling, and bounce generation on exhaustion/permanent failure.
  ## Returns false if the entry no longer exists.
  var entry: QueueEntry
  block find:
    withLock(queue.lock):
      for e in queue.entries:
        if e.id == entryId:
          entry = e
          break find
    return false

  # Mark as active
  withLock(queue.lock):
    for i, e in queue.entries:
      if e.id == entry.id:
        queue.entries[i].status = qsActive
        break

  # Build delivery request. The spool file may have been removed by an
  # external tool (purge CLI) since it was listed; drop silently then.
  var content: string
  try:
    content = stRead(queue.store, entry.path)
  except CatchableError:
    queue.removeEntry(entry.id)
    return false
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
    let outcome = deliverProc(req)
    case outcome.decision
    of ddOk:
      # Partial acceptance: bounce permanently rejected recipients now
      # and requeue only the temporarily rejected ones, so accepted
      # recipients are never re-delivered.
      var deferred: seq[string]
      for f in outcome.failedRcpts:
        if f.permanent:
          discard routeBounce(localStore, queue, entry.mailFrom, f.rcpt,
                              entry.heloName, dsnFailed,
                              "rejected by remote host")
          if logitGlobal != nil:
            logitGlobal.info("[queue] bounced rejected recipient " & f.rcpt &
                             " for queue entry " & entry.id)
        else:
          deferred.add(f.rcpt)
      queue.markDelivered(entry.id)
      if deferred.len > 0 and entry.rcptTo.len > deferred.len:
        discard queue.enqueue(DeliveryRequest(
          mailFrom: entry.mailFrom,
          rcptTo: deferred,
          data: msgData,
          heloName: entry.heloName))
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
  result = true

proc flushQueue*(queue: Queue,
                 deliverProc: proc(req: DeliveryRequest): DeliveryOutcome {.gcsafe.},
                 localStore: MaildirStore = nil): int =
  ## Force immediate delivery of every deferred entry, overriding the backoff
  ## schedule (nextRetry is reset to now). Returns the number of entries
  ## attempted. Used by `meowmail queue flush` and the admin API.
  block reschedule:
    withLock(queue.lock):
      for i, entry in queue.entries:
        if entry.status == qsDeferred and entry.nextRetry > getTime():
          queue.entries[i].nextRetry = getTime()
          queue.saveMeta(queue.entries[i])
  let due = queue.pending()
  for entry in due:
    discard attemptEntry(queue, entry.id, deliverProc, localStore)
    inc result

proc runQueue*(queue: Queue,
               deliverProc: proc(req: DeliveryRequest): DeliveryOutcome {.gcsafe.},
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
        discard attemptEntry(queue, entry.id, deliverProc, localStore)

      sleep(intervalMs)
