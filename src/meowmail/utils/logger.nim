## Logger is a simple and efficient logging library for Nim, designed to provide
## a flexible and easy-to-use logging solution for applications of all sizes.
## It supports logging to both files and the console, with customizable log levels,
## namespaces, and formatting options.
## 
## This is a modified version of the original Logger library, from [Miqueas Martínez](https://github.com/Miqueas)
## [Nelson "darltrash" López](https://github.com/darltrash).
## 
## This modified version makes use of a read-write lock to ensure thread safety when
## multiple threads are logging simultaneously.
## 
## License zlib | (c) 2026 Miqueas Martínez & Nelson López.
## 
## Modified by George Lemon for Supranim Framework | https://supranim.com 

import std/[os, times, tables, syncio,
            strutils, strformat, options, json]

import pkg/threading/rwlock

type
  LogLevel* = enum OTHER, TRACE, INFO, DEBUG, WARN, ERROR, FATAL
  LogFormat* = enum fmtText, fmtJson
  Logger* = ref object
    # Private
    file: File # Internal file used to write logs
    logsFolder: string # Path where logs are saved
    # Public
    filePrefix*: TimeFormat # Log file name prefix
    namespace*: string # Logging namespace
    exitOnError*: bool # Enable/disable calling `quit` in case of `ERROR` or `FATAL`
    logToFile*: bool # Enable/disable logging to file
    logToConsole*: bool # Enable/disable logging to console
    defaultLogLevel*: LogLevel # Default logging level
    minLevel*: LogLevel # Minimum level to actually emit (runtime filter)
    format*: LogFormat # Output format (text or JSON)
    maxFileSize*: int # Max log file size in bytes (0 = no rotation)
    maxFiles*: int # Max number of rotated log files to keep

var logitRwLock = createRwLock()

proc e(n: varargs[int]): string =
  '\e' & '[' & join(n, ";") & 'm'

proc `$`*(lvl: LogLevel): string =
  return case lvl:
    of OTHER: "OTHER"
    of TRACE: "TRACE"
    of INFO: "INFO"
    of DEBUG: "DEBUG"
    of WARN: "WARN"
    of ERROR: "ERROR"
    of FATAL: "FATAL"

const
  fmt = (
    fileName: "$1_$2.log",
    time: "HH:mm:ss",
    fileLine: "$1 [$3.$2] $4 $5:$6 $7\n", # $3=level, $2=namespace, $4=threadId, $5=filename, $6=line, $7=message
    consoleLine: fmt"{e(2)}$1 [{e(0,1)}$3$4{e(0,2)}.$2] $5 $6:$7{e(0)} $8",
    #                                  ^~ This one is used for the log level color
    fileHeader: "\n$1 [$2]\n\n",
    consoleHeader: '\n' & fmt"{e(2)}$1 [{e(0, 1)}$2{e(0, 2)}]{e(0)}" & '\n',
    fileExit: "$1 [EXIT]\n",
    consoleExit: fmt"{e(2)}$1 [{e(0, 1)}$2EXIT{e(0, 2)}]{e(0)}",
    #                                   ^~ This one is used for the log level color
    threadId: "TID-$1"
  )

  assoc = toTable({
    OTHER: 30,
    TRACE: 32,
    INFO: 34,
    DEBUG: 36,
    WARN: 33,
    ERROR: 31,
    FATAL: 35,
  })

# Creates a new `Logger` object using the given properties
# or fallback to default values if not arguments
# given
proc newLogger*(
   logsFolder = getTempDir(),
   namespace = "Logger",
   defaultLogLevel = OTHER,
   logToFile = true,
   logToConsole = false,
   exitOnError = false,
   filePrefix = initTimeFormat("YYYY-MM-dd"),
   minLevel = OTHER,
   format = fmtText,
   maxFileSize = 0,
   maxFiles = 0,
): Logger {.raises: [IOError].} =
  ## Initializes a `Logger` instance with the specified configuration.
  if not dirExists(logsFolder):
    raise newException(IOError, fmt"`{logsFolder}` isn't a valid path or doesn't exists")

  return Logger(
    logsFolder: logsFolder,
    filePrefix: filePrefix,
    namespace: namespace,
    exitOnError: exitOnError,
    logToFile: logToFile,
    logToConsole: logToConsole,
    defaultLogLevel: defaultLogLevel,
    minLevel: minLevel,
    format: format,
    maxFileSize: maxFileSize,
    maxFiles: maxFiles,
  )

proc start*(self: var Logger) {.raises: [IOError, ValueError].} =
  ## Prepares Logger for logging using the given `Logger` instance.
  ## This function assumes that `Logger` has everything ready to start logging,
  ## that means you must have set the `path` property.
  if self.logToFile:
    let
      date = now().format(self.filePrefix)
      filename = fmt.fileName.format(date, self.namespace)
      fullPath = self.logsFolder / filename
    try:
      self.file = open(self.logsFolder / filename, fmAppend)
      self.file.flushFile() # ensure handle is initialized/flushed
    except:
      raise newException(IOError, fmt"can't open/write file {filename}")

# Logging API
type
  InstantiationInfo* = tuple[filename: string, line: int, column: int]

template log*(self: Logger, level: LogLevel, message: string,
              autoNewLine = true, someInfo = none(InstantiationInfo)) =
  ## Logs a message with the specified log level. The `message` can be a string
  ## or any expression that evaluates to a string. The `autoNewLine` parameter determines
  ## whether to automatically add a newline after the message (default is true).
  # Runtime level filter: skip messages below the configured minimum level
  if ord(level) < ord(self.minLevel):
    discard
  else:
    let
      time = now().format(fmt.time)
      info =
        if someInfo.isSome:
          someInfo.get()
        else:
          instantiationInfo(0)
      tid = when declared(getThreadId):
        fmt.threadId.format($getThreadId())
      else:
        fmt.threadId.format("0")

    if self.logToFile:
      writeWith logitRwLock:
        var msg: string
        if self.format == fmtJson:
          msg = "{\"time\":\"" & time & "\",\"level\":\"" & $level &
                "\",\"ns\":\"" & self.namespace & "\",\"tid\":\"" & tid &
                "\",\"file\":\"" & info.filename & "\",\"line\":" & $info.line &
                ",\"msg\":" & escapeJson(message) & "}\n"
        else:
          msg = fmt.fileLine.format(time, self.namespace,
                        $level, tid, info.filename, info.line, message)

        if autoNewLine: self.file.write(msg)
        else: self.file.write(msg.substr(0, msg.len - 2))

        # ensure the message is written to disk immediately
        self.file.flushFile()

        # Log rotation: check file size and rotate if needed
        if self.maxFileSize > 0 and self.file.getFileSize() >= self.maxFileSize:
          self.file.close()
          let date = now().format(self.filePrefix)
          let baseName = fmt.fileName.format(date, self.namespace)
          # Rotate existing files
          if self.maxFiles > 0:
            for i in countdown(self.maxFiles - 1, 1):
              let old = self.logsFolder / (baseName & "." & $i)
              let newf = self.logsFolder / (baseName & "." & $(i + 1))
              if fileExists(old):
                try: moveFile(old, newf)
                except CatchableError: discard
            let rotated = self.logsFolder / (baseName & ".1")
            try: moveFile(self.logsFolder / baseName, rotated)
            except CatchableError: discard
          # Reopen fresh file
          try:
            self.file = open(self.logsFolder / baseName, fmAppend)
          except CatchableError:
            discard
    
    if self.logToConsole:
      writeWith logitRwLock:
        var msg: string
        if self.format == fmtJson:
          msg = "{\"time\":\"" & time & "\",\"level\":\"" & $level &
                "\",\"ns\":\"" & self.namespace & "\",\"tid\":\"" & tid &
                "\",\"file\":\"" & info.filename & "\",\"line\":" & $info.line &
                ",\"msg\":" & escapeJson(message) & "}"
        else:
          msg = fmt.consoleLine.format(time, self.namespace,
                      e(assoc[level]), $level, tid, info.filename, info.line, message)

        if autoNewLine: echo msg
        else:
            stdout.write(msg)
            stdout.flushFile()

    if self.exitOnError and ord(level) > ord(WARN):
      if self.logToFile:
        writeWith logitRwLock:
          self.file.write(fmt.fileExit.format(time))
          self.file.close()

      if self.logToConsole:
        quit(fmt.consoleExit.format(time, e(assoc[level])), QuitFailure)

      quit(QuitFailure)

# Shortcuts
template log*(self: Logger, message = "", autoNewLine = true) = self.log(self.defaultLogLevel, message, autoNewLine)
template other*(self: Logger, message = "", autoNewLine = true) = self.log(OTHER, message, autoNewLine)
template trace*(self: Logger, message = "", autoNewLine = true) = self.log(TRACE, message, autoNewLine)
template info*(self: Logger, message = "", autoNewLine = true) = self.log(INFO, message, autoNewLine)
template debug*(self: Logger, message = "", autoNewLine = true) = self.log(DEBUG, message, autoNewLine)
template warn*(self: Logger, message = "", autoNewLine = true) = self.log(WARN, message, autoNewLine)
template error*(self: Logger, message = "", autoNewLine = true) = self.log(ERROR, message, autoNewLine)
template fatal*(self: Logger, message = "", autoNewLine = true) = self.log(FATAL, message, autoNewLine)
    
# Writes a "header"
proc header*(self: Logger, message: string) =
  let time = now().format(fmt.time)
  if self.logToFile: self.file.write(fmt.fileHeader.format(time, message))
  if self.logToConsole: echo fmt.consoleHeader.format(time, message)

# Closes the internal file. Call this proc if you're sure you'll not need to use a `Logger` instance anymore
proc finish*(self: var Logger) {.inline.} = self.file.close()

# Getter for `path`
proc logsFolder*(self: Logger): string {.inline.} = return self.logsFolder

# Setter for `path`
proc `logsFolder=`*(self: var Logger, newLogsFolder: string) {.raises: [IOError, ValueError].} =
  if not dirExists(newLogsFolder):
    raise newException(IOError, fmt"`{newLogsFolder}` isn't a valid path or doesn't exists")
  self.logsFolder = newLogsFolder

