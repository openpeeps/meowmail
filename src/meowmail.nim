# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

from std/net import Port, `$`
import ./meowmail/[smtpserver, smtpauth, imapserver, socksubmission]

when isMainModule:
  # This is a simple example of how to start the MeowMail server with a
  # custom authentication provider and delivery provider.
  import std/[options, os]
  
  let certs = some((absolutePath("tests/certs/smtp-cert.pem"), absolutePath("tests/certs/smtp-key.pem")))
  var smtpServerInstance = newSMTPServer(
    port = Port(2525),
    someTlsCerts = certs,
    enable587 = false,
    enable465 = false,
    enableMxDelivery = true,
    mxConfig = initMXProviderConfig(
      heloName = "mail.yourdomain.tld",
      requireStartTls = false,
      debug = true
    )
  )

  var thr: array[0..1, Thread[(ptr SMTPServer, Port)]]

  proc initSMTPServer(args: (ptr SMTPServer, Port)) {.thread.} =
    {.gcsafe.}:
      let (server, port) = args
      # The auth provider is a callback that the server will call
      # when a client attempts to authenticate. It should return an `AuthDecision`
      # indicating whether the authentication was successful, and if so, any
      # associated user information.
      server[].authProvider = proc(req: AuthRequest): AuthDecision {.gcsafe.} =
        # todo implement a real auth system here
        if req.username == "alice" and req.password == "secret":
          result = AuthDecision.authOk # otherwise default `AuthDecision.authInvalid` is returned
      echo "Start MeowMail server: ", port
      server[].start()

  # create thread for main SMTP server
  createThread(thr[0], initSMTPServer,
              (addr(smtpServerInstance), Port(2525)))

  # give the main server a moment to start up
  # before starting the submission server
  sleep(100)

  proc initSubmissionServer(args: (ptr SMTPServer, Port)) =
    let (server, port) = args
    echo "Starting submission socket server on port ", port
    server[].startSubmissionSocketServer(port)

  # create thread for submission socket server
  createThread(thr[1], initSubmissionServer,
                (addr(smtpServerInstance), Port(587)))

  # give the submission server a moment to start up
  sleep(100)

  # create thread for imap server
  proc initImapServer(port: Port = Port(143)) =
    echo "Starting IMAP server on port ", port
    let imapServerInstance = newIMAPServer(port)
    imapServerInstance.start()

  var imapThread: Thread[Port]
  createThread(imapThread, initImapServer, Port(143))

  joinThreads(thr)
