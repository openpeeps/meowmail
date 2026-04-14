# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

from std/net import Port, `$`
import ./meowmail/[smtpserver, smtpauth, imapserver]

when isMainModule:
  # This is a simple example of how to start the MeowMail server with a
  # custom authentication provider and delivery provider.
  import std/[options, os]
  import pkg/smtp
  
  let certs = some((absolutePath("tests/certs/smtp-cert.pem"), absolutePath("tests/certs/smtp-key.pem")))
  var smtpServerInstance = newSMTPServer(
    settings = SMTPSettings(
      certifications: certs,
      mxConfig: initMXProviderConfig(
        heloName = "mail.yourdomain.tld",
        requireStartTls = false,
        debug = true
      )
    )
  )

  var thr: array[0..1, Thread[(ptr SMTPServer, Port)]]

  proc initSMTPServer(args: (ptr SMTPServer, Port)) {.thread.} =
    # Initialize the SMTP server with the specified port and set up the authentication provider.
    {.gcsafe.}:
      let (server, port) = args
      # when the server receives and auth request, this auth provider will be triggered to 
      # validate the credentials. In a real implementation, you will need to
      # bring your own user database and the logic to validate the credentials.
      # - You can use pkg/ozark for ORM and database access if needed
      # - For password hashing and validation, consider using `pkg/e2ee`
      server[].authProvider = proc(req: AuthRequest): AuthDecision {.gcsafe.} =
        # todo implement a real auth system here
        if req.username == "alice" and req.password == "secret":
          result = AuthDecision.authOk # otherwise default `AuthDecision.authInvalid` is returned
      server[].start()

  # create thread for main SMTP server
  createThread(thr[0], initSMTPServer, (addr(smtpServerInstance), Port(25)))

  # give the main server a moment to start up
  # before starting the submission server
  sleep(100)

  # create thread for imap server
  proc initImapServer(port: Port) =
    let imapServerInstance = newIMAPServer(port)
    imapServerInstance.start()

  var imapThread: Thread[Port]
  createThread(imapThread, initImapServer, Port(143))

  joinThreads(thr)
       
