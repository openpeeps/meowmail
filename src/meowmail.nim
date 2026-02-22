# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail
import std/envvars

from std/net import Port, `$`
import ./meowmail/smtpserver

when isMainModule:
  import std/options

  # swaks --server 127.0.0.1 --port 465 --tls-on-connect \
  #   --from alice@example.com --to bob@example.com \
  #   --auth LOGIN --auth-user alice --auth-password secret

  let server = newSMTPServer(port = Port(2525),
            someTlsCerts = some(("tests/certs/smtp-cert.pem", "tests/certs/smtp-key.pem")))
  
  server.authProvider = proc(req: AuthRequest): AuthDecision {.gcsafe.} =
    # a sample auth provider that only accepts a single username/password pair
    if req.username == "alice" and req.password == "secret":
      result = adOk # otherwise default `AuthDecision.adInvalid` is returned

  echo "SMTP server running on port ", server.port
  start(server)
