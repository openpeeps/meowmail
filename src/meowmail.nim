# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

from std/net import Port, `$`
import ./meowmail/server/smtpserver

when isMainModule:
  let server = newSMTPServer(Port(2525))
  echo "SMTP server running on port ", server.port
  start(server)