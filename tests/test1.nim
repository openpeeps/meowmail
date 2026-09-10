when defined(macosx):
  # spf2 headers require arpa/nameser.h before the spf package's forced
  # "-include spf.h". Must precede imports (same as src/meowmail.nim).
  {.passC: "-include arpa/nameser.h".}

import unittest
import meowmail

let swaks1 = """
swaks --server 127.0.0.1:2525 --from alice@example.com --to bob@example.com --data "Subject: test\n\nHello from swaks"
"""

test "swaks send unauth email":
  discard

test "swaks send email with auth":
  let swaksCommand = """swaks --server 127.0.0.1 --port 2525 \
  --ehlo test.local \
  --from alice@example.com \
  --to bob@example.com \
  --auth LOGIN \
  --auth-user alice \
  --auth-password secret \
  --data $'Subject: test\r\n\r\nHello from swaks'"""

test"swaks send email with bad auth":
  let swaksCommand = """swaks --server 127.0.0.1 --port 2525 \
  --from alice@example.com \
  --to bob@example.com \
  --auth LOGIN \
  --auth-user alice \
  --auth-password wrongpass"""


test "swaks send email with 465 implicit TLS":
  let swaksCommand = """swaks --server 127.0.0.1 --port 465 --tls-on-connect \
  --from alice@example.com --to bob@example.com \
  --auth LOGIN --auth-user alice --auth-password secret"""

test "swaks send email with 587 STARTTLS":
  let swaksCommand = """swaks --server 127.0.0.1 --port 587 --tls \
  --from alice@example.com --to bob@example.com \
  --auth LOGIN --auth-user alice --auth-password secret"""