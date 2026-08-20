<p align="center">
  <img src="https://github.com/openpeeps/meowmail/blob/main/.github/meowmail.png" width="130px" height="130px"><br>
  A high-performance Mail Transfer Agent built on <a href="https://github.com/openpeeps/powpow">powpow</a>.<br>
  Written in Nim language
</p>

<p align="center">
  <code>nimble install meowmail</code>
</p>

<p align="center">
  <a href="https://openpeeps.github.io/meowmail/">API reference</a><br>
  <img src="https://github.com/openpeeps/meowmail/workflows/test/badge.svg" alt="Github Actions">
</p>

## What is MeowMail?

MeowMail is a high-performance, all-in-one mail server written in Nim. It handles SMTP (inbound/outbound), IMAP4rev1, and JMAP for modern clients — all built on powpow's event-driven networking (kqueue/epoll).

It's designed for developers and sysadmins who want to host their own email, from development environments to production deployments.

## Key Features

### SMTP Server
- Dual-stack IPv4/IPv6 listeners (ports 25, 587, 465)
- STARTTLS + implicit TLS (port 465)
- AUTH PLAIN / LOGIN with local users or HTTP auth proxy
- DKIM signing (RSA-SHA256)
- SPF verification (inbound + outbound)
- DMARC/DKIM verification (inbound)
- SIZE extension (50 MB)
- Persistent outbound queue with exponential backoff retry
- Bounce/DSN generation on delivery failure
- Rate limiting (per-IP connections, auth lockout)
- Configurable send policies (default, local-only, internal-only, no-relay)

### IMAP Server
- Full IMAP4rev1 implementation
- Maildir++ storage format
- UID/UIDVALIDITY persistence
- FETCH: ENVELOPE, BODYSTRUCTURE, BODY[section], partial, RFC822
- STORE, COPY, MOVE, EXPUNGE
- SEARCH (full query language)
- IDLE (poll-based)
- UIDPLUS, CHILDREN, NAMESPACE extensions
- STARTTLS support

### JMAP Server (RFC 8620/8621)
- Core/echo
- Mailbox/get, Mailbox/set, Mailbox/query
- Email/get, Email/set, Email/query
- Identity/get
- EmailSubmission/set
- Session discovery (`/.well-known/jmap`, `/jmap/session`)

### Operations
- Queue management CLI (`mailq`, `flush`, `retry`, `delete`, `purge`)
- Admin HTTP API (health, queue stats, metrics)
- Structured logging (text or JSON, rotation, level filtering)
- TOML configuration

## Prerequisites

- Nim >= 2.2.0
- OpenSSL development libraries
- libspf2 (SPF verification)
- libopendmarc (DMARC verification)

### Install dependencies

**macOS (Homebrew):**
```bash
brew install openssl spf2 opendmarc
```

**Debian/Ubuntu:**
```bash
apt-get install libssl-dev libspf2-dev libopendmarc-dev
```

**Arch Linux:**
```bash
pacman -S openssl spf2 opendmarc
```

## Quick Start

### 1. Initialize a config

```bash
meowmail init meowmail.toml
```

### 2. Edit the config

```toml
[smtp]
hostname = "mail.example.com"

[smtp.listen.port25]
enabled = true
port = 25

[smtp.auth]
required = true

[smtp.auth.users]
"alice@example.com" = "secret-password"

[maildir]
base = "./maildir"
local_domains = ["example.com"]

[imap]
enabled = true
port = 143

[jmap]
enabled = true
port = 8080
```

### 3. Start the server

```bash
meowmail start meowmail.toml
```

### 4. Test with swaks

```bash
swaks --server 127.0.0.1 --port 587 \
  --tls \
  --auth LOGIN \
  --auth-user alice@example.com \
  --auth-password secret-password \
  --from alice@example.com \
  --to bob@example.com \
  --header "Subject: Hello from MeowMail" \
  --body "This is a test email."
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `meowmail init <path>` | Generate a default config file |
| `meowmail start <config>` | Start the mail server |
| `meowmail queue list <dir>` | List queued messages |
| `meowmail queue stats <dir>` | Show queue statistics |
| `meowmail queue flush <dir>` | Force delivery of pending messages |
| `meowmail queue retry <dir> <id>` | Requeue a specific message |
| `meowmail queue delete <dir> <id>` | Remove a message from the queue |
| `meowmail queue purge <dir>` | Remove delivered/bounced/failed messages |
| `meowmail spf <ip4>` | Generate an SPF DNS record |
| `meowmail dkim <keyfile>` | Generate a DKIM DNS record |
| `meowmail dmarc <policyfile>` | Generate a DMARC DNS record |

## Configuration

MeowMail uses TOML configuration. See `example/meowmail.config.toml` for all options.

### Key sections

```toml
[smtp]              # SMTP server settings
[smtp.auth]         # Authentication (local users or HTTP provider)
[smtp.tls]          # TLS certificate configuration
[smtp.delivery]     # Delivery mode (mx or spool)
[maildir]           # Local Maildir storage
[imap]              # IMAP server settings
[jmap]              # JMAP server settings
[dkim]              # DKIM signing
[logging]           # Log format, rotation, level filtering
[queue]             # Outbound queue settings
[admin]             # Admin API endpoint
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `MEOWMAIL_SMTP_PORT` | Override SMTP listen port |
| `MEOWMAIL_IMAP_PORT` | Override IMAP listen port |
| `MEOWMAIL_MAILDIR` | Override maildir base path |
| `MEOWMAIL_LOCAL_DOMAINS` | Comma-separated local domains |

## Roadmap

### Completed
- [x] SMTP server with STARTTLS + implicit TLS
- [x] IMAP4rev1 with Maildir++
- [x] JMAP server (Core, Mailbox, Email, Submission)
- [x] DKIM signing (RSA-SHA256)
- [x] SPF/DKIM/DMARC verification
- [x] Persistent outbound queue with retry
- [x] Bounce/DSN generation
- [x] Rate limiting + brute-force protection
- [x] Queue management CLI
- [x] Admin API
- [x] Structured logging (JSON, rotation)

### In Progress
- [ ] Queue runner integration (background thread)
- [ ] spNoRelay enforcement
- [ ] requireTlsForAuth enforcement

### Planned
- [ ] IPv6 outbound (Happy Eyeballs)
- [ ] Native DNS resolver (replace dig)
- [ ] ARC (Authenticated Received Chain)
- [ ] MTA-STS (RFC 8461)
- [ ] DANE/TLSA
- [ ] SMTPUTF8 (RFC 6531)
- [ ] Admin web dashboard
- [ ] Prometheus metrics

## Contributing

- Found a bug? [Create an issue](https://github.com/openpeeps/meowmail/issues)
- Want to contribute? [Fork and open a PR](https://github.com/openpeeps/meowmail/fork)

## License

MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
