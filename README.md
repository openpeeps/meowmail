<p align="center">
  <img src="https://github.com/openpeeps/meowmail/blob/main/.github/meowmail.png" width="130px" height="130px"><br>
  A high-performance Mail Transfer Agent based on <a href="https://github.com/openpeeps/libevent-nim">LibEvent</a>.<br>
  👑 Written in Nim language
</p>

<p align="center">
  <code>nimble install meowmail</code>
</p>

<p align="center">
  <a href="https://openpeeps.github.io/meowmail/">API reference</a><br>
  <img src="https://github.com/openpeeps/meowmail/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/openpeeps/meowmail/workflows/docs/badge.svg" alt="Github Actions">
</p>

## What's up?
We want to build a simple, efficient, and easy-to-use SMTP server in Nim that can be used for sending and receiving emails in various applications, from testing email functionality in development environments to running a fully-featured mail server for anyone who wants to host their own email.

MeowMail is designed to be a lightweight and high-performance SMTP server that can handle a large number of concurrent connections while providing essential features like TLS encryption, authentication, and MX delivery. It also includes an IMAP server for email retrieval and management.

## 😍 Key Features
- High-performance SMTP & IMAP server
- Based on LibEvent library for efficient event-driven networking
- Supports SMTP authentication and TLS encryption
- Efficient handling of concurrent connections
- Simple API for handling incoming emails and IMAP commands
- HTTP auth proxy for integration with external authentication systems
- Made for Unix-like systems (Linux, macOS, BSD)

### Prerequisites
- Nim compiler >= 2.0
- OpenSSL development libraries
- LibEvent development libraries

## Examples
Testing MeowMail on a home connection can be tricky due to ISP restrictions on port 25. If your ISP blocks the outgoing SMTP port 25, the only way to test MeowMail is to run it locally and connect to it using an email client configured to use `localhost` as the SMTP server.

Otherwise, you can use a VPS or any cloud server with an open port 25 to test sending emails to external addresses. Try a VPS from [Hetzner using our referral link](https://hetzner.cloud/?ref=Hm0mYGM9NxZ4) for easy testing.

### Test MeowMail
Use a temporary, disposable email account service like [TempMail](https://temp-mail.org/) to receive test emails.

Note, ensure you have `swaks` installed for testing SMTP functionality.

_todo_

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/meowmail/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/meowmail/fork)
- 😎 [Get €20 in cloud credits from Hetzner](https://hetzner.cloud/?ref=Hm0mYGM9NxZ4)

### 🎩 License
MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
