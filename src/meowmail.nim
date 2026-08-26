# MeowMail - A high-performance SMTP based on LibEvent
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/meowmail

when defined(macosx):
  # spf2 headers require arpa/nameser.h (ns_type) to be included first; the
  # passC flags in meowmail.nims are applied after the pkg/spf pragmas.
  {.passC: "-include arpa/nameser.h".}

when isMainModule:
  import pkg/kapsis
  import ./meowmail/cli/commands

  initKapsis do:
    commands:
      -- "Configuration"
      init string(init):
        ## Initialize a MeowMail config file

      -- "SMTP Server"
      start path(config):
        ## Start the MeowMail server

      -- "DNS Records"
      spf string(ip4), ?string(ip6), ?string(includes):
        ## Generate SPF record
      dkim path(dkim):
        ## Generate DKIM record
      dmarc path(dmarc):
        ## Generate DMARC record

      -- "Queue Management"
      queue:
        ## Manage queue messages
        list string(queueDir):
          ## List queued messages
        stats string(queueDir):
          ## Show queue statistics
        flush string(queueDir):
          ## Force delivery of pending messages
        retry string(queueDir), string(id):
          ## Requeue a specific message
        delete string(queueDir), string(id):
          ## Remove a message from queue
        purge string(queueDir):
          ## Remove delivered/bounced/failed messages

else:
  import ./meowmail/smtp/[smtpserver, smtpdelivery, smtpauth, mxprovider]
  export smtpserver, smtpdelivery, smtpauth, mxprovider