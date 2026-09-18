local ban = import '_ban.jsonnet';
local recidive = import '_recidive.jsonnet';
{
  streams: {
    mail: {
      cmd: ['tail', '-F', '/var/log/mail.log'],
      filters: {
        postfix: {
          regex: [
            @'warning: [-._\w]+\[<ip>\]: SASL (?:LOGIN|PLAIN|(?:CRAM|DIGEST)-MD5) authentication failed',
            @'improper command pipelining after CONNECT from \S*[<ip>]',
            @'NOQUEUE: reject: RCPT from \S*[<ip>]: .* (?:Recipient address rejected: User unknown|Relay access denied) ',
          ],
          retry: 5,
          retryperiod: '10m',
          actions: ban(time='10m') + recidive,
        },
        dovecot: {
          regex: [
            @'warning: [-._\w]+\[<ip>\]: SASL (?:LOGIN|PLAIN|(?:CRAM|DIGEST)-MD5) authentication failed',
            @' Disconnected: Connection closed (auth failed, \d+ attempts in \d+ secs): .* rip=<ip>, ',
          ],
          retry: 5,
          retryperiod: '10m',
          actions: ban(time='10m') + recidive,
        },
      },
    },
  },
}
