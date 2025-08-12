local ban = import '_ban.jsonnet';
local recidive = import '_recidive.jsonnet';
{
  streams: {
    postfix_smtpd: {
      cmd: ['tail', '-F', '/var/log/mail.log'],
      filters: {
        sasl: {
          regex: [
            @'warning: [-._\w]+\[<ip>\]: SASL (?:LOGIN|PLAIN|(?:CRAM|DIGEST)-MD5) authentication failed',
          ],
          retry: 5,
          retryperiod: '10m',
          actions: ban(time='10m', port='smtp') + recidive,
        },
      },
    },
  },
}
