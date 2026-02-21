local ban = import '_ban.jsonnet';
local recidive = import '_recidive.jsonnet';
{
  streams: {
    ssh: {
      cmd: ['journalctl', '-fn0', '-u', 'ssh'],
      filters: {
        failedlogin: {
          regex: [
            // Auth fail
            @'authentication failure;.*rhost=<ip>',
            // More specific auth fail
            @'Failed password for .* from <ip>',
            // Other auth failures
            @'Connection from <ip> port [0-9]*: invalid format',
            @'Invalid user .* from <ip>',
          ],
          retry: 3,
          retryperiod: '1h',
          actions: ban('3h') + recidive,
        },
      },
    },
  },
}
