local ban = import '_ban.jsonnet';
local recidive = import '_recidive.jsonnet';
{
  streams: {
    ssh: {
      cmd: ['journalctl', '-fn0', '-u', 'ssh'],
      filters: {
        failedlogin: {
          regex: [
            // TODO
          ],
          retry: 3,
          retryperiod: '1h',
          actions: ban('3h') + recidive,
        },
      },
    },
  },
}
