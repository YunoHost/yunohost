local banFor = import '_ban.jsonnet';
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
          actions: banFor('3h'),
        },
      },
    },
  },
}
