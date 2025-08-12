local file = '/var/lib/reaction/recidive';
{
  start: [
    ['sh', '-c', 'echo > %s' % file],
  ],

  streams: {
    recidive: {
      cmd: ['tail', '-fn0', file],
    },
  },
}
