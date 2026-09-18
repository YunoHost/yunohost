local ban = import '_ban.jsonnet';
{
  streams: {
    recidive: {
      type: 'virtual',
      filters: {
        weekban: {
          regex: ['^<ip>$'],
          // After 5 bans in one week, we ban the IP on all ports for one week.
          retry: 20,
          retryperiod: '7d',
          actions: ban(time='7d') + ban(time='7d', ssh=true),
        },
      },
    },
  },
}
