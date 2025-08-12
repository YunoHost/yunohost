local ban = import '_ban.jsonnet';
local recidive = import '_recidive.jsonnet';
{
  streams: {
    nginx: {
      filters: {
        yunohostapi: {
          regex: [
            @'^<ip> -.*\"POST /yunohost/api/login HTTP/\d.\d\" 401',
          ],
          retry: 10,
          retryperiod: '10m',
          actions: ban(time='10m', service='http,https') + recidive,
        },
        yunohostportalapi: {
          regex: [
            @'^<ip> -.*\"POST /yunohost/portalapi/login HTTP/\d.\d\" 401',
          ],
          retry: 20,
          retryperiod: '10m',
          actions: ban(time='10m', service='http,https') + recidive,
        },
      },
    },
  },
}
