local ban = import '_ban.jsonnet';
local recidive = import '_recidive.jsonnet';
{
  streams: {
    nginx: {

      cmd: [
        'sh',
        '-c',
        // the shell interprets the *glob
        // then disappears and only the tail command stays
        // -F → follow file changes by logrotate
        // -q → do not print file names, only their contents
        // -n0 → do not print any old log lines (-n defaults to 10)
        'exec tail -Fqn0 /var/log/nginx/*access.log /var/log/nginx/*error.log',
      ],
      filters: {

        // // TODO HTTP Basic auth
        // basicauth: {
        //   regex: [
        //     @'',
        //   ],
        //   retry: 20,
        //   retryperiod: '10m',
        //   actions: ban(time='10m') + recidive,
        // },

        // Yunohost
        yunohostapi: {
          regex: [
            @'^<ip> -.*\"POST /yunohost/api/login HTTP/\d.\d\" 401',
          ],
          retry: 10,
          retryperiod: '10m',
          actions: ban(time='10m') + recidive,
        },
        yunohostportalapi: {
          regex: [
            @'^<ip> -.*\"POST /yunohost/portalapi/login HTTP/\d.\d\" 401',
          ],
          retry: 20,
          retryperiod: '10m',
          actions: ban(time='10m') + recidive,
        },
      },
    },
  },
}
