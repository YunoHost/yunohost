{
  streams: {
    nginx: {
      cmd: [
        'sh',
        '-c',
        // the shell interprets the *glob
        // then disappears and only the tail command stays
        // -F → follow file changes by logrotate
        // -n0 → do not print any old log lines (-n defaults to 10)
        'exec tail -Fn0 /var/log/nginx/*access.log /var/log/nginx/*error.log',
      ],
    },
  },
}
