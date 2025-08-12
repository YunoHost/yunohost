// ports can be 'all' or any port (list) understood by nftables
local banFor(time='10m', service='http,https') = {

  // function that generates an nft command
  // example output:
  // nft add element inet reaction banport4 { <ip> . dport { http, https } }
  local command(command, iptype) = [
    'nft',
    '%(command) element inet reaction %(set)%(iptype) { <ip> %(port) }'
    % {
      command: command,
      iptype: iptype,
      set: if service == 'all' then 'ban' else 'banport',
      port: if service == 'all' then '' else '. dport { %s }' % service,
    },
  ],

  ban4: {
    cmd: command('add', '4'),
  },
  ban6: {
    cmd: command('add', '6'),
  },
  unban4: {
    cmd: command('del', '4'),
    after: time,
  },
  unban6: {
    cmd: command('del', '6'),
    after: time,
  },
};

banFor
