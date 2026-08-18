// ports can be 'all' or any port (list) understood by nftables
local ban(time='10m', ssh=false) = {

  local set = if ssh then 'ban-ssh' else 'ban-all-but-ssh',

  // function that generates an nft command
  // example output:
  // nft add element inet reaction ban6 { <ip> }
  // nft del element inet reaction banport4 { <ip> . dport { http, https } }
  local command(command, iptype) = [
    'nft',
    command,
    'element',
    'inet',
    'reaction',
    set + iptype,
    '{ <ip> }',
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

ban
