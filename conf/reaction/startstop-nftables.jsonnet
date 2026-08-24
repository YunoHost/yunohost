// Calculate the IP range
// Example if SSH port is 22: "1-21, 23-65536"
local ynh_settings = import '/etc/yunohost/settings.json';
local ssh_port = ynh_settings['security.ssh.port'].value;
local range = '1-%(less1), %(more1)-65536' % { less1: std.toString(ssh_port - 1), more1: std.toString(ssh_port + 1) };

{
  start: [
    [
      'nft',
      |||
        table inet reaction {
          # IP sets to ban on all ports but ssh
          set ban-all-but-ssh4 {
            type ipv4_addr
            flags interval
          }
          set ban-all-but-ssh6 {
            type ipv6_addr
            flags interval
          }

          # IP sets to ban on ssh
          set ban-ssh4 {
            type ipv4_addr
            flags interval
          }
          set ban-ssh6 {
            type ipv6_addr
            flags interval
          }

          chain ingress {
            # type filter → we're only accepting or dropping packets
            # hook ingress → before all kernel treatment
            type filter hook ingress priority 0

            policy accept

            # Check if IP is in all ports but ssh set
            dport { %(range) } ip  saddr @ban-all-but-ssh4 drop
            dport { %(range) } ip6 saddr @ban-all-but-ssh6 drop

            # Check if (IP, port) ssh set
            dport %(ssh_port) ip  saddr @ban-ssh4 drop
            dport %(ssh_port) ip6 saddr @ban-ssh6 drop
          }
        }
      ||| % { range: range, ssh_port: ssh_port },
    ],
  ],

  stop: [
    ['nft', 'delete table inet reaction'],
  ],
}
