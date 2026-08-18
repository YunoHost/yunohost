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

          chain input {
            # type filter → we're only accepting or dropping packets
            # hook ingress → before all kernel treatment
            type filter hook ingress priority 0

            policy accept

            # Check if IP is in all ports but ssh set
            dport { 1-21, 23-65536 } ip  saddr @ban-all-but-ssh4 drop
            dport { 1-21, 23-65536 } ip6 saddr @ban-all-but-ssh6 drop

            # Check if (IP, port) ssh set
            dport 22 ip  saddr @ban-ssh4 drop
            dport 22 ip6 saddr @ban-ssh6 drop
          }
          # chain forward? (docker...)
        }
      |||,
    ],
  ],

  stop: [
    ['nft', 'delete table inet reaction'],
  ],
}
