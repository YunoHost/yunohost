{
  start: [
    [
      'nft',
      |||
        table inet reaction {
          # IP sets to ban on all ports
          set ban4 {
            type ipv4_addr
            flags interval
          }
          set ban6 {
            type ipv6_addr
            flags interval
          }

          # IP sets to ban on multiport
          set banport4 {
            type ipv4_addr . inet_service
            flags interval
          }
          set banport6 {
            type ipv6_addr . inet_service
            flags interval
          }

          chain input {
            # type filter → we're only accepting or dropping packets
            # hook ingress → before all kernel treatment
            type filter hook ingress priority 0

            policy accept

            # Check if IP is in all ports set
            ip  saddr @ban4 drop
            ip6 saddr @ban6 drop

            # Check if (IP, port) tuple is in multiport set
            ip  saddr . tcp dport @banport4 drop
            ip6 saddr . tcp dport @banport6 drop
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
