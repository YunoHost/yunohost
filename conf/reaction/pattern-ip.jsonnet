{
  patterns: {
    ip: {
      // Accept IPv4 & IPv6
      type: 'ip',
      // Group IPv6 by /64
      ipv6mask: 64,
      // Ignore localhost
      ignore: [
        '127.0.0.1',
        '::1',
      ],
    },
  },
}
