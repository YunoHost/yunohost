// Import IPs to ignore
local ynh_settings = import '/etc/yunohost/settings.json';
local allowlist = ynh_settings['security.reaction.reaction_allowlist'].value;
local ignorecidr = std.map(std.split(allowlist, ','), std.trim);

{
  patterns: {
    HOST: {
      // Accept IPv4 & IPv6
      type: 'ip',
      // Group IPv6 by /64
      ipv6mask: 64,
      // Ignore localhost
      ignore: [
        '127.0.0.1',
        '::1',
      ],
      ignorecidr: ignorecidr,
    },
    // Some apps use <ADDR> instead of <HOST>
    // So we alias it
    ADDR: self.HOST,
  },
}
