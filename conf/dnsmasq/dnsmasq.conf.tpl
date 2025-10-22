domain-needed
expand-hosts
localise-queries

{% set interfaces = wireless_interfaces.strip().split(' ') %}
{% for interface in interfaces %}
interface={{ interface }}
{% endfor %}
resolv-file=/etc/resolv.dnsmasq.conf
cache-size=256

# Gotta force the usage of resolvers for spamhaus,
# Which will otherwise complain that we may be using an open resolver...
# cf https://www.spamhaus.com/resource-center/successfully-accessing-spamhauss-free-block-lists-using-a-public-dns/#yes-but-why-block-queries-from-public-recursive-name-servers
# We pick one of spamhaus' a/b/c/d/e nameservers, cf https://multirbl.valli.org/detail/zen.spamhaus.org.html
server=/*.zen.spamhaus.org/c.gns.spamhaus.org