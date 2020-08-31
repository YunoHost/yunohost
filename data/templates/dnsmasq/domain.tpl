address=/{{ domain }}/{{ ipv4 }}
{% if ipv6 %}
address=/{{ domain }}/{{ ipv6 }}
{% endif %}
txt-record={{ domain }},"v=spf1 mx a -all"
mx-host={{ domain }},{{ domain }},5
srv-host=_xmpp-client._tcp.{{ domain }},{{ domain }},5222,0,5
srv-host=_xmpp-server._tcp.{{ domain }},{{ domain }},5269,0,5
