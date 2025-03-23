{% set interfaces_list = interfaces.split(' ') %}
{% for interface in interfaces_list %}
interface-name={{ domain }},{{ interface }}
{% endfor %}
{% if ipv6 %}
host-record={{ domain }},{{ ipv6 }}
{% endif %}
{% if mail_out == "1" %}
txt-record={{ domain }},"v=spf1 mx a -all"
{% endif %}
{% if mail_in == "1" %}
mx-host={{ domain }},{{ domain }},5
{% endif %}
