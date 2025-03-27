{% set interfaces_list = interfaces.split(' ') %}
{% for interface in interfaces_list %}
interface-name={{ domain }},{{ interface }}
{% endfor %}
{% if ipv6 %}
host-record={{ domain }},{{ ipv6 }}
{% endif %}
txt-record={{ domain }},"v=spf1 mx a -all"
{% if mail_in == "True" %}
mx-host={{ domain }},{{ domain }},5
{% endif %}
