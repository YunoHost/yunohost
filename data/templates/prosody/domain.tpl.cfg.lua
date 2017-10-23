VirtualHost "{{ domain }}"
  ssl = {
        key = "/etc/yunohost/certs/{{ domain }}/key.pem";
        certificate = "/etc/yunohost/certs/{{ domain }}/crt.pem";
  }
  authentication = "ldap"
  ldap_base = "ou=users,dc=yunohost,dc=org"
