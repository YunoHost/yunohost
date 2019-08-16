VirtualHost "{{ domain }}"
  ssl = {
        key = "/etc/yunohost/certs/{{ domain }}/key.pem";
        certificate = "/etc/yunohost/certs/{{ domain }}/crt.pem";
  }
  authentication = "ldap2"
  ldap = {
     hostname      = "localhost",
     user = {
       basedn        = "ou=users,dc=yunohost,dc=org",
       filter        = "(&(objectClass=posixAccount)(mail=*@{{ domain }})(permission=cn=main.metronome,ou=permission,dc=yunohost,dc=org))",
       usernamefield = "mail",
       namefield     = "cn",
       },
  }
