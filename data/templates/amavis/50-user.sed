use strict;

#
# Place your configuration directives here.  They will override those in
# earlier files.
#
# See /usr/share/doc/amavisd-new/ for documentation and examples of
# the directives you can use in this file
#

$myhostname = "{{ main_domain }}";

$mydomain = "{{ main_domain }}";

# Enable LDAP support 
$enable_ldap  = 1;

# Default LDAP settings 
$default_ldap = {
    hostname => "127.0.0.1",
    tls => 0,
    version => 3,
    base => "dc=yunohost,dc=org",
    scope => "sub",
    query_filter => "(&(objectClass=inetOrgPerson)(mail=%m))",
};


#------------ Do not modify anything below this line -------------
1;  # ensure a defined return
