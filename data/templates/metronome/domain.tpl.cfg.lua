VirtualHost "{{ domain }}"
  enable = true
  ssl = {
        key = "/etc/yunohost/certs/{{ domain }}/key.pem";
        certificate = "/etc/yunohost/certs/{{ domain }}/crt.pem";
  }
  authentication = "ldap2"
  ldap = {
     hostname      = "localhost",
     user = {
       basedn        = "ou=users,dc=yunohost,dc=org",
       filter        = "(&(objectClass=posixAccount)(mail=*@{{ domain }})(permission=cn=xmpp.main,ou=permission,dc=yunohost,dc=org))",
       usernamefield = "mail",
       namefield     = "cn",
       },
  }

  -- Discovery items
  disco_items = {
    { "muc.{{ domain }}" },
    { "pubsub.{{ domain }}" },
    { "jabber.{{ domain }}" },
    { "vjud.{{ domain }}" },
    { "xmpp-upload.{{ domain }}" },
  };

--  contact_info = {
--    abuse = { "mailto:abuse@{{ domain }}", "xmpp:admin@{{ domain }}" };
--    admin = { "mailto:root@{{ domain }}", "xmpp:admin@{{ domain }}" };
--  };

------ Components ------
-- You can specify components to add hosts that provide special services,
-- like multi-user conferences, and transports.

---Set up a MUC (multi-user chat) room server
Component "muc.{{ domain }}" "muc"
  name = "{{ domain }} Chatrooms"

  modules_enabled = {
    "muc_limits";
    "muc_log";
    "muc_log_mam";
    "muc_log_http";
    "muc_vcard";
  }

  muc_event_rate = 0.5
  muc_burst_factor = 10
  room_default_config = {
    logging = true,
    persistent = true
  };

---Set up a PubSub server
Component "pubsub.{{ domain }}" "pubsub"
  name = "{{ domain }} Publish/Subscribe"

  unrestricted_node_creation = true -- Anyone can create a PubSub node (from any server)

---Set up a HTTP Upload service
Component "xmpp-upload.{{ domain }}" "http_upload_external"
  name = "{{ domain }} Sharing Service"

  modules_enabled = {
    "http_upload_external";
  }

  http_file_external_url = "https://xmpp-upload.{{ domain }}/upload/share.php/"
  http_file_external_delete_url = "https://xmpp-upload.{{ domain }}/upload/share.php/"
  http_file_secret = "{{ HTTP_FILE_SECRET }}"
  http_file_delete_secret = "{{ HTTP_FILE_DELETE_SECRET }}" 

---Set up a VJUD service
Component "vjud.{{ domain }}" "vjud"
  vjud_disco_name = "{{ domain }} User Directory"
