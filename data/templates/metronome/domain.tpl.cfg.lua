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
Component "xmpp-upload.{{ domain }}" "http_upload"
  name = "{{ domain }} Sharing Service"

  http_file_path = "/var/xmpp-upload/{{ domain }}/upload"
  http_external_url = "https://xmpp-upload.{{ domain }}:443"
  http_file_base_path = "/upload"
  http_file_size_limit = 6*1024*1024
  http_file_quota = 60*1024*1024
  http_upload_file_size_limit = 100 * 1024 * 1024 -- bytes
  http_upload_quota = 10 * 1024 * 1024 * 1024 -- bytes

  http_file_allowed_mime_types = {
      ["3gp"] = "video/3gpp",
      ["7z"] = "application/x-7z-compressed",
      ["aac"] = "audio/aac",
      ["abw"] = "application/x-abiword",
      ["apk"] = "application/vnd.android.package-archive",
      ["arc"] = "application/octet-stream",
      ["avi"] = "video/x-msvideo",
      ["azw"] = "application/vnd.amazon.ebook",
      ["bin"] = "application/octet-stream",
      ["bmp"] = "image/bmp",
      ["bz2"] = "application/x-bzip2",
      ["bz"] = "application/x-bzip",
      ["csh"] = "application/x-csh",
      ["css"] = "text/css",
      ["csv"] = "text/csv",
      ["doc"] = "application/msword",
      ["docx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      ["eot"] = "application/vnd.ms-fontobject",
      ["epub"] = "application/epub+zip",
      ["gif"] = "image/gif",
      ["gz"] = "application/x-compressed",
      ["html"] = "text/html",
      ["htm"] = "text/html",
      ["ico"] = "image/x-icon",
      ["ics"] = "text/calendar",
      ["jar"] = "application/java-archive",
      ["jpeg"] = "image/jpeg",
      ["jpg"] = "image/jpeg",
      ["js"] = "application/javascript",
      ["json"] = "application/json",
      ["m4a"] = "audio/mp4",
      ["midi"] = "audio/midi",
      ["mov"] = "video/quicktime",
      ["mp3"] = "audio/mpeg",
      ["mp4"] = "video/mp4",
      ["mpeg"] = "video/mpeg",
      ["mpkg"] = "application/vnd.apple.installer+xml",
      ["odp"] = "application/vnd.oasis.opendocument.presentation",
      ["ods"] = "application/vnd.oasis.opendocument.spreadsheet",
      ["odt"] = "application/vnd.oasis.opendocument.text",
      ["oga"] = "audio/ogg",
      ["ogg"] = "application/ogg",
      ["ogv"] = "video/ogg",
      ["ogx"] = "application/ogg",
      ["otf"] = "font/otf",
      ["pdf"] = "application/pdf",
      ["pgp"] = "text/plain",
      ["png"] = "image/png",
      ["ppt"] = "application/vnd.ms-powerpoint",
      ["pptx"] = "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      ["qt"] = "video/quicktime",
      ["rar"] = "application/x-rar-compressed",
      ["rtf"] = "application/rtf",
      ["sh"] = "application/x-sh",
      ["svg"] = "image/svg+xml",
      ["swf"] = "application/x-shockwave-flash",
      ["tar"] = "application/x-tar",
      ["tiff"] = "image/tiff",
      ["ts"] = "application/typescript",
      ["ttf"] = "font/ttf",
      ["txt"] = "text/plain",
      ["vsd"] = "application/vnd.visio",
      ["wav"] = "audio/wav",
      ["weba"] = "audio/webm",
      ["webm"] = "video/webm",
      ["webp"] = "image/webp",
      ["woff2"] = "font/woff2",
      ["woff"] = "font/woff",
      ["xhtml"] = "application/xhtml+xml",
      ["xls"] = "application/vnd.ms-excel",
      ["xlsx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      ["xml"] = "text/xml",
      ["xul"] = "application/vnd.mozilla.xul+xml",
      ["zip"] = "application/zip"
  }


---Set up a VJUD service
Component "vjud.{{ domain }}" "vjud"
  vjud_disco_name = "{{ domain }} User Directory"
