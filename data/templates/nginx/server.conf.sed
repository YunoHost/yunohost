server {
    listen 80;
    listen [::]:80;
    server_name {{ domain }};

    access_by_lua_file /usr/share/ssowat/access.lua;

    include conf.d/{{ domain }}.d/*.conf;

    location /yunohost/admin {
        return 301 https://$http_host$request_uri;
    }

    access_log /var/log/nginx/{{ domain }}-access.log;
    error_log /var/log/nginx/{{ domain }}-error.log;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {{ domain }};

    ssl_certificate /etc/yunohost/certs/{{ domain }}/crt.pem;
    ssl_certificate_key /etc/yunohost/certs/{{ domain }}/key.pem;
    ssl_session_timeout 5m;
    ssl_session_cache shared:SSL:50m;
    ssl_prefer_server_ciphers on;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ALL:!aNULL:!eNULL:!LOW:!EXP:!RC4:!3DES:+HIGH:+MEDIUM;

    add_header Strict-Transport-Security "max-age=31536000;";

    # Uncomment the following directive after DH generation
    # > openssl dhparam -out /etc/ssl/private/dh2048.pem -outform PEM -2 2048
    #ssl_dhparam /etc/ssl/private/dh2048.pem;

    access_by_lua_file /usr/share/ssowat/access.lua;

    include conf.d/{{ domain }}.d/*.conf;

    include conf.d/yunohost_admin.conf.inc;
    include conf.d/yunohost_api.conf.inc;

    access_log /var/log/nginx/{{ domain }}-access.log;
    error_log /var/log/nginx/{{ domain }}-error.log;
}
