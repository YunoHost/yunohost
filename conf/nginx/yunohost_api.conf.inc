location /yunohost/api/ {
    proxy_read_timeout 3600s;
    proxy_pass http://127.0.0.1:6787/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;

    {% if webadmin_allowlist_enabled == "True" %}
    {% for ip in webadmin_allowlist.split(',') %}
    allow {{ ip }};
    {% endfor %}
    deny all;
    {% endif %}

    # Custom 502 error page
    error_page 502 /yunohost/api/error/502;
}

# Yunohost admin output complete 502 error page, so use only plain text.
location = /yunohost/api/error/502 {
    return 502 '502 - Bad Gateway';
    add_header Content-Type text/plain;
    internal;
}

location /yunohost/portalapi/ {

    # FIXME FIXME FIXME : we should think about what we really want here ... 
    more_set_headers "Access-Control-Allow-Origin: $http_origin";
    more_set_headers "Access-Control-Allow-Methods: GET, HEAD, POST, OPTIONS, DELETE";
    more_set_headers "Access-Control-Allow-Headers: Accept,Authorization,Cache-Control,Content-Type,DNT,If-Modified-Since,Keep-Alive,Origin,User-Agent,X-Requested-With";
    more_set_headers "Access-Control-Allow-Credentials: true";

    if ($request_method = 'OPTIONS') {
        more_set_headers "Content-Type: text/plain; charset=utf-8";
        more_set_headers "Content-Length: 0";
        return 204;
    }

    proxy_read_timeout 5s;
    proxy_pass http://127.0.0.1:6788/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $http;

    # Custom 502 error page
    error_page 502 /yunohost/portalapi/error/502;
}


# Yunohost admin output complete 502 error page, so use only plain text.
location = /yunohost/portalapi/error/502 {
    return 502 '502 - Bad Gateway';
    add_header Content-Type text/plain;
    internal;
}
