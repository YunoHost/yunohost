location /yunohost/api/ {
    proxy_read_timeout 3600s;
    proxy_pass http://127.0.0.1:6787/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $http_host;

    # Rewrite CORS headers due to bug inside moulinette
    # cause it's very difficult to add them with bottle 
    # framework 0.12.
    # https://github.com/YunoHost/moulinette/pull/324
    more_set_headers "Access-Control-Allow-Origin : *";
    more_set_headers "Access-Control-Allow-Headers: x-requested-with";
    more_set_headers "Allow: GET, POST, PUT, DELETE, OPTIONS";
    more_set_headers "Access-Control-Allow-Credentials: true";

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
