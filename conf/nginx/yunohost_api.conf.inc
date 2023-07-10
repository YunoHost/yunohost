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
