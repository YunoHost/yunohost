# Avoid the nginx path/alias traversal weakness ( #1037 )
rewrite ^/yunohost/admin$ /yunohost/admin/ permanent;

location /yunohost/admin/ {
    alias /usr/share/yunohost/admin/;
    default_type text/html;
    index index.html;

    {% if webadmin_allowlist_enabled == "True" %}
    {% if webadmin_allowlist.strip() -%}
    {% for ip in webadmin_allowlist.strip().split(',') -%}
    allow {{ ip.strip() }};
    {% endfor -%}
    {% endif -%}
    deny all;
    {% endif %}

    location = /yunohost/admin/index.html {
        etag off;
        expires off;
        more_set_headers "Cache-Control: no-store, no-cache, must-revalidate";
    }

    location /yunohost/admin/applogos/ {
        alias /usr/share/yunohost/applogos/;
        expires 1M;
        # max-age in seconds, one month
        add_header Cache-Control "max-age=2629746, public";
    }

    more_set_headers "Content-Security-Policy: upgrade-insecure-requests; default-src 'self'; connect-src 'self' https://paste.yunohost.org wss://$host; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'; object-src 'none'; img-src 'self' data:;";
    more_set_headers "Content-Security-Policy-Report-Only:";
}
