# Avoid the nginx path/alias traversal weakness ( #1037 )
rewrite ^/yunohost/sso$ /yunohost/sso/ permanent;

location /yunohost/sso/ {
    alias /usr/share/yunohost/portal/;
    default_type text/html;
    index index.html;
    try_files $uri $uri/ /index.html;

    location = /yunohost/sso/index.html {
        etag off;
        expires off;
        more_set_headers "Cache-Control: no-store, no-cache, must-revalidate";
    }

    location /yunohost/sso/applogos/ {
        alias /usr/share/yunohost/applogos/;
        expires 1M;
        # max-age in seconds, one month
        add_header Cache-Control "max-age=2629746, public";
    }

    more_set_headers "Content-Security-Policy: upgrade-insecure-requests; default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; img-src 'self' data:;";
}
