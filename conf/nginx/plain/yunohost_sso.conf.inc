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

    more_set_headers "Content-Security-Policy: upgrade-insecure-requests; default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; img-src 'self' data:;";
}
