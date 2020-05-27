# Avoid the nginx path/alias traversal weakness ( #1037 )
rewrite ^/yunohost/admin$ /yunohost/admin/ permanent;

location /yunohost/admin/ {
    alias /usr/share/yunohost/admin/;
    default_type text/html;
    index index.html;

    more_set_headers "Content-Security-Policy: upgrade-insecure-requests; default-src 'self'; connect-src 'self' https://raw.githubusercontent.com https://paste.yunohost.org wss://$host; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'; object-src 'none';";
    more_set_headers "Content-Security-Policy-Report-Only:";

    # Short cache on handlebars templates
    location ~* \.(?:ms)$ {
      expires 5m;
      add_header Cache-Control "public";
    }
}
