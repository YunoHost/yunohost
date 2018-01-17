# Fix the nginx traversal weak ( #1034 )
rewrite ^/yunohost/admin$ /yunohost/admin/ permanent;
location /yunohost/admin/ {
    alias /usr/share/yunohost/admin/;
    default_type text/html;
    index index.html;

    # Short cache on handlebars templates
    location ~* \.(?:ms)$ {
      expires 5m;
      add_header Cache-Control "public";
    }
}
