# Avoid the nginx path/alias traversal weakness ( #1037 )
rewrite ^/yunohost/sso$ /yunohost/sso/ permanent;

location /yunohost/sso/ {
    alias /usr/share/ssowat/portal/;
    index index.html;
}
