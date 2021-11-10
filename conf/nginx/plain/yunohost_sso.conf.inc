# Avoid the nginx path/alias traversal weakness ( #1037 )
rewrite ^/yunohost/sso$ /yunohost/sso/ permanent;

location /yunohost/sso/ {
   # This is an empty location, only meant to avoid other locations
   # from matching /yunohost/sso, such that it's correctly handled by ssowat
}
