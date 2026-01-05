include proxy_params_no_auth.conf.inc;

# Set Authentication header, in addition to the header by ssowat.
# Note ssowat inject YNH_USER and here we inject Ynh-User which is different.
proxy_set_header   Authorization        $http_authorization;
proxy_set_header   Ynh-User             $http_ynh_user;
proxy_set_header   Ynh-User-Email       $http_ynh_user_email;
proxy_set_header   Ynh-User-Fullname    $http_ynh_user_fullname;
proxy_set_header   REMOTE_USER          $http_ynh_user;
proxy_set_header   X-Forwarded-User     $http_ynh_user;
