include fastcgi_params_no_auth.conf.inc;

fastcgi_param  REMOTE_USER        $http_ynh_user if_not_empty;
