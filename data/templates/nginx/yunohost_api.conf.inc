location /yunohost/api/ {
    proxy_read_timeout 3600s;
    proxy_pass http://127.0.0.1:6787/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
