ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;  # about 200000 sessions
ssl_session_tickets off;

# nginx 1.10 in stretch doesn't support TLS1.3 and Mozilla doesn't have any
# "modern" config recommendation with it.
# So until buster the modern conf is same as intermediate
{% if compatibility == "modern" %} {% else %} {% endif %}

# Ciphers with intermediate compatibility
# generated 2020-04-03, Mozilla Guideline v5.4, nginx 1.10.3, OpenSSL 1.1.0l, intermediate configuration
# https://ssl-config.mozilla.org/#server=nginx&version=1.10.3&config=intermediate&openssl=1.1.0l&guideline=5.4
ssl_protocols TLSv1.2;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# Uncomment the following directive after DH generation
# > openssl dhparam -out /etc/ssl/private/dh2048.pem -outform PEM -2 2048
#ssl_dhparam /etc/ssl/private/dh2048.pem;

# Follows the Web Security Directives from the Mozilla Dev Lab and the Mozilla Obervatory + Partners
# https://wiki.mozilla.org/Security/Guidelines/Web_Security
# https://observatory.mozilla.org/
more_set_headers "Content-Security-Policy : upgrade-insecure-requests";
more_set_headers "Content-Security-Policy-Report-Only : default-src https: data: 'unsafe-inline' 'unsafe-eval'";
more_set_headers "X-Content-Type-Options : nosniff";
more_set_headers "X-XSS-Protection : 1; mode=block";
more_set_headers "X-Download-Options : noopen";
more_set_headers "X-Permitted-Cross-Domain-Policies : none";
more_set_headers "X-Frame-Options : SAMEORIGIN";

# Disable gzip to protect against BREACH
# Read https://trac.nginx.org/nginx/ticket/1720 (text/html cannot be disabled!)
gzip off;
