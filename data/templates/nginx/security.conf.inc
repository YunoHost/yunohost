ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;  # about 200000 sessions
ssl_session_tickets off;

{% if compatibility == "modern" %}
# generated 2020-08-14, Mozilla Guideline v5.6, nginx 1.14.2, OpenSSL 1.1.1d, modern configuration
# https://ssl-config.mozilla.org/#server=nginx&version=1.14.2&config=modern&openssl=1.1.1d&guideline=5.6
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
{% else %}
# Ciphers with intermediate compatibility
# generated 2020-08-14, Mozilla Guideline v5.6, nginx 1.14.2, OpenSSL 1.1.1d, intermediate configuration
# https://ssl-config.mozilla.org/#server=nginx&version=1.14.2&config=intermediate&openssl=1.1.1d&guideline=5.6
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# Pre-defined FFDHE group (RFC 7919)
# From https://ssl-config.mozilla.org/ffdhe2048.txt
# https://security.stackexchange.com/a/149818
ssl_dhparam /usr/share/yunohost/other/ffdhe2048.pem;
{% endif %}


# Follows the Web Security Directives from the Mozilla Dev Lab and the Mozilla Obervatory + Partners
# https://wiki.mozilla.org/Security/Guidelines/Web_Security
# https://observatory.mozilla.org/
{% if experimental == "True" %}
more_set_headers "Content-Security-Policy : upgrade-insecure-requests; default-src https: data:";
{% else %}
more_set_headers "Content-Security-Policy : upgrade-insecure-requests";
{% endif %}
more_set_headers "Content-Security-Policy-Report-Only : default-src https: data: 'unsafe-inline' 'unsafe-eval'  ";
more_set_headers "X-Content-Type-Options : nosniff";
more_set_headers "X-XSS-Protection : 1; mode=block";
more_set_headers "X-Download-Options : noopen";
more_set_headers "X-Permitted-Cross-Domain-Policies : none";
more_set_headers "X-Frame-Options : SAMEORIGIN";

# Disable the disaster privacy thing that is FLoC
{% if experimental == "True" %}
more_set_headers "Permissions-Policy : fullscreen=(), geolocation=(), payment=(), accelerometer=(), battery=(), magnetometer=(), usb=(), interest-cohort=()";
# Force HTTPOnly and Secure for all cookies
proxy_cookie_path ~$ "; HTTPOnly; Secure;";
{% else %}
more_set_headers "Permissions-Policy : interest-cohort=()";
{% endif %}

# Disable gzip to protect against BREACH
# Read https://trac.nginx.org/nginx/ticket/1720 (text/html cannot be disabled!)
gzip off;
