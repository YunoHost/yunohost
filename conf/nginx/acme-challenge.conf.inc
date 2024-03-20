location ^~ '/.well-known/acme-challenge/'
{
        default_type "text/plain";
        alias /var/www/.well-known/acme-challenge-public/;
        gzip off;
}
