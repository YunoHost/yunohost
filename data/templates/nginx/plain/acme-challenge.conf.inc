location ^~ '/.well-known/acme-challenge/'
{
        default_type "text/plain";
        alias /tmp/acme-challenge-public/;
        gzip off;
}
