FROM php:8.2-apache

RUN set -eux; \
    docker-php-ext-install mysqli; \
    a2enmod headers; \
    sed -ri -e 's!/var/www/html!/var/www/html/public!g' /etc/apache2/sites-available/000-default.conf; \
    sed -ri -e 's!<Directory /var/www/>!<Directory /var/www/html/public/>!g' /etc/apache2/apache2.conf; \
    { \
      echo 'ServerTokens Prod'; \
      echo 'ServerSignature Off'; \
      echo 'TraceEnable Off'; \
      echo 'Header always set X-Content-Type-Options "nosniff"'; \
      echo 'Header always set X-Frame-Options "DENY"'; \
      echo 'Header always set Referrer-Policy "no-referrer"'; \
      echo 'Header always set Content-Security-Policy "default-src '\''none'\''; frame-ancestors '\''none'\''; base-uri '\''none'\''"'; \
    } > /etc/apache2/conf-available/hardening.conf; \
    a2enconf hardening; \
    { \
      echo 'expose_php = Off'; \
      echo 'display_errors = Off'; \
      echo 'log_errors = On'; \
      echo 'session.use_strict_mode = 1'; \
      echo 'session.cookie_httponly = 1'; \
    } > /usr/local/etc/php/conf.d/security.ini

WORKDIR /var/www/html
