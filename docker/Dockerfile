FROM php:8.2-apache

ENV APACHE_DOCUMENT_ROOT=/var/www/html/public \
    APP_PORT=443 \
    TLS_CERT_FILE=/etc/apache2/ssl/server.crt \
    TLS_KEY_FILE=/etc/apache2/ssl/server.key \
    GENERATE_SELF_SIGNED_TLS=1 \
    TLS_CERT_CN=localhost \
    TLS_CERT_SAN=DNS:localhost,IP:127.0.0.1,IP:::1 \
    TLS_SELF_SIGNED_DAYS=30 \
    ENFORCE_HTTPS=1

RUN apt-get update && apt-get install -y --no-install-recommends \
  libpng-dev \
  libjpeg-dev \
  libwebp-dev \
  libgif-dev \
  openssl \
  && docker-php-ext-configure gd --with-jpeg --with-webp \
  && docker-php-ext-install gd pdo pdo_mysql mysqli \
  && rm -rf /var/lib/apt/lists/*

COPY docker/apache/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY docker/apache/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf
COPY docker/apache/entrypoint.sh /usr/local/bin/docker-entrypoint-tls.sh

RUN set -eux; \
  sed -ri -e 's!/var/www/html!/var/www/html/public!g' /etc/apache2/apache2.conf; \
  { \
  echo 'ServerTokens Prod'; \
  echo 'ServerSignature Off'; \
  echo 'TraceEnable Off'; \
  echo 'ServerName localhost'; \
  } > /etc/apache2/conf-available/hardening.conf; \
  a2enconf hardening; \
  a2enmod headers rewrite ssl socache_shmcb; \
  a2ensite default-ssl; \
  mkdir -p /etc/apache2/ssl; \
  chmod 755 /usr/local/bin/docker-entrypoint-tls.sh; \
  { \
  echo 'expose_php = Off'; \
  echo 'display_errors = Off'; \
  echo 'log_errors = On'; \
  echo 'session.use_strict_mode = 1'; \
  echo 'session.cookie_httponly = 1'; \
  } > /usr/local/etc/php/conf.d/security.ini

WORKDIR /var/www/html
ENTRYPOINT ["/usr/local/bin/docker-entrypoint-tls.sh"]
CMD ["apache2-foreground"]
