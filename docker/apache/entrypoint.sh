#!/bin/sh
set -eu

tls_cert_file="${TLS_CERT_FILE:-/etc/apache2/ssl/server.crt}"
tls_key_file="${TLS_KEY_FILE:-/etc/apache2/ssl/server.key}"
tls_cert_dir="$(dirname "$tls_cert_file")"
tls_key_dir="$(dirname "$tls_key_file")"
tls_cert_cn="${TLS_CERT_CN:-localhost}"
tls_cert_san="${TLS_CERT_SAN:-DNS:localhost,IP:127.0.0.1,IP:::1}"
tls_self_signed_days="${TLS_SELF_SIGNED_DAYS:-30}"
generate_self_signed_tls="${GENERATE_SELF_SIGNED_TLS:-1}"

mkdir -p "$tls_cert_dir" "$tls_key_dir"

prepare_runtime_dir() {
    target_dir="$1"

    mkdir -p "$target_dir"
    chown www-data:www-data "$target_dir"
    chmod 0770 "$target_dir"
}

prepare_runtime_dir /var/www/html/storage
prepare_runtime_dir /var/www/html/storage/logs
prepare_runtime_dir /var/www/html/storage/uploads
prepare_runtime_dir /var/www/html/storage/uploads/profile_images

if [ ! -s "$tls_cert_file" ] || [ ! -s "$tls_key_file" ]; then
    if [ "$generate_self_signed_tls" != "1" ]; then
        echo "[tls] TLS certificate or key missing and GENERATE_SELF_SIGNED_TLS is disabled." >&2
        exit 1
    fi

    echo "[tls] Generating self-signed development certificate for ${tls_cert_cn}."
    openssl req \
        -x509 \
        -newkey rsa:4096 \
        -sha256 \
        -nodes \
        -days "$tls_self_signed_days" \
        -subj "/CN=${tls_cert_cn}" \
        -addext "subjectAltName = ${tls_cert_san}" \
        -keyout "$tls_key_file" \
        -out "$tls_cert_file"
    chmod 600 "$tls_key_file"
fi

exec "$@"
