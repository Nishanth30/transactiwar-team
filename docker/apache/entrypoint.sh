#!/bin/sh
set -eu

# ── Root-only setup (runs as PID 1 before privilege drop) ──────────────

tls_cert_file="${TLS_CERT_FILE:-/etc/apache2/ssl/server.crt}"
tls_key_file="${TLS_KEY_FILE:-/etc/apache2/ssl/server.key}"
tls_cert_dir="$(dirname "$tls_cert_file")"
tls_key_dir="$(dirname "$tls_key_file")"
tls_cert_cn="${TLS_CERT_CN:-localhost}"
tls_cert_san="${TLS_CERT_SAN:-DNS:localhost,IP:127.0.0.1,IP:::1}"
tls_self_signed_days="${TLS_SELF_SIGNED_DAYS:-30}"
generate_self_signed_tls="${GENERATE_SELF_SIGNED_TLS:-1}"
tls_key_algorithm="${TLS_KEY_ALGORITHM:-ecdsa}"

# Ensure TLS and storage directories exist with correct ownership.
# Directories are pre-created in the Dockerfile, but bind-mounted volumes
# (docker-compose) may overlay them, so we fix ownership at runtime too.
mkdir -p "$tls_cert_dir" "$tls_key_dir"

ensure_dir_owned() {
    target_dir="$1"
    mkdir -p "$target_dir"
    chown www-data:www-data "$target_dir"
    chmod 0770 "$target_dir"
}

ensure_dir_owned /var/www/html/storage
ensure_dir_owned /var/www/html/storage/logs
ensure_dir_owned /var/www/html/storage/uploads
ensure_dir_owned /var/www/html/storage/uploads/profile_images

if [ ! -s "$tls_cert_file" ] || [ ! -s "$tls_key_file" ]; then
    if [ "$generate_self_signed_tls" != "1" ]; then
        echo "[tls] TLS certificate or key missing and GENERATE_SELF_SIGNED_TLS is disabled." >&2
        exit 1
    fi

    echo "[tls] Generating self-signed development certificate for ${tls_cert_cn}."
    case "$tls_key_algorithm" in
        ecdsa)
            openssl req \
                -x509 \
                -newkey ec \
                -pkeyopt ec_paramgen_curve:prime256v1 \
                -pkeyopt ec_param_enc:named_curve \
                -sha256 \
                -nodes \
                -days "$tls_self_signed_days" \
                -subj "/CN=${tls_cert_cn}" \
                -addext "subjectAltName = ${tls_cert_san}" \
                -keyout "$tls_key_file" \
                -out "$tls_cert_file"
            ;;
        rsa)
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
            ;;
        *)
            echo "[tls] Unsupported TLS_KEY_ALGORITHM='${tls_key_algorithm}'. Use 'ecdsa' or 'rsa'." >&2
            exit 1
            ;;
    esac
    # Key readable by www-data so Apache can load it after privilege drop.
    chown www-data:www-data "$tls_key_file" "$tls_cert_file"
    chmod 640 "$tls_key_file"
    chmod 644 "$tls_cert_file"
fi

# ── H6 FIX: Drop to www-data for the entire Apache process ────────────
# Apache now listens on unprivileged ports (8080/8443) so it no longer
# needs root for port binding. Docker-compose maps host 80→8080, 443→8443.
# setpriv (part of util-linux, already in the Debian base image) replaces
# the current process with www-data uid/gid, so any RCE through the PHP
# application cannot escalate to root. No external tools required.
exec setpriv --reuid=www-data --regid=www-data --init-groups "$@"
