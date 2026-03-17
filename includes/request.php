<?php

declare(strict_types=1);

function get_trusted_proxy_ips(): array
{
    static $cached = null;

    if ($cached !== null) {
        return $cached;
    }

    $raw = trim((string) getenv('TRUSTED_PROXIES'));
    if ($raw === '') {
        $cached = [];
        return $cached;
    }

    $trusted = [];
    foreach (explode(',', $raw) as $candidate) {
        $ip = trim($candidate);
        if ($ip === '') {
            continue;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
            $trusted[] = $ip;
        }
    }

    $cached = array_values(array_unique($trusted));
    return $cached;
}

function is_request_from_trusted_proxy(): bool
{
    $remoteAddr = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    if (!filter_var($remoteAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
        return false;
    }

    return in_array($remoteAddr, get_trusted_proxy_ips(), true);
}

function get_forwarded_client_ip(): ?string
{
    if (!is_request_from_trusted_proxy()) {
        return null;
    }

    $forwardedFor = trim((string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
    if ($forwardedFor === '') {
        return null;
    }

    $trustedProxies = get_trusted_proxy_ips();
    $forwardedIps = array_reverse(array_map('trim', explode(',', $forwardedFor)));

    foreach ($forwardedIps as $candidate) {
        if (
            $candidate === ''
            || !filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)
        ) {
            continue;
        }

        if (!in_array($candidate, $trustedProxies, true)) {
            return $candidate;
        }
    }

    return null;
}

function get_request_client_ip(): string
{
    $forwardedIp = get_forwarded_client_ip();
    if ($forwardedIp !== null) {
        return $forwardedIp;
    }

    $remoteAddr = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    if (filter_var($remoteAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
        return $remoteAddr;
    }

    return '0.0.0.0';
}

function is_secure_request(): bool
{
    $https = strtolower((string) ($_SERVER['HTTPS'] ?? ''));
    if ($https !== '' && $https !== 'off') {
        return true;
    }

    if ((string) ($_SERVER['SERVER_PORT'] ?? '') === '443') {
        return true;
    }

    // Reverse proxy / load balancer TLS termination (e.g. nginx, Docker ingress).
    // HTTP_X_FORWARDED_PROTO is only trusted when the request arrives from a
    // known proxy — REMOTE_ADDR spoofing is not possible at the TCP level.
    $forwardedProto = strtolower(trim((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
    if ($forwardedProto === 'https' && is_request_from_trusted_proxy()) {
        return true;
    }

    return false;
}

function get_request_scheme(): string
{
    return is_secure_request() ? 'https' : 'http';
}

function get_request_host(): string
{
    $host = trim((string) ($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost'));
    $host = preg_replace('/[^a-zA-Z0-9.\-:\[\]]/', '', $host);

    return $host !== '' ? $host : 'localhost';
}

function get_request_origin(): string
{
    return get_request_scheme() . '://' . get_request_host();
}

function should_enforce_https(): bool
{
    $raw = strtolower(trim((string) (getenv('ENFORCE_HTTPS') ?: '1')));

    return !in_array($raw, ['', '0', 'false', 'no', 'off'], true);
}

function get_https_port(): ?int
{
    $raw = trim((string) (getenv('APP_PORT') ?: ''));
    if ($raw === '' || !ctype_digit($raw)) {
        return null;
    }

    $port = (int) $raw;
    if ($port < 1 || $port > 65535) {
        return null;
    }

    return $port;
}

function get_request_hostname(): string
{
    $host = get_request_host();
    $parsed = parse_url('http://' . $host);
    $hostname = (string) ($parsed['host'] ?? '');

    return $hostname !== '' ? $hostname : 'localhost';
}

function get_https_redirect_host(): string
{
    $hostname = get_request_hostname();
    $port = get_https_port();

    if ($port === null || $port === 443) {
        return $hostname;
    }

    if (filter_var($hostname, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $hostname = '[' . trim($hostname, '[]') . ']';
    }

    return $hostname . ':' . $port;
}

function enforce_https(): void
{
    if (!should_enforce_https() || is_secure_request()) {
        return;
    }

    $url = 'https://' . get_https_redirect_host() . ($_SERVER['REQUEST_URI'] ?? '/');
    $url = preg_replace('/[\r\n]/', '', $url ?? '');

    header('HTTP/1.1 301 Moved Permanently');
    header('Location: ' . $url);
    exit;
}
