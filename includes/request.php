<?php

declare(strict_types=1);

function get_request_client_ip(): string
{
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
    if (strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') {
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
