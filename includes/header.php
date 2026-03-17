<?php

declare(strict_types=1);

require_once __DIR__ . '/request.php';
require_once __DIR__ . '/ai_traps.php';

// IP Firewall — must run before any page content.
// Blocks IPs that the team has put on cooldown/ban via the firewall CLI.
require_once __DIR__ . '/ip_firewall.php';
checkIpFirewall();

define('HSTS_MAX_AGE', 31536000);
define('CSP_NONCE_BYTES', 16);

function get_csp_nonce(): string
{
    if (!isset($GLOBALS['csp_nonce'])) {
        $GLOBALS['csp_nonce'] = base64_encode(random_bytes(CSP_NONCE_BYTES));
    }

    return $GLOBALS['csp_nonce'];
}

function build_csp(string $nonce): string
{
    $directives = [
        "default-src 'self'",
        "script-src 'self' 'nonce-{$nonce}' 'strict-dynamic'",
        "style-src 'self'",
        "img-src 'self' data: blob:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "frame-src 'none'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "manifest-src 'self'",
        "worker-src 'self'",
    ];

    if (is_secure_request()) {
        $directives[] = 'upgrade-insecure-requests';
        $directives[] = 'block-all-mixed-content';
    }

    // CSP violation reporting — see what XSS attempts the CSP blocks
    $directives[] = "report-uri /csp-report.php";

    return implode('; ', $directives);
}

function build_asset_csp(): string
{
    return implode('; ', [
        "default-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self' data:",
        "object-src 'none'",
        "base-uri 'self'",
    ]);
}

function remove_disclosure_headers(): void
{
    header_remove('X-Powered-By');
    header_remove('X-Generator');
    header_remove('X-Runtime');
    header_remove('X-Version');
}

function send_security_headers(): void
{
    enforce_https();

    if (headers_sent($file, $line)) {
        error_log(
            "header.php: headers already sent in {$file} on line {$line}."
        );
        return;
    }

    remove_disclosure_headers();

    header('Content-Security-Policy: ' . build_csp(get_csp_nonce()));
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header(
        'Permissions-Policy: ' .
        'accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), ' .
        'camera=(), display-capture=(), document-domain=(), encrypted-media=(), ' .
        'execution-while-not-rendered=(), execution-while-out-of-viewport=(), ' .
        'fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), ' .
        'magnetometer=(), microphone=(), midi=(), payment=(), ' .
        'picture-in-picture=(), publickey-credentials-get=(), ' .
        'screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()'
    );
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-XSS-Protection: 1; mode=block');
    header('Cross-Origin-Embedder-Policy: require-corp');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('Content-Type: text/html; charset=UTF-8');

    if (is_secure_request()) {
        header(
            'Strict-Transport-Security: max-age=' . HSTS_MAX_AGE . '; includeSubDomains; preload'
        );
    }
}

function send_asset_headers(string $contentType = 'application/octet-stream'): void
{
    enforce_https();

    if (headers_sent()) {
        return;
    }

    remove_disclosure_headers();

    header('Content-Security-Policy: ' . build_asset_csp());
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Cache-Control: public, max-age=' . HSTS_MAX_AGE . ', immutable');
    header('Content-Type: ' . $contentType);

    if (is_secure_request()) {
        header(
            'Strict-Transport-Security: max-age=' . HSTS_MAX_AGE . '; includeSubDomains; preload'
        );
    }
}

function send_json_headers(): void
{
    enforce_https();

    if (headers_sent()) {
        return;
    }

    remove_disclosure_headers();

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Access-Control-Allow-Origin: ' . get_own_origin());
    header('Access-Control-Allow-Methods: POST, GET');
    header('Access-Control-Allow-Headers: X-CSRF-Token, Content-Type');
    header('Access-Control-Allow-Credentials: true');

    if (is_secure_request()) {
        header(
            'Strict-Transport-Security: max-age=' . HSTS_MAX_AGE . '; includeSubDomains; preload'
        );
    }
}

function get_own_origin(): string
{
    return get_request_origin();
}

function no_cache(): void
{
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
}

function cache_for(int $seconds): void
{
    header("Cache-Control: public, max-age={$seconds}");
    header('Expires: ' . gmdate('D, d M Y H:i:s', time() + $seconds) . ' GMT');
}

function send_error_headers(int $statusCode): void
{
    enforce_https();

    if (headers_sent()) {
        return;
    }

    remove_disclosure_headers();
    http_response_code($statusCode);
    header('Cache-Control: no-store');
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
}

function debug_headers(): void
{
    if (getenv('APP_DEBUG') !== 'true') {
        return;
    }

    echo '<pre class="debug-headers-pre">';
    echo "=== SECURITY HEADERS SET ===\n\n";
    foreach (headers_list() as $header) {
        echo htmlspecialchars($header, ENT_QUOTES, 'UTF-8') . "\n";
    }
    echo '</pre>';
}

function render_page_head(string $title, string $extraHead = ''): void
{
    // AI anti-exploitation traps in <head>
    echo aiTrapHead();
    $safeTitle = htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    echo '<meta charset="UTF-8">' . PHP_EOL;
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">' . PHP_EOL;
    echo '<title>' . $safeTitle . '</title>' . PHP_EOL;
    if ($extraHead !== '') {
        echo $extraHead . PHP_EOL;
    }
    echo '<link rel="stylesheet" href="/assets/vendor/bootstrap/css/bootstrap.min.css" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH">' . PHP_EOL;
    echo '<link rel="stylesheet" href="/assets/css/style.css">' . PHP_EOL;
}
