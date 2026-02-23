<?php
// includes/headers.php
// HTTP Security Headers Framework
// No external dependencies — pure PHP header() calls
//
// Defends against:
//   XSS, Clickjacking, MIME sniffing, SSL stripping,
//   URL leaking, Cache attacks, MITM, Feature abuse,
//   Information disclosure, Protocol downgrade attacks
//
// Usage:
//   require_once '../includes/headers.php';  ← FIRST line of every PHP file
//   send_security_headers();                 ← call before any output

declare(strict_types=1);


// ══════════════════════════════════════════════════════════════════
//  CONSTANTS
// ══════════════════════════════════════════════════════════════════

// HSTS max age — 1 year in seconds
define('HSTS_MAX_AGE', 31536000);

// CSP nonce length in bytes
define('CSP_NONCE_BYTES', 16);


// ══════════════════════════════════════════════════════════════════
//  SECTION 1 — NONCE GENERATOR
//  CSP nonce allows specific inline scripts without
//  opening up all inline scripts
// ══════════════════════════════════════════════════════════════════

/**
 * Generate a cryptographically secure CSP nonce.
 * Generated once per request, stored in $GLOBALS.
 * Use in both the CSP header and your script tags.
 *
 * Usage in PHP:
 *   $nonce = get_csp_nonce();
 *
 * Usage in HTML:
 *   <script nonce="<?= get_csp_nonce() ?>">
 *     // this inline script is allowed
 *   </script>
 */
function get_csp_nonce(): string {
    if (!isset($GLOBALS['csp_nonce'])) {
        $GLOBALS['csp_nonce'] = base64_encode(random_bytes(CSP_NONCE_BYTES));
    }
    return $GLOBALS['csp_nonce'];
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 2 — CSP BUILDER
//  Content Security Policy — most powerful header
//  Controls exactly what browser is allowed to load/execute
// ══════════════════════════════════════════════════════════════════

/**
 * Build the Content-Security-Policy header value.
 *
 * Directives explained:
 *   default-src  → fallback for anything not specified
 *   script-src   → where JavaScript can come from
 *   style-src    → where CSS can come from
 *   img-src      → where images can come from
 *   font-src     → where fonts can come from
 *   connect-src  → where fetch/XHR/WebSocket can connect
 *   frame-src    → what can be loaded in iframes
 *   object-src   → Flash/plugins (none allowed)
 *   base-uri     → restricts <base> tag hijacking
 *   form-action  → where forms can submit to
 *   upgrade-insecure-requests → auto upgrade HTTP to HTTPS
 */
function build_csp(string $nonce): string {
    $directives = [

        // Default: only same origin, no inline, no eval
        "default-src 'self'",

        // Scripts: same origin + nonce for specific inline scripts
        // 'strict-dynamic' trusts scripts loaded by trusted scripts
        // No 'unsafe-inline' — that would defeat the purpose
        // No 'unsafe-eval' — prevents eval(), setTimeout(string) etc
        "script-src 'self' 'nonce-{$nonce}' 'strict-dynamic'",

        // Styles: same origin + nonce for inline styles
        // Bootstrap loaded locally so 'self' covers it
        "style-src 'self' 'nonce-{$nonce}'",

        // Images: same origin + data URIs (for inline images)
        // blob: for any canvas/generated images
        "img-src 'self' data: blob:",

        // Fonts: same origin only (Bootstrap fonts served locally)
        "font-src 'self'",

        // AJAX/fetch: same origin only
        // Prevents XSS from exfiltrating data to evil.com
        "connect-src 'self'",

        // Frames: nobody can frame anything
        // Belt AND suspenders with X-Frame-Options
        "frame-src 'none'",

        // No plugins — Flash, Java, Silverlight all blocked
        "object-src 'none'",

        // No embedding of your pages
        "frame-ancestors 'none'",

        // Prevent <base> tag hijacking
        // Attacker inserting <base href="http://evil.com">
        // would redirect all relative URLs to evil.com
        "base-uri 'self'",

        // Forms can only submit to same origin
        // Prevents XSS from creating forms that submit to evil.com
        "form-action 'self'",

        // Manifests: same origin only
        "manifest-src 'self'",

        // Workers: same origin only
        "worker-src 'self'",

        // Auto upgrade any accidental HTTP requests to HTTPS
        "upgrade-insecure-requests",

        // Block all mixed content (HTTP resources on HTTPS page)
        "block-all-mixed-content",
    ];

    return implode('; ', $directives);
}

/**
 * Build a relaxed CSP for static asset pages.
 * Less strict — allows caching of styles/scripts.
 */
function build_asset_csp(): string {
    $directives = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
    ];

    return implode('; ', $directives);
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 3 — REMOVE INFORMATION DISCLOSURE HEADERS
//  PHP and Apache leak version info by default
//  Attackers use this to find known vulnerabilities
// ══════════════════════════════════════════════════════════════════

/**
 * Remove headers that leak server information.
 *
 * Removes:
 *   X-Powered-By: PHP/8.2.1    ← tells attacker PHP version
 *   Server: Apache/2.4.51      ← tells attacker server version
 */
function remove_disclosure_headers(): void {
    // Remove PHP version header
    header_remove('X-Powered-By');

    // Remove server signature if possible
    // (Full removal requires Apache config but this helps)
    header_remove('Server');

    // Remove any existing headers that might leak info
    header_remove('X-Generator');
    header_remove('X-Runtime');
    header_remove('X-Version');
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 4 — CORE SECURITY HEADERS
// ══════════════════════════════════════════════════════════════════

/**
 * Send all security headers for sensitive pages.
 * Call this as the FIRST thing in every PHP page.
 *
 * Covers:
 *   - XSS via CSP
 *   - Clickjacking via X-Frame-Options + frame-ancestors
 *   - MIME sniffing via X-Content-Type-Options
 *   - SSL stripping via HSTS
 *   - URL leaking via Referrer-Policy
 *   - Feature abuse via Permissions-Policy
 *   - Cache attacks via Cache-Control
 *   - Information disclosure via header removal
 *   - Protocol downgrade via HSTS
 *   - MITM via HSTS
 *
 * Usage — first line of every PHP file:
 *   <?php
 *   require_once '../includes/headers.php';
 *   send_security_headers();
 */
function send_security_headers(): void {
    // Must be called before any output
    if (headers_sent($file, $line)) {
        error_log(
            "headers.php: headers already sent in {$file} on line {$line}. " .
            "require headers.php BEFORE any output."
        );
        return;
    }

    // ── Step 1: Remove information disclosure ────────────────────
    remove_disclosure_headers();

    // ── Step 2: Generate nonce for this request ───────────────────
    $nonce = get_csp_nonce();

    // ── Step 3: Content Security Policy ──────────────────────────
    // Most important header — controls what browser executes
    header('Content-Security-Policy: ' . build_csp($nonce));

    // ── Step 4: Clickjacking Protection ──────────────────────────
    // Older browsers use this (CSP frame-ancestors covers modern)
    header('X-Frame-Options: DENY');

    // ── Step 5: MIME Sniffing Protection ─────────────────────────
    // Browser must use declared Content-Type, never guess
    header('X-Content-Type-Options: nosniff');

    // ── Step 6: HTTPS Enforcement (HSTS) ─────────────────────────
    // Browser remembers: always use HTTPS for this domain
    // includeSubDomains: covers all subdomains too
    // preload: allows inclusion in browser preload lists
    header(
        'Strict-Transport-Security: max-age=' . HSTS_MAX_AGE .
        '; includeSubDomains; preload'
    );

    // ── Step 7: Referrer Policy ───────────────────────────────────
    // No referrer sent to ANY site — URLs stay private
    header('Referrer-Policy: no-referrer');

    // ── Step 8: Permissions Policy ────────────────────────────────
    // Disable ALL browser features not needed by a banking app
    header(
        'Permissions-Policy: ' .
        'accelerometer=(), ' .
        'ambient-light-sensor=(), ' .
        'autoplay=(), ' .
        'battery=(), ' .
        'camera=(), ' .
        'display-capture=(), ' .
        'document-domain=(), ' .
        'encrypted-media=(), ' .
        'execution-while-not-rendered=(), ' .
        'execution-while-out-of-viewport=(), ' .
        'fullscreen=(), ' .
        'geolocation=(), ' .
        'gyroscope=(), ' .
        'keyboard-map=(), ' .
        'magnetometer=(), ' .
        'microphone=(), ' .
        'midi=(), ' .
        'payment=(), ' .
        'picture-in-picture=(), ' .
        'publickey-credentials-get=(), ' .
        'screen-wake-lock=(), ' .
        'sync-xhr=(), ' .
        'usb=(), ' .
        'web-share=(), ' .
        'xr-spatial-tracking=()'
    );

    // ── Step 9: Cache Control ─────────────────────────────────────
    // Sensitive pages must NEVER be cached
    // Prevents data exposure on shared computers
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');   // HTTP/1.0 backward compatibility
    header('Expires: 0');         // Proxies and older browsers

    // ── Step 10: Legacy XSS Protection ───────────────────────────
    // For old IE/Edge browsers before CSP was supported
    // mode=block stops rendering rather than sanitizing
    header('X-XSS-Protection: 1; mode=block');

    // ── Step 11: Cross-Origin Policies ───────────────────────────
    // COEP: prevents loading cross-origin resources without permission
    header('Cross-Origin-Embedder-Policy: require-corp');

    // COOP: prevents cross-origin windows from accessing your window
    header('Cross-Origin-Opener-Policy: same-origin');

    // CORP: prevents other origins from reading your responses
    header('Cross-Origin-Resource-Policy: same-origin');

    // ── Step 12: Content Type ─────────────────────────────────────
    // Always declare content type explicitly
    header('Content-Type: text/html; charset=UTF-8');
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 5 — ASSET HEADERS
//  For CSS, JS, image files — can be cached
// ══════════════════════════════════════════════════════════════════

/**
 * Send headers for static assets (CSS, JS, images).
 * Less strict cache policy — assets can be cached.
 *
 * Usage in serve_image.php (Member 2):
 *   send_asset_headers('image/jpeg');
 */
function send_asset_headers(string $contentType = 'application/octet-stream'): void {
    if (headers_sent()) {
        return;
    }

    remove_disclosure_headers();

    header('Content-Security-Policy: ' . build_asset_csp());
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');

    // Assets CAN be cached — 1 year
    header('Cache-Control: public, max-age=' . HSTS_MAX_AGE . ', immutable');

    // Declare the correct content type
    header('Content-Type: ' . $contentType);
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 6 — API / JSON HEADERS
//  For any AJAX endpoints
// ══════════════════════════════════════════════════════════════════

/**
 * Send headers for JSON API responses.
 * Strict — no caching, correct content type.
 *
 * Usage in any AJAX handler:
 *   send_json_headers();
 *   echo json_encode($data);
 *   exit;
 */
function send_json_headers(): void {
    if (headers_sent()) {
        return;
    }

    remove_disclosure_headers();

    // No caching for API responses
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

    // Correct content type — prevents MIME sniffing JSON as HTML
    header('Content-Type: application/json; charset=UTF-8');

    // Security headers
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');

    // CORS — same origin only
    // No Access-Control-Allow-Origin wildcard
    header('Access-Control-Allow-Origin: ' . get_own_origin());
    header('Access-Control-Allow-Methods: POST, GET');
    header('Access-Control-Allow-Headers: X-CSRF-Token, Content-Type');
    header('Access-Control-Allow-Credentials: true');
}

/**
 * Get the application's own origin for CORS.
 * Derived from current request — no hardcoding needed.
 */
function get_own_origin(): string {
    $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'
        ? 'https'
        : 'http';

    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';

    // Sanitize host — prevent header injection
    $host = preg_replace('/[^a-zA-Z0-9.\-:]/', '', $host);

    return $scheme . '://' . $host;
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 7 — CACHE HELPERS
//  Fine-grained cache control per page type
// ══════════════════════════════════════════════════════════════════

/**
 * Force no caching for this response.
 * Use on: login, register, dashboard, transfer, profile, history
 */
function no_cache(): void {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
}

/**
 * Allow caching for a specified number of seconds.
 * Use on: public static pages only
 */
function cache_for(int $seconds): void {
    header("Cache-Control: public, max-age={$seconds}");
    header('Expires: ' . gmdate('D, d M Y H:i:s', time() + $seconds) . ' GMT');
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 8 — HTTPS ENFORCEMENT
//  Redirect HTTP to HTTPS in production
// ══════════════════════════════════════════════════════════════════

/**
 * Force HTTPS redirect in production.
 * Skip on localhost/development.
 *
 * Call after send_security_headers() if on production.
 *
 * Usage:
 *   send_security_headers();
 *   enforce_https();
 */
function enforce_https(): void {
    // Skip on localhost — HSTS causes problems in local dev
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    if (str_contains($host, 'localhost') ||
        str_contains($host, '127.0.0.1') ||
        str_contains($host, '::1')) {
        return;
    }

    // If not HTTPS — redirect permanently
    if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
        $url = 'https://' . $host . ($_SERVER['REQUEST_URI'] ?? '/');

        // Sanitize before redirect
        $url = preg_replace('/[\r\n]/', '', $url ?? '');

        header('HTTP/1.1 301 Moved Permanently');
        header('Location: ' . $url);
        exit;
    }
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 9 — ERROR PAGE HEADERS
//  For 403, 404, 500 error pages
// ══════════════════════════════════════════════════════════════════

/**
 * Send headers for error pages.
 * No caching, correct status code.
 *
 * Usage:
 *   send_error_headers(403);
 *   die('Access denied.');
 */
function send_error_headers(int $statusCode): void {
    if (headers_sent()) {
        return;
    }

    remove_disclosure_headers();
    http_response_code($statusCode);

    header('Cache-Control: no-store');
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 10 — HEADER VERIFICATION (DEBUG ONLY)
//  Verify all headers are set correctly
//  Remove before submission
// ══════════════════════════════════════════════════════════════════

/**
 * Dump all currently set headers for debugging.
 * Only works in CLI or before output.
 *
 * Usage:
 *   send_security_headers();
 *   debug_headers();   ← REMOVE BEFORE SUBMISSION
 */
function debug_headers(): void {
    if (getenv('APP_DEBUG') !== 'true') {
        return;
    }

    $headers = headers_list();
    echo '<pre style="background:#1a1a1a;color:#00ff00;padding:20px;">';
    echo "=== SECURITY HEADERS SET ===\n\n";
    foreach ($headers as $header) {
        echo htmlspecialchars($header, ENT_QUOTES, 'UTF-8') . "\n";
    }
    echo '</pre>';
}