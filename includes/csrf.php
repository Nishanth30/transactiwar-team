<?php
// includes/csrf.php
// Custom CSRF protection — no frameworks used
// Defends against: forgery, timing attacks, replay, token fixation,
//                  header injection, AJAX forgery, missing/empty tokens,
//                  session fixation binding, origin spoofing, output buffer leaks,
//                  weak SameSite cookie config

declare(strict_types=1);

require_once __DIR__ . '/request.php';

// ─── Constants ───────────────────────────────────────────────────────────────

define('CSRF_TOKEN_BYTES',   32);              // 256-bit raw entropy
define('CSRF_SESSION_KEY',   'csrf_token');
define('CSRF_FIELD_NAME',    'csrf_token');
define('CSRF_HEADER_NAME',   'X-CSRF-Token'); // for AJAX requests
define('CSRF_MAX_AGE',       3600);            // token expires after 1 hour (seconds)
define('CSRF_ALLOWED_ORIGIN', trim((string) (getenv('CSRF_ALLOWED_ORIGIN') ?: ''))); // e.g. https://example.com


// ─── Internal Helpers ────────────────────────────────────────────────────────

/**
 * Abort the request with 403. Hard stop — nothing continues.
 * Clears any buffered output first so partial page content isn't sent.
 * Generic message to avoid leaking reason details to attacker.
 */
function _csrfFail(string $reason): never {
    // Flush and discard any buffered output to prevent partial page leaks
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    http_response_code(403);

    // Log failure if logger is already loaded (avoid circular dependency)
    if (function_exists('logActivity')) {
        // Sanitize reason before logging to prevent log injection
        $safeReason = preg_replace('/[^\w\s_\-]/', '', $reason);
        logActivity('CSRF_FAIL:' . $safeReason);
    }

    // Generic response — don't reveal which check failed to attacker
    die('Request forbidden.');
}

/**
 * Assert session is active before we touch $_SESSION.
 * Also warns if SameSite cookie is not configured — CSRF protection
 * is weakened without it.
 */
function _csrfAssertSession(): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        // Hard crash — developer error, not a user error
        throw new RuntimeException(
            'csrf.php: session_start() must be called before any CSRF function.'
        );
    }

    // Warn (once per request) if session cookie has no SameSite attribute.
    // SameSite=Lax/Strict is an independent CSRF defence layer.
    static $sameSiteChecked = false;
    if (!$sameSiteChecked) {
        $sameSiteChecked = true;
        $params = session_get_cookie_params();
        if (empty($params['samesite'])) {
            trigger_error(
                'csrf.php: Session cookie SameSite attribute is not set. ' .
                'Set session.cookie_samesite = "Lax" or "Strict" in php.ini ' .
                'or via session_set_cookie_params() before session_start().',
                E_USER_WARNING
            );
        }
    }
}

/**
 * Validate the HTTP Origin or Referer header against the allowed origin.
 *
 * Origin header is sent by all modern browsers on cross-origin requests.
 * Referer is a fallback for older browsers / same-origin form submissions.
 *
 * Returns true  → origin is acceptable (or check is disabled).
 * Returns false → origin is missing or does not match.
 *
 * NOTE: If CSRF_ALLOWED_ORIGIN is left empty the check is skipped entirely.
 * You should always set it in production.
 */
function _csrfCheckOrigin(): bool {
    $allowed = CSRF_ALLOWED_ORIGIN;

    // Fail-safe default: if env var is unset, enforce same-origin for this host.
    if ($allowed === '') {
        $allowed = get_request_origin();
    }

    if ($allowed === '') {
        return false;
    }

    // Prefer Origin header (set by browsers on cross-site requests).
    // Fall back to Referer for same-site form submissions where Origin may be absent.
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    if ($origin === '') {
        // Referer may include a path — only compare the scheme+host portion
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        if ($referer !== '') {
            $parts  = parse_url($referer);
            $scheme = $parts['scheme'] ?? '';
            $host   = $parts['host']   ?? '';
            $port   = isset($parts['port']) ? ':' . $parts['port'] : '';
            $origin = $scheme . '://' . $host . $port;
        }
    }

    if ($origin === '') {
        /*
         * Some privacy settings/policies can strip Origin + Referer.
         * In that case, rely on Fetch Metadata as a strict fallback.
         */
        $fetchSite = strtolower(trim((string) ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '')));
        if (in_array($fetchSite, ['same-origin', 'same-site', 'none'], true)) {
            return true;
        }

        // No trustworthy origin signals available — fail closed.
        return false;
    }

    // Normalise trailing slash differences, case-insensitive scheme+host
    return strcasecmp(rtrim($origin, '/'), rtrim($allowed, '/')) === 0;
}


// ─── Token Lifecycle ─────────────────────────────────────────────────────────

/**
 * Generate a fresh cryptographically secure HMAC-bound token.
 *
 * The raw token (256 bits of CSPRNG entropy) is HMAC'd with a server-side
 * secret so that a token from session A is always invalid in session B,
 * defeating session-fixation-assisted CSRF attacks.
 *
 * Stored format: "<hmac>.<raw_hex>"
 *   hmac    — SHA-256 HMAC of raw_hex keyed by session_id(), 64 hex chars
 *   raw_hex — bin2hex(random_bytes(32)),                      64 hex chars
 */
function csrfGenerate(): void {
    _csrfAssertSession();
    // Generate secret if missing (e.g. session existed before secret was introduced)
    if (empty($_SESSION['csrf_secret'])) {
        $_SESSION['csrf_secret'] = bin2hex(random_bytes(32));
    }

    $raw  = bin2hex(random_bytes(CSRF_TOKEN_BYTES));  // 64 hex chars, 256 bits
    $hmac = hash_hmac('sha256', $raw, $_SESSION['csrf_secret']);  // bind to server-side secret
    $_SESSION[CSRF_SESSION_KEY] = [
        'token'      => $hmac . '.' . $raw,
        'created_at' => time(),
    ];
}

/**
 * Ensure a valid, non-expired token exists. Create one if missing or expired.
 */
function csrfEnsure(): void {
    _csrfAssertSession();

    $entry = $_SESSION[CSRF_SESSION_KEY] ?? null;

    $needsNew =
        $entry === null ||                                  // never set
        !is_array($entry) ||                               // corrupted
        empty($entry['token']) ||                          // empty token
        !isset($entry['created_at']) ||                    // no timestamp
        (time() - $entry['created_at']) > CSRF_MAX_AGE;   // expired

    if ($needsNew) {
        csrfGenerate();
    }
}

/**
 * Return the current token string (the full "<hmac>.<raw>" value).
 * Generates a new token if one does not exist or has expired.
 */
function csrfToken(): string {
    csrfEnsure();
    return $_SESSION[CSRF_SESSION_KEY]['token'];
}

/**
 * Rotate the token. Call after every successful validation.
 * Prevents replay attacks — each token is single-use.
 */
function csrfRotate(): void {
    csrfGenerate();
}


// ─── Output Helpers ───────────────────────────────────────────────────────────

/**
 * Return a hidden input field to embed inside any HTML form.
 *
 * Usage inside any form:
 *     <?= csrfField() ?>
 */
function csrfField(): string {
    $token = htmlspecialchars(csrfToken(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $name  = htmlspecialchars(CSRF_FIELD_NAME, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    return '<input type="hidden" name="' . $name . '" value="' . $token . '">';
}

/**
 * Return the token for use in JavaScript (e.g., fetch/AJAX calls).
 * Embed in a <meta> tag in your <head>, never in a URL.
 *
 * Usage in HTML <head>:
 *     <?= csrfMeta() ?>
 *
 * Usage in JavaScript:
 *     const token = document.querySelector('meta[name="csrf-token"]').content;
 *     fetch('/transfer.php', {
 *         method: 'POST',
 *         headers: { 'X-CSRF-Token': token },
 *         body: formData
 *     });
 */
function csrfMeta(): string {
    $token = htmlspecialchars(csrfToken(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    return '<meta name="csrf-token" content="' . $token . '">';
}


// ─── Validation ───────────────────────────────────────────────────────────────

/**
 * Core validation logic — shared by form and AJAX validators.
 *
 * Verifies three things:
 *   1. Session contains a valid, non-expired token entry.
 *   2. Submitted value is non-empty and matches via constant-time comparison.
 *   3. The HMAC embedded in the token is valid for the current session ID,
 *      preventing cross-session token transplant attacks.
 *
 * Returns true on success, false on any failure.
 */
function _csrfValidateToken(string $submitted): bool {
    _csrfAssertSession();

    // Fail safely if secret is missing
    if (empty($_SESSION['csrf_secret'])) {
        return false;
    }

    $entry = $_SESSION[CSRF_SESSION_KEY] ?? null;

    // Reject if session has no token at all
    if (!is_array($entry) || empty($entry['token']) || empty($entry['created_at'])) {
        return false;
    }

    // Reject expired tokens (extra server-side check beyond session lifetime)
    if ((time() - $entry['created_at']) > CSRF_MAX_AGE) {
        csrfRotate(); // clean up expired token
        return false;
    }

    // Reject empty submitted value
    if ($submitted === '') {
        return false;
    }

    $stored = $entry['token'];

    // ── Step 1: Constant-time full-token comparison ──────────────────────────
    // hash_equals prevents timing oracle — must run even if we later reject
    if (!hash_equals($stored, $submitted)) {
        return false;
    }

    // ── Step 2: HMAC session-binding verification ────────────────────────────
    // Format: "<hmac>.<raw_hex>"
    // Re-derive the expected HMAC from the raw portion and the server-side
    // secret. If the token was lifted from a different session the HMAC won't match.
    $parts = explode('.', $submitted, 2);
    if (count($parts) !== 2) {
        return false; // malformed token
    }

    [$submittedHmac, $raw] = $parts;

    // Constant-time comparison for the HMAC portion as well
    $expectedHmac = hash_hmac('sha256', $raw, $_SESSION['csrf_secret']);
    if (!hash_equals($expectedHmac, $submittedHmac)) {
        return false;
    }

    return true;
}

/**
 * Validate CSRF token from a standard HTML form (POST body).
 * Call this at the TOP of every POST handler before reading $_POST.
 *
 * Also validates the Origin/Referer header when CSRF_ALLOWED_ORIGIN is set.
 * Dies with 403 on failure. Rotates token on success.
 */
function verifyCsrf(): void {
    // Only enforce on state-changing methods
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? '');
    if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        return; // GET/HEAD are read-only, skip
    }

    // Origin / Referer check — independent of token, second layer of defence
    if (!_csrfCheckOrigin()) {
        _csrfFail('origin_mismatch');
    }

    $submitted = (string)($_POST[CSRF_FIELD_NAME] ?? '');

    if (!_csrfValidateToken($submitted)) {
        _csrfFail('form_token_invalid');
    }

    // Success — rotate token to prevent replay
    csrfRotate();
}

/**
 * Validate CSRF token from an AJAX/fetch request (custom header).
 * Call this at the TOP of any AJAX endpoint handler.
 *
 * Custom request headers (X-CSRF-Token) cannot be set by a simple cross-origin
 * HTML form, which provides an additional implicit layer of protection.
 *
 * Also validates the Origin header when CSRF_ALLOWED_ORIGIN is set.
 * Dies with 403 on failure. Rotates token on success.
 */
function verifyCsrfAjax(): void {
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? '');
    if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        return;
    }

    // Origin check — AJAX callers always send an Origin header
    if (!_csrfCheckOrigin()) {
        _csrfFail('ajax_origin_mismatch');
    }

    // PHP converts header names: X-CSRF-Token → HTTP_X_CSRF_TOKEN
    $submitted = (string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');

    if (!_csrfValidateToken($submitted)) {
        _csrfFail('ajax_token_invalid');
    }

    csrfRotate();
}

/**
 * Explicitly choose which verifier to call based on how the endpoint is used.
 *
 * NOTE: Auto-detection via X-Requested-With was removed because:
 *   - X-Requested-With is a jQuery-era convention; modern fetch() does not
 *     set it by default.
 *   - An attacker could omit the header and silently route to verifyCsrf(),
 *     which reads from $_POST — empty for JSON AJAX calls, causing a false pass.
 *
 * For AJAX endpoints: call verifyCsrfAjax() directly.
 * For HTML form endpoints: call verifyCsrf() directly.
 *
 * This wrapper is kept for legacy call sites but you should prefer the
 * explicit functions above. It now requires a $mode argument.
 *
 * @param string $mode  'form' | 'ajax'
 */
function verifyCsrfAuto(string $mode = 'form'): void {
    if ($mode === 'ajax') {
        verifyCsrfAjax();
    } else {
        verifyCsrf();
    }
}
