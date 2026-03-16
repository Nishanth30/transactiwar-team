<?php
// includes/csrf.php
// Custom CSRF protection — no frameworks used
// Defends against: forgery, timing attacks, replay, token fixation,
//                  header injection, AJAX forgery, missing/empty tokens,
//                  session fixation binding, origin spoofing, output buffer leaks,
//                  weak SameSite cookie config

declare(strict_types = 1)
;

require_once __DIR__ . '/request.php';

// ─── Constants ───────────────────────────────────────────────────────────────

define('CSRF_TOKEN_BYTES', 32); // 256-bit raw entropy
define('CSRF_POOL_KEY', 'csrf_pool'); // H3 FIX: session key for token pool
define('CSRF_FIELD_NAME', 'csrf_token');
define('CSRF_HEADER_NAME', 'X-CSRF-Token'); // for AJAX requests
define('CSRF_MAX_AGE', 3600); // token expires after 1 hour (seconds)
define('CSRF_MAX_TOKENS', 5); // max concurrent tokens (multi-tab support)
$allowedOrigin = trim((string)getenv('CSRF_ALLOWED_ORIGIN'));
if ($allowedOrigin === '') {
    error_log('WARNING: CSRF_ALLOWED_ORIGIN not set - origin validation disabled');
    // Hard fail in production to ensure security
    if (getenv('APP_ENV') === 'production' || getenv('APP_DEBUG') !== '1') {
        throw new RuntimeException('CSRF_ALLOWED_ORIGIN must be set in production');
    }
}
define('CSRF_ALLOWED_ORIGIN', $allowedOrigin);


// ─── Internal Helpers ────────────────────────────────────────────────────────

/**
 * Abort the request with 403. Hard stop — nothing continues.
 * Clears any buffered output first so partial page content isn't sent.
 * Generic message to avoid leaking reason details to attacker.
 */
function _csrfFail(string $reason): never
{
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
function _csrfAssertSession(): void
{
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
function _csrfCheckOrigin(): bool
{
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
            $parts = parse_url($referer);
            $scheme = $parts['scheme'] ?? '';
            $host = $parts['host'] ?? '';
            $port = isset($parts['port']) ? ':' . $parts['port'] : '';
            $origin = $scheme . '://' . $host . $port;
        }
    }

    if ($origin === '') {
        /*
         * Some privacy settings/policies can strip Origin + Referer.
         * In that case, rely on Fetch Metadata as a strict fallback.
         */
        $fetchSite = strtolower(trim((string)($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '')));
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
//
// H3 FIX: Replaced single-slot token with a bounded pool (CSRF_MAX_TOKENS).
//
// Problem: The old design stored exactly one token in $_SESSION['csrf_token'].
// When Tab A submitted a form, csrfRotate() overwrote the session token,
// invalidating the token already embedded in Tab B's form. An attacker could
// weaponize this by tricking the victim into visiting any POST-protected page,
// thereby invalidating CSRF tokens in every other open tab.
//
// Fix: Each page render adds a fresh token to a pool. Validation searches the
// pool and removes only the consumed token. Other tabs' tokens remain valid.
// The pool is capped at CSRF_MAX_TOKENS and expired entries are pruned on
// every generation, so memory growth is bounded.

/**
 * Generate a fresh HMAC-bound token and add it to the session pool.
 *
 * Returns the new token string ("<hmac>.<raw_hex>").
 *
 * Pool maintenance:
 *   - Expired tokens are pruned on every call.
 *   - If the pool exceeds CSRF_MAX_TOKENS, the oldest entry is evicted.
 *   - Legacy single-slot key ('csrf_token') is cleaned up on first call.
 */
function csrfGenerate(): string
{
    _csrfAssertSession();

    // Ensure per-session HMAC secret exists.
    if (empty($_SESSION['csrf_secret'])) {
        $_SESSION['csrf_secret'] = bin2hex(random_bytes(32));
    }

    // One-time migration: drop the old single-slot key so it does not
    // confuse debugging or consume session storage indefinitely.
    unset($_SESSION['csrf_token']);

    // Build the new token.
    $raw = bin2hex(random_bytes(CSRF_TOKEN_BYTES)); // 64 hex chars
    $hmac = hash_hmac('sha256', $raw, $_SESSION['csrf_secret']);
    $token = $hmac . '.' . $raw;
    $now = time();

    // Initialise / sanitise the pool.
    if (!isset($_SESSION[CSRF_POOL_KEY]) || !is_array($_SESSION[CSRF_POOL_KEY])) {
        $_SESSION[CSRF_POOL_KEY] = [];
    }

    // Prune expired entries.
    $_SESSION[CSRF_POOL_KEY] = array_values(array_filter(
        $_SESSION[CSRF_POOL_KEY],
    static fn(array $e): bool => ($now - ($e['created_at'] ?? 0)) <= CSRF_MAX_AGE
    ));

    // Append the new token.
    $_SESSION[CSRF_POOL_KEY][] = [
        'token' => $token,
        'created_at' => $now,
    ];

    // Evict the oldest if the pool is over capacity.
    if (count($_SESSION[CSRF_POOL_KEY]) > CSRF_MAX_TOKENS) {
        $_SESSION[CSRF_POOL_KEY] = array_slice(
            $_SESSION[CSRF_POOL_KEY],
            -CSRF_MAX_TOKENS
        );
    }

    return $token;
}

/**
 * Return the CSRF token for the current request.
 *
 * A fresh token is generated once per HTTP request (cached via static) so
 * that every form and meta tag on the same page shares the same value,
 * while different page loads (tabs) each receive a unique token.
 */
function csrfToken(): string
{
    // Per-request cache: all forms rendered in the same response share one
    // token so we only consume one pool slot per page load.
    static $requestToken = null;
    if ($requestToken !== null) {
        return $requestToken;
    }

    $requestToken = csrfGenerate();
    return $requestToken;
}


// ─── Output Helpers ───────────────────────────────────────────────────────────

/**
 * Return a hidden input field to embed inside any HTML form.
 *
 * Usage inside any form:
 *     <?= csrfField() ?>
 */
function csrfField(): string
{
    $token = htmlspecialchars(csrfToken(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $name = htmlspecialchars(CSRF_FIELD_NAME, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

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
function csrfMeta(): string
{
    $token = htmlspecialchars(csrfToken(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    return '<meta name="csrf-token" content="' . $token . '">';
}


// ─── Validation ───────────────────────────────────────────────────────────────

/**
 * Core validation logic — shared by form and AJAX validators.
 *
 * H3 FIX: Searches the token pool instead of comparing against a single
 * slot. On match the consumed token is removed (single-use preserved).
 *
 * Verifies three things per pool entry:
 *   1. The entry is not expired.
 *   2. The submitted value matches via constant-time comparison.
 *   3. The HMAC embedded in the token is valid for the current session
 *      secret, preventing cross-session token transplant attacks.
 *
 * Returns true on success, false on any failure.
 */
function _csrfValidateToken(string $submitted): bool
{
    _csrfAssertSession();

    // Fail safely if secret or submitted value is missing.
    if (empty($_SESSION['csrf_secret']) || $submitted === '') {
        return false;
    }

    $pool = $_SESSION[CSRF_POOL_KEY] ?? [];
    if (!is_array($pool) || $pool === []) {
        return false;
    }

    // Pre-parse the submitted token so we only do it once.
    $parts = explode('.', $submitted, 2);
    if (count($parts) !== 2) {
        return false; // malformed
    }
    [$submittedHmac, $raw] = $parts;

    // Re-derive the expected HMAC once — it is the same for every pool entry
    // because all tokens in the pool share the same session secret.
    $expectedHmac = hash_hmac('sha256', $raw, $_SESSION['csrf_secret']);

    // ── Step 1: Verify the HMAC (session-binding) ────────────────────────────
    if (!hash_equals($expectedHmac, $submittedHmac)) {
        return false;
    }

    // ── Step 2: Search the pool for a matching, non-expired entry ────────────
    $now = time();
    $matchedIndex = null;

    foreach ($pool as $i => $entry) {
        if (!is_array($entry) || empty($entry['token']) || empty($entry['created_at'])) {
            continue; // corrupt entry
        }

        // Skip expired tokens.
        if (($now - (int)$entry['created_at']) > CSRF_MAX_AGE) {
            continue;
        }

        // Constant-time full-token comparison.
        if (hash_equals($entry['token'], $submitted)) {
            $matchedIndex = $i;
            break;
        }
    }

    if ($matchedIndex === null) {
        return false;
    }

    // ── Step 3: Consume the token (single-use) ──────────────────────────────
    unset($_SESSION[CSRF_POOL_KEY][$matchedIndex]);
    $_SESSION[CSRF_POOL_KEY] = array_values($_SESSION[CSRF_POOL_KEY]);

    return true;
}

/**
 * Validate CSRF token from a standard HTML form (POST body).
 * Call this at the TOP of every POST handler before reading $_POST.
 *
 * Also validates the Origin/Referer header when CSRF_ALLOWED_ORIGIN is set.
 * Dies with 403 on failure. On success the consumed token is removed from the
 * pool by _csrfValidateToken() — no separate rotation step needed.
 */
function verifyCsrf(): void
{
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

// Token already consumed (removed from pool) by _csrfValidateToken().
}

/**
 * Validate CSRF token from an AJAX/fetch request (custom header).
 * Call this at the TOP of any AJAX endpoint handler.
 *
 * Custom request headers (X-CSRF-Token) cannot be set by a simple cross-origin
 * HTML form, which provides an additional implicit layer of protection.
 *
 * Also validates the Origin header when CSRF_ALLOWED_ORIGIN is set.
 * Dies with 403 on failure. On success the consumed token is removed from the
 * pool by _csrfValidateToken().
 */
function verifyCsrfAjax(): void
{
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

// Token already consumed (removed from pool) by _csrfValidateToken().
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
function verifyCsrfAuto(string $mode = 'form'): void
{
    if ($mode === 'ajax') {
        verifyCsrfAjax();
    }
    else {
        verifyCsrf();
    }
}
