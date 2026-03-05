# Transactiwar Security Assessment Report

**Date:** 2026-03-04 (updated 2026-03-05)
**Scope:** Full static + dynamic security audit of the Transactiwar PHP application
**Repository:** transactiwar-team (local Docker Compose stack)
**Methodology:** Line-by-line static analysis of all in-scope files + dynamic PoC validation against local Docker stack

---

## Executive Summary

The Transactiwar application demonstrates strong security fundamentals: parameterized queries throughout (no SQLi found), HMAC-bound CSRF tokens with single-use rotation, bcrypt password hashing with anti-enumeration timing, session hardening (strict mode, SameSite=Strict, periodic rotation), robust upload MIME validation, and DB-level constraints (balance non-negative, minimum transfer, self-transfer prevention).

However, the audit uncovered **4 High**, **8 Medium**, and **6 Low** severity findings across authentication logic, session management, information disclosure, supply chain, and configuration gaps.

**Top critical-path findings:**
1. **Login lockout bypass** — `login_user()` returns a truthy `'locked'` string that the caller treats as success, clearing the lockout record (HIGH-1)
2. **Broken session hijack detection** — undefined `$now` variable causes a TypeError that prevents session reset on fingerprint mismatch (HIGH-2)
3. **`display_errors = 1`** on the login page overrides Dockerfile hardening, leaking stack traces and file paths (HIGH-3)
4. **Missing security headers** on 5+ pages — register, search, profile, view_profile, and index lack CSP/HSTS/X-Frame-Options (HIGH-4)

None of the findings enable direct unauthenticated RCE or SQL injection. The primary risks are defense-in-depth failures, logic flaws, and configuration drift.

---

## Findings

### HIGH-1: Login Lockout Bypass via Truthy `'locked'` Return Value

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | AuthN / Broken Access Control |
| **File** | `includes/auth.php:207`, `public/login.php:48-54` |
| **Exploitability** | Moderate (requires concurrent requests at lockout threshold) |

**Description:**

`login_user()` returns a union type `bool|string`:
- `true` on success
- `'locked'` when the IP is rate-limited (`auth.php:221`)
- `false` on invalid credentials

In `login.php:48-54`:
```php
$success = login_user($pdo, $usernameOrEmail, $password);
if ($success) {                         // 'locked' is truthy!
    clearLoginAttempts(get_client_ip()); // clears the lockout
    logActivity(LOG_LOGIN_SUCCESS);      // false-positive log
    header('Location: /index.php');
    exit;
}
```

The string `'locked'` is truthy in PHP. When `login_user()` returns `'locked'`, the code enters the success branch and calls `clearLoginAttempts()`, which **deletes the lockout record**.

**Exploit path (race condition):**
1. Attacker accumulates 4 failed login attempts from one IP
2. Two concurrent requests arrive simultaneously
3. Request A: `isIpBruteForcing()` returns false (4 attempts, not yet locked)
4. Request A: `login_user()` records the 5th failure, sets lockout
5. Request B: `isIpBruteForcing()` also returned false (checked before Request A's write committed)
6. Request B: `login_user()` sees `is_ip_locked()` = true, returns `'locked'`
7. Request B: `$success = 'locked'` is truthy, `clearLoginAttempts()` **deletes the lockout**
8. Attacker is unlocked and can continue brute-forcing

Note: the user is NOT authenticated (`$_SESSION` vars are not set), so this doesn't grant access. But it **resets the brute-force lockout**, allowing unlimited password guessing.

**Additionally** (from prior dynamic validation): The codebase has two parallel lockout mechanisms — `auth.php:record_failed_attempt()` and `logger.php:recordFailedLogin()` — both of which are called on failure. This causes double-incrementing of the attempt counter. While this is primarily an availability concern (premature lockout), it interacts with the above race condition by making the threshold effectively `MAX_LOGIN_ATTEMPTS / 2`.

**Recommended Fix:**
```php
// login.php — use strict boolean comparison
$result = login_user($pdo, $usernameOrEmail, $password);
if ($result === true) {
    clearLoginAttempts(get_client_ip());
    logActivity(LOG_LOGIN_SUCCESS);
    header('Location: /index.php');
    exit;
} elseif ($result === 'locked') {
    $error = 'Too many attempts. Please try again later.';
    logActivity(LOG_BRUTE_FORCE);
} else {
    $error = 'Invalid credentials.';
    recordFailedLogin(get_client_ip());
    logActivity(LOG_LOGIN_FAIL);
}
```

Also: remove the duplicate `recordFailedLogin()` call in `login.php:57` since `login_user()` already calls `record_failed_attempt()` internally. Use a single lockout mechanism.

**Verification:** After fix, send 6+ failed logins concurrently. Confirm the lockout persists and is NOT cleared by subsequent requests during the lockout window. Verify attempt count increments by exactly 1 per failed login.

---

### HIGH-2: Session Hijack Detection Broken by Undefined `$now`

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | Session Management |
| **File** | `config/session.php:51-65, 73` |
| **Exploitability** | Passive (defenses silently fail) |

**Description:**

The session fingerprint check runs at line 51-65, but calls `resetSession($now)` where `$now` is defined later at line 73:

```php
// Line 51-65: fingerprint check
$currentFingerprint = hash('sha256',
    ($_SERVER['HTTP_USER_AGENT'] ?? '') . $_SERVER['REMOTE_ADDR']
);
if (!isset($_SESSION['fingerprint'])) {
    $_SESSION['fingerprint'] = $currentFingerprint;
} elseif (!hash_equals($_SESSION['fingerprint'], $currentFingerprint)) {
    resetSession($now);  // $now is UNDEFINED here!
}

// Line 73: $now is defined AFTER the fingerprint check
$now = time();
```

Since `declare(strict_types=1)` is active, passing the undefined `$now` (null) to `resetSession(int $now)` throws a `TypeError`. This fatal error means:
- The session is **NOT reset**
- The potentially hijacked session **continues to work**
- Session hijack detection is completely broken

**Dynamic evidence (from prior validation):** Changing User-Agent with the same session cookie returned `Undefined variable $now` and `Fatal error: Uncaught TypeError` with full path disclosure (`/var/www/html/config/session.php`). Combined with HIGH-3 (`display_errors=1` on login.php), this leaks internal filesystem paths to the attacker.

**Recommended Fix:**
Move `$now = time();` to before the fingerprint check (before line 51):
```php
$now = time();  // Initialize BEFORE fingerprint check

$currentFingerprint = hash('sha256', ...);
// ... rest of fingerprint check using $now
```

**Verification:** Set a session cookie, then replay it from a different User-Agent. Before fix: TypeError crash, session persists. After fix: session is destroyed, user redirected to login, no error details exposed.

---

### HIGH-3: `display_errors = 1` Overrides Dockerfile Hardening

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | Information Disclosure |
| **File** | `public/login.php:4-5` |
| **Exploitability** | Easy (trigger any PHP warning/error on the login page) |

**Description:**

```php
ini_set('display_errors', 1);
error_reporting(E_ALL);
```

The Dockerfile correctly sets `display_errors = Off` in `security.ini`. However, the runtime `ini_set()` call in `login.php` **overrides** this setting. Any PHP warning, notice, or error on the login page is displayed to the user, revealing:
- Internal file paths (`/var/www/html/...`)
- Database connection details in stack traces
- PHP version and configuration
- Session configuration internals

The login page is the most exposed endpoint (no authentication required, handles attacker-controlled input) and is the exact page where HIGH-2's TypeError will render.

**Recommended Fix:**
Delete lines 4-5 from `public/login.php`.

**Verification:** Trigger a PHP error on the login page. Confirm no error details are displayed; only generic error messages appear.

---

### HIGH-4: Inconsistent Security Header Application

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Category** | Security Misconfiguration |
| **Files** | Multiple (see table) |
| **Exploitability** | Easy (target unprotected pages for clickjacking, XSS) |

**Description:**

`send_security_headers()` provides comprehensive protection (CSP with nonce, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy, COEP/COOP/CORP, etc.), but is only called on some pages:

| Page | `send_security_headers()` | Consequence |
|------|--------------------------|-------------|
| `login.php` | YES | Protected |
| `payment_page.php` | YES | Protected |
| `success.php` | YES | Protected |
| `failure.php` | YES | Protected |
| `transfer_result.php` | YES | Protected |
| **`register.php`** | **NO** | No CSP, no HSTS, no clickjacking protection |
| **`searchbox.php`** | **NO** | No CSP, no HSTS, no clickjacking protection |
| **`profile.php`** | **NO** | No CSP, no clickjacking protection |
| **`view_profile.php`** | **NO** | No CSP, no clickjacking protection |
| **`index.php`** | **Partial** | Only manual X-Content-Type-Options and Cache-Control |

Pages without CSP lose the XSS mitigation layer. Pages without X-Frame-Options are vulnerable to clickjacking (e.g., framing the profile edit page to trick users into uploading malicious files).

**Dynamic evidence (from prior validation):** Header audit confirmed `/login.php`, `/payment_page.php`, `/success.php`, `/failure.php` have full app-level headers. `/index.php`, `/register.php`, `/searchbox.php`, `/view_profile.php`, `/profile.php` lack HSTS/COEP/nonced CSP.

**Recommended Fix:**
Add to every `public/*.php` file, before any output:
```php
require_once __DIR__ . '/../includes/header.php';
send_security_headers();
```
Ideally, centralize this in a single mandatory bootstrap include.

**Verification:** `curl -I` each page. Confirm `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy` are present on all routes.

---

### MEDIUM-5: Logout CSRF — GET Request Without Anti-Forgery Token

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | CSRF |
| **File** | `public/logout.php:1-10` |
| **Exploitability** | Easy |

**Description:**

Logout is performed via a GET request with no CSRF token:
```php
session_unset();
session_destroy();
header('Location: /login.php');
```

An attacker can force any authenticated user to log out:
```html
<img src="https://target.com/logout.php">
```

Additionally, `logout.php` does not call the existing `logout_user()` function from `auth.php`, which properly logs the event and clears the session cookie.

**Dynamic evidence (from prior validation):** Authenticated user accessing `/searchbox.php` returned `200 OK`. GET `/logout.php` (no CSRF token) returned `302 /login.php`. Subsequent `/searchbox.php` returned `302 /login.php` (session terminated).

**Recommended Fix:**
Convert logout to POST with CSRF token. Use the existing `logout_user()` function:
```php
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed');
}
verifyCsrf();
logout_user();
header('Location: /login.php');
exit;
```
Update `header.html` to use a form with CSRF token instead of a plain link.

---

### MEDIUM-6: Exception Messages Leaked to Users via Session

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | Information Disclosure |
| **File** | `includes/process_payment.php:97`, `public/failure.php:13-16` |

**Description:**

```php
// process_payment.php:97
$_SESSION['transfer_error'] = $e->getMessage();

// failure.php:14-16
echo "<p style='color:red;'>Error: " . escape_output($_SESSION['transfer_error']) . "</p>";
```

Raw exception messages (which may contain SQL error details, constraint names, or internal state like `SQLSTATE[23000]: Integrity constraint violation`) are stored in the session and displayed to the user. While HTML-escaped (no XSS), this leaks internal implementation details.

**Dynamic evidence:** Failure page displayed backend-generated message `Cant send money to self`, confirming exception text propagation.

**Recommended Fix:**
```php
error_log('Transfer failed: ' . $e->getMessage());
$_SESSION['transfer_error'] = 'Transfer could not be completed. Please try again.';
```

---

### MEDIUM-7: GitHub Actions Not Pinned to Commit SHAs

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | Supply Chain |
| **Files** | `.github/workflows/semgrep.yml:25`, `.github/workflows/security.yml:14,19` |

**Description:**

```yaml
- uses: actions/checkout@v4                              # mutable tag
- uses: anthropics/claude-code-security-review@main      # mutable branch!
```

The `@main` pin is particularly dangerous as it tracks a moving branch. A compromised upstream action could inject malicious code into CI/CD with `contents: read` and `pull-requests: write` permissions.

**Recommended Fix:** Pin all actions to full commit SHAs.

---

### MEDIUM-8: Docker Base Images Not Pinned to Digests

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | Supply Chain |
| **Files** | `docker/Dockerfile:1`, `docker/docker-compose.yml:3,30` |

**Description:**

```dockerfile
FROM php:8.2-apache     # mutable tag
image: mysql:8.4        # mutable tag
image: semgrep/semgrep  # no tag at all (latest)
```

Prior dynamic scanning via `docker scout` found 1 critical + 7 high CVEs in the `mysql:8.4` image.

**Recommended Fix:** Pin to digest-qualified references. Add recurring image CVE scan in CI/CD.

---

### MEDIUM-9: No Rate Limiting on Registration

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | Business Logic |
| **File** | `public/register.php` |

The registration endpoint has no rate limiting. An attacker can create accounts at high volume (account flooding), fill the database with junk data, and accumulate storage via profile images.

**Recommended Fix:** Add IP-based rate limiting similar to `isIpBruteForcing()` for login.

---

### MEDIUM-10: Inconsistent IP Source for Rate Limiting

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | AuthN / Rate Limiting |
| **Files** | `includes/auth.php:211`, `includes/sanitize.php:654-682`, `public/login.php:51,57` |

**Description:**

Two IP resolution strategies are used across rate-limiting paths:

| Code Path | IP Source | Spoofable? |
|-----------|-----------|------------|
| `login_user()` internal | `$_SERVER['REMOTE_ADDR']` | No |
| `isIpBruteForcing()` | `get_client_ip()` (trusts `X-Forwarded-For`) | Yes |
| `recordFailedLogin()` | `get_client_ip()` | Yes |
| `clearLoginAttempts()` | `get_client_ip()` | Yes |

An attacker can spoof `X-Forwarded-For` to record failures against a different IP or clear lockout records for another IP.

**Recommended Fix:** Standardize all rate-limiting to use `REMOTE_ADDR` exclusively, or configure `get_client_ip()` to only trust proxy headers when behind a known reverse proxy.

---

### MEDIUM-11: Diagnostic Endpoint on Home Page

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | Information Disclosure |
| **File** | `public/index.php:10-54` |

When `APP_DIAGNOSTIC_MODE=1`, the unauthenticated home page lists all database table names. Even when disabled, it outputs `PHP running` and `Diagnostic mode disabled.`, confirming the tech stack and revealing the existence of a diagnostic toggle.

**Dynamic evidence:** Unauthenticated GET `/index.php` returned `PHP running` and `Diagnostic mode disabled.`

**Recommended Fix:** Remove diagnostic logic from public entrypoint. Gate diagnostics behind an authenticated admin route.

---

### MEDIUM-12: No Server-Level Upload Directory Protection

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Category** | File Upload Safety |
| **Files** | `public/uploads/`, `docker/Dockerfile` |

Uploaded files are served directly by Apache. While application-level upload validation is strong (MIME check via `finfo`, extension whitelist, filename sanitization), there is no server-level defense preventing PHP execution if a bypass is found.

**Dynamic evidence (from prior validation):** PHP payload upload was rejected by MIME allowlist. However, no server-level backup defense exists.

**Recommended Fix:**
Add to Dockerfile's Apache hardening:
```apache
<Directory /var/www/html/public/uploads>
    php_admin_flag engine off
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</Directory>
```

---

### LOW-13: CSRF Token Exposed in GET URL (Search)

| **File** | `public/searchbox.php:34-36` |
|----------|------------------------------|

Search form uses `method="GET"` with `csrfField()`. Token appears in URLs, browser history, server logs. The token is never verified on GET (by design in `verifyCsrf()`), so it's included but pointless and exposed.

**Dynamic evidence:** App access log captured `GET /searchbox.php?csrf_token=...&q=test`.

**Fix:** Remove `<?= csrfField(); ?>` from the GET search form.

---

### LOW-14: CSRF Origin Check Disabled

| **File** | `includes/csrf.php:18` |
|----------|------------------------|

`CSRF_ALLOWED_ORIGIN` is empty string, disabling the Origin/Referer header check. Token-based CSRF protection is still active but this weakens defense-in-depth.

**Fix:** Set `CSRF_ALLOWED_ORIGIN` to the application's production origin.

---

### LOW-15: Predictable Upload Filenames

| **File** | `includes/profile_update_logic.php:56` |
|----------|----------------------------------------|

```php
$final_filename = 'avatar_' . time() . '_' . rand(1000, 9999) . '_' . $safe_filename;
```

Uses `time()` (predictable) and `rand()` (9000 possible values, not cryptographically secure). An attacker could enumerate uploaded files.

**Fix:** Use `bin2hex(random_bytes(16))` for the random component.

---

### LOW-16: `logout.php` Bypasses `logout_user()` Function

| **File** | `public/logout.php` |
|----------|---------------------|

`auth.php` defines `logout_user()` that properly logs the event and clears the session cookie. `logout.php` uses raw `session_unset()` + `session_destroy()`, missing logging and cookie cleanup.

**Fix:** Use `logout_user()` after addressing MEDIUM-5.

---

### LOW-17: LIKE Wildcards Not Escaped in Search

| **File** | `public/searchbox.php:48` |
|----------|---------------------------|

```php
$searchTerm = "%" . $query . "%";
```

User input `%` or `_` wildcards pass unescaped to a LIKE clause. Input `%` matches all users. Not SQL injection (parameterized), but unintended broad matching.

**Fix:** `$query = addcslashes($query, '%_');`

---

### LOW-18: No User-Visible Transaction History

| **Category** | Security Usability |
|--------------|-------------------|

Users cannot view their transaction history, making it difficult to detect unauthorized transfers. The `transactions` table exists but no UI endpoint exposes it.

**Fix:** Add a transaction history page for authenticated users.

---

## Observed Secure Controls (Validated)

The following security controls are well-implemented and effective:

1. **Parameterized queries everywhere** — No SQL injection found across all 14 database interactions (auth, search, transfer, profile, logging)
2. **CSRF token system** — HMAC-bound to server-side secret, session-tied, constant-time `hash_equals()`, single-use rotation after each POST
3. **Password handling** — bcrypt with `PASSWORD_DEFAULT`, anti-enumeration timing via `DUMMY_HASH`, randomized delay on all login attempts
4. **Session hardening** — `use_strict_mode=1`, `cookie_httponly=1`, `samesite=Strict`, 48-char session IDs, periodic rotation every 5 min, 30-min inactivity timeout, 1-hour absolute lifetime
5. **Upload validation** — `finfo` MIME check on actual file content (not browser-declared type), extension whitelist (jpg/png/gif/webp only), `sanitize_filename()` strips path traversal/null bytes/unicode tricks, 2MB size limit
6. **Transaction integrity** — `SELECT ... FOR UPDATE` row locking, DB-level `CHECK (sender_id <> receiver_id)`, DB-level `CHECK (amount_paise >= 100)`, DB-level `CHECK (balance_paise >= 0)`, atomic commit/rollback
7. **Input sanitization** — Comprehensive `sanitize.php` covering null bytes, control characters, type-specific validators, output encoding with `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and double-encoding
8. **Docker hardening** — `no-new-privileges`, read-only source mounts, internal backend network, `ServerTokens Prod`, `ServerSignature Off`, `TraceEnable Off`, `expose_php = Off`
9. **Stored XSS prevention** — Bio input is `strip_tags()` + `escape_output()` on display; verified dynamically that `<script>alert(1)</script>` is rendered as escaped text
10. **Balance privacy gate** — Balance is only exposed to the profile owner (`$profileData['is_mine']` check)

---

## Coverage Matrix

| Security Domain | Status | Finding IDs |
|-----------------|--------|-------------|
| AuthN/AuthZ and broken access controls | Findings confirmed | HIGH-1, MEDIUM-9, MEDIUM-10 |
| Session management and CSRF | Findings confirmed | HIGH-2, MEDIUM-5, LOW-13, LOW-14 |
| Input validation and injection (SQLi/XSS/header/path/file) | Reviewed, no injection found; config gaps | HIGH-3, HIGH-4, MEDIUM-6, LOW-17 |
| Business logic and transaction integrity | Finding confirmed | HIGH-1 (lockout), LOW-18 |
| File upload and storage safety | Findings confirmed | MEDIUM-12, LOW-15 |
| Error handling and information disclosure | Findings confirmed | HIGH-3, MEDIUM-6, MEDIUM-11 |
| Secrets/configuration management | Minor issues only | Weak dev passwords (by design for local) |
| Dependency/container/workflow supply-chain | Findings confirmed | MEDIUM-7, MEDIUM-8 |
| Clickjacking | Gap via missing headers | HIGH-4 (pages without X-Frame-Options) |
| Path traversal | Reviewed, no issues | `basename()` and sanitization prevent traversal |
| Header injection | Reviewed, no issues | `sanitize_header()` strips CRLF |
| Deserialization | Not applicable | No deserialization primitives found |
| Privilege escalation | Reviewed, no path found | No privilege boundary bypass in app logic |

---

## Remediation Priority

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| 1 | HIGH-2: Move `$now = time()` before fingerprint check | 1 line move | Restores session hijack detection |
| 2 | HIGH-3: Delete `display_errors` lines from login.php | 2 line delete | Stops info disclosure on most exposed page |
| 3 | HIGH-1: Strict `=== true` comparison + deduplicate lockout | ~15 lines | Prevents lockout bypass, fixes double-increment |
| 4 | HIGH-4: Centralize security headers in all entrypoints | ~2 lines per file | Full header coverage on all routes |
| 5 | MEDIUM-5: POST-based logout with CSRF | ~20 lines | Prevents forced logout |
| 6 | MEDIUM-6: Generic error messages in transfers | 2 line change | Stops internal error leakage |
| 7 | MEDIUM-12: Upload directory PHP execution prevention | 5 lines Apache config | Defense-in-depth for uploads |
| 8 | MEDIUM-10: Standardize IP source to REMOTE_ADDR | Moderate refactor | Consistent rate limiting |
| 9 | MEDIUM-11: Gate diagnostic endpoint | ~10 lines | Reduce recon surface |
| 10 | MEDIUM-7/8: Pin actions/images to SHAs/digests | Config changes | Supply chain hardening |
| 11 | MEDIUM-9: Registration rate limiting | ~30 lines | Prevent account flooding |
| 12 | LOW-13 through LOW-18 | Small changes | Polish and defense-in-depth |

---

## Residual Risk / Limitations

1. Dynamic CVE scanning used Docker Scout fallback because `trivy/grype/syft` are unavailable locally. Results are point-in-time and should be re-run in CI on each build.
2. This assessment did not include external network penetration testing beyond local Dockerized app behavior.
3. No fuzzing was performed on file upload parsing or query parameter edge cases.
4. The race condition in HIGH-1 is timing-dependent; full exploitation requires concurrent request capability.

---

*Report generated by comprehensive static code review with dynamic validation evidence. All file/line references verified against repository HEAD.*
