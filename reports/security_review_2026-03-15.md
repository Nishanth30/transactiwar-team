# TransactiWar Security Hardening Review

**Date:** 2026-03-15
**Scope:** Full codebase security audit -- PHP, MySQL, Docker, Apache
**Auditor:** Automated deep review (4 parallel security analysis passes)

---

## Executive Summary

The TransactiWar codebase demonstrates **significantly above-average security engineering** for a PHP application: 100% prepared statements, HMAC-bound CSRF tokens, ordered `FOR UPDATE` locks preventing transfer deadlocks, GD image reprocessing, nonce-based CSP, and comprehensive security headers. However, **28 distinct findings** were identified across authentication, payments, file handling, and infrastructure. 4 are Critical, 9 are High, 10 are Medium, and 5 are Low.

---

## Confirmed Security Strengths

| Area | Implementation |
|------|---------------|
| SQL Injection | 100% prepared statements with parameter binding -- zero concatenation |
| CSRF | HMAC-bound tokens, single-use rotation, constant-time comparison, origin validation |
| Transfers | Ordered FOR UPDATE locks (deadlock-safe), DB CHECK on balance >= 0, BIGINT UNSIGNED |
| File Uploads | MIME validation, dimension caps, GD reprocessing, random filenames, storage outside webroot |
| Sessions | HMAC fingerprint (IP+UA), strict mode, HttpOnly, SameSite=Strict, 30m inactivity, 1h absolute, 5m regen |
| Passwords | bcrypt via PASSWORD_DEFAULT, constant-time comparison, dummy hash for anti-enumeration |
| Headers | CSP w/ nonces, HSTS w/ preload, X-Frame-Options DENY, COEP/COOP/CORP, Permissions-Policy |
| Dangerous Functions | Zero usage of eval/system/exec/unserialize/extract |

---

## CRITICAL Findings

### C1 -- Database Credentials Fail Open to root/empty

**File:** `config/db.php:12-15`
**Severity:** CRITICAL

```php
$user = getenv('MYSQL_USER') ?: 'root';   // Falls back to root
$pass = getenv('MYSQL_PASSWORD') ?: '';     // Falls back to empty
```

**Attack Scenario:** If environment variables are unset (misconfigured deploy, container restart losing env), the app silently connects as MySQL `root` with no password. Any SQL injection, even in a tangential feature, becomes full DB compromise with DDL/FILE privileges.

**Fix:**
```php
$host = getenv('MYSQL_HOST');
$db   = getenv('MYSQL_DATABASE');
$user = getenv('MYSQL_USER');
$pass = getenv('MYSQL_PASSWORD');

if ($host === false || $db === false || $user === false || $pass === false) {
    http_response_code(500);
    error_log('FATAL: Required database environment variables are not set.');
    exit('Internal server error.');
}
```

---

### C2 -- Login Lockout Race Condition (Concurrent Bypass)

**File:** `includes/auth.php:114-165` (record_failed_attempt / is_ip_locked)
**Severity:** CRITICAL

**Attack Scenario:** The `is_ip_locked()` check and `record_failed_attempt()` write are NOT in the same transaction. An attacker sends 20 concurrent login requests -- all 20 read `attempts=0`, all 20 pass the lockout check, and the counter increments slower than the request rate. This allows testing hundreds of passwords before lockout triggers instead of the intended 20.

**Fix:** Wrap lockout check + counter increment in a `SELECT ... FOR UPDATE` transaction:
```php
$pdo->beginTransaction();
$stmt = $pdo->prepare("
    SELECT attempts, locked_until, last_attempt
    FROM login_attempts WHERE ip = :ip FOR UPDATE
");
$stmt->execute(['ip' => $attemptKey]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if ($row && $row['locked_until'] > time()) {
    $pdo->commit();
    return 'locked';
}
// ... check backoff, then commit before proceeding to password_verify
$pdo->commit();
```

---

### C3 -- Pentest Payload PHP File Committed to Repository

**File:** `reports/pentest/2026-03-05/runtime/payload.php`
**Severity:** CRITICAL

```php
<?php echo "owned"; ?>
```

**Attack Scenario:** A live PHP executable in the repo. If `reports/` is ever accidentally exposed (misconfigured Apache Alias, changed DocumentRoot), an attacker gets code execution. Normalizes presence of executable PHP outside app directories.

**Fix:** Delete the file. Store pentest evidence as `.txt`. Add to `.gitignore`:
```
reports/pentest/**/runtime/*.php
```

---

### C4 -- Hardcoded Credentials in Git History

**File:** `docker/.env` (historically committed, now gitignored)
**Severity:** CRITICAL

**Attack Scenario:** If `docker/.env` was ever committed, `SESSION_SECRET` and `MYSQL_ROOT_PASSWORD` are recoverable via `git log --all --full-history -- docker/.env`. Anyone with the `SESSION_SECRET` can forge session fingerprints and CSRF tokens.

**Fix:**
1. Rotate `SESSION_SECRET` and all MySQL passwords immediately
2. Run `git filter-repo` to purge `docker/.env` from history
3. Add pre-commit hook to block `.env` files

---

## HIGH Findings

### H1 -- Exponential Backoff Uses sleep() -- Thread-Exhaustion DoS

**File:** `includes/auth.php:541-543`
**Severity:** HIGH

```php
$backoffSeconds = get_backoff_delay($pdo, $attemptKey);
if ($backoffSeconds > 0) {
    sleep($backoffSeconds);  // Holds PHP-FPM worker for up to 30 seconds
}
```

**Attack Scenario:** Trigger a few failed logins to raise the backoff counter, then send ~50 concurrent login requests. Each holds a PHP-FPM worker for 30 seconds, exhausting the pool and causing total application DoS for all users.

**Fix:** Return `429 Too Many Requests` with `Retry-After` header instead of sleeping server-side:
```php
if ($backoffSeconds > 0) {
    $stmt = $pdo->prepare("SELECT last_attempt FROM login_attempts WHERE ip = :ip");
    $stmt->execute(['ip' => $attemptKey]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row && (time() - (int)$row['last_attempt']) < $backoffSeconds) {
        header('Retry-After: ' . $backoffSeconds);
        http_response_code(429);
        return 'throttled';
    }
}
```

---

### H2 -- Account Enumeration via Registration Duplicate Message

**File:** `public/register.php:60`
**Severity:** HIGH

```php
$flash_error = 'Username or email already exists.';
```

**Attack Scenario:** Attacker submits registrations with candidate emails. "Already exists" = account confirmed; "Registration successful" = no account. Classic oracle for credential stuffing target lists.

**Fix:** Return a uniform success-like message:
```php
if ($result === true || $result === 'duplicate') {
    $flash_success = 'If the details are valid, your account has been created. Try logging in.';
}
```

---

### H3 -- CSRF Single-Token Slot Breaks Multi-Tab Usage (Weaponizable)

**File:** `includes/csrf.php:160-163, 199-201, 332-333`
**Severity:** HIGH

**Attack Scenario:** User opens two tabs. Tab A submits, rotating the token, invalidating Tab B's token. An attacker can weaponize this by tricking the victim into visiting any POST-protected page, invalidating CSRF tokens in all other open tabs.

**Fix:** Replace single slot with a token pool (max 5 tokens), each with creation timestamp. Validate against pool, remove used token, expire old ones.

---

### H4 -- No Maximum Transfer Amount

**File:** `includes/sanitize.php:276-285`
**Severity:** HIGH

**Attack Scenario:** `sanitize_amount()` enforces minimum 100 paise but no maximum. Extremely large transfers could cause MySQL BIGINT UNSIGNED overflow on the receiver's balance, triggering transaction rollback as a DoS against the receiver.

**Fix:**
```php
function sanitize_amount(mixed $value): ?int
{
    $int = sanitize_int($value);
    if ($int === null || $int < MIN_TRANSFER_PAISE || $int <= 0) return null;

    $MAX_TRANSFER_PAISE = 100_000_000; // 10 lakh rupees
    if ($int > $MAX_TRANSFER_PAISE) return null;

    return $int;
}
```

---

### H5 -- Transfer Nonce Single-Slot (Multi-Tab Double-Spend Window)

**File:** `public/payment_page.php:49-50`, `includes/process_payment.php:9-18`
**Severity:** HIGH

**Attack Scenario:** Two payment tabs open. Tab B overwrites `$_SESSION['transfer_nonce']` from Tab A. Tab A's nonce becomes invalid (DoS). The nonce is also not bound to a specific (sender, receiver, amount) tuple.

**Fix:** Bind nonce to target UUID:
```php
// payment_page.php
$nonceKey = 'transfer_nonce_' . $targetUuid;
$_SESSION[$nonceKey] = bin2hex(random_bytes(16));

// process_payment.php
$nonceKey = 'transfer_nonce_' . $target_uuid;
if (!hash_equals($_SESSION[$nonceKey] ?? '', $nonce)) { /* fail */ }
unset($_SESSION[$nonceKey]);
```

---

### H6 -- Container Runs as Root

**File:** `docker/Dockerfile`
**Severity:** HIGH

The Dockerfile never drops to a non-root user. PID 1 runs as root. Any RCE gives attacker root inside the container.

**Fix:** Add `USER www-data` after build steps, or use `gosu www-data "$@"` at end of entrypoint.sh.

---

### H7 -- Docker Volume Mounts Expose Source and Allow Write to Certs

**File:** `docker/docker-compose.yml:92-96`
**Severity:** HIGH

```yaml
- ../:/var/www/html:ro          # Entire repo including .git/, scripts/debug/
- ../storage:/var/www/html/storage  # Read-write (no :ro)
- ./certs:/etc/apache2/ssl          # Read-write (no :ro)
```

**Attack Scenario:** Container compromise exposes `.git/` history and allows overwriting TLS certificates.

**Fix:**
```yaml
volumes:
  - ../public:/var/www/html/public:ro
  - ../includes:/var/www/html/includes:ro
  - ../config:/var/www/html/config:ro
  - upload_storage:/var/www/html/storage/uploads
  - ./certs:/etc/apache2/ssl:ro
```

---

### H8 -- Missing session.cookie_secure in PHP INI

**File:** `docker/Dockerfile:41-47` (security.ini block)
**Severity:** HIGH

`session.cookie_httponly = 1` is set but `session.cookie_secure = 1` is not. If any code path starts a session before `config/session.php` loads, the cookie goes over plaintext HTTP.

**Fix:** Add to security.ini: `session.cookie_secure = 1` and `session.cookie_samesite = Strict`.

---

### H9 -- Seed Accounts Use Real Names, Reset on Every Restart

**File:** `docker/setup.sh:150-158`
**Severity:** HIGH

Six accounts with real team member names and bcrypt hashes committed. `ON DUPLICATE KEY UPDATE` resets passwords on every container restart. 'trudy' is a well-known adversary placeholder.

**Fix:** Gate behind `SEED_DEMO_ACCOUNTS=1` env var. Use generic names (`agent_alpha`, etc.). Generate random passwords at seed time, output to stdout only.

---

## MEDIUM Findings

### M1 -- CSP Policy Conflict Between .htaccess and PHP

**File:** `public/.htaccess:6` vs `includes/header.php:78`
**Severity:** MEDIUM

`.htaccess` sets static CSP without nonce. PHP sends nonce-based CSP. Browser enforces the intersection (most restrictive), potentially blocking nonce-based scripts.

**Fix:** Remove CSP from `.htaccess` entirely -- PHP handles it dynamically.

---

### M2 -- `public/uploads/` .htaccess Weaker Than `storage/uploads/`

**File:** `public/uploads/.htaccess`
**Severity:** MEDIUM

Uses `FilesMatch` to block specific extensions instead of `Require all denied`. Unusual extensions (`.php8`, `.pht`) bypass the filter. Directory appears vestigial.

**Fix:** Delete `public/uploads/` entirely, or replace .htaccess with `Require all denied`.

---

### M3 -- AllowOverride All in Apache Config

**File:** `docker/apache/default-ssl.conf:19`
**Severity:** MEDIUM

Allows any `.htaccess` in any subdirectory to override Apache directives. Attacker-written .htaccess could re-enable PHP execution.

**Fix:** `AllowOverride FileInfo Options=Indexes AuthConfig`

---

### M4 -- GIF Reprocessing Preserves Comment-Block Polyglots

**File:** `includes/profile_update_logic.php:124-129`
**Severity:** MEDIUM

GD's `imagegif()` preserves GIF89a comment extensions that can contain PHP code. Currently mitigated by serving through `serve_image.php` with MIME validation.

**Fix:** Convert GIFs to PNG during reprocessing: `imagepng($img, $png_destination)`.

---

### M5 -- No Rate Limiting on Registration Endpoint

**File:** `public/register.php`
**Severity:** MEDIUM

Login has exponential backoff; registration has none. Enables username/email enumeration at scale and spam account creation.

**Fix:** Reuse `login_attempts` table with `reg:` prefix key.

---

### M6 -- bcrypt 72-Byte Password Truncation

**File:** `includes/auth.php:449`
**Severity:** MEDIUM

bcrypt silently truncates at 72 bytes. `MAX_PASSWORD_LEN` is 128. Two passwords sharing 72-byte prefix are equivalent.

**Fix:** Pre-hash with SHA-384 before bcrypt:
```php
$preHash = base64_encode(hash('sha384', $password, true));
return password_hash($preHash, PASSWORD_DEFAULT);
```

---

### M7 -- error_log() Leaks PDO Exception Details

**Files:** `includes/auth.php:417,481`, `includes/profile_update_logic.php:204`
**Severity:** MEDIUM

PDO exceptions can contain SQL fragments, table/column names.

**Fix:** Log class + error code only: `error_log('Failed: ' . get_class($e) . ' code=' . $e->getCode());`

---

### M8 -- Security Event Logger Strips Forensic Characters

**File:** `includes/logger.php:155`
**Severity:** MEDIUM

```php
$detail = preg_replace('/[^\w\s\-:.\/]/', '', $detail);
```

Strips `<`, `>`, `=`, `@`, etc. from logged attack payloads, making forensic logs useless.

**Fix:** Hex-encode non-printable characters but preserve printable ASCII.

---

### M9 -- `transfer_complete` Flag Blocks All Transfers Until index.php Visit

**File:** `includes/process_payment.php:165`, `public/payment_page.php:19-24`
**Severity:** MEDIUM

After a transfer, ALL subsequent transfers are blocked until the user visits `index.php`.

**Fix:** Clear the flag on payment page GET: `unset($_SESSION['transfer_complete']);`

---

### M10 -- Container Missing read_only and Resource Limits

**File:** `docker/docker-compose.yml`
**Severity:** MEDIUM

No `read_only: true`, no memory/CPU limits. Post-exploit persistence and resource exhaustion are possible.

**Fix:**
```yaml
app:
  read_only: true
  tmpfs: [/tmp, /var/run/apache2, /var/lock/apache2]
  deploy:
    resources:
      limits: { memory: 512M, cpus: '1.0' }
```

---

## LOW Findings

### L1 -- Dummy Hash Cost Mismatch (Timing Oracle)

**File:** `includes/auth.php:24-25`
**Severity:** LOW

`DUMMY_HASH` uses cost 12; `PASSWORD_DEFAULT` may use cost 10. ~150ms timing difference could leak user existence despite `usleep()` jitter.

**Fix:** Generate `DUMMY_HASH` at the same cost factor as `PASSWORD_DEFAULT`.

---

### L2 -- PDO Returns Strings, Strict Comparison Fails

**File:** `includes/auth.php:192`
**Severity:** LOW

```php
if (!$row || $row['attempts'] === 0) {
```

PDO returns `'0'` (string), `=== 0` (int) is always false. Backoff delay may never reset.

**Fix:** `(int) $row['attempts'] === 0`

---

### L3 -- searchbox.php `die()` Reveals DB Component Status

**File:** `public/searchbox.php:49`
**Severity:** LOW

```php
die("<div class='alert alert-danger'>Database connection failed.</div>");
```

Confirms to attackers which infrastructure component is down.

**Fix:** Redirect to generic error page.

---

### L4 -- No Rate Limiting on Search Endpoint

**File:** `public/searchbox.php`
**Severity:** LOW

Enables brute-force username enumeration via exact-match search.

---

### L5 -- Logger syslog Fallback Includes Unsanitized Exception Message

**File:** `includes/logger.php:133-138`
**Severity:** LOW

Potential log injection in syslog consumers.

**Fix:** `preg_replace('/[^\x20-\x7E]/', '', substr($e->getMessage(), 0, 200))`

---

## Prioritized Hardening Checklist

### CRITICAL -- Fix Before Next Deploy

| # | Finding | File | Effort |
|---|---------|------|--------|
| 1 | C1 -- DB fails open to root | config/db.php | 10 min |
| 2 | C4 -- Rotate leaked secrets, purge git history | docker/.env | 30 min |
| 3 | C3 -- Delete pentest payload.php | reports/pentest/ | 5 min |
| 4 | C2 -- Lockout race condition (FOR UPDATE) | includes/auth.php | 1 hour |

### HIGH -- Fix This Sprint

| # | Finding | File | Effort |
|---|---------|------|--------|
| 5 | H1 -- Replace sleep() with 429 response | includes/auth.php | 30 min |
| 6 | H4 -- Add max transfer cap | includes/sanitize.php | 15 min |
| 7 | H8 -- Add cookie_secure to php.ini | docker/Dockerfile | 5 min |
| 8 | H6 -- Drop root in container | docker/Dockerfile + entrypoint.sh | 1 hour |
| 9 | H7 -- Fix volume mounts (scope + :ro) | docker/docker-compose.yml | 30 min |
| 10 | H2 -- Uniform registration response | public/register.php | 15 min |
| 11 | H3 -- CSRF token pool | includes/csrf.php | 1 hour |
| 12 | H5 -- Bind transfer nonce to target UUID | payment_page.php + process_payment.php | 30 min |
| 13 | H9 -- Generic seed accounts, env-gated | docker/setup.sh | 30 min |

### MEDIUM -- Fix Next Sprint

| # | Finding | File | Effort |
|---|---------|------|--------|
| 14 | M1 -- Remove CSP from .htaccess | public/.htaccess | 5 min |
| 15 | M2 -- Delete or harden public/uploads/ | public/uploads/ | 10 min |
| 16 | M3 -- Restrict AllowOverride | docker/apache/default-ssl.conf | 5 min |
| 17 | M5 -- Rate limit registration | public/register.php | 30 min |
| 18 | M6 -- Pre-hash passwords with SHA-384 | includes/auth.php | 30 min |
| 19 | M7 -- Sanitize error_log output | includes/auth.php, profile_update_logic.php | 15 min |
| 20 | M8 -- Preserve forensic detail in logger | includes/logger.php | 15 min |
| 21 | M9 -- Clear transfer_complete on GET | public/payment_page.php | 5 min |
| 22 | M10 -- read_only + resource limits | docker/docker-compose.yml | 30 min |
| 23 | M4 -- GIF-to-PNG conversion | includes/profile_update_logic.php | 30 min |

### LOW -- Backlog

| # | Finding | File | Effort |
|---|---------|------|--------|
| 24 | L1 -- Dummy hash cost alignment | includes/auth.php | 10 min |
| 25 | L2 -- Cast PDO int comparison | includes/auth.php | 5 min |
| 26 | L3 -- Generic DB error in searchbox | public/searchbox.php | 5 min |
| 27 | L4 -- Rate limit search endpoint | public/searchbox.php | 30 min |
| 28 | L5 -- Sanitize syslog fallback message | includes/logger.php | 5 min |

---

## War-Game Preparation Notes

For the security war-game specifically:

1. **Attackers will target C2 first** -- concurrent login brute-force bypassing lockout is the highest-value exploit
2. **H4 (no max transfer)** combined with **H5 (nonce race)** could enable creative double-spend attempts
3. **C3 (payload.php)** is a planted flag -- expect teams to find it immediately
4. **H9 (seed accounts)** gives attackers a known target list; 'trudy' is the obvious first attempt
5. **M1 (CSP conflict)** may silently break defenses without the team noticing during the game

**Recommended pre-game hardening priority:** C1 > C4 > C2 > H1 > H4 > H6 > H8

---

*Report generated 2026-03-15. 28 findings across 4 severity levels. 4 parallel analysis passes covering auth/session, transfers/payments, file upload/Docker, and full codebase scan.*
