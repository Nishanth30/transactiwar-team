# TransactiWar Security Hardening Audit

**Date**: 2026-03-16
**Auditor**: Claude Security Engineer (Automated)
**Application**: TransactiWar Banking War-Game (PHP 8.2 / MySQL 8.4 / Apache / Docker)
**Scope**: Full codebase review -- SQL injection, XSS, CSRF, IDOR, session management, race conditions, file uploads, input validation, cookies, security headers, Docker configuration
**Objective**: Identify all remaining vulnerabilities and produce a prioritized hardening checklist for war-game readiness

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Findings by Severity](#2-findings-by-severity)
   - [CRITICAL](#critical)
   - [HIGH](#high)
   - [MEDIUM](#medium)
   - [LOW](#low)
   - [INFORMATIONAL](#informational)
3. [Security Strengths](#3-security-strengths)
4. [IDOR Analysis](#4-idor-analysis)
5. [Race Condition Analysis](#5-race-condition-analysis)
6. [XSS Audit Matrix](#6-xss-audit-matrix)
7. [File Upload Audit Matrix](#7-file-upload-audit-matrix)
8. [Docker & Infrastructure Matrix](#8-docker--infrastructure-matrix)
9. [Prioritized Hardening Checklist](#9-prioritized-hardening-checklist)

---

## 1. Executive Summary

The TransactiWar application has undergone significant hardening (evidenced by H1-H7, M1-M10, L1-L5, C1-C3 fix annotations throughout the code). Core defenses -- prepared statements, HMAC-bound CSRF tokens, ordered `FOR UPDATE` transfer locks, GD image reprocessing, session fingerprinting, and container read-only filesystem -- are well-implemented.

This audit identified **2 Critical**, **3 High**, **8 Medium**, **7 Low**, and **6 Informational** findings. The two critical findings involve committed secrets and must be addressed before any war-game engagement.

**Overall Security Posture**: Strong with targeted gaps.

---

## 2. Findings by Severity

---

### CRITICAL

---

#### C1: Production Secrets Committed to Version Control

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **File** | `docker/.env` (lines 1-7) |
| **Category** | Secret Management |
| **CVSS** | 9.1 |

**Description**: The `docker/.env` file is tracked in Git and contains live credentials:

```
MYSQL_ROOT_PASSWORD=notrootpassword
MYSQL_PASSWORD=notsqlpassword
SESSION_SECRET=a64c6739fe927a1b3a451458f00ae69b9188d00bb0bfdaab2be9b2bc317c7183
```

The `SESSION_SECRET` is 64 hex characters of real entropy. Anyone with repository access can forge session cookies via HMAC computation and impersonate any user.

**Attack Scenario**: Attacker clones the public/shared repo, extracts `SESSION_SECRET`, computes a valid session fingerprint HMAC for any target IP+UA pair, and injects a forged session cookie to authenticate as any user without credentials.

**Fix**:
1. Rotate ALL secrets immediately (MySQL passwords, `SESSION_SECRET`)
2. Add `docker/.env` to `.gitignore`
3. Use `docker/.env.example` with placeholder values only
4. Remove `docker/.env` from Git history: `git filter-branch` or `git filter-repo`
5. Consider Docker Secrets or HashiCorp Vault for production

---

#### C2: Seed Accounts Use Pre-Computed Password Hashes Recoverable from Source

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **File** | `docker/setup.sh` (lines 150-157) |
| **Category** | Authentication |
| **CVSS** | 8.5 |

**Description**: Six seed accounts (`nishanth`, `tejas`, `divyansh`, `harshavardhan`, `vrishin`, `trudy`) are created with pre-computed bcrypt hashes baked into the setup script. The original plaintext passwords were used to generate these hashes offline. Anyone with repo access can:
- Run offline brute-force against the known hashes (bcrypt cost 10 is ~100ms/guess on consumer GPU)
- Target real team members by name (V16)
- Use `trudy` as the canonical attack account

**Attack Scenario**: Attacker extracts hashes from `setup.sh`, runs hashcat with common password lists against bcrypt cost-10 hashes, recovers plaintext passwords for all six accounts before the war-game begins.

**Fix**:
1. Generate random passwords at container startup and display them once via `docker logs`
2. Replace real names with generic identifiers (e.g., `player_01` through `player_06`)
3. Force password change on first login via a `must_change_password` DB flag
4. Do not commit password hashes to source control

---

### HIGH

---

#### H1: `CSRF_ALLOWED_ORIGIN` Not Set in Production Environment

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **File** | `docker/.env` (missing key), `includes/csrf.php:21` |
| **Category** | CSRF |

**Description**: The production `.env` omits `CSRF_ALLOWED_ORIGIN`. The code falls back to `get_request_origin()` which derives origin from `HTTP_HOST` -- an attacker-controllable header in some proxy configurations. The `.env.example` correctly sets `CSRF_ALLOWED_ORIGIN=https://localhost`.

**Attack Scenario**: Behind a misconfigured reverse proxy that passes through a forged `Host` header, an attacker's cross-origin form submission would pass the origin check because the expected origin matches the attacker-supplied `Host`.

**Fix**: Set `CSRF_ALLOWED_ORIGIN` explicitly in `docker/.env` to the canonical application URL (e.g., `https://transactiwar.local`).

---

#### H2: Login Throttle Key Varies for Non-Existent Users

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **File** | `includes/auth.php:729-731` |
| **Category** | Authentication / Rate Limiting |

**Description**: When the target user exists, the throttle key is `uid:<id>+IP`. When the user does not exist, the key is `identifier+IP`. An attacker cycling through different non-existent usernames gets `MAX_LOGIN_ATTEMPTS` (20) tries per unique fake username before lockout per username. This allows large-scale credential stuffing with varied usernames from a single IP without triggering a global lockout.

**Attack Scenario**: Attacker submits 20 login attempts for `admin1`, 20 for `admin2`, 20 for `admin3`, etc. -- each getting a fresh counter. With 100 fake usernames, the attacker gets 2,000 attempts before any single key locks out.

**Fix**: Add a secondary IP-only rate limit (e.g., 100 total attempts from any single IP in 15 minutes) that applies regardless of the identifier used.

---

#### H3: `X-Forwarded-For` Not Parsed Even When Trusted Proxy Is Configured

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **File** | `includes/request.php:44-52` |
| **Category** | Rate Limiting / Operational |

**Description**: `get_request_client_ip()` always returns `REMOTE_ADDR`, ignoring `X-Forwarded-For` even when `TRUSTED_PROXIES` is set and `is_request_from_trusted_proxy()` returns true. Behind any reverse proxy or load balancer, ALL clients share one IP from the rate limiter's perspective.

**Attack Scenario**: Application deployed behind nginx/HAProxy. All login attempts, registration attempts, and search queries appear from the proxy IP (`172.18.0.1`). After 20 failed logins by one attacker, ALL legitimate users are locked out of login.

**Fix**: When `is_request_from_trusted_proxy()` returns true, parse the leftmost untrusted IP from `X-Forwarded-For`:

```php
function get_request_client_ip(): string {
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (is_request_from_trusted_proxy()) {
        $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        $ips = array_map('trim', explode(',', $xff));
        // Leftmost untrusted IP (first IP not in trusted proxies)
        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP) && !is_trusted_proxy($ip)) {
                return $ip;
            }
        }
    }
    return filter_var($remoteAddr, FILTER_VALIDATE_IP) ? $remoteAddr : '0.0.0.0';
}
```

---

### MEDIUM

---

#### M1: Password Change Throttling Not Atomic (TOCTOU Race)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `includes/auth.php:545-623` |
| **Category** | Race Condition |

**Description**: Password change checks `is_password_change_locked()` and `get_password_change_retry_after()` as separate read-then-act operations outside a transaction, then starts a transaction for the actual update. The attempt recording happens outside the `FOR UPDATE` lock. Compare with `gate_login_attempt()` which atomically locks, checks, and increments in one transaction.

**Attack Scenario**: Two concurrent AJAX requests submit password change attempts simultaneously. Both pass the lockout check before either increments the counter, allowing more than `MAX_PASSWORD_CHANGE_ATTEMPTS` (5) current-password guesses.

**Fix**: Refactor password change throttling to use the same atomic `SELECT ... FOR UPDATE` pattern as `gate_login_attempt()`.

---

#### M2: Fragile `nl2br()` on Pre-Escaped Bio Data in `view_profile.php`

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `public/view_profile.php:38,66`, `includes/profile_view_logic.php:83` |
| **Category** | XSS (Defense-in-Depth) |

**Description**: Bio is escaped in the logic layer (`escape_output($user['bio'])`), then passed through `nl2br()` in the template. While currently safe (escape runs first), the pattern is architecturally fragile. If anyone moves escaping to the template or adds a new code path that skips the logic layer, `nl2br()` will inject raw `<br />` into unescaped attacker-controlled content.

**Attack Scenario**: Future developer refactors template to `<?= nl2br(escape_output($raw_bio)) ?>` but forgets to remove the logic-layer escaping, causing double-encoding. Or worse, removes logic-layer escaping without adding template-layer escaping.

**Fix**: Move `escape_output()` to the template and apply `nl2br()` after it:
```php
<?= nl2br(escape_output($profileData['bio'])) ?>
```
Store the raw sanitized value (not pre-escaped) in `$profileData['bio']`.

---

#### M3: Content-Disposition Header Lacks Quote Escaping (Defense-in-Depth)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `public/serve_image.php:73` |
| **Category** | Header Injection |

**Description**: The `Content-Disposition` header uses the filename directly:
```php
header('Content-Disposition: inline; filename="' . $filename . '"');
```
The current regex `[a-zA-Z0-9._\-]+` blocks quotes and newlines, but if the regex is ever loosened for internationalized filenames, a `"` would break out of the value.

**Attack Scenario**: If regex is relaxed to support Unicode filenames, an attacker uploads a file named `test".html` which breaks the header parameter boundary.

**Fix**:
```php
$safeFilename = str_replace(['"', '\\'], '', $filename);
header('Content-Disposition: inline; filename="' . $safeFilename . '"');
```

---

#### M4: `die()` Used in Profile View Logic Bypasses Security Headers

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `includes/profile_view_logic.php:67-68,74` |
| **Category** | Information Disclosure / Header Omission |

**Description**: `die("A system error occurred...")` and `die("Agent not found...")` bypass output buffering cleanup, footer rendering, and any security headers that haven't been flushed yet. The response may lack CSP, HSTS, and other protection headers.

**Attack Scenario**: Attacker triggers the error path, receives a response without CSP headers, and chains with a separate reflected XSS (if found) in the same origin.

**Fix**: Use `http_response_code(500)` + proper error template + `exit`, or redirect to a generic error page that sends full security headers.

---

#### M5: Default Docker Bind Address Exposes All Interfaces

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `docker/docker-compose.yml:94-95` |
| **Category** | Network Exposure |

**Description**: `APP_BIND` defaults to `0.0.0.0`, exposing ports 80/443 on all network interfaces. The `.env` does not override this default.

**Attack Scenario**: On a shared host or cloud VM with a public IP, the application is accessible from the internet without any firewall rule.

**Fix**: Set `APP_BIND=127.0.0.1` in `docker/.env` (or `.env.example`) unless public access is intentional.

---

#### M6: Transaction IDs Expose Business Intelligence

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `public/transaction_history.php:114` |
| **Category** | Information Disclosure |

**Description**: Sequential `INT UNSIGNED AUTO_INCREMENT` transaction IDs are displayed directly. An attacker can estimate total transaction volume and identify busy/quiet periods from their own ID range.

**Attack Scenario**: Attacker performs transactions at known times, observes their transaction IDs (e.g., #42, then #67 an hour later), and deduces 25 other transactions occurred in that window.

**Fix**: Display a hash or short UUID derived from the transaction ID instead of the raw value. Or add a `public_id` UUID column to the `transactions` table.

---

#### M7: PDO Emulated Prepared Statements Not Disabled

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `config/db.php:26-31` |
| **Category** | SQL Injection (Defense-in-Depth) |

**Description**: PDO's `ATTR_EMULATE_PREPARES` is not set to `false`. By default, PDO emulates prepared statements client-side. While all queries use parameterized binding correctly (no SQLi found), disabling emulation ensures MySQL itself enforces statement/parameter separation.

**Attack Scenario**: A future developer introduces a query with an unusual parameter type or multi-statement pattern that emulated prepares handle incorrectly.

**Fix**: Add to PDO options:
```php
PDO::ATTR_EMULATE_PREPARES => false,
```

---

#### M8: `storage` Volume Mounted Without `noexec`

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `docker/docker-compose.yml:122` |
| **Category** | Container Hardening |

**Description**: All tmpfs mounts have `noexec,nosuid`, but the `storage/` bind mount does not. This is the one directory where attacker-controlled content (uploaded images) is written. An attacker with RCE could place an executable in `storage/` and run it.

**Attack Scenario**: Attacker achieves code execution via PHP vulnerability, writes a reverse shell to `storage/uploads/shell.elf`, marks it executable, and runs it.

**Fix**: Docker bind mounts don't natively support `noexec`. Options:
1. Use a named volume with `driver_opts` supporting mount flags
2. Document as accepted risk given `read_only: true` + `no-new-privileges`
3. Add a runtime `mount -o remount,noexec /var/www/html/storage` in the entrypoint

---

### LOW

---

#### L1: `Sec-Fetch-Site` Fallback Accepts `none` Value

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `includes/csrf.php:126` |
| **Category** | CSRF (Defense-in-Depth) |

**Description**: When both `Origin` and `Referer` headers are absent, the code falls back to `Sec-Fetch-Site` and accepts `same-origin`, `same-site`, and `none`. The value `none` is sent for direct navigations (bookmarks, URL bar), not cross-site form submissions, but accepting it weakens the defense-in-depth layer.

**Fix**: Remove `'none'` from accepted values, or only accept it for GET requests.

---

#### L2: `secure` Cookie Flag Dynamic, Not Forced True

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `config/session.php:16-17` |
| **Category** | Cookie Security |

**Description**: The `Secure` flag is set dynamically based on `is_secure_request()`. If `ENFORCE_HTTPS=0` (dev mode), cookies are sent without `Secure`, making them interceptable on the wire.

**Fix**: Hardcode `secure => true` in production. Consider a `FORCE_SECURE_COOKIES` env var.

---

#### L3: `.php8` Extension Missing from `storage/uploads/.htaccess`

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `storage/uploads/.htaccess:14` |
| **Category** | File Upload (Defense-in-Depth) |

**Description**: `RemoveHandler` and `RemoveType` directives omit `.php8`, which `public/uploads/.htaccess` does include. Storage is outside web root with `Require all denied`, but consistency matters.

**Fix**: Add `.php8` to both `RemoveHandler` and `RemoveType` lines.

---

#### L4: `password_needs_rehash()` Uses `PASSWORD_DEFAULT` Instead of `PASSWORD_BCRYPT`

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `includes/auth.php:85` |
| **Category** | Authentication |

**Description**: `safe_password_hash()` uses `PASSWORD_BCRYPT` with pinned cost 10, but `needs_rehash()` checks against `PASSWORD_DEFAULT`. If PHP's default changes to argon2, every login will trigger unnecessary rehashing.

**Fix**:
```php
return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
```

---

#### L5: `escape_js()` Returns `false` on JSON Encoding Failure

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `includes/sanitize.php:86-90` |
| **Category** | XSS (Edge Case) |

**Description**: `json_encode()` returns `false` on malformed UTF-8. The function declares `string` return type, so PHP throws a `TypeError` in strict mode. In non-strict callers, the output becomes `var recipientName = ;` -- a JS syntax error that breaks the confirmation modal.

**Fix**:
```php
$encoded = json_encode((string)$value, JSON_HEX_TAG | ...);
return $encoded === false ? '""' : $encoded;
```

---

#### L6: DB Schema Lacks Upper Bound on `amount_paise`

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `database/init.sql:40` |
| **Category** | Database Integrity |

**Description**: `CHECK (amount_paise >= 100)` exists but no maximum. PHP enforces `MAX_TRANSFER_PAISE = 100_000_000` but the DB has no matching constraint.

**Fix**: Add `CHECK (amount_paise <= 10000000000)` to the `transactions` table.

---

#### L7: `AllowOverride` Includes `ExecCGI` in Apache SSL Config

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `docker/apache/default-ssl.conf:22` |
| **Category** | Server Hardening |

**Description**: `AllowOverride FileInfo AuthConfig Options=ExecCGI,Indexes` permits `.htaccess` to enable CGI execution. The application doesn't need CGI.

**Fix**: Change to `AllowOverride FileInfo Limit` or `AllowOverride None`.

---

### INFORMATIONAL

---

#### I1: `SESSION_SECRET` Misconfiguration Error Visible to End Users

| File | `config/session.php:38` |
|-------|-------|
| **Detail** | `die("Server misconfiguration: SESSION_SECRET not set.")` reveals internal config details. Use a generic 500 page and log the specifics server-side. |

#### I2: DSN Built via String Interpolation of Env Vars

| File | `config/db.php:24` |
|-------|-------|
| **Detail** | `$host` and `$db` from `getenv()` are interpolated into the DSN without validation. A malicious env var could inject DSN parameters. Not exploitable in Docker. |

#### I3: `sanitize_public_user_id()` vs `sanitize_uuid()` Naming Inconsistency

| File | `includes/profile_view_logic.php:20` |
|-------|-------|
| **Detail** | Both functions are identical. Standardize on `sanitize_uuid()` for consistency. |

#### I4: Image Reprocessing Overwrites In-Place Instead of Atomic Rename

| File | `includes/profile_update_logic.php:110-147` |
|-------|-------|
| **Detail** | `imagejpeg()` writes directly to the upload path. A disk-full condition mid-write could leave a truncated file with original malicious content. Write to `.tmp` then `rename()`. |

#### I5: `serve_image.php` Error Paths Lack Security Headers

| File | `public/serve_image.php:22,30,54,69` |
|-------|-------|
| **Detail** | `exit('Invalid filename.')` sends `text/html` without `X-Content-Type-Options: nosniff`. Not exploitable (static error strings) but inconsistent. |

#### I6: `APP_PORT` Conflicts Between `.env` and `docker-compose.yml`

| File | `docker/.env:5` vs `docker/docker-compose.yml` |
|-------|-------|
| **Detail** | `.env` sets `APP_PORT=8080` but compose sets `APP_PORT: 443`. Compose env takes precedence but creates confusion. |

---

## 3. Security Strengths

The application demonstrates strong security engineering in the following areas:

| Domain | Implementation | Quality |
|--------|---------------|---------|
| **SQL Injection** | 100% prepared statements with named parameters across all files | Excellent |
| **CSRF** | HMAC-bound, pooled (max 5), single-use tokens with origin+referer+Sec-Fetch-Site validation | Excellent |
| **Transfer Safety** | Ordered `FOR UPDATE` locks (lower ID first), atomic transactions, nonce-per-recipient | Excellent |
| **Password Storage** | SHA-384 pre-hash + bcrypt cost 10 (defeats 72-byte truncation), transparent legacy migration | Excellent |
| **Login Throttling** | Atomic `SELECT...FOR UPDATE` gate, exponential backoff (timestamp-based, not `sleep()`), hard lock at 20 attempts | Excellent |
| **Session Security** | HMAC fingerprint (IP+UA), IP binding, version-based invalidation, 30m inactivity + 1h absolute + 5m regen | Excellent |
| **Anti-Enumeration** | Constant-time comparison, dummy hash, 250-400ms random delay, generic error messages | Excellent |
| **Image Uploads** | GD reprocessing (strips polyglots/EXIF), dimension check before RAM load, GIF-to-PNG conversion, storage outside web root | Excellent |
| **Security Headers** | CSP with nonce-based `script-src`, HSTS, X-Frame-Options DENY, Permissions-Policy, COEP/COOP/CORP | Excellent |
| **Container Hardening** | Read-only root, tmpfs with noexec/nosuid, no-new-privileges, resource limits, unprivileged ports | Excellent |
| **Output Encoding** | `escape_output()` (HTML), `escape_js()` (JS), `escape_attr()` (attributes) used consistently | Very Good |
| **Rate Limiting** | Login (IP+user), registration (IP), search (user), password change (user+IP) | Very Good |
| **Database Constraints** | `CHECK (balance >= 0)`, `CHECK (amount >= 100)`, `CHECK (sender != receiver)`, username immutability trigger | Very Good |

---

## 4. IDOR Analysis

| Endpoint | Authorization Method | Verdict |
|----------|---------------------|---------|
| `process_payment.php` | Sender from `$_SESSION['user_id']`, receiver via UUID lookup | SECURE |
| `transaction_history.php` | `WHERE sender_id = :uid OR receiver_id = :uid` scoped to session | SECURE |
| `profile_update_logic.php` | All writes keyed to `$_SESSION['user_id']` | SECURE |
| `profile_view_logic.php` | Balance gated: `CASE WHEN id = :viewer_id THEN balance ELSE NULL END` | SECURE |
| `change_password_logic.php` | `$_SESSION['user_id']` only | SECURE |
| `serve_image.php` | Filename randomized (`bin2hex(random_bytes(16))`), any authenticated user can request | LOW RISK |
| `searchbox.php` | Returns only username + public_id, no sensitive data | SECURE |

**Conclusion**: No exploitable IDOR vulnerabilities. The application consistently uses session-bound user IDs and never trusts user-supplied internal IDs for write operations.

---

## 5. Race Condition Analysis

| Scenario | Protection | Verdict |
|----------|-----------|---------|
| Double-spend via concurrent transfers | `FOR UPDATE` ordered locks + balance check under transaction + session nonce | SECURE |
| A-to-B / B-to-A deadlock | Lock acquisition ordered by `min(id)` first | SECURE |
| Profile image orphaned files | `FOR UPDATE` row lock, old file deleted while locked | SECURE |
| Login counter bypass | `gate_login_attempt()` uses `SELECT...FOR UPDATE` in transaction | SECURE |
| Session nonce replay | Nonce `unset()` before any DB work | SECURE |
| Password change counter bypass | Separate read/check/increment (not atomic) | **VULNERABLE (M1)** |

---

## 6. XSS Audit Matrix

| File:Line | Output Method | Escaped? | Status |
|-----------|--------------|----------|--------|
| `view_profile.php:38,66` | `nl2br($profileData['bio'])` | Pre-escaped upstream | **M2** -- fragile |
| `payment_page.php:77` | `render_page_head('...' . $receiverUsername)` | Escaped inside function | Fragile pattern |
| `payment_page.php:90` | `escape_output($receiverUsername)` | Yes | SAFE |
| `payment_page.php:174` | `escape_js($receiverUsername)` | Yes | SAFE |
| `profile.php:36,43` | `escape_output($flash)` | Yes | SAFE |
| `searchbox.php:99` | `escape_output($row['username'])` | Yes | SAFE |
| `transaction_history.php:114-136` | All `escape_output()` | Yes | SAFE |
| `login.php:96,102` | `escape_output($error)` | Yes | SAFE |
| `register.php:116,122` | `escape_output($error)` | Yes | SAFE |
| `change_password.php:26` | `escape_output($error_message)` | Yes | SAFE |
| `transaction_result.php:46` | `escape_output($error)` | Yes | SAFE |

**Conclusion**: No exploitable XSS. Two fragile patterns identified (M2, payment_page.php:77) that should be refactored for maintainability.

---

## 7. File Upload Audit Matrix

| Check | Status | Location |
|-------|--------|----------|
| `is_uploaded_file()` verification | PASS | `profile_update_logic.php:69` |
| File size limit (2MB) | PASS | `profile_update_logic.php:73` |
| MIME type validation (finfo) | PASS | `profile_update_logic.php:78-85` |
| Decompression bomb defense (1200x1200 max) | PASS | `profile_update_logic.php:89-93` |
| Filename sanitization (path traversal, null bytes, double extensions) | PASS | `sanitize.php:sanitize_filename()` |
| Storage outside web root | PASS | `storage/uploads/` |
| GD reprocessing (strips metadata/polyglots) | PASS | `profile_update_logic.php:110-147` |
| GIF-to-PNG polyglot elimination | PASS | `profile_update_logic.php:128-139` |
| Extension whitelist (jpg/jpeg/png/gif/webp) | PASS | `profile_update_logic.php:78-85` |
| Old file cleanup under DB lock | PASS | `profile_update_logic.php:188-195` |
| Served via gatekeeper only | PASS | `serve_image.php` |

---

## 8. Docker & Infrastructure Matrix

| Control | Status | Notes |
|---------|--------|-------|
| Non-root container (`www-data`) | PASS | `Dockerfile` + `setpriv` |
| Read-only filesystem | PASS | `read_only: true` |
| `no-new-privileges` | PASS | Security opt |
| Resource limits (CPU + RAM) | PASS | 512M/1CPU app, 512M/0.5CPU db |
| Internal backend network for DB | PASS | `internal: true` |
| tmpfs with `noexec,nosuid` | PASS | /tmp, /var/run, /var/lock, /var/log |
| MySQL `--local-infile=0` | PASS | Blocks LOAD DATA attacks |
| PHP `display_errors=Off`, `expose_php=Off` | PASS | Dockerfile php.ini |
| ServerTokens Prod, ServerSignature Off | PASS | Apache hardening |
| TLS 1.2+ only, strong ciphers | PASS | `default-ssl.conf` |
| Committed secrets in `.env` | **FAIL** | **C1** |
| Default bind `0.0.0.0` | **FAIL** | **M5** |
| `storage/` mount lacks `noexec` | **FAIL** | **M8** |

---

## 9. Prioritized Hardening Checklist

### CRITICAL -- Fix Before War-Game

| # | Finding | Action | Effort |
|---|---------|--------|--------|
| 1 | **C1**: Committed secrets | Rotate all secrets, `.gitignore` docker/.env, scrub Git history | 1 hour |
| 2 | **C2**: Recoverable seed passwords | Generate random passwords at startup, use generic usernames, force first-login change | 2 hours |

### HIGH -- Fix This Week

| # | Finding | Action | Effort |
|---|---------|--------|--------|
| 3 | **H1**: Missing `CSRF_ALLOWED_ORIGIN` | Add to production `.env` with canonical URL | 5 min |
| 4 | **H2**: Throttle key varies for non-existent users | Add secondary IP-only global rate limit (100 attempts/15 min) | 1 hour |
| 5 | **H3**: `X-Forwarded-For` ignored behind proxy | Parse leftmost untrusted IP when trusted proxy detected | 1 hour |

### MEDIUM -- Fix Before Deployment

| # | Finding | Action | Effort |
|---|---------|--------|--------|
| 6 | **M1**: Password change throttle TOCTOU | Refactor to atomic `SELECT...FOR UPDATE` pattern | 1 hour |
| 7 | **M2**: Fragile `nl2br()` escaping order | Move `escape_output()` to template layer | 30 min |
| 8 | **M3**: Content-Disposition quote escaping | Strip `"` and `\` from filename before header | 10 min |
| 9 | **M4**: `die()` bypasses security headers | Replace with proper error template + `exit` | 30 min |
| 10 | **M5**: Default `0.0.0.0` bind | Set `APP_BIND=127.0.0.1` in `.env` | 5 min |
| 11 | **M6**: Sequential transaction IDs | Add `public_id` UUID column or display hash | 1 hour |
| 12 | **M7**: Emulated prepares not disabled | Add `PDO::ATTR_EMULATE_PREPARES => false` | 5 min |
| 13 | **M8**: `storage/` mount without `noexec` | Document accepted risk or add entrypoint remount | 30 min |

### LOW -- Hardening Polish

| # | Finding | Action | Effort |
|---|---------|--------|--------|
| 14 | **L1**: `Sec-Fetch-Site` accepts `none` | Remove from accepted values | 5 min |
| 15 | **L2**: Dynamic `Secure` cookie flag | Hardcode `true` for production | 5 min |
| 16 | **L3**: Missing `.php8` in storage `.htaccess` | Add extension | 5 min |
| 17 | **L4**: `needs_rehash()` uses `PASSWORD_DEFAULT` | Change to `PASSWORD_BCRYPT` with cost | 5 min |
| 18 | **L5**: `escape_js()` returns false on failure | Handle with fallback `'""'` | 5 min |
| 19 | **L6**: No DB upper bound on `amount_paise` | Add `CHECK` constraint | 10 min |
| 20 | **L7**: `AllowOverride` includes `ExecCGI` | Tighten to `FileInfo Limit` | 5 min |

### INFORMATIONAL -- Nice to Have

| # | Finding | Action |
|---|---------|--------|
| 21 | **I1**: Config error message leaks internals | Generic 500 page |
| 22 | **I2**: DSN string interpolation | Validate env vars format |
| 23 | **I3**: Function naming inconsistency | Standardize on `sanitize_uuid()` |
| 24 | **I4**: Image reprocessing not atomic | Write to `.tmp` then `rename()` |
| 25 | **I5**: Error paths lack `nosniff` header | Add `Content-Type: text/plain` on error exits |
| 26 | **I6**: `APP_PORT` conflict | Align `.env` and compose values |

---

*End of Security Hardening Audit -- 2026-03-16*
*Total findings: 2 Critical, 3 High, 8 Medium, 7 Low, 6 Informational*
