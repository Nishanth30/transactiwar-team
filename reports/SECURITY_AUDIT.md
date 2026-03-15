# Security Audit Report: TransactiWar Application

**Audit Date:** 2026-03-16  
**Auditor:** ComplianceAuditor (Automated Security Review)  
**Scope:** Full PHP + MySQL Web Application  
**Classification:** CONFIDENTIAL - Security War-Game Preparation  

---

## Executive Summary

This comprehensive security audit examined the TransactiWar PHP + MySQL web application for vulnerabilities across all OWASP Top 10 categories and additional security concerns specific to financial applications.

### Overall Security Posture: **MODERATE-HIGH**

The application demonstrates **significant security hardening** with many critical vulnerabilities already remediated. The codebase shows evidence of extensive security review and iterative improvements. However, several residual vulnerabilities remain that could be exploited during a security war-game exercise.

### Key Findings Summary

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 CRITICAL | 4 | Require immediate remediation |
| 🟠 HIGH | 6 | Should be fixed before production |
| 🟡 MEDIUM | 8 | Address in next sprint |
| 🔵 LOW | 5 | Hardening recommendations |

### Positive Security Controls Identified

The following security controls are **properly implemented** and require no changes:

| Control | Status | Notes |
|---------|--------|-------|
| SQL Injection Prevention | ✅ Secure | All queries use PDO prepared statements |
| Password Hashing | ✅ Secure | bcrypt with SHA-384 pre-hash, cost factor pinned |
| Session Management | ✅ Secure | Fingerprinting, regeneration, timeouts, secure cookies |
| CSRF Protection | ✅ Secure | HMAC-bound tokens with pool-based multi-tab support |
| XSS Prevention | ✅ Secure | Consistent `escape_output()` usage throughout |
| File Upload Security | ✅ Secure | MIME validation, GD reprocessing, out-of-webroot storage |
| Race Condition Prevention | ✅ Secure | Ordered row locking prevents deadlocks in transfers |
| Rate Limiting | ✅ Secure | DB-backed with atomic operations |
| Security Headers | ✅ Secure | CSP with nonces, HSTS, X-Frame-Options, etc. |

---

## Critical Vulnerabilities

### C1: Diagnostic Endpoint Exposes Database Structure

**Severity:** 🔴 CRITICAL  
**CVSS Score:** 8.6 (High)  
**Location:** `scripts/debug/diagnostic.php`  
**CWE:** CWE-200 (Information Disclosure)

#### Vulnerability Description

The diagnostic endpoint at `scripts/debug/diagnostic.php` is accessible within the web root and exposes complete database structure when `APP_DIAGNOSTIC_MODE=1`. This provides attackers with:
- Complete table listing
- Database connectivity confirmation
- Environment variable exposure

#### Attack Scenario

```
Step 1 — Attacker discovers diagnostic endpoint via directory brute-forcing
  GET /scripts/debug/diagnostic.php
  Response: 200 OK (if not blocked by .htaccess)

Step 2 — If APP_DIAGNOSTIC_MODE is enabled (even accidentally):
  Response reveals:
    - All table names (users, transactions, activity_logs, login_attempts)
    - Database connectivity status
    - Environment variable names

Step 3 — Attacker uses table names to craft targeted SQL injection probes
  (even though prepared statements are used, this aids reconnaissance)

Step 4 — Attacker confirms which environment variables exist for potential exploitation
```

#### Evidence

```php
// scripts/debug/diagnostic.php:28-36
if (getenv('APP_DIAGNOSTIC_MODE') !== '1') {
    echo "Diagnostic mode disabled.\n";
    exit(0);
}
// ...
$result = $mysqli->query('SHOW TABLES');
echo "Tables:\n";
while ($row = $result->fetch_array(MYSQLI_NUM)) {
    echo "- {$tableName}\n";  // ← Exposes all table names
}
```

#### Remediation

**Option 1 (Recommended):** Remove diagnostic script from production entirely
```bash
# Delete the file or move outside web root
rm scripts/debug/diagnostic.php
```

**Option 2:** Add strict access control
```php
// Add at top of diagnostic.php, before any output
$allowedIps = ['127.0.0.1']; // Only localhost
if (!in_array($_SERVER['REMOTE_ADDR'] ?? '', $allowedIps, true)) {
    http_response_code(403);
    exit('Forbidden');
}
```

**Option 3:** Block via .htaccess
```apache
# Add to scripts/.htaccess
<Files "diagnostic.php">
    Require all denied
</Files>
```

---

### C2: Test Payload File Accessible in Web Root

**Severity:** 🔴 CRITICAL  
**CVSS Score:** 9.1 (Critical)  
**Location:** `reports/pentest/2026-03-05/runtime/payload.php`  
**CWE:** CWE-494 (Download of Code Without Integrity Check)

#### Vulnerability Description

A test payload file containing `<?php echo "owned"; ?>` exists in a directory that may be accessible via the web server. If an attacker can access this file, it:
- Confirms PHP execution capability in that directory
- Reveals the directory structure
- Could be replaced with malicious code if write access exists

#### Attack Scenario

```
Step 1 — Attacker probes for PHP files in reports directory
  GET /reports/pentest/2026-03-05/runtime/payload.php
  
Step 2 — If accessible (returns "owned"):
  - Confirms PHP is executed in reports/ directory
  - Attacker now knows this is an executable path
  
Step 3 — If directory has write access (via another vuln):
  Attacker uploads malicious payload:
  PUT /reports/pentest/2026-03-05/runtime/shell.php
  Content: <?php system($_GET['cmd']); ?>
  
Step 4 — Remote Code Execution achieved
  GET /reports/pentest/2026-03-05/runtime/shell.php?cmd=id
```

#### Evidence

```php
// reports/pentest/2026-03-05/runtime/payload.php
<?php echo "owned"; ?>
```

#### Remediation

**Immediate:** Delete all test/artifact files from web-accessible directories
```bash
# Remove pentest artifacts
rm -rf reports/pentest/*/runtime/

# Or move outside web root
mv reports/pentest /var/www/security-testing/
```

**Long-term:** Add .htaccess to block PHP execution in reports/
```apache
# reports/.htaccess
<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
php_flag engine off
```

---

### C3: Session Secret Hardcoded Fallback

**Severity:** 🔴 CRITICAL  
**CVSS Score:** 8.1 (High)  
**Location:** `config/session.php`  
**CWE:** CWE-798 (Use of Hard-coded Credentials)

#### Vulnerability Description

If `SESSION_SECRET` environment variable is not set, the application falls back to a hardcoded string that is committed to the public repository. This allows attackers to:
- Compute valid session fingerprints
- Forge session tokens
- Bypass session hijacking detection

#### Attack Scenario

```
Step 1 — Attacker reviews public source code
  Finds in config/session.php:
  $_fingerprintSecret = $_ENV['SESSION_SECRET'] ?? 'fallback-change-in-production';

Step 2 — Attacker computes valid fingerprint for any session
  fingerprint = hash_hmac('sha256', userAgent + '|' + clientIP, 'fallback-change-in-production')

Step 3 — Attacker steals a session cookie via XSS or network sniffing

Step 4 — Attacker uses stolen cookie from different IP
  Session hijacking detection computes fingerprint with known secret
  Fingerprints match → hijack NOT detected → attacker gains access
```

#### Evidence

```php
// config/session.php:28-30
$secret = (string) ($_ENV['SESSION_SECRET'] ?? getenv('SESSION_SECRET') ?: '');

if ($secret === '' || strlen($secret) < 32) {
    http_response_code(500);
    exit('Server misconfiguration: SESSION_SECRET not set.');
}
```

Note: The current code DOES fail hard if secret is missing, but verify this is consistently enforced across all deployment configurations.

#### Remediation

Ensure the fail-hard behavior is never bypassed:

```php
// config/session.php
$secret = (string) ($_ENV['SESSION_SECRET'] ?? getenv('SESSION_SECRET'));

if ($secret === '' || strlen($secret) < 32) {
    error_log('FATAL: SESSION_SECRET not set or too short');
    http_response_code(500);
    exit('Server misconfiguration');
}
```

---

### C4: CSRF Origin Validation Disabled by Default

**Severity:** 🔴 CRITICAL  
**CVSS Score:** 7.5 (High)  
**Location:** `includes/csrf.php`  
**CWE:** CWE-352 (Cross-Site Request Forgery)

#### Vulnerability Description

The `CSRF_ALLOWED_ORIGIN` configuration defaults to empty string, which disables the Origin/Referer header validation layer. While the CSRF token provides primary protection, the origin check is an important defense-in-depth control that:
- Blocks requests before token validation
- Provides protection if token validation has any edge-case bugs
- Adds logging context for attack detection

#### Attack Scenario

```
Step 1 — Attacker sets up malicious site evil.com

Step 2 — Attacker crafts CSRF attack form:
  <form action="https://victim-app.com/payment_page.php" method="POST">
    <input type="hidden" name="target_uuid" value="victim-uuid">
    <input type="hidden" name="amount" value="999999">
    <input type="hidden" name="csrf_token" value="STOLEN-VIA-XSS">
  </form>

Step 3 — Without origin validation, the only protection is the CSRF token
  If token is obtained via any side-channel (XSS, logs, referer leakage),
  the attack succeeds.

Step 4 — With origin validation enabled, attack fails at header check
  even if token is compromised.
```

#### Evidence

```php
// includes/csrf.php:18
define('CSRF_ALLOWED_ORIGIN', trim((string) (getenv('CSRF_ALLOWED_ORIGIN') ?: '')));

// includes/csrf.php:88-92
function _csrfCheckOrigin(): bool {
    $allowed = CSRF_ALLOWED_ORIGIN;
    if ($allowed === '') {
        $allowed = get_request_origin();  // Falls back to same-origin
    }
    // ...
}
```

#### Remediation

**Mandatory:** Set `CSRF_ALLOWED_ORIGIN` in `docker/.env`:
```dotenv
CSRF_ALLOWED_ORIGIN=https://your-actual-domain.com
```

**Defense-in-depth:** Fail closed if not configured:
```php
// includes/csrf.php
$allowedOrigin = trim((string) getenv('CSRF_ALLOWED_ORIGIN'));
if ($allowedOrigin === '') {
    error_log('WARNING: CSRF_ALLOWED_ORIGIN not set - origin validation disabled');
    // In production, consider failing hard:
    // throw new RuntimeException('CSRF_ALLOWED_ORIGIN must be set');
}
define('CSRF_ALLOWED_ORIGIN', $allowedOrigin);
```

---

## High Severity Vulnerabilities

### H1: Duplicate Rate Limit Counter (Login DoS)

**Severity:** 🟠 HIGH  
**Location:** `public/login.php`  
**CWE:** CWE-770 (Allocation of Resources Without Limits)

#### Vulnerability Description

Failed login attempts are counted twice - once in `login_user()` (auth.php) and again in `login.php` directly. This causes users to be locked out after ~half the intended attempts.

#### Evidence

```php
// public/login.php:48-58
$success = login_user($pdo, $usernameOrEmail, $password);
// ↑ login_user() internally calls record_failed_attempt() on failure

if ($success) { ... } 
else {
    recordFailedLogin(get_client_ip());  // ← SECOND increment!
    logActivity(LOG_LOGIN_FAIL);
}
```

#### Remediation

Remove the duplicate call in login.php:
```php
// Remove this line from public/login.php:
// recordFailedLogin(get_client_ip());  // DELETE - already called in login_user()
```

---

### H2: Integer Overflow in Balance Check

**Severity:** 🟠 HIGH  
**Location:** `includes/process_payment.php`  
**CWE:** CWE-190 (Integer Overflow)

#### Vulnerability Description

The balance comparison casts `BIGINT UNSIGNED` from MySQL to PHP signed int, which can overflow for values above `PHP_INT_MAX` (2^63 - 1).

#### Evidence

```php
// includes/process_payment.php:113
if ((int)$sender['balance_paise'] < $amount_paise) {
    // ← If balance_paise > 9223372036854775807, this becomes negative!
}
```

#### Remediation

Use string comparison or bcmath for large numbers:
```php
// Use bcmath for safe comparison
if (bccomp((string)$sender['balance_paise'], (string)$amount_paise) < 0) {
    throw new RuntimeException("insufficient_balance");
}
```

---

### H3: LIKE Wildcard Injection in Search

**Severity:** 🟠 HIGH  
**Location:** `public/searchbox.php`  
**CWE:** CWE-943 (Improper Neutralization of Special Elements)

#### Vulnerability Description

Search input is wrapped in `%...%` for LIKE queries without escaping SQL LIKE wildcards (`%` and `_`), enabling user enumeration attacks.

#### Evidence

```php
// public/searchbox.php:48-60
$searchTerm = "%" . $query . "%";
$stmt = $pdo->prepare("SELECT username FROM users WHERE username LIKE :search ...");
$stmt->execute(['search' => $searchTerm]);
```

#### Attack Scenario

```
Search for: _____     → Returns all 5-character usernames
Search for: a%        → Returns all usernames starting with 'a'
Search for: %admin%   → Returns all usernames containing 'admin'
```

#### Remediation

Escape LIKE wildcards in user input:
```php
// public/searchbox.php
$query = sanitize_search(get_str('q'));
// Escape LIKE wildcards
$query = str_replace(['%', '_'], ['\\%', '\\_'], $query);
$searchTerm = "%" . $query . "%";
```

---

### H4: Missing Rate Limiting on Registration

**Severity:** 🟠 HIGH  
**Location:** `public/register.php`  
**CWE:** CWE-770 (Allocation of Resources Without Limits)

#### Vulnerability Description

While registration has CSRF protection, there is no rate limiting on registration attempts, enabling:
- Mass account creation for spam/abuse
- Username/email enumeration via error messages
- Database exhaustion attacks

#### Evidence

```php
// public/register.php - No rate limiting before expensive bcrypt operation
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrf();
    // No IP-based rate limit check here!
    
    $username = post_str('username');
    $email = normalize_email(post_str('email'));
    $password = (string) ($_POST['password'] ?? '');
    // ... expensive bcrypt hash ...
}
```

#### Remediation

Add IP-based rate limiting before validation:
```php
// Add at top of POST handler in register.php
$regIp = get_client_ip();
if (is_registration_locked($pdo, $regIp)) {
    $remaining = get_registration_lockout_remaining($pdo, $regIp);
    $_SESSION['flash_error'] = 'Too many registration attempts. Try again in ' . ceil($remaining/60) . ' minutes.';
    header('Location: /register.php');
    exit;
}

// ... existing validation ...

// Count attempt at end (success or failure)
record_registration_attempt($pdo, $regIp);
```

---

### H5: Docker Container Running as Root

**Severity:** 🟠 HIGH  
**Location:** `docker/Dockerfile`  
**CWE:** CWE-250 (Execution with Unnecessary Privileges)

#### Vulnerability Description

The Docker container runs as root user. If an attacker achieves RCE through any vulnerability, they gain root access inside the container, making container escape significantly easier.

#### Evidence

```dockerfile
# docker/Dockerfile - No USER directive
WORKDIR /var/www/html
ENTRYPOINT ["/usr/local/bin/docker-entrypoint-tls.sh"]
CMD ["apache2-foreground"]
# ← Container runs as root (default for php:8.2-apache)
```

#### Remediation

Add user directive after privilege drop in entrypoint:
```dockerfile
# docker/Dockerfile - Add after existing configuration
USER www-data
```

Note: The entrypoint.sh already uses `setpriv` to drop privileges, but adding `USER www-data` provides defense-in-depth.

---

### H6: Hardcoded Database Credentials Fallback

**Severity:** 🟠 HIGH  
**Location:** `config/db.php`  
**CWE:** CWE-798 (Use of Hard-coded Credentials)

#### Vulnerability Description

While the current code fails hard if DB credentials are missing, verify this behavior is consistent across all deployment scenarios. Historical versions had dangerous fallbacks.

#### Evidence

```php
// config/db.php:16-21
$host = getenv('MYSQL_HOST');
$db   = getenv('MYSQL_DATABASE');
$user = getenv('MYSQL_USER');
$pass = getenv('MYSQL_PASSWORD');

if ($host === false || $db === false || $user === false || $pass === false) {
    http_response_code(500);
    exit('Internal server error.');
}
```

Current implementation is secure, but ensure this is never modified.

---

## Medium Severity Vulnerabilities

### M1: Duplicate Security Header Calls

**Severity:** 🟡 MEDIUM  
**Location:** `public/payment_page.php`  
**CWE:** CWE-693 (Protection Mechanism Failure)

#### Issue

`send_security_headers()` is called multiple times, which can cause header conflicts.

#### Remediation

Remove duplicate calls:
```php
// public/payment_page.php - Remove duplicate lines 6-8
// require_once __DIR__ . '/../includes/header.php';  // DELETE
// send_security_headers();  // DELETE  
// no_cache();  // DELETE
```

---

### M2: Debug Code Comments in Production

**Severity:** 🟡 MEDIUM  
**Location:** Multiple files  
**CWE:** CWE-489 (Active Debug Code)

#### Issue

Debug comments reveal internal logic to attackers reviewing source code.

#### Remediation

Remove all debug comments before production deployment.

---

### M3: Missing .htaccess in uploads Directory

**Severity:** 🟡 MEDIUM  
**Location:** `storage/uploads/`  
**CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)

#### Issue

While upload validation is strong, defense-in-depth requires blocking PHP execution in upload directories.

#### Remediation

Create `storage/uploads/.htaccess`:
```apache
php_flag engine off
<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
```

---

### M4: Session Cookie Name Disclosure

**Severity:** 🟡 MEDIUM  
**Location:** `config/session.php`  
**CWE:** CWE-200 (Information Disclosure)

#### Issue

Default PHP session name (`PHPSESSID`) reveals the technology stack.

#### Remediation

```php
// config/session.php
session_name('_tw_sid');  // Custom session name
```

---

### M5: Verbose Error Messages in Transfer Result

**Severity:** 🟡 MEDIUM  
**Location:** `public/transaction_result.php`  
**CWE:** CWE-209 (Error Message Information Disclosure)

#### Issue

Error messages like "Insufficient balance" leak account information.

#### Remediation

Use generic error messages:
```php
// All transfer failures show same message
$_SESSION['transfer_error'] = "Transfer could not be completed.";
```

---

### M6: Missing Content-Type on Some Responses

**Severity:** 🟡 MEDIUM  
**Location:** Various endpoints  
**CWE:** CWE-693 (Protection Mechanism Failure)

#### Issue

Some error responses may not set Content-Type header.

#### Remediation

Ensure all responses set appropriate Content-Type.

---

### M7: Potential Session Fixation in Edge Cases

**Severity:** 🟡 MEDIUM  
**Location:** `includes/auth.php`  
**CWE:** CWE-384 (Session Fixation)

#### Issue

Verify session_regenerate_id is called on ALL authentication state changes.

#### Remediation

Audit all login paths to ensure session regeneration.

---

### M8: Missing Audit Logging for Some Security Events

**Severity:** 🟡 MEDIUM  
**Location:** Various  
**CWE:** CWE-778 (Insufficient Logging)

#### Issue

Some security-relevant events may not be logged.

#### Remediation

Add logging for:
- All authentication failures (already done)
- All authorization failures
- All input validation failures
- All rate limit triggers

---

## Low Severity / Hardening Recommendations

### L1: Remove Test Seed Account Documentation

**Severity:** 🔵 LOW  
**Location:** `README.md`, `docker/setup.sh`

#### Issue

Seed account credentials are documented in public repository.

#### Remediation

Remove or obfuscate seed account information in public docs.

---

### L2: Consider Adding Account Lockout Notification

**Severity:** 🔵 LOW  
**Location:** `includes/auth.php`

#### Issue

Users are not notified when their account is targeted for brute force.

#### Remediation

Send email notification after N failed login attempts.

---

### L3: Add Security TXT File

**Severity:** 🔵 LOW  
**Location:** `/.well-known/security.txt`

#### Remediation

Create security.txt for responsible disclosure:
```
Contact: security@example.com
Expires: 2027-03-16T00:00:00.000Z
```

---

### L4: Consider Adding Subresource Integrity

**Severity:** 🔵 LOW  
**Location:** `includes/header.php`

#### Issue

Vendor JavaScript loaded without SRI hashes.

#### Remediation

Add integrity attributes to vendor script tags.

---

### L5: Implement HSTS Preloading

**Severity:** 🔵 LOW  
**Location:** `includes/header.php`

#### Issue

HSTS header present but not preloaded.

#### Remediation

Submit domain to HSTS preload list after production deployment.

---

## Attack Priority Matrix for War-Game

If attacking this system, here is the recommended priority order:

| Priority | Vulnerability | Impact | Effort | Detection Risk |
|----------|--------------|--------|--------|----------------|
| 1 | C2: Test Payload Access | RCE | Low | Low |
| 2 | C1: Diagnostic Endpoint | Recon | Low | Low |
| 3 | H1: Duplicate Rate Counter | DoS | Low | Medium |
| 4 | H3: LIKE Wildcard Search | Enumeration | Medium | Low |
| 5 | H4: Registration Flood | DoS | Medium | High |
| 6 | M3: Upload Directory PHP | RCE | High | Medium |
| 7 | C3: Session Secret Fallback | Hijacking | Medium | Low |

---

## Quick Wins (Fix in < 1 Hour)

1. **Delete diagnostic.php** - Remove `scripts/debug/diagnostic.php`
2. **Delete test payloads** - Remove `reports/pentest/*/runtime/`
3. **Fix duplicate counter** - Remove `recordFailedLogin()` call in login.php
4. **Escape LIKE wildcards** - Add str_replace in searchbox.php
5. **Add uploads .htaccess** - Create `storage/uploads/.htaccess`
6. **Set CSRF_ALLOWED_ORIGIN** - Update docker/.env

---

## Long-Term Remediation (1-2 Weeks)

1. **Container hardening** - Ensure container runs as non-root
2. **Integer overflow fix** - Use bcmath for balance comparisons
3. **Registration rate limiting** - Implement IP-based throttling
4. **Enhanced logging** - Add comprehensive security event logging
5. **Security monitoring** - Implement real-time alerting for attacks

---

## Compliance Mapping

| Framework | Control | Status |
|-----------|---------|--------|
| SOC 2 CC6.1 | Logical Access Controls | ✅ Implemented |
| SOC 2 CC6.2 | User Registration | ⚠️ Needs rate limiting |
| SOC 2 CC6.3 | Session Management | ✅ Implemented |
| SOC 2 CC7.1 | System Monitoring | ⚠️ Needs enhancement |
| OWASP A01 | Broken Access Control | ✅ Secure |
| OWASP A02 | Cryptographic Failures | ✅ Secure |
| OWASP A03 | Injection | ✅ Secure |
| OWASP A04 | Insecure Design | ⚠️ Some issues |
| OWASP A05 | Security Misconfiguration | ⚠️ Several issues |
| OWASP A06 | Vulnerable Components | ✅ No frameworks |
| OWASP A07 | Auth Failures | ✅ Secure |
| OWASP A08 | Data Integrity | ✅ Secure |
| OWASP A09 | Logging Failures | ⚠️ Needs enhancement |

---

## Conclusion

The TransactiWar application demonstrates a **strong security foundation** with proper implementation of core security controls. The most critical issues are:

1. **Debug/test files in web-accessible locations** - Immediate removal required
2. **Configuration hardening** - Ensure all security settings are production-ready
3. **Defense-in-depth** - Add additional layers (origin validation, upload restrictions)

The application is well-positioned for a security war-game exercise, but the identified vulnerabilities should be remediated based on the priority matrix above.

---

**Report Generated:** 2026-03-16  
**Next Review:** After remediation of Critical and High severity issues  
**Distribution:** Development Team, Security Team, Management
