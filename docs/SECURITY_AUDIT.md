# TransactiWar Security Audit Report

**Application:** TransactiWar - PHP + MySQL Financial Transfer Application
**Audit Date:** March 18, 2026
**Auditor:** Security Engineering Team
**Version:** Full Stack Review (Docker Deployment)

---

## Executive Summary

This security audit examined the TransactiWar application, a PHP + MySQL web application for financial transfers between users. The application demonstrates **significant security hardening efforts** with many industry-standard protections already implemented.

### Overall Security Posture: **MODERATE**

| Category | Status |
|----------|--------|
| SQL Injection | ✅ Well Protected |
| XSS Prevention | ✅ Well Protected |
| CSRF Protection | ✅ Well Protected |
| Session Management | ✅ Well Protected |
| Password Security | ✅ Well Protected |
| Rate Limiting | ✅ Well Protected |
| Input Validation | ✅ Well Protected |
| File Upload Security | ✅ Well Protected |
| Race Conditions | ✅ Well Protected |
| Docker Security | ⚠️ Minor Issues |
| Information Disclosure | ⚠️ Minor Issues |
| Security Headers | ✅ Well Protected |

### Summary Statistics

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 0 | All remediated |
| HIGH | 2 | Require attention |
| MEDIUM | 5 | Should be addressed |
| LOW | 4 | Acceptable risk |

### Key Findings

**Positive Observations:**
- Comprehensive CSRF protection with token pooling and HMAC validation
- Strong session security with fingerprinting, regeneration, and timeout controls
- Parameterized queries throughout (no SQL injection vectors found)
- Output encoding applied consistently (XSS protected)
- Rate limiting for login, registration, password changes, and searches
- Race condition protection in money transfers with proper locking
- Secure file upload with MIME validation, dimension checks, and GD reprocessing
- Comprehensive activity logging with Discord alerting
- Docker container hardening with read-only filesystem and resource limits

**Areas Requiring Attention:**
- Diagnostic endpoint exposed in production configurations
- CSP report endpoint lacks authentication
- Self-signed TLS certificates generated at runtime
- Verbose error messages in some edge cases
- Missing security.txt and security contact information

---

## Vulnerability Findings

### HIGH Severity

---

#### H1: Diagnostic Endpoint Exposed Without Authentication

**Severity:** HIGH
**Location:** `/scripts/debug/diagnostic.php`
**CVSS Score:** 6.5 (Medium)

**Description:**
The diagnostic endpoint at `/scripts/debug/diagnostic.php` exposes database structure information when `APP_DIAGNOSTIC_MODE=1`. While guarded by an environment variable, this endpoint:
- Reveals all table names in the database
- Provides infrastructure reconnaissance data to attackers
- Is accessible from the public web root

**Attack Scenario:**
```
Step 1 — Attacker discovers diagnostic endpoint via directory brute-forcing
  GET /scripts/debug/diagnostic.php

Step 2 — If APP_DIAGNOSTIC_MODE=1 (common in development-to-production migrations)
  Response:
    PHP running
    Tables:
    - users
    - transactions
    - activity_logs
    - blocked_ips
    - login_attempts

Step 3 — Attacker now knows:
  - Exact table names for targeted SQL injection attempts
  - Database schema structure
  - Application is running (service enumeration)
```

**Current Mitigation:**
```php
if (getenv('APP_DIAGNOSTIC_MODE') !== '1') {
    echo "Diagnostic mode disabled.\n";
    exit(0);
}
```

**Recommended Fix:**
1. **Remove from production:** Never deploy diagnostic scripts to production
2. **Add authentication:** Require admin authentication even with env var enabled
3. **IP whitelist:** Only allow access from trusted management IPs
4. **Move outside web root:** Place diagnostic tools outside the document root

```php
// Recommended implementation
if (getenv('APP_ENV') === 'production') {
    http_response_code(404);
    exit('Not found');
}

if (getenv('APP_DIAGNOSTIC_MODE') !== '1') {
    http_response_code(403);
    exit('Access denied');
}

// Add admin authentication check
require_once __DIR__ . '/../includes/auth.php';
if (!is_admin_user()) {
    http_response_code(403);
    exit('Access denied');
}
```

---

#### H2: CSP Report Endpoint Accepts Unauthenticated POST

**Severity:** HIGH
**Location:** `/public/csp-report.php`
**CVSS Score:** 5.3 (Medium)

**Description:**
The CSP violation report collector accepts POST requests from any source without authentication. While designed to receive browser-generated CSP reports, this endpoint:
- Can be abused for log flooding attacks
- Accepts attacker-controlled data in the `detail` field
- Could be used to inject false security events

**Attack Scenario:**
```
Step 1 — Attacker sends crafted CSP reports
  POST /csp-report.php
  Content-Type: application/json
  
  {
    "csp-report": {
      "blocked-uri": "javascript:alert(document.cookie)",
      "violated-directive": "script-src",
      "source-file": "https://evil.com/attack.js",
      "document-uri": "https://victim-app.com/payment_page.php"
    }
  }

Step 2 — Each report creates a security log entry
  logSecurityEvent('CSP_VIOLATION', 'blocked=... directive=...')

Step 3 — Attacker floods with 1000+ reports
  - Fills activity_logs table
  - Triggers Discord alert rate limits
  - Masks real CSP violations from actual attacks
  - Potentially causes DoS via log storage exhaustion
```

**Current Mitigation:**
```php
// Size limit on report
if ($raw === false || strlen($raw) === 0 || strlen($raw) > 10000) {
    http_response_code(204);
    exit;
}
```

**Recommended Fix:**
1. **Rate limit by IP:** Use existing login_attempts table or separate rate limit
2. **Validate report origin:** Only accept reports from own domain
3. **Batch reports:** Accumulate and log periodically instead of per-request
4. **Add proof-of-work:** Require computational cost for each report

```php
// Add IP-based rate limiting
$ip = get_client_ip();
$now = time();
$windowStart = $now - 60; // 1 minute window

$stmt = $pdo->prepare("
    SELECT COUNT(*) FROM activity_logs 
    WHERE client_ip = ? AND webpage = 'CSP_VIOLATION' 
    AND created_at > FROM_UNIXTIME(?)
");
$stmt->execute([$ip, $windowStart]);
$count = (int) $stmt->fetchColumn();

if ($count > 10) { // Max 10 CSP reports per IP per minute
    http_response_code(429);
    exit;
}
```

---

### MEDIUM Severity

---

#### M1: Self-Signed TLS Certificates Generated at Runtime

**Severity:** MEDIUM
**Location:** `/docker/Dockerfile`, `/docker/docker-compose.yml`
**CVSS Score:** 4.3 (Medium)

**Description:**
The Docker configuration generates self-signed TLS certificates at container startup:
```yaml
GENERATE_SELF_SIGNED_TLS: ${GENERATE_SELF_SIGNED_TLS:-1}
TLS_CERT_CN: ${TLS_CERT_CN:-localhost}
```

This creates several security issues:
- Browser certificate warnings train users to ignore security warnings
- No certificate transparency logging
- Vulnerable to MITM attacks if attacker can intercept initial connection
- Certificate Common Name may not match actual deployment hostname

**Attack Scenario:**
```
Step 1 — Attacker positions on same network as victim (public WiFi)
Step 2 — Attacker performs ARP spoofing to intercept traffic
Step 3 — Victim connects to https://app.local
Step 4 — Browser shows certificate warning (self-signed)
Step 5 — User clicks "Accept Risk and Continue" (trained behavior)
Step 6 — Attacker decrypts all traffic including session cookies
```

**Recommended Fix:**
1. **Use Let's Encrypt:** Automate with certbot in entrypoint script
2. **Pre-provision certificates:** Generate certificates before deployment
3. **Disable self-signed in production:** Set `GENERATE_SELF_SIGNED_TLS=0`
4. **Use reverse proxy:** Terminate TLS at nginx/HAProxy with proper certs

```bash
# Example: Let's Encrypt in entrypoint
if [ "$APP_ENV" = "production" ] && [ "$GENERATE_SELF_SIGNED_TLS" = "1" ]; then
    echo "ERROR: Self-signed certs not allowed in production"
    exit 1
fi
```

---

#### M2: Verbose Error Messages in Transaction Processing

**Severity:** MEDIUM
**Location:** `/includes/process_payment.php`
**CVSS Score:** 4.0 (Medium)

**Description:**
While the code properly catches exceptions and shows generic messages to users, some error paths log detailed internal state that could aid attackers:

```php
logSecurityEvent(LOG_TRANSFER_INVALID, 'bad_amount_format:' . substr($raw_rupees, 0, 30));
logSecurityEvent(LOG_TRANSFER_INVALID, 'amount_out_of_range:' . substr($raw_rupees, 0, 30));
logSecurityEvent(LOG_TRANSFER_INVALID, 'receiver_not_found:' . substr($target_uuid, 0, 36));
```

These logs are sent to Discord webhooks, potentially exposing:
- Partial user input data
- Internal error codes
- UUID format validation details

**Attack Scenario:**
```
Step 1 — Attacker monitors Discord webhook (compromised team member)
Step 2 — Attacker sees detailed error logs from failed transfers
Step 3 — Error messages reveal:
  - Which UUIDs are valid vs invalid (user enumeration)
  - Amount validation thresholds
  - Internal error handling logic
Step 4 — Attacker uses this intelligence to craft more targeted attacks
```

**Recommended Fix:**
1. **Generic log messages:** Log only event type, not user input
2. **Separate forensic logs:** Store detailed logs in secure location
3. **Redact sensitive data:** Sanitize before Discord transmission

```php
// Instead of:
logSecurityEvent(LOG_TRANSFER_INVALID, 'receiver_not_found:' . substr($target_uuid, 0, 36));

// Use:
logSecurityEvent(LOG_TRANSFER_INVALID, 'uuid_lookup_failed');
```

---

#### M3: Missing Security.txt File

**Severity:** MEDIUM
**Location:** N/A (Missing)
**CVSS Score:** 3.7 (Low)

**Description:**
The application lacks a `security.txt` file at the well-known location (`/.well-known/security.txt`). This RFC 9116 standard:
- Provides security researchers a way to report vulnerabilities
- Reduces likelihood of public disclosure without contact
- Shows security maturity

**Recommended Fix:**
Create `/.well-known/security.txt`:
```
Contact: mailto:security@transactiwar.example.com
Expires: 2027-03-18T00:00:00.000Z
Encryption: https://transactiwar.example.com/pgp-key.txt
Acknowledgments: https://transactiwar.example.com/security/hall-of-fame.html
Policy: https://transactiwar.example.com/security/policy.html
Hiring: https://transactiwar.example.com/careers
```

---

#### M4: Session Secret Rotation Not Supported

**Severity:** MEDIUM
**Location:** `/config/session.php`
**CVSS Score:** 3.7 (Low)

**Description:**
The session fingerprint uses a static `SESSION_SECRET` from environment variables. If this secret is compromised:
- All existing session fingerprints can be forged
- Session hijacking detection becomes ineffective
- Secret rotation requires invalidating all active sessions

**Attack Scenario:**
```
Step 1 — Attacker gains read access to environment variables
  (via SSRF, XXE, or compromised CI/CD)
Step 2 — Attacker reads SESSION_SECRET value
Step 3 — Attacker computes valid fingerprints for any user:
  fingerprint = hash_hmac('sha256', userAgent + '|' + clientIP, SESSION_SECRET)
Step 4 — Attacker creates forged session cookies
Step 5 — Session hijacking detection is bypassed
```

**Recommended Fix:**
1. **Per-session secrets:** Generate unique secret per session
2. **Key rotation support:** Implement secret versioning
3. **Hardware security module:** Store secrets in HSM for production

---

#### M5: Missing Rate Limiting on CSP Reports

**Severity:** MEDIUM
**Location:** `/public/csp-report.php`
**CVSS Score:** 4.3 (Medium)

**Description:**
The CSP report endpoint has no rate limiting, allowing attackers to:
- Flood the activity_logs table
- Exhaust Discord webhook rate limits (30/minute)
- Mask real security events with noise

**Recommended Fix:**
Add rate limiting using the existing login_attempts infrastructure or a dedicated rate limit table.

---

### LOW Severity

---

#### L1: AI Trap Comments May Confuse Security Tools

**Severity:** LOW
**Location:** `/includes/ai_traps.php`
**CVSS Score:** 2.0 (Low)

**Description:**
The AI trap HTML comments contain fake vulnerability hints:
```html
<!-- DEV NOTE: The test account admin:admin123 should be removed -->
<!-- WARNING: The JWT secret is hardcoded as "supersecretkey123" -->
```

While intended to waste attacker time, these may:
- Trigger false positives in automated security scanners
- Confuse legitimate security auditors
- Be accidentally committed with real credentials

**Recommended Fix:**
1. **Clearly mark as traps:** Add obvious "SECURITY TRAP - NOT REAL" markers
2. **Remove in production:** Strip trap comments in production builds
3. **Document internally:** Keep team informed about trap locations

---

#### L2: Discord Webhook URLs in Environment Variables

**Severity:** LOW
**Location:** `/docker/docker-compose.yml`
**CVSS Score:** 2.5 (Low)

**Description:**
Discord webhook URLs are stored in environment variables:
```yaml
DISCORD_WEBHOOK_URL: ${DISCORD_WEBHOOK_URL:-}
```

If environment variables are leaked (via phpinfo(), error messages, or SSRF), webhook URLs could be abused to:
- Send phishing messages to team Discord
- Spam Discord channels
- Gather information about security events

**Recommended Fix:**
1. **Validate webhook URLs:** Ensure they match Discord pattern (already implemented)
2. **Separate alert channels:** Use different webhooks for different severity levels
3. **Monitor webhook usage:** Alert on unusual webhook activity

---

#### L3: No Rate Limiting on Profile Image Requests

**Severity:** LOW
**Location:** `/public/serve_image.php`
**CVSS Score:** 3.1 (Low)

**Description:**
The image serving endpoint has no rate limiting. An attacker could:
- Enumerate profile image filenames
- Cause bandwidth exhaustion
- Probe for existence of specific users

**Recommended Fix:**
Add rate limiting per user session for image requests.

---

#### L4: Missing Content-Type Options on Some Endpoints

**Severity:** LOW
**Location:** Various
**CVSS Score:** 2.0 (Low)

**Description:**
While most endpoints set proper headers, some code paths may not set `X-Content-Type-Options: nosniff` before early exits.

**Recommended Fix:**
Ensure all exit paths include security headers.

---

## Security Strengths

The following security controls are **well-implemented** and should be maintained:

### 1. SQL Injection Protection ✅
- All queries use PDO prepared statements
- No string concatenation in SQL
- Proper parameter binding throughout

### 2. XSS Prevention ✅
- Consistent use of `escape_output()` (htmlspecialchars with ENT_QUOTES)
- Context-aware escaping for HTML attributes and JavaScript
- Input sanitization with `clean_input()` and field-specific sanitizers

### 3. CSRF Protection ✅
- Token-based CSRF with HMAC validation
- Token pooling for multi-tab support
- Origin/Referer header validation
- Single-use token consumption
- AJAX and form endpoints properly protected

### 4. Session Security ✅
- Session fingerprinting (IP + User-Agent binding)
- Automatic session regeneration
- Inactivity and absolute timeouts
- Secure cookie attributes (HttpOnly, Secure, SameSite=Strict)
- Proper session destruction on logout

### 5. Password Security ✅
- bcrypt with cost factor 10
- SHA-384 pre-hashing for full password entropy
- Password strength requirements
- Dummy hash for timing-safe user enumeration prevention
- Session invalidation on password change

### 6. Rate Limiting ✅
- Login attempts: 20 attempts, 30-minute lockout
- Registration: 5 attempts, 15-minute lockout
- Password changes: 5 attempts, 15-minute lockout
- Search: 30 attempts per minute per user
- All backed by database-level atomic operations

### 7. File Upload Security ✅
- MIME type validation
- File extension validation
- Dimension checks (decompression bomb prevention)
- GD reprocessing to strip polyglots
- Storage outside web root
- Served through gatekeeper script

### 8. Race Condition Prevention ✅
- Deadlock prevention with consistent lock ordering
- FOR UPDATE row locking
- Transaction-based balance updates
- Nonce-based transfer protection
- Page-load ID for back-button protection

### 9. Docker Hardening ✅
- Read-only container filesystem
- tmpfs for writable directories
- Resource limits (CPU, memory)
- Non-root user execution
- Security options (no-new-privileges)
- Internal network for database

### 10. Security Headers ✅
- Content-Security-Policy with nonces
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Strict-Transport-Security
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-* headers

---

## Prioritized Hardening Checklist

### Immediate (This Week)

- [ ] **H1:** Remove or secure diagnostic endpoint
  - Set `APP_DIAGNOSTIC_MODE=0` in production
  - Add authentication check
  - Consider removing from production deployment

- [ ] **H2:** Add rate limiting to CSP report endpoint
  - Implement IP-based rate limiting
  - Add report origin validation

- [ ] **M1:** Disable self-signed certificate generation in production
  - Set `GENERATE_SELF_SIGNED_TLS=0`
  - Provision proper TLS certificates

### Short-Term (This Month)

- [ ] **M2:** Sanitize detailed error messages in logs
- [ ] **M3:** Create security.txt file
- [ ] **M4:** Implement session secret rotation strategy
- [ ] **L2:** Audit Discord webhook URL exposure
- [ ] Review and update all environment variable defaults

### Medium-Term (This Quarter)

- [ ] **L3:** Add rate limiting to image serving
- [ ] Implement automated security scanning in CI/CD
- [ ] Set up regular penetration testing
- [ ] Create incident response procedures
- [ ] Document security architecture for team

---

## Quick Wins for Immediate Remediation

These changes can be made in under 1 hour each:

### 1. Disable Diagnostic Mode (5 minutes)
```bash
# In docker/.env
APP_DIAGNOSTIC_MODE=0
```

### 2. Add Rate Limit to CSP Reports (15 minutes)
Add to `/public/csp-report.php`:
```php
// After getting client IP
$rateLimitKey = 'csp_report:' . get_client_ip();
// Check login_attempts or create simple file-based counter
```

### 3. Create security.txt (10 minutes)
Create `/.well-known/security.txt` with contact information.

### 4. Remove Self-Signed Cert Generation (5 minutes)
```bash
# In docker/.env
GENERATE_SELF_SIGNED_TLS=0
```

### 5. Add Production Environment Check (15 minutes)
In all debug/diagnostic files:
```php
if (getenv('APP_ENV') === 'production') {
    http_response_code(404);
    exit;
}
```

---

## Appendix: Files Reviewed

### Configuration Files
- `/config/db.php` - Database connection
- `/config/session.php` - Session configuration

### Include Files
- `/includes/auth.php` - Authentication logic
- `/includes/csrf.php` - CSRF protection
- `/includes/sanitize.php` - Input sanitization
- `/includes/logger.php` - Activity logging
- `/includes/header.php` - Security headers
- `/includes/request.php` - Request handling
- `/includes/ip_firewall.php` - IP blocking
- `/includes/ai_traps.php` - Anti-AI traps
- `/includes/discord_webhook.php` - Discord alerts
- `/includes/process_payment.php` - Payment processing
- `/includes/profile_update_logic.php` - Profile updates
- `/includes/profile_view_logic.php` - Profile viewing
- `/includes/change_password_logic.php` - Password changes

### Public Files
- `/public/login.php`
- `/public/register.php`
- `/public/index.php`
- `/public/profile.php`
- `/public/view_profile.php`
- `/public/payment_page.php`
- `/public/transaction_history.php`
- `/public/transaction_result.php`
- `/public/logout.php`
- `/public/confirm_logout.php`
- `/public/change_password.php`
- `/public/searchbox.php`
- `/public/serve_image.php`
- `/public/csp-report.php`

### Docker Files
- `/docker/Dockerfile`
- `/docker/docker-compose.yml`
- `/docker/apache/000-default.conf`
- `/docker/apache/default-ssl.conf`

### Database
- `/database/init.sql`

### Security Files
- `/includes/.htaccess`
- `/public/.htaccess`
- `/storage/uploads/.htaccess`

---

## Conclusion

The TransactiWar application demonstrates a **strong security foundation** with comprehensive protections against OWASP Top 10 vulnerabilities. The development team has implemented industry-standard security controls including:

- Parameterized queries (SQL injection prevention)
- Output encoding (XSS prevention)
- CSRF tokens with HMAC validation
- Secure session management
- Rate limiting across all sensitive endpoints
- Secure file upload handling
- Race condition prevention in financial transactions

The remaining issues are primarily **operational hardening** items rather than fundamental security flaws. Addressing the HIGH severity findings (diagnostic endpoint exposure and CSP report rate limiting) should be prioritized before production deployment.

**Overall Risk Assessment:** LOW-MEDIUM
**Recommendation:** Address HIGH severity items before production deployment. MEDIUM and LOW items can be addressed in regular development cycles.

---

*This audit was conducted through static code analysis. A comprehensive security assessment should include dynamic testing, penetration testing, and third-party security review before production deployment.*
