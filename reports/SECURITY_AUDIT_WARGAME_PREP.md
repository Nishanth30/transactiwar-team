# Security Audit & Hardening Report
**Date:** March 18, 2026
**Target:** Transactiwar Team PHP + MySQL Web Application
**Purpose:** Security War-Game Preparation

## 1. Executive Summary
A comprehensive security review of the application was performed to identify vulnerabilities across SQL injection, XSS, CSRF, IDOR, session management, race conditions, file uploads, and infrastructure configurations. 

**Current Posture:** The application has already implemented an exceptionally strong baseline of security controls. Critical vulnerabilities like SQLi, traditional XSS, IDOR, race conditions, and session hijacking have been proactively mitigated through architectural defenses (e.g., PDO, CSP nonces, DB-backed rate limiting, UUIDs, atomic `FOR UPDATE` queries, and strict file upload bounds checking).

However, a few residual weak practices and edge-case vulnerabilities were identified that could be exploited during a dedicated security war-game. The prioritized checklist below details these findings and provides concrete remediation steps.

---

## 2. Vulnerability Findings & Hardening Recommendations

### [MEDIUM] Insecure Temporary File Storage for Rate Limiter
*   **Location:** `includes/discord_webhook.php` (Functions `_discordRateLimitOk` & `_discordRateLimitRecord`)
*   **Attack Scenario:** The Discord webhook rate limiter uses `sys_get_temp_dir() . '/transactiwar_discord_ratelimit.json'`. On many systems, this resolves to the world-writable `/tmp` directory. If an attacker gains limited local access (or if the container shares `/tmp` with other services), they can modify or delete this file, causing a Denial of Service (DoS) for security alerts, or potentially triggering PHP warnings if the file is replaced with a directory.
*   **Exact Fix:** Move the state file into the application's restricted storage directory.
    ```php
    // Change from:
    // $stateFile = sys_get_temp_dir() . '/transactiwar_discord_ratelimit.json';
    
    // To:
    $stateFile = __DIR__ . '/../storage/logs/discord_ratelimit.json';
    ```

### [LOW] Missing Strict-Transport-Security (HSTS) on Error Pages
*   **Location:** `includes/header.php` (Function `send_error_headers`)
*   **Attack Scenario:** When an error occurs and `send_error_headers(int $statusCode)` is called, it correctly clears disclosure headers and sets CSP/X-Frame-Options, but it *fails* to set the `Strict-Transport-Security` (HSTS) header. A Man-in-the-Middle (MitM) attacker could intercept error pages and attempt to strip TLS protections.
*   **Exact Fix:** Append the HSTS header block to the `send_error_headers` function.
    ```php
    function send_error_headers(int $statusCode): void {
        // ... existing code ...
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        if (is_secure_request()) {
            header('Strict-Transport-Security: max-age=' . HSTS_MAX_AGE . '; includeSubDomains; preload');
        }
    }
    ```

### [LOW] Incomplete Apache Server Header Masking
*   **Location:** `docker/Dockerfile` and `docker/apache/000-default.conf`
*   **Attack Scenario:** The Dockerfile uses `echo 'ServerTokens Prod';` and `echo 'ServerSignature Off';`. While this removes the OS and PHP version, Apache still broadcasts `Server: Apache` in the HTTP response headers. Attackers use this for automated reconnaissance.
*   **Exact Fix:** Use Apache's `mod_headers` to completely unset the Server header in the VirtualHost configuration or hardening script.
    ```apache
    # Add to docker/apache/000-default.conf or hardening.conf
    Header unset Server
    ```

### [LOW] Lax Proxy Validation Risk Downgrading Session Security
*   **Location:** `includes/request.php` (Function `is_secure_request`)
*   **Attack Scenario:** The session configuration (`config/session.php`) relies on `is_secure_request()` to set the `Secure` flag on cookies. If the app is behind a reverse proxy but `TRUSTED_PROXIES` is not explicitly set in the `.env` file, `is_secure_request()` might return `false` on HTTPS traffic terminated at the load balancer. This results in session cookies being issued *without* the Secure flag.
*   **Exact Fix:** Enforce a hard fail in production if reverse proxies are detected but `TRUSTED_PROXIES` is empty. 
    ```php
    // In includes/request.php get_trusted_proxy_ips()
    if ($raw === '') {
        if (isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
             error_log('WARNING: HTTP_X_FORWARDED_PROTO detected but TRUSTED_PROXIES is empty. TLS termination may be misconfigured.');
        }
        $cached = [];
        return $cached;
    }
    ```

---

## 3. Verified Security Controls (Do Not Modify)
During the audit, several highly secure patterns were verified. These should be maintained "as-is" for the war-game:

1.  **Race Condition Defense:** `includes/process_payment.php` correctly sorts database IDs (`if ($sender_id < $receiver_id)`) before acquiring `FOR UPDATE` locks. This perfectly prevents deadlocks and TOCTOU (Time-of-Check to Time-of-Use) attacks.
2.  **Anti-Enumeration:** `includes/auth.php` utilizes a constant-time `DUMMY_HASH` verification and `usleep()` randomization. This successfully defeats timing-based user enumeration.
3.  **Advanced CSRF Pool:** `includes/csrf.php` limits concurrent tokens and binds them via HMAC `$_SESSION['csrf_secret']`. This blocks cross-tab token invalidation and token-fixation.
4.  **File Upload Decompression Bomb Check:** `includes/profile_update_logic.php` runs `@getimagesize()` *before* doing any memory-intensive GD image manipulation, preventing CPU/RAM exhaustion DoS attacks.
5.  **Docker Hardening:** The `docker-compose.yml` mounts the application with `read_only: true` and restricted `tmpfs` volumes, drastically mitigating the impact of any potential RCE.

---

## 4. Prioritized Hardening Checklist for War-Game

- [ ] **CRITICAL:** (None identified; baseline is highly fortified)
- [ ] **HIGH:** (None identified; core vulnerabilities are thoroughly patched)
- [ ] **MEDIUM:** Relocate `transactiwar_discord_ratelimit.json` from `/tmp` to `storage/logs/`.
- [ ] **LOW:** Add HSTS header to `send_error_headers()`.
- [ ] **LOW:** Strip Apache `Server` header completely via `Header unset Server`.
- [ ] **LOW:** Validate `TRUSTED_PROXIES` enforcement to ensure `Secure` cookie flags are strictly applied.
- [ ] **INFO:** Ensure `APP_ENV=production` is set so debugging loops/headers are disabled.