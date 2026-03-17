# Security Audit & Hardening Report: Transactiwar

## Overview
A comprehensive security review of the Transactiwar PHP + MySQL application was performed. The application demonstrates a very strong baseline security posture, with robust mitigations already in place for SQL Injection (PDO prepared statements), Cross-Site Scripting (rigorous output encoding and CSP), Cross-Site Request Forgery (session-bound token pooling), and Race Conditions (deadlock-free `SELECT ... FOR UPDATE` locking).

However, several architectural misconfigurations and logic flaws remain that could be exploited during a war-game scenario, primarily leading to Denial of Service (DoS) and potential Remote Code Execution (RCE) via infrastructure misconfiguration.

---

## 🚨 Prioritized Hardening Checklist

### CRITICAL: Docker Misconfiguration (RCE Vector)
*   **Vulnerability**: Insecure Apache `AllowOverride` Configuration
*   **Location**: `docker/apache/default-ssl.conf`
*   **Scenario**: The Apache configuration explicitly permits `Options=ExecCGI` within the `AllowOverride` directive (`AllowOverride FileInfo AuthConfig Options=ExecCGI,Indexes`). If an attacker finds any path to upload an `.htaccess` file (even if uploaded as a seemingly harmless file type and renamed, or via a new bypass in the upload logic), they can enable CGI execution for image files or other extensions, leading to full Remote Code Execution (RCE).
*   **Exact Fix**:
    Modify the `AllowOverride` directive to remove `ExecCGI`.
    Change line 16 from:
    ```apache
    AllowOverride FileInfo AuthConfig Options=ExecCGI,Indexes
    ```
    To:
    ```apache
    AllowOverride FileInfo AuthConfig Options=Indexes
    ```

### HIGH: Improper IP Validation leading to Global Denial of Service (DoS)
*   **Vulnerability**: Proxy IP Trust Failure causing Rate-Limiting Collisions
*   **Location**: `includes/request.php` (in `get_request_client_ip()`)
*   **Scenario**: The application is designed to run behind a proxy (e.g., Docker ingress, Nginx) as indicated by `TRUSTED_PROXIES`. However, `get_request_client_ip()` strictly returns `$_SERVER['REMOTE_ADDR']`. Because all traffic routes through the proxy, `REMOTE_ADDR` will be the proxy's IP. All users will share the same IP address. If an attacker intentionally triggers the login or registration rate-limit (e.g., `MAX_LOGIN_FAILS`), **every user on the platform will be locked out**, resulting in a catastrophic global DoS.
*   **Exact Fix**:
    Update the IP resolution logic to trust the `X-Forwarded-For` header if the request originates from a trusted proxy.
    ```php
    function get_request_client_ip(): string
    {
        if (is_request_from_trusted_proxy() && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $realIp = trim($ips[0]);
            if (filter_var($realIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
                return $realIp;
            }
        }

        $remoteAddr = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        if (filter_var($remoteAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
            return $remoteAddr;
        }

        return '0.0.0.0';
    }
    ```

### MEDIUM: Database CPU Exhaustion (DoS)
*   **Vulnerability**: Uncapped Pagination Offsets
*   **Location**: `public/transaction_history.php`
*   **Scenario**: The transaction history page accepts a user-controlled `page` parameter to calculate the SQL `OFFSET`. An attacker can write a script to repeatedly request extremely high page numbers (e.g., `?page=999999999`). High-offset queries force MySQL to scan and discard millions of rows per request, rapidly exhausting database CPU and memory.
*   **Exact Fix**:
    Cap the maximum allowed page number or offset.
    Change line 23:
    ```php
    $rawPage = get_int('page');
    $page = ($rawPage !== null && $rawPage > 0) ? $rawPage : 1;
    // Add a hard cap to the page number
    if ($page > 1000) { $page = 1000; }
    $offset = ($page - 1) * $perPage;
    ```

### LOW: Docker Secrets Misconfiguration
*   **Vulnerability**: Credentials Exposed in Environment
*   **Location**: `docker/docker-compose.yml`
*   **Scenario**: The MySQL database credentials (`MYSQL_ROOT_PASSWORD`, `MYSQL_PASSWORD`) are passed as plaintext environment variables. Any user or process with access to the Docker daemon can view these credentials via `docker inspect`.
*   **Exact Fix**:
    Migrate from standard environment variables to Docker Secrets. Update `docker-compose.yml` to define secrets and use the `MYSQL_ROOT_PASSWORD_FILE` and `MYSQL_PASSWORD_FILE` environment variables.

---

## 🛡️ Summary of Verified Defenses (Do Not Alter)
During the audit, the following security controls were verified as **highly effective** and should remain untouched:
1.  **Race Conditions in Money Transfer**: Mitigated flawlessly in `includes/process_payment.php` using globally ordered `SELECT ... FOR UPDATE` row locking to prevent deadlocks and TOCTOU vulnerabilities.
2.  **Insecure File Uploads**: `includes/profile_update_logic.php` successfully validates the MIME type, enforces a size limit, uses `getimagesize()` *before* GD processing, and utilizes GD rendering functions (`imagepng`) to neuter PHP polyglot payloads.
3.  **SQL Injection**: 100% PDO prepared statements across the application.
4.  **XSS**: `escape_output()` correctly escapes HTML entities including quotes and null bytes. Strict Content-Security-Policy (CSP) with nounces prevents inline script execution.
5.  **CSRF**: A robust token pool restricts tab collisions, binds HMAC signatures to the session, and enforces strict origin checks.