# Security Hardening Review & War-Game Preparation Plan

## Objective
Perform a comprehensive security hardening review of the Transactiwar PHP + MySQL application. The goal is to identify vulnerabilities and weak security practices and provide concrete, actionable fixes without introducing external frameworks or breaking existing functionality.

---

## 🚨 Prioritized Hardening Checklist

### 1. CRITICAL: Application Denial of Service (DoS) via Thread Exhaustion
- **Severity:** CRITICAL
- **File/Location:** `includes/auth.php` (functions `login_user` and `change_password_for_user`)
- **Attack Scenario:** The authentication rate-limiting logic relies on `usleep(...)` to throttle brute-force attempts. Because PHP (via Apache mod_php or PHP-FPM) uses a fixed pool of worker processes, an attacker can intentionally trigger the lockout and keep multiple connection requests open. By sending a concurrent burst of requests to locked endpoints, the attacker will force all PHP workers to sleep simultaneously, causing a complete Denial of Service for the entire application.
- **Exact Fix:** Remove all `usleep(...)` calls. Rate limiting should immediately reject the request without blocking the thread.
  - In `includes/auth.php`, delete `usleep(...)` statements in both the `login_user` and `change_password_for_user` functions.
  - Modify the logic to immediately return `'locked'` (yielding an HTTP 429 or generic error) when the attempt count crosses the rate limit threshold.

### 2. HIGH: Rate Limiting Bypass / DoS via Trusted Proxy IP Mishandling
- **Severity:** HIGH
- **File/Location:** `includes/request.php` (function `get_request_client_ip()`)
- **Attack Scenario:** The `get_request_client_ip()` function explicitly returns `$_SERVER['REMOTE_ADDR']` and completely ignores `HTTP_X_FORWARDED_FOR`. If the application is deployed behind a reverse proxy or load balancer (e.g., Docker ingress, Nginx, Cloudflare), all incoming traffic will appear to originate from the proxy's IP. If a single user triggers the brute-force lockout threshold, the proxy's IP gets blacklisted in the `login_attempts` table, inadvertently blocking *all legitimate users* from logging in.
- **Exact Fix:** Modify `get_request_client_ip()` to conditionally extract the real IP if the request originates from a trusted proxy.
  ```php
  function get_request_client_ip(): string
  {
      if (is_request_from_trusted_proxy() && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
          $forwarded = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
          $ip = trim(end($forwarded));
          if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
              return $ip;
          }
      }
      $remoteAddr = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
      if (filter_var($remoteAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
          return $remoteAddr;
      }
      return '0.0.0.0';
  }
  ```

### 3. HIGH: Docker Misconfiguration (Container running as Root)
- **Severity:** HIGH
- **File/Location:** `docker/Dockerfile`
- **Attack Scenario:** The `php:8.2-apache` image runs the main Apache process and the container context as the `root` user. Although Apache worker threads drop privileges to `www-data` during request handling, any severe vulnerability resulting in Remote Code Execution (RCE) or misconfiguration could be leveraged to execute commands as `root` inside the container. This makes a container escape to the host system significantly easier.
- **Exact Fix:** Ensure the container runs entirely as a non-root user. Because binding to ports below 1024 requires root privileges, change the Apache ports to 8080/8443, adjust the Docker configuration, and drop privileges in the Dockerfile.
  - In `docker/Dockerfile`: Add `USER www-data` immediately before the `ENTRYPOINT` instruction.
  - In `docker/apache/000-default.conf` and `docker/apache/default-ssl.conf`: Update `<VirtualHost *:80>` to `<VirtualHost *:8080>` and `<VirtualHost *:443>` to `<VirtualHost *:8443>`. You must also update `ports.conf` inside the image to `Listen 8080` and `Listen 8443`.
  - In `docker/docker-compose.yml`: Update ports mapping to `- "${APP_BIND:-0.0.0.0}:80:8080"` and `- "${APP_BIND:-0.0.0.0}:443:8443"`.

### 4. MEDIUM: Web Cache Poisoning / Open Redirect via Host Header Injection
- **Severity:** MEDIUM
- **File/Location:** `includes/request.php` (function `enforce_https()`)
- **Attack Scenario:** The `enforce_https()` function builds a 301 redirect URL using `get_request_host()`, which reflects the user-supplied `HTTP_HOST` header. It then executes `exit;` immediately without setting `Cache-Control` headers. An attacker can send an HTTP request with `Host: attacker.com`, and the server will reply with a `301 Redirect` to `https://attacker.com/`. If a CDN or caching proxy is in front of the application, it might cache this response, automatically redirecting subsequent legitimate HTTP visitors to the attacker's domain.
- **Exact Fix:** Add `Cache-Control` headers before the redirect exits to mitigate caching of poisoned host headers.
  ```php
  function enforce_https(): void
  {
      if (!should_enforce_https() || is_secure_request()) {
          return;
      }
      $url = 'https://' . get_https_redirect_host() . ($_SERVER['REQUEST_URI'] ?? '/');
      $url = preg_replace('/[\r\n]/', '', $url ?? '');

      header('HTTP/1.1 301 Moved Permanently');
      header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0'); // Explicit cache prevention
      header('Location: ' . $url);
      exit;
  }
  ```

### 5. MEDIUM: Lack of Maximum Length Constraint on Login Password
- **Severity:** MEDIUM
- **File/Location:** `public/login.php`
- **Attack Scenario:** In `public/login.php`, the raw `$_POST['password']` is accepted without a maximum length constraint and passed directly to authentication functions. While `password_verify()` naturally mitigates CPU DoS by silently truncating bcrypt inputs to 72 bytes, allocating extremely large strings in memory for every login attempt can be weaponized by an attacker to cause an application-level Denial of Service via memory exhaustion (`Allowed memory size of X bytes exhausted`).
- **Exact Fix:** Enforce a maximum length validation on the password input in `login.php` prior to any string processing or DB lookups.
  ```php
  $password = (string) ($_POST['password'] ?? '');
  if (strlen($password) > 1024) { // Reject absurdly large payloads immediately
      $_SESSION['flash_error'] = 'Invalid credentials.';
      logActivity(LOG_INVALID_INPUT);
      header('Location: /login.php');
      exit;
  }
  ```

### 6. LOW: Security Header Conflict (Broken Functionality & Unsafe Inline)
- **Severity:** LOW (Primarily functional, but weakens CSS security)
- **File/Location:** `public/.htaccess` and `includes/header.php`
- **Attack Scenario:** The PHP layer (`includes/header.php`) dynamically generates a strict, nonce-based Content-Security-Policy (CSP) header. However, `public/.htaccess` *also* statically injects a secondary CSP header (`script-src 'self'; style-src 'self' 'unsafe-inline';`). Browsers combine multiple CSPs using strict intersection logic. Because the `.htaccess` CSP lacks the nonce and `strict-dynamic`, all valid inline scripts (such as the transfer confirmation modal in `payment_page.php`) will be blocked by the browser. Additionally, it needlessly allows `'unsafe-inline'` for styles.
- **Exact Fix:** Remove the static `Header always set Content-Security-Policy ...` directive entirely from `public/.htaccess` and rely exclusively on the dynamically generated CSP from the PHP application logic.

### 7. LOW: Weak Practice - PDO Statement Emulation Enabled
- **Severity:** LOW
- **File/Location:** `config/db.php`
- **Attack Scenario:** The PDO `ATTR_EMULATE_PREPARES` attribute is not explicitly disabled. By default in many environments, PDO emulates prepared statements for MySQL, simulating parameter binding rather than using native MySQL prepared statements at the server level. While the `charset=utf8mb4` DSN configuration mitigates classical character-encoding bypasses, leaving emulation enabled technically allows multiple statements to be executed in a single query (e.g., `value; DROP TABLE users;`) if a secondary flaw is ever discovered.
- **Exact Fix:** Explicitly disable statement emulation to ensure true, native prepared statements are strictly utilized.
  ```php
  $options = [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
      PDO::ATTR_EMULATE_PREPARES => false, // Ensure native prepares are used
  ];
  ```

---

## 🛡️ Summary of Validated Defenses (No Action Needed)
During the review, several critical security features were closely analyzed and confirmed to be securely implemented. These areas require no changes and demonstrate strong defensive postures:
- **Race Conditions in Transfers:** Fully mitigated. The logic in `includes/process_payment.php` correctly enforces ordered ID-locking (`SELECT ... FOR UPDATE` starting with the lowest ID) inside the database transaction. This guarantees deadlock-free execution and absolutely prevents concurrent TOCTOU double-spend exploits.
- **File Uploads:** Highly secure. `includes/profile_update_logic.php` successfully checks MIME types using `finfo`, enforces out-of-webroot storage (`../storage/uploads/`), effectively sanitizes filenames (`sanitize_filename()`), and crucially relies on GD Library regeneration (`imagejpeg`, etc.) to strip entirely embedded payloads.
- **Cross-Site Scripting (XSS):** Handled uniformly and robustly via strict HTML entity encoding (`escape_output()`) and DOM injection guards throughout rendering scripts.
- **Cross-Site Request Forgery (CSRF):** Successfully guarded via strict constant-time HMAC token comparisons and HTTP Origin/Referer checks in `includes/csrf.php`.
- **Insecure Direct Object Reference (IDOR):** All sensitive queries and updates strictly leverage the active session's `user_id`, enforcing proper ownership and preventing parameter manipulation attacks.