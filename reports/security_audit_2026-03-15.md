# TransactiWar Security Audit (War-Game Hardening)

**Date:** 2026-03-15  
**Application:** PHP 8.2 + MySQL 8.4 + Apache + Docker  
**Method:** Full repository review (read-only, no code changes)  
**Scope:** `public/`, `includes/`, `config/`, `database/`, `docker/`, `scripts/`, and security-relevant repository artifacts

---

## Executive Summary

The application already has strong baseline security controls (prepared statements, CSRF token pool, strict session controls, nonce-based CSP, transfer row-locking, and hardened upload pipeline). I found **no confirmed active SQL injection, XSS, CSRF bypass, IDOR, or transfer double-spend race** in current runtime flows.

Main remaining risk is **hardening drift**: proxy/IP handling, operational artifacts, and Apache config choices that become exploitable under common deployment mistakes.

### Finding Count

- **CRITICAL:** 0
- **HIGH:** 3
- **MEDIUM:** 4
- **LOW:** 3

---

## Coverage Matrix (Requested Classes)

| Area | Verdict |
|---|---|
| SQL Injection | No confirmed exploitable SQLi in reviewed runtime paths |
| XSS | No confirmed exploitable stored/reflected XSS in reviewed templates/flows |
| CSRF | Core protection is robust; no direct bypass confirmed |
| IDOR | No confirmed direct IDOR in profile/transfer paths |
| Session issues | Core controls are strong; proxy/IP edge cases remain |
| Money transfer race | Current transfer locking appears robust |
| File upload security | Strong controls in place; no direct bypass confirmed |
| Input validation | Mostly strong; some boundary hardening gaps remain |
| Cookies/headers | Strong baseline; host/proxy redirect behavior needs tightening |
| Docker misconfig | Container hardening is good overall; Apache override policy can be tighter |

---

## Findings by Severity

## HIGH

### H1 — Rate-limit identity collapse behind reverse proxy

- **Severity:** HIGH
- **File/Location:** `includes/request.php:44-52`, `includes/request.php:34-42`, `includes/auth.php:729-731`
- **Attack Scenario:**  
  `get_request_client_ip()` always returns `REMOTE_ADDR` and ignores `X-Forwarded-For`, even though trusted-proxy logic exists. Behind nginx/HAProxy, all users can appear as the proxy IP. A single attacker can trigger lockouts that affect all users or distort brute-force controls in shared-proxy deployments.
- **Exact Fix:**  
  In `get_request_client_ip()`, when `is_request_from_trusted_proxy()` is true, parse `HTTP_X_FORWARDED_FOR` and return the first valid non-trusted IP; otherwise keep `REMOTE_ADDR` fallback. Keep strict IP validation and default to `0.0.0.0` on invalid input.
- **Confidence:** High

---

### H2 — Executable PHP payload tracked in repository artifacts

- **Severity:** HIGH (environment-dependent)
- **File/Location:** `reports/pentest/2026-03-05/runtime/payload.php:1`
- **Attack Scenario:**  
  If deployment regresses to serving repo directories (or `reports/` is accidentally exposed), this file becomes executable and can be used as a ready-made webshell foothold marker.
- **Exact Fix:**  
  Replace executable artifact with non-executable evidence file (`payload.txt`), and add a rule preventing `reports/**/runtime/*.php` from being committed. Defense-in-depth: deny execution for non-public directories in web server config.
- **Confidence:** High

---

### H3 — Debug diagnostic endpoint can leak internal schema metadata

- **Severity:** HIGH (environment-dependent)
- **File/Location:** `scripts/debug/diagnostic.php:24-27`, `scripts/debug/diagnostic.php:37-43`
- **Attack Scenario:**  
  If this script is ever routed through HTTP and `APP_DIAGNOSTIC_MODE=1`, unauthenticated callers can enumerate table names and backend connectivity, improving recon for subsequent attacks.
- **Exact Fix:**  
  Force CLI-only execution (`PHP_SAPI === 'cli'`), keep `APP_DIAGNOSTIC_MODE=0` outside local debug, and keep `scripts/` outside any web-served path.
- **Confidence:** High

---

## MEDIUM

### M1 — Password-change throttling is non-atomic (TOCTOU window)

- **Severity:** MEDIUM
- **File/Location:** `includes/auth.php:301-317`, `includes/auth.php:319-341`, `includes/change_password_logic.php:44-47`, `includes/auth.php:552-563`
- **Attack Scenario:**  
  Lock checks and failed-attempt increments for password changes occur in separate operations. Concurrent attempts can pass checks before counters update, allowing more guesses than intended within a short window.
- **Exact Fix:**  
  Refactor password-change gate to mirror `gate_login_attempt()` style: single transaction with `SELECT ... FOR UPDATE`, check lock/backoff, and pre-increment atomically.
- **Confidence:** Medium

---

### M2 — Host-derived HTTPS redirect target

- **Severity:** MEDIUM (deployment-dependent)
- **File/Location:** `docker/apache/000-default.conf:6`, `includes/request.php:147-152`, `includes/request.php:81-87`
- **Attack Scenario:**  
  Redirect target includes host header-derived value. In permissive proxy/CDN setups, this can enable open redirect chains or cache-poisoned redirect behavior.
- **Exact Fix:**  
  Redirect only to a canonical configured host (allowlist/env var), not directly from `HTTP_HOST`. Keep CRLF stripping and reject unknown hosts.
- **Confidence:** Medium

---

### M3 — Apache override policy still allows high-risk options

- **Severity:** MEDIUM
- **File/Location:** `docker/apache/default-ssl.conf:22`
- **Attack Scenario:**  
  `AllowOverride ... Options=ExecCGI,Indexes` broadens impact if any future write primitive hits web root. Attackers can leverage `.htaccess` overrides for code execution or content exposure.
- **Exact Fix:**  
  Reduce to least privilege (`AllowOverride None` or only specific non-dangerous categories strictly required by app behavior).
- **Confidence:** Medium

---

### M4 — Native prepared statements not explicitly enforced

- **Severity:** MEDIUM (hardening best practice)
- **File/Location:** `config/db.php:26-31`
- **Attack Scenario:**  
  PDO emulate-prepares behavior can vary by environment/driver defaults. While current queries are parameterized, not explicitly disabling emulation weakens assurance and can reintroduce edge-case parser risks.
- **Exact Fix:**  
  Add `PDO::ATTR_EMULATE_PREPARES => false` to PDO options in `config/db.php`.
- **Confidence:** Medium

---

## LOW

### L1 — Unbounded login password input size

- **Severity:** LOW
- **File/Location:** `public/login.php:39`, `public/login.php:42-50`, `public/login.php:116-118`
- **Attack Scenario:**  
  Oversized password payloads can force unnecessary memory/CPU work before auth rejection, enabling low-grade application resource pressure.
- **Exact Fix:**  
  Add a conservative server-side max length check on `$password` before authentication logic (and mirror with `maxlength` in form input for UX).
- **Confidence:** Medium

---

### L2 — Legacy Apache deny syntax in `includes/.htaccess`

- **Severity:** LOW (compatibility hardening)
- **File/Location:** `includes/.htaccess:1`
- **Attack Scenario:**  
  `Deny from all` is legacy syntax and can be brittle depending on Apache module/config compatibility. Misinterpretation may weaken expected protection if directory exposure regresses.
- **Exact Fix:**  
  Use Apache 2.4-native directive: `Require all denied` (optionally keep legacy directive for compatibility if needed).
- **Confidence:** Medium

---

### L3 — Sensitive local material stored under repository path

- **Severity:** LOW (operational)
- **File/Location:** `docker/.env`, `docker/certs/server.key`, `transactiwar-vm_key.pem` (present in working tree; not all tracked)
- **Attack Scenario:**  
  Even if gitignored, secrets/keys under repo paths are at higher risk of accidental copy/archive/exfiltration.
- **Exact Fix:**  
  Store secrets outside repository tree, enforce strict file permissions, and rotate any reused credentials/keys if shared beyond local dev.
- **Confidence:** Medium

---

## Already Hardened (Preserve These)

- Prepared statements and parameterized SQL across core runtime paths.
- CSRF token pool with HMAC binding and origin/referrer/fetch-site checks (`includes/csrf.php`).
- Session hardening with strict mode, `HttpOnly`, `SameSite=Strict`, periodic regeneration, fingerprint binding (`config/session.php`).
- Transfer race/deadlock mitigation using transaction + deterministic ordered row locks (`includes/process_payment.php`).
- File upload controls: MIME/dimension checks, re-encoding, randomized filenames, out-of-webroot storage (`includes/profile_update_logic.php`, `public/serve_image.php`).
- Strong response headers and CSP nonce model (`includes/header.php`).
- Container hardening including read-only root FS, dropped privileges, internal DB network, and narrowed bind mounts (`docker/docker-compose.yml`, `docker/Dockerfile`, `docker/apache/entrypoint.sh`).

---

## Prioritized Hardening Checklist

## CRITICAL

- No confirmed CRITICAL findings in current reviewed runtime paths.

## HIGH

- [ ] Fix trusted-proxy client IP extraction for rate-limiting/auth controls (`includes/request.php`).
- [ ] Remove/neutralize executable pentest artifact (`reports/pentest/.../payload.php`) and block future `.php` runtime artifacts.
- [ ] Restrict diagnostics to CLI/local-only (`scripts/debug/diagnostic.php`) and enforce non-public routing boundaries.

## MEDIUM

- [ ] Make password-change throttling atomic using transactional lock/check/increment.
- [ ] Replace host-header-derived redirect targets with canonical host allowlisting.
- [ ] Tighten Apache `AllowOverride` scope; remove `ExecCGI/Indexes` overrides unless strictly required.
- [ ] Explicitly disable PDO emulated prepares in `config/db.php`.

## LOW

- [ ] Add login password length caps (server-side + HTML `maxlength`).
- [ ] Modernize `includes/.htaccess` to Apache 2.4-native deny directive.
- [ ] Move secrets/keys out of repository path and maintain rotation/permissions hygiene.

