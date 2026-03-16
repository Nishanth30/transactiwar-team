# TransactiWar Consolidated Vulnerability Register

This file merges findings from multiple security audits and assigns
**unique vulnerability IDs**.

------------------------------------------------------------------------

# Summary

  Severity    Count
  ----------- --------
  CRITICAL    5
  HIGH        10
  MEDIUM      11
  LOW         4
  **TOTAL**   **30**

------------------------------------------------------------------------

# CRITICAL

## TXW-VULN-001 --- Production Secrets Committed to Repository

Secrets such as MySQL passwords and SESSION_SECRET stored in `.env`
committed to Git.

## TXW-VULN-002 --- Seed Account Password Hashes in Source

Pre-computed bcrypt hashes for seed accounts committed in setup scripts.

## TXW-VULN-003 --- Diagnostic Endpoint Exposes DB Structure

`/scripts/debug/diagnostic.php` reveals database tables when diagnostic
mode is enabled.

## TXW-VULN-004 --- Pentest Payload PHP File in Repository

`reports/.../payload.php` executable artifact may enable RCE if
directory becomes exposed.

## TXW-VULN-005 --- Database Credentials Fail Open

Application falls back to `root` user with empty password if environment
variables are missing.

------------------------------------------------------------------------

# HIGH

## TXW-VULN-006 --- Login Lockout Bypass via Truthy Return

`login_user()` returns `'locked'` which login handler treats as success.

## TXW-VULN-007 --- Session Fingerprint Crash

Undefined `$now` variable breaks session hijack detection.

## TXW-VULN-008 --- display_errors Enabled on Login Page

Stack traces and file paths leak to attackers.

## TXW-VULN-009 --- Missing Security Headers on Several Pages

CSP/HSTS/X‑Frame‑Options inconsistently applied.

## TXW-VULN-010 --- Login Rate Limit Race Condition

Lock check and increment occur outside a transaction.

## TXW-VULN-011 --- Thread Exhaustion DoS via sleep/usleep

Authentication throttling blocks worker threads.

## TXW-VULN-012 --- Trusted Proxy IP Mishandling

`X‑Forwarded‑For` ignored even with trusted proxy configuration.

## TXW-VULN-013 --- CSRF Token Leakage in GET URLs

Tokens appear in query strings and server logs.

## TXW-VULN-014 --- Docker Container Runs as Root

Container never drops privileges.

## TXW-VULN-015 --- Runtime Image CVEs

Critical/high vulnerabilities in container images.

------------------------------------------------------------------------

# MEDIUM

## TXW-VULN-016 --- Logout CSRF

Logout endpoint accepts GET without CSRF token.

## TXW-VULN-017 --- Duplicate Login Attempt Counters

Two different functions increment failed login counters.

## TXW-VULN-018 --- Host Header Redirect Poisoning

HTTPS redirect uses user-supplied Host header.

## TXW-VULN-019 --- Password Change Throttle Race

Lock checks and increments are not atomic.

## TXW-VULN-020 --- PDO Emulated Prepared Statements Enabled

Prepared statement emulation not explicitly disabled.

## TXW-VULN-021 --- Content-Disposition Filename Injection Risk

Filename used directly in header construction.

## TXW-VULN-022 --- die() Bypasses Security Headers

Error paths skip header pipeline.

## TXW-VULN-023 --- Docker Bind Address Exposes All Interfaces

Application binds to `0.0.0.0` by default.

## TXW-VULN-024 --- Transaction IDs Leak Business Intelligence

Sequential IDs reveal transaction volume.

## TXW-VULN-025 --- Fragile nl2br() Escaping Pattern

Template escaping pattern could introduce future XSS.

## TXW-VULN-026 --- No Maximum Transfer Amount

Extremely large transfers could cause overflow or DoS.

------------------------------------------------------------------------

# LOW

## TXW-VULN-027 --- Unbounded Login Password Length

Very large payloads could cause memory exhaustion.

## TXW-VULN-028 --- Apache AllowOverride Too Permissive

ExecCGI and Indexes allowed via .htaccess.

## TXW-VULN-029 --- CSRF Origin Validation Not Strictly Configured

Origin validation relies on fallback logic.

## TXW-VULN-030 --- Account Enumeration via Registration Message

Duplicate registration message reveals existing users.
