# TransactiWar Security Audit (War-Game Hardening)

**Date:** 2026-03-17  
**Reviewer:** Security Engineer Agent (`engineering-security-engineer`)  
**Scope:** Full repository (`PHP + MySQL + Docker`)  
**Mode:** Read-only audit (no code changes)

---

## Executive Summary

The application has a solid baseline against common web attacks (prepared statements, CSRF checks, output escaping, session controls, and transactional transfer locking).  

Primary risk is operational hardening: **secrets/keys in repository files**, **host-header redirect trust**, and a **tracked executable payload artifact**. These are high-value targets for a security war-game and should be remediated first.

---

## Findings

### SEC-001 — Secrets and Private Keys Present in Repository Workspace

- **Severity:** **CRITICAL**
- **CWE:** CWE-798, CWE-522
- **Location:**
  - `transactiwar-vm_key.pem:1`
  - `docker/certs/server.key:1`
  - `docker/.env:1-10`
- **Evidence:**
  - Private key headers present (`BEGIN RSA PRIVATE KEY`, `BEGIN PRIVATE KEY`)
  - `.env` contains real secrets (`MYSQL_ROOT_PASSWORD`, `MYSQL_PASSWORD`, `SESSION_SECRET`)
- **Attack scenario:**
  - Any repository leak (backup exposure, accidental publish, compromised workstation/CI artifact) yields infra and DB credentials; attacker can impersonate infra users and target session integrity.
- **Exact fix:**
  1. Rotate all exposed credentials and keys immediately (SSH keys, DB passwords, `SESSION_SECRET`).
  2. Remove secrets from tracking and purge from git history where applicable.
  3. Keep only templates (`.env.example`) with placeholders.
  4. Enforce secret scanning in pre-commit/CI to block future commits of `*.pem`, `*.key`, real `.env`.
- **Residual risk after fix:** Low (process/governance dependent).

---

### SEC-002 — Host Header Trust in HTTPS Redirect Path

- **Severity:** **HIGH**
- **CWE:** CWE-601, CWE-20
- **Location:**
  - `includes/request.php:83` (`HTTP_HOST` trust)
  - `includes/request.php:147` (redirect built from derived host)
  - `docker/apache/000-default.conf:6` (`https://%{HTTP_HOST}%{REQUEST_URI}`)
- **Attack scenario:**
  - Attacker sends crafted `Host` header and receives redirect to attacker-controlled domain, enabling phishing/open-redirect style abuse and downstream cache poisoning patterns.
- **Exact fix:**
  1. Add a strict hostname allowlist (`APP_ALLOWED_HOSTS`) and reject non-allowed hosts with `400`.
  2. Use canonical host in redirects (not raw `%{HTTP_HOST}`).
  3. Enable canonical host behavior in Apache and pin redirect target to trusted hostname.
- **Residual risk after fix:** Low.

---

### SEC-003 — Executable Pentest Payload Tracked in Repository

- **Severity:** **HIGH**
- **CWE:** CWE-94
- **Location:** `reports/pentest/2026-03-05/runtime/payload.php:1`
- **Evidence:** File content is executable PHP (`<?php echo "owned"; ?>`)
- **Attack scenario:**
  - If deployment/mount rules drift and this path becomes web-served, the file becomes executable and validates code execution in non-runtime paths; can become a foothold for malicious payload substitution.
- **Exact fix:**
  1. Remove executable payload files from repository reporting directories.
  2. Add CI policy to fail if executable code appears under `reports/` or other non-runtime artifact paths.
  3. Keep offensive testing payloads in separate isolated storage/repo.
- **Residual risk after fix:** Low.

---

### SEC-004 — Runtime DDL in Request Path (Privilege Expansion Risk)

- **Severity:** **MEDIUM**
- **CWE:** CWE-250
- **Location:** `includes/auth.php:88-138`
- **Evidence:** `ensure_session_version_support()` can execute:
  - `ALTER TABLE users ADD COLUMN session_version ...`
- **Attack scenario:**
  - Web app DB user requires DDL rights in normal runtime. If application layer is compromised, elevated DB privileges increase blast radius (schema tampering/destructive actions).
- **Exact fix:**
  1. Remove schema mutation from request path.
  2. Perform schema evolution only during setup/migration stage.
  3. Restrict app DB account to least privilege (DML only; no ALTER/CREATE/DROP).
- **Residual risk after fix:** Low–Medium (depends on DB role governance).

---

### SEC-005 — Container Exposure Defaults and Writable TLS Mount

- **Severity:** **MEDIUM**
- **CWE:** CWE-284, CWE-16
- **Location:** `docker/docker-compose.yml:94-95,125`
- **Evidence:**
  - Default bind fallback exposes `0.0.0.0` for 80/443.
  - Cert mount is writable by default (`./certs:/etc/apache2/ssl`), not `:ro`.
- **Attack scenario:**
  - Unintended broad network exposure in non-production environments.
  - Writable cert mounts allow post-compromise persistence/tampering with TLS materials.
- **Exact fix:**
  1. Default guidance and env to localhost bind (`127.0.0.1`) unless explicitly public.
  2. Mount certs read-only in production (`:ro`).
  3. Keep/extend container hardening (`no-new-privileges`, `cap_drop: [ALL]`, strict writable mounts only).
- **Residual risk after fix:** Low.

---

## Coverage Matrix (Requested Attack Classes)

| Category | Result | Notes |
|---|---|---|
| SQL injection | No exploitable path found | Core query paths use prepared statements and bound params. |
| XSS | No confirmed exploitable path found | Output escaping patterns are generally consistent in reviewed views. |
| CSRF | No confirmed exploitable path found | CSRF verification appears on state-changing endpoints. |
| IDOR | No confirmed exploitable path found | Authz checks in critical profile/payment flows reviewed. |
| Session issues | **Finding present** | Secret hygiene risk in `docker/.env` impacts session trust model (SEC-001). |
| Race conditions (money transfer) | No exploitable race found | Transfer flow uses transaction + deterministic lock ordering. |
| Insecure file uploads | No confirmed exploitable path found | Upload handling appears constrained and re-encoded in reviewed paths. |
| Improper input validation | **Finding present** | Host header canonicalization/redirect trust issue (SEC-002). |
| Insecure cookies | No critical flag misconfig found | Cookie/session flags appear hardened; secret exposure remains key risk. |
| Missing security headers | No high-impact omission found | Core header posture appears strong on main app routes. |
| Docker misconfigurations | **Findings present** | Exposure default + writable cert mount (SEC-005). |

---

## Prioritized Hardening Checklist

### CRITICAL

- [ ] Rotate leaked secrets/keys immediately (`SESSION_SECRET`, DB creds, SSH keypair, TLS key if reused).
- [ ] Remove sensitive files from tracking and purge historical exposure where needed.
- [ ] Enforce secret scanning gates in pre-commit and CI/CD.

### HIGH

- [ ] Replace host-header-derived redirects with canonical allowlisted host logic in Apache + PHP.
- [ ] Remove `reports/**/runtime/*.php` payload artifacts and block executable code under report/artifact paths in CI.

### MEDIUM

- [ ] Remove runtime schema mutation (`ALTER TABLE`) from request lifecycle.
- [ ] Reduce DB app user to least privilege (no DDL).
- [ ] Harden Docker defaults: loopback bind by default, read-only cert volume in production, maintain no-new-privileges and strict mounts.

### LOW

- [ ] Add periodic config drift checks for security headers, cookie flags, and container runtime hardening.
- [ ] Add repository policy checks for dangerous tracked file types (`*.pem`, `*.key`, real `.env`, executable artifacts in `reports/`).

---

## Notes for War-Game Readiness

1. Focus first on **secret rotation + host-header redirect hardening**; these provide the best attacker leverage reduction quickly.
2. Treat repository hygiene as part of attack surface, not just source control hygiene.
3. Re-run this audit after remediations and validate through targeted adversarial tests (host-header abuse, secret exposure simulation, deployment-path checks).
