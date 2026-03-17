# Reddit Posts — TransactiWar Bug Bounty Invitation

---

## Post 1: r/bugbounty

**Title:** Come break our banking war-game app — open invite for security testing (PHP/MySQL/Docker)

**Body:**

Hey r/bugbounty,

My team built a banking war-game web application as a university security project. We've done our own internal security review and hardening, and now we want real-world attackers to stress-test it before our final assessment.

**Target:** https://20.219.19.72 (self-signed TLS cert — you'll need to accept the warning)

**Stack:** PHP 8.2 / MySQL 8.4 / Apache / Docker on Ubuntu 24.04

**What it is:** A mock banking app where users register, transfer "money" to each other, upload profile images, search users, etc. Think of it as a CTF target but with a full production-style defense stack.

**Scope — everything on the target is fair game:**

- Authentication (login, registration, password change)
- Session management
- CSRF protections
- SQL injection / XSS / command injection
- File upload attacks
- Business logic (transfers, double-spend, race conditions)
- Path traversal
- Infrastructure (TLS config, headers, container escape if you can)

**Out of scope:**

- DoS / DDoS (it's a small VM, please don't kill it)
- Attacks against the hosting provider (Azure)
- Social engineering the team

**What we've already hardened:**

- Prepared statements everywhere
- HMAC-bound single-use CSRF tokens with origin validation
- Session fingerprinting (IP + UA), regeneration, proper destruction
- Image reprocessing via GD library (strips EXIF/polyglots)
- Transfer nonces + FOR UPDATE row locking (anti-double-spend)
- CSP with nonce-based strict-dynamic
- Read-only container filesystem, no-new-privileges
- Rate limiting on login, search, registration
- Fail2ban + UFW on the host

**Recognition:** Anyone who finds a valid vulnerability gets credited in our project report and a hall-of-fame section. Please DM me or comment with your findings — include reproduction steps and we'll acknowledge you.

**Rules of engagement:**

1. Don't destroy data — if you get DB access, please don't DROP tables
2. Don't attack other users' accounts for real harassment
3. Register your own test accounts freely
4. Share your methodology — we want to learn

This is a genuine learning exercise. We want to know what we missed.

---

## Post 2: r/netsec

**Title:** University banking war-game app open for community security review — full stack details inside

**Body:**

We're a university team that built a banking war-game web application (PHP 8.2, MySQL 8.4, Apache, Docker) and spent several weeks hardening it against OWASP Top 10 attacks. We'd like the community to validate our work.

**Target:** https://20.219.19.72

**Architecture overview:**

- Apache serves from `public/` only — includes/config directories are outside the web root
- Images stored in `storage/uploads/` (outside web root), served through a PHP proxy with realpath validation
- Session: HMAC-SHA256 fingerprint (IP + UA), 30-min inactivity timeout, 1-hour absolute timeout, 5-min regeneration
- CSRF: HMAC-bound tokens, single-use with pool for multi-tab support, origin validation
- Transfers: Database transactions with ordered FOR UPDATE locks (deadlock-safe), transfer nonces bound to target UUID
- Container: read-only rootfs, no-new-privileges, tmpfs scratch, resource limits, separate Docker networks
- File uploads: MIME whitelist, GD reprocessing, dimension limits (anti-decompression-bomb)

**What we're specifically interested in:**

- Anything we missed in our CSRF implementation
- Session management edge cases
- Business logic flaws in the transfer system (we think the FOR UPDATE locking is solid but would love someone to try)
- File upload bypasses (we reprocess with GD but maybe there's a way through)
- Any infrastructure misconfiguration we haven't caught

**Not in scope:** DoS, attacks on Azure infrastructure, social engineering.

We'll credit anyone who finds valid issues. This is an open, good-faith security review for educational purposes.

---

## Post 3: r/websecurity

**Title:** Open security challenge — PHP banking app hardened against OWASP Top 10, come find what we missed

**Body:**

My team built and hardened a banking web application as a university project. We've gone through multiple rounds of internal security audits and believe we've addressed the OWASP Top 10 comprehensively. Now we want external validation.

**Target:** https://20.219.19.72 (self-signed cert)

**Stack:** PHP 8.2 / MySQL 8.4 / Apache 2.4 / Docker / Ubuntu 24.04

**Features to test:**

- User registration and login
- Money transfers between users
- Profile editing with avatar image upload
- User search
- Password change
- Transaction history

**Our defense summary:**

| Category | Implementation |
|----------|---------------|
| SQL Injection | Prepared statements (PDO) on every query |
| XSS | strip_tags + htmlspecialchars + nonce-based CSP |
| CSRF | HMAC-bound, single-use, origin-validated tokens |
| Session | IP+UA fingerprint, strict mode, HttpOnly+Secure+SameSite=Strict |
| File Upload | MIME whitelist, GD reprocess, dimension check, .htaccess blocks |
| Race Conditions | FOR UPDATE with ordered lock acquisition |
| Brute Force | Exponential backoff + hard lockout |
| Infrastructure | Read-only container, no-new-privileges, UFW, fail2ban |

**Rules:**

- Don't DoS the server
- Don't tamper with other testers' accounts maliciously
- Do share your methodology — we're here to learn
- Findings get credited in our final report

Looking forward to seeing what the community finds.
