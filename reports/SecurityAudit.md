# TransactiWar Security Audit Report — 2026-03-15

Four parallel security audits completed across auth/sessions, data handling/SQLi/XSS, infrastructure/Docker, and file upload/serving. Here's the consolidated findings.

---

## CRITICAL (fix immediately)

| # | Finding | File |
|---|---------|------|
| C1 | **TLS private key exists in working tree** — only `.gitignore` prevents commit; `git add -f` bypasses it | `docker/certs/server.key` |
| C2 | **Production secrets in `docker/.env`** — SESSION_SECRET (64-char hex) and DB passwords on disk | `docker/.env` |
| C3 | **DB credentials fail-open to root/empty** when env vars unset | `config/db.php:12-15` |

## HIGH

| # | Finding | File |
|---|---------|------|
| H1 | **Login lockout race condition (TOCTOU)** — concurrent requests bypass the 20-attempt limit; no `FOR UPDATE` on lockout check | `includes/auth.php:114-165` |
| H2 | **`htmlspecialchars_decode()` before `sanitize_bio()`** — decodes attacker-encoded HTML *before* `strip_tags()`, relying entirely on `strip_tags()` reliability | `includes/profile_update_logic.php:51` |
| H3 | **Container runs as root** — no `USER` directive in Dockerfile; entrypoint stays root | `docker/Dockerfile` |
| H4 | **Entire git repo mounted into container** — `.git/`, `reports/`, debug scripts all accessible inside container | `docker/docker-compose.yml:88` |
| H5 | **Docker binds `0.0.0.0` by default** — exposes app to all network interfaces | `docker/docker-compose.yml:69-70` |

## MEDIUM

| # | Finding | File |
|---|---------|------|
| M1 | **`sleep()`-based backoff = worker exhaustion DoS** — holds PHP workers up to 30s per failed login | `includes/auth.php:540-543` |
| M2 | **CSRF token survives login** — `csrf_secret` preserved through `session_regenerate_id()`, not bound to user identity | `includes/csrf.php` / `auth.php:562` |
| M3 | **Unescaped `balance_rupees`** in profile view | `public/view_profile.php:44` |
| M4 | **`nl2br()` on pre-escaped bio** — fragile encoding order; removing `escape_output()` upstream = instant stored XSS | `public/view_profile.php:36,61` |
| M5 | **No `upload_max_filesize`/`post_max_size` in php.ini** — PHP buffers full POST body before app-level check | `docker/Dockerfile` |
| M6 | **`public/uploads/` vestigial but web-accessible** — `.htaccess` FilesMatch doesn't block `.svg`/`.html` | `public/uploads/` |
| M7 | **Account enumeration via registration** — "Username or email already exists" confirms account presence | `public/register.php:64` |
| M8 | **Session reset depends on `strict_mode`** — if `ini_set` removed, `resetSession()` becomes session fixation | `config/session.php:60-74` |
| M9 | **Float precision risk in payment math** — `(float)$raw_rupees * 100` can produce IEEE 754 errors | `includes/process_payment.php:66` |
| M10 | **Dual IP-binding + proxy blindness** — ignores `X-Forwarded-For` even from trusted proxies; breaks behind LB | `config/session.php:41`, `auth.php:594-608` |
| M11 | **`AllowOverride All`** in Apache VirtualHost — attacker-written `.htaccess` can override security config | `docker/apache/default-ssl.conf:19` |
| M12 | **Seed accounts re-seeded with fixed hashes** on every startup via `ON DUPLICATE KEY UPDATE` | `docker/setup.sh:150-162` |
| M13 | **No log retention policy** — `activity_logs` grows unbounded under war-game load | `includes/logger.php` |
| M14 | **Missing INDEX on `activity_logs(client_ip)`** — monitoring queries do full table scans | `database/init.sql` |

## LOW

| # | Finding | File |
|---|---------|------|
| L1 | Null bytes in passwords bypass bcrypt | `auth.php:449,547` |
| L2 | Bcrypt 72-byte truncation with 128-char max allowed | `auth.php:449` |
| L3 | `strpos()` path check instead of `str_starts_with() + DIRECTORY_SEPARATOR` | `serve_image.php:41,50` |
| L4 | `SESSION_SECRET` entropy not validated (32 repeated chars passes) | `config/session.php:34-39` |
| L5 | Logout regenerates then destroys session (unnecessary) | `auth.php:737-759` |
| L6 | Commented-out debug code (`print_r($_SESSION)`) in payment | `process_payment.php:2-17` |
| L7 | PDO emulated prepares enabled (default) — client-side binding | `config/db.php` |
| L8 | `.env.example` contains real-looking SESSION_SECRET suffix | `docker/.env.example:12` |
| L9 | No `.dockerignore` — full repo sent as build context | repo root |
| L10 | No container resource limits (memory/CPU) | `docker-compose.yml` |
| L11 | Missing `Cross-Origin-Resource-Policy` on served images | `serve_image.php` / `header.php` |

---

## Key Race Conditions Identified

1. **H1 — Login lockout TOCTOU**: `is_ip_locked()` reads without `FOR UPDATE`; N concurrent requests all pass before any increment lands.
2. **M1 — Worker exhaustion via sleep()**: Blocking `sleep()` in backoff holds workers hostage; 50 concurrent failed logins = full DoS.
3. **M9 — Float precision in transfers**: IEEE 754 rounding on `float * 100` could cause off-by-one paise in transfers (mitigated by `round()`).

## Notable Strengths

The app is significantly above average for a PHP application:
- **Zero SQL injection** across 44+ queries (all parameterized PDO)
- **GD image reprocessing** strips metadata/polyglots/steganography
- **Ordered `FOR UPDATE` locks** on transfers prevent deadlocks and double-spend
- **CSP nonce-based policy** + comprehensive security headers
- **Anti-enumeration on login** with dummy bcrypt hash + random delays
- **Session version invalidation** on password change forces logout everywhere
- **Storage outside web root** with cryptographic filenames

---

## Top 5 Remediation Priorities

1. **Rotate the exposed SESSION_SECRET** in `docker/.env` and add pre-commit hooks blocking `*.key` files
2. **Fail-fast on missing DB credentials** — remove the `root`/empty fallback in `config/db.php`
3. **Fix login lockout race** — wrap check + record in a single transaction with `SELECT ... FOR UPDATE`
4. **Drop to non-root after entrypoint** — add `gosu www-data` before `apache2-foreground`
5. **Replace `sleep()` backoff** with timestamp-based 429 rejection to prevent worker exhaustion
