# auth.php — A-Class Security Fix Documentation

This document explains every **A-class security fix** applied to `includes/auth.php`. It is split into two sections:

1. **Vulnerabilities & Exploits** — issues that an attacker could actively exploit to compromise the system
2. **Code Quality & Hardening** — issues that are not directly exploitable but weaken the security posture or create future risk

The fixes marked as blunders (A1 — wrong file path, A11 — dead commented code) are excluded from this document as they carry no security significance.

---

## Section 1 — Vulnerabilities & Exploits

---

### A2 — Public Profile Endpoint Leaks Sensitive Financial Data

**Severity:** 🔴 Critical

#### What Was Wrong

`get_user_by_public_id()` was fetching six columns from the `users` table — including `email` and `balance_paise` — and returning them to any caller:

```php
// ❌ Before
SELECT id, public_id, username, email, balance_paise, bio, profile_image_path
FROM users WHERE public_id = :public_id
```

This function is used by search and transfer pages where any logged-in user can look up *another* user by their public ID.

#### Why This Is a Vulnerability

A public profile lookup must only return fields that are safe to share. Because `email` and `balance_paise` were included in every call:

- **Any authenticated user** could query another user's email address by simply knowing or guessing their `public_id`.
- **Any authenticated user** could see another user's exact balance — this is real financial data.

Since `public_id` values are UUIDs (long, but finite), an attacker could systematically resolve user balances and emails across the entire user base. In any financial application, exposing a balance to third parties is a **data breach** by definition.

#### How the Fix Prevents It

The query was split into two purpose-specific functions:

```php
// ✅ Public lookup — safe fields only
SELECT id, public_id, username, bio, profile_image_path
FROM users WHERE public_id = :public_id
```

```php
// ✅ Owner-only profile — requires DB lookup by internal user ID
function get_own_profile(PDO $pdo, int $userId): ?array
{
    SELECT id, public_id, username, email, balance_paise, ...
    FROM users WHERE id = :id
}
```

The sensitive version requires the **internal integer `id`** (only available from an authenticated session), making it inaccessible to peer lookups. The public function now returns nothing a viewer shouldn't see.

---

### A3 + A4 — IP Lockout Bypassed; Lockout Events Never Logged

**Severity:** 🔴 Critical

#### What Was Wrong

Two separate failures in the lockout branch of `login_user()`:

```php
// ❌ Before
if (is_ip_locked($pdo, $ip)) {
    /* logActivity(LOG_LOGIN_LOCKED); */   ← commented out
    usleep(random_int(...));
    return 'locked';                        ← returns a truthy string, not false
}
```

**Issue A3:** The function returned the *string* `'locked'` on lockout. In `login.php` (before fix LG1), the check was `if (login_user(...))`, which evaluates any non-empty string as `true` — meaning the **locked branch was treated as a successful login**.

**Issue A4:** The `logActivity(LOG_LOGIN_LOCKED)` call was commented out, so brute-force lockout events were silently swallowed and never appeared in security logs.

#### Why These Are Vulnerabilities

- **A3 (Authentication Bypass):** An attacker whose IP gets rate-limited would have their login call return `'locked'` — a truthy value — which in a loose `if (login_user(...))` check resolves to `true`. The attacker is admitted as a logged-in user **without ever providing a valid password**. This is a complete authentication bypass triggered *by* the lockout mechanism itself.

- **A4 (Blind Defender):** Without logging, the security team has no visibility into ongoing brute-force attacks. The attacker can repeatedly trigger lockouts knowing no alarm will fire and no record will be kept.

#### How the Fixes Prevent It

```php
// ✅ After — both fixes applied together
if (is_ip_locked($pdo, $ip)) {
    logActivity(LOG_LOGIN_LOCKED);   // A4: lockout events now recorded
    usleep(random_int(...));
    return false;                    // A3: unambiguous failure value
}
```

Returning `false` is now strictly `false` — it cannot be misinterpreted as truthy. And every lockout is logged, giving defenders a reliable signal of active brute-force attempts.

---

### A5 — Session Cookie Deletion Missing `SameSite` Attribute

**Severity:** 🔴 Critical

#### What Was Wrong

`logout_user()` deleted the session cookie using the old PHP positional argument signature:

```php
// ❌ Before
setcookie(
    session_name(), '',
    time() - 42000,
    $params['path'],
    $params['domain'],
    $params['secure'],
    $params['httponly']
    // ← SameSite not set at all
);
```

#### Why This Is a Vulnerability

The `SameSite` attribute controls whether a cookie is sent with cross-site requests. Without it, browsers default to `SameSite=None` (older browsers) or `SameSite=Lax` depending on the version — but critically, the **deletion cookie** sent at logout may not match the `SameSite` value of the original session cookie set by PHP.

More importantly, this creates a **Cross-Site Request Forgery (CSRF) window**:
- If an attacker can trick the browser into making a cross-site request to `/logout`, they can force-logout a victim — a denial-of-service on the session.
- More dangerously, if the `SameSite` attribute is inconsistently set between the session cookie and the deletion cookie, some browsers may reject the deletion — leaving the old session cookie alive after the user believes they have logged out.

#### How the Fix Prevents It

```php
// ✅ After — array-form sets all attributes explicitly
setcookie(session_name(), '', [
    'expires'  => time() - 42000,
    'path'     => $params['path'],
    'domain'   => $params['domain'],
    'secure'   => $params['secure'],
    'httponly' => $params['httponly'],
    'samesite' => $params['samesite'] ?? 'Lax',
]);
```

The deletion cookie now mirrors all attributes of the original session cookie, including `SameSite`. This guarantees browsers treat them as the same cookie and honour the deletion. `SameSite=Lax` also blocks CSRF-based logout attacks from cross-origin pages.

---

### A6 — IP Address Read Directly From `$_SERVER`, Bypassing Proxy-Aware Detection

**Severity:** 🟡 Medium

#### What Was Wrong

Both `login_user()` and `require_login()` read the user's IP directly:

```php
// ❌ Before
$ip = sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
```

The application also has a `get_client_ip()` function in `logger.php` that correctly handles `X-Forwarded-For` headers from trusted reverse proxies.

#### Why This Is a Vulnerability

If the application runs behind a load balancer or reverse proxy (very common in production), `$_SERVER['REMOTE_ADDR']` will always be the **proxy's IP**, not the user's real IP. This means:

1. **Rate limiting is broken** — `is_ip_locked()` uses the IP gathered at login time. If all users appear to come from the same proxy IP, locking one user's IP locks *every* user on the platform (unintentional denial-of-service).
2. **Session IP binding is broken** — `$_SESSION['ip']` is stored at login but checked at every request. If `login_user()` and `require_login()` resolve the IP differently (one using `REMOTE_ADDR`, the other using `get_client_ip()`), legitimate users can be logged out on every request, or the binding check becomes useless.
3. **IP spoofing via header injection** — an attacker who knows `REMOTE_ADDR` is trusted unconditionally can inject a controlled `REMOTE_ADDR` in relay scenarios to falsify their source IP.

#### How the Fix Prevents It

```php
// ✅ After — consistent proxy-aware IP detection
$ip = function_exists('get_client_ip')
    ? get_client_ip()
    : sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
```

Both functions now use the same code path. The IP resolved at login (and stored in `$_SESSION['ip']`) will always match the IP resolved on subsequent requests, making the session binding check reliable. The fallback ensures the code degrades safely if `logger.php` is not loaded.

---

### A8 — UUID v1 Generated by Database Instead of Cryptographically Random UUID v4

**Severity:** 🟡 Medium

#### What Was Wrong

`register_user()` issued an `INSERT` without providing a `public_id`, relying on the database to call `UUID()` via a trigger or default:

```php
// ❌ Before — DB generates UUID via MySQL UUID() = UUID version 1
INSERT INTO users (username, email, password_hash)
VALUES (:username, :email, :password_hash)
```

#### Why This Is a Vulnerability

MySQL's `UUID()` function generates **UUID version 1**, which is derived from:
- The **current timestamp** (encoded in the UUID structure)
- The **MAC address** of the database server's network interface

This means every `public_id` in the system leaks:
- **Temporal information** — when a user registered, to sub-millisecond precision
- **Infrastructure information** — the MAC address of the DB server (or a random node ID if virtual)

An attacker who obtains one UUID can:
1. Determine *exactly* when that user registered
2. Predict UUID values generated near that time — because the timestamp increments predictably, nearby registrations will have nearby UUIDs
3. Enumerate other users by probing UUID values derived from adjacent timestamps

In a game/payment app where `public_id` controls who you can send money to, predictable public IDs are a significant enumeration and targeting risk.

#### How the Fix Prevents It

```php
// ✅ After — cryptographically random UUID v4 generated in PHP
function generate_uuid_v4(): string {
    $data    = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

INSERT INTO users (public_id, username, email, password_hash)
VALUES (:public_id, :username, :email, :password_hash)
// 'public_id' => generate_uuid_v4()
```

`random_bytes(16)` uses the OS cryptographic random number generator (equivalent to `/dev/urandom`). The resulting UUID has **122 bits of entropy**, making it computationally infeasible to enumerate or predict — even with knowledge of surrounding UUIDs.

---

### A9 — Logout Does Not Regenerate Session ID Before Destroying Session

**Severity:** 🟡 Medium

#### What Was Wrong

```php
// ❌ Before
$_SESSION = [];
session_destroy();
```

#### Why This Is a Vulnerability

This is a **session fixation / session persistence** vulnerability:

1. **Session fixation at logout:** When `session_destroy()` is called, PHP invalidates the server-side session data but the **session ID itself remains valid in the browser cookie** until its expiry. If an attacker had previously stolen or fixed the session ID (e.g., via XSS), calling `session_destroy()` does not invalidate that ID on the server fast enough — there is a brief window.

2. **Session ID reuse:** More critically, without calling `session_regenerate_id(true)`, the old session ID is not explicitly deleted from the session store. In some session backends (file-based sessions with PHP defaults), the old ID file may linger, and an attacker holding that cookie can reuse it before garbage collection runs.

3. **Logout CSRF leading to partial session survival:** If an attacker can time a request with the old session ID to land between `$_SESSION = []` and the cookie deletion, the server may still recognise the ID.

#### How the Fix Prevents It

```php
// ✅ After
session_regenerate_id(true);   // ← invalidates old ID in session store immediately
$_SESSION = [];
session_destroy();
```

`session_regenerate_id(true)` with the `delete_old_session` flag set to `true` **immediately removes the old session file/record from the session store**. Any attacker holding the old session cookie will receive an invalid session ID the next time they use it — the server no longer recognises it.

---

### A10 — `logSecurityEvent()` Called Without Checking If It Exists

**Severity:** 🟡 Medium

#### What Was Wrong

Throughout `auth.php`, the pattern used to guard logging calls was:

```php
// ❌ Before — checks for logActivity but calls logSecurityEvent
if (function_exists('logActivity')) {
    logSecurityEvent(LOG_SESSION_HIJACK, 'IP mismatch in require_login');
}
```

In specific places (such as the IP mismatch handler in `require_login()`), the check tested whether `logActivity` exists, but the actual call was to `logSecurityEvent` — a completely different function.

#### Why This Is a Vulnerability

`logActivity` and `logSecurityEvent` are separate functions likely defined in `logger.php`. If `logger.php` is not loaded (file missing, autoload failure, or conditional inclusion) — or if only one of the two functions is defined — the guard check succeeds even though the real function is absent.

The result is a **fatal PHP error** (`Call to undefined function logSecurityEvent()`) thrown at the exact moment a session hijack is detected. This kills the request mid-execution:

- The `session_unset()` / `session_destroy()` cleanup code below the log call **never runs**
- The `header('Location: /login.php')` redirect **never fires**
- The hijacked session **remains active**

An attacker who can trigger a session IP mismatch (e.g., by stealing a session cookie and using it from a different IP) will cause the fatal error, **bypassing the hijack detection handler entirely** and keeping their stolen session alive.

#### How the Fix Prevents It

```php
// ✅ After — check matches the actual function being called
if (function_exists('logSecurityEvent')) {
    logSecurityEvent(LOG_SESSION_HIJACK, 'IP mismatch in require_login');
}
```

The guard now tests for exactly the function that is about to be called. If `logSecurityEvent` is unavailable, the block is skipped gracefully — the detection logic continues, the session is still invalidated, and the redirect still fires.

---

## Section 2 — Code Quality & Hardening

The following fixes address weaknesses that do not constitute direct exploits on their own, but reduce robustness, complicate incident response, or create conditions where exploits become easier.

---

### A7 — `ensure_session_started()` Does Not Validate That a Session Actually Started

**Issue:** The original implementation silently did nothing if the session config file was missing or if `session_start()` (called inside `session.php`) silently failed. Every function that called `ensure_session_started()` would then run with `$_SESSION` undefined or stale, potentially falling back on shared or injected session data.

**Fix applied:** The hardened version checks `session_status()` after requiring `session.php` and throws `RuntimeException` if the session is still not active. This converts a silent failure into a loud, traceable crash that can be caught, logged, and alerted on.

---

*This document covers A2, A3/A4, A5, A6, A8, A9, A10 (vulnerabilities) and A7 (hardening). Fixes A1 and A11 are excluded as they are code correctness issues with no security impact.*
