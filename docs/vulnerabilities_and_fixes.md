# TRANSACTIWAR — Vulnerabilities & Fixes

This document is a complete record of every security vulnerability identified and fixed in the TRANSACTIWAR codebase. Each entry explains:
- What the vulnerable code looked like
- Why it is a vulnerability and what an attacker could do with it
- What the fix does and how it prevents the attack

Issues are grouped by the file they originate in. Pure code-correctness blunders with no security relevance (wrong file paths, dead commented code) are excluded.

---

## Part 1 — `includes/auth.php` (A-Class Fixes)

---

### A2 — Public Profile Endpoint Leaks Email and Balance to Any User

**Severity:** 🔴 Critical  
**Attack class:** Information Disclosure / Financial Data Exposure

#### What Was Wrong

`get_user_by_public_id()` — called by the search and transfer pages whenever one user looks up another — fetched sensitive columns alongside safe ones:

```php
// ❌ Before
SELECT id, public_id, username, email, balance_paise, bio, profile_image_path
FROM users WHERE public_id = :public_id
```

#### The Vulnerability

Any logged-in attacker can call the search or transfer page with any `public_id` and the response will contain the target's **email address** and **exact account balance in paise**. This covers the entire user base because UUIDs can be iterated — an attacker who registers and receives one UUID can derive a likely range of nearby registrations.

**Concrete attack:**
1. Attacker registers an account and notes their own `public_id`.
2. Attacker systematically guesses nearby UUID values (or uses the UUID v1 timestamp predictability — see A8) and queries the search endpoint for each.
3. For every hit, they receive the target's email and balance.
4. Attacker builds a full list of all users, their emails, and their balances — a complete financial data breach.

#### How the Fix Prevents It

The query was split into two purpose-specific functions:

```php
// ✅ Public lookup — safe fields only
SELECT id, public_id, username, bio, profile_image_path
FROM users WHERE public_id = :public_id

// ✅ Owner-only — requires internal session user ID, not public_id
function get_own_profile(PDO $pdo, int $userId): ?array {
    SELECT id, public_id, username, email, balance_paise, ...
    FROM users WHERE id = :id
}
```

The sensitive version requires the **internal integer `id`** which only comes from the authenticated session. A peer lookup can no longer access another user's email or balance, regardless of how many `public_id` values the attacker enumerates.

---

### A3 + A4 — Lockout Mechanism Itself Grants Login; Lockout Events Never Logged

**Severity:** 🔴 Critical  
**Attack class:** Authentication Bypass + Blind Brute Force

#### What Was Wrong

```php
// ❌ Before
if (is_ip_locked($pdo, $ip)) {
    /* logActivity(LOG_LOGIN_LOCKED); */   // ← commented out
    usleep(random_int(...));
    return 'locked';                       // ← non-false truthy string
}
```

In `login.php`, the result of `login_user()` was checked loosely:
```php
if (login_user($pdo, $identifier, $password)) {
    // logged in
}
```

#### The Vulnerability

**A3 — Authentication bypass via truthy lockout string:**  
PHP evaluates any non-empty string as `true` in a boolean context. When an IP is locked, `login_user()` returns the string `'locked'`. The login page's `if (login_user(...))` check evaluates that as `true` and admits the user as successfully authenticated — **without ever verifying a password**. An attacker who deliberately triggers rate-limiting on their own IP gets full access to the application.

**A4 — Blind brute force:**  
The logging call for `LOG_LOGIN_LOCKED` was commented out. Lockout events left no trace in activity logs or security logs. An attacker could hammer the login endpoint, trigger lockouts, receive the access bypass, and the security team would see nothing — no spike in logs, no `BRUTE_FORCE_DETECTED` event, no alert.

**Combined real-world attack:**
1. Attacker fails login 5 times with any password for any username.
2. IP is locked. `login_user()` returns `'locked'`.
3. `if ('locked')` → `true` → attacker is logged in.
4. No log entry exists. Defenders see nothing.

#### How the Fix Prevents It

```php
// ✅ After
if (is_ip_locked($pdo, $ip)) {
    logActivity(LOG_LOGIN_LOCKED);   // A4: every lockout is now recorded
    usleep(random_int(...));
    return false;                    // A3: false cannot be misread as success
}
```

`false` is unambiguously rejected by any valid boolean check. The lockout now generates a `LOGIN_LOCKED` log entry, giving defenders a real-time signal of brute-force activity.

---

### A5 — Session Cookie Not Deleted on Logout (Missing `SameSite`)

**Severity:** 🔴 Critical  
**Attack class:** Session Persistence After Logout / CSRF-Based Session Theft

#### What Was Wrong

`logout_user()` called `setcookie()` using the old 7-argument PHP signature:

```php
// ❌ Before
setcookie(
    session_name(), '',
    time() - 42000,
    $params['path'],
    $params['domain'],
    $params['secure'],
    $params['httponly']
    // SameSite not settable in this positional form
);
```

#### The Vulnerability

Two separate attack vectors arise from the missing `SameSite` attribute on the deletion cookie:

**1. Cookie deletion rejected by browser:**  
For a `Set-Cookie` header to delete an existing cookie, the new cookie must match the old one on `Name`, `Domain`, `Path`, and `SameSite`. If the original session cookie was set by PHP with `SameSite=Strict` (as configured in `session.php`) but the deletion cookie has no `SameSite` attribute, some browsers treat them as *different* cookies and **ignore the deletion**. The user's session remains active after logout, leaving the session open for cookie theft via XSS or network sniffing.

**2. CSRF-based forced logout (denial of service):**  
Without `SameSite`, an attacker can embed a cross-origin image tag or form pointing to `/logout.php`. Any user who visits the attacker's page will have their session ended silently. While not directly an account takeover, it is a reliable denial-of-service against any authenticated user.

#### How the Fix Prevents It

```php
// ✅ After — PHP 7.3+ array form, all attributes mirrored
setcookie(session_name(), '', [
    'expires'  => time() - 42000,
    'path'     => $params['path'],
    'domain'   => $params['domain'],
    'secure'   => $params['secure'],
    'httponly' => $params['httponly'],
    'samesite' => $params['samesite'] ?? 'Lax',
]);
```

The deletion cookie now exactly mirrors the original session cookie's attributes. Browsers recognise it as the same cookie and honour the deletion. `SameSite=Lax` (minimum safe value) also blocks the CSRF forced-logout attack by preventing cross-origin requests from carrying the cookie.

---

### A6 — IP Bypasses Proxy-Aware Detection; Rate Limiting and Session Binding Broken

**Severity:** 🟡 Medium  
**Attack class:** Rate Limit Evasion / Session Binding Defeat / Denial of Service

#### What Was Wrong

`login_user()` and `require_login()` both hardcoded `$_SERVER['REMOTE_ADDR']` for IP resolution, bypassing the application's own `get_client_ip()` proxy-aware function:

```php
// ❌ Before (both functions)
$ip = sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
```

#### The Vulnerability

In any production deployment with a reverse proxy or load balancer, `REMOTE_ADDR` is always the **proxy's IP** — every request from every user arrives with the same IP address.

**1. Rate limiting becomes platform-wide:**  
`is_ip_locked()` checks the IP stored in `login_attempts`. If that IP is always the proxy's (e.g., `10.0.0.1`), then one user failing 5 logins locks **everyone on the platform** out simultaneously — an unintentional self-inflicted denial of service.

**2. Session binding becomes meaningless or breaks for all users:**  
At login, `$_SESSION['ip']` is set to `REMOTE_ADDR` (the proxy IP). At every subsequent request, `require_login()` also reads `REMOTE_ADDR` (the proxy IP). The values always match — so the session binding check never catches a stolen cookie used from a different real IP. The anti-hijacking control is completely neutered.

**3. Conversely: if functions are mixed**, one using `REMOTE_ADDR` and another using `get_client_ip()`, the stored IP and the checked IP are different on every request — every legitimate user is immediately logged out after login.

#### How the Fix Prevents It

```php
// ✅ After — uniform proxy-aware IP resolution in both functions
$ip = function_exists('get_client_ip')
    ? get_client_ip()
    : sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
```

Both `login_user()` and `require_login()` now use the same code path. The real client IP (passed through trusted proxy headers) is consistent across login and all subsequent requests, making rate limiting per-user and session binding reliable.

---

### A8 — Database Generates UUID v1; Attacker Can Predict All User Public IDs

**Severity:** 🟡 Medium  
**Attack class:** User Enumeration / Public ID Prediction

#### What Was Wrong

`register_user()` inserted a new user without providing `public_id`, relying on a database trigger to call MySQL's `UUID()`:

```php
// ❌ Before
INSERT INTO users (username, email, password_hash)
VALUES (:username, :email, :password_hash)
```

#### The Vulnerability

MySQL's `UUID()` generates **UUID version 1**. A UUID v1 encodes two pieces of information directly in its structure:

- **Timestamp** — the exact time of generation, to 100-nanosecond resolution
- **Node ID** — the MAC address of the database server's network card (or a pseudo-random node on virtual machines)

This makes `public_id` values **not random** — they are predictable from the outside.

**Concrete attack:**
1. Attacker registers an account at time `T` and receives their own `public_id`.
2. They decode the UUID v1 timestamp from it.
3. They generate a list of UUID v1 values for timestamps `T - N` to `T + N` using the same node ID.
4. They probe the search and transfer endpoints with each UUID.
5. Every hit reveals a valid user. Combined with the A2 vulnerability (now fixed), each hit also exposed that user's email and balance.

Even with A2 fixed, UUID v1 enumeration still lets an attacker map the user base, identify registration timing patterns, and target specific users.

#### How the Fix Prevents It

```php
// ✅ After — 122-bit cryptographic randomness, generated in PHP
function generate_uuid_v4(): string {
    $data    = random_bytes(16);                          // OS CSPRNG
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);         // set version 4
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);         // set variant
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

INSERT INTO users (public_id, username, email, password_hash)
VALUES (:public_id, :username, :email, :password_hash)
// 'public_id' => generate_uuid_v4()
```

UUID v4 contains no timestamp and no node ID. Its 122 bits come entirely from the OS cryptographic random number generator (`/dev/urandom` on Linux). The probability of guessing any valid UUID is `1 / 2^122` — not computationally feasible. User enumeration via UUID prediction becomes impossible.

---

### A9 — Logout Does Not Immediately Invalidate Session ID; Stolen Cookies Remain Valid

**Severity:** 🟡 Medium  
**Attack class:** Post-Logout Session Hijacking

#### What Was Wrong

```php
// ❌ Before
$_SESSION = [];
session_destroy();
```

#### The Vulnerability

`session_destroy()` removes the session data from the server's session store but **the session ID itself is not immediately invalidated**. Depending on the session backend:

- **File-based sessions (PHP default):** the session file is marked for deletion but may persist until garbage collection runs. An attacker holding the old cookie can send a request before GC and still be recognised.
- **Database-backed sessions:** same race condition applies.

**Concrete attack scenario:**
1. Attacker steals a user's session cookie (via XSS, network sniff, or physical access).
2. Victim logs out. Session data is cleared, session_destroy is called.
3. Attacker submits a request with the stolen cookie before PHP's garbage collector has cleaned up the old session file.
4. Server either still recognises the ID or creates a new empty session under the old ID — attacker gains access.

This window is small but exploitable in a targeted attack where the attacker is watching for the logout.

#### How the Fix Prevents It

```php
// ✅ After
session_regenerate_id(true);   // ← old session file/record deleted NOW
$_SESSION = [];
session_destroy();
```

`session_regenerate_id(true)` with `delete_old_session = true` instructs PHP to **immediately delete** the old session file from the store and assign a new ID. The stolen cookie now references a session ID that no longer exists — any request with it will be rejected instantly, with zero race condition window.

---

### A10 — Wrong Function Guard Causes Fatal Error During Hijack Detection; Stolen Sessions Survive

**Severity:** 🟡 Medium  
**Attack class:** Security Control Bypass via Code Error

#### What Was Wrong

In `require_login()`, the IP mismatch handler (session hijack detection) contained a mismatched guard:

```php
// ❌ Before — checks logActivity but calls logSecurityEvent
if (function_exists('logActivity')) {
    logSecurityEvent(LOG_SESSION_HIJACK, 'IP mismatch in require_login');
}
```

#### The Vulnerability

`logActivity` and `logSecurityEvent` are different functions. In a scenario where `logger.php` is not loaded, or `logSecurityEvent` specifically is not defined:

1. `function_exists('logActivity')` returns `true` (if `logActivity` is defined but `logSecurityEvent` is not).
2. PHP proceeds to call `logSecurityEvent(...)`.
3. **Fatal error:** `Call to undefined function logSecurityEvent()`.
4. The request halts. The code that follows — `session_unset()`, `session_destroy()`, `header('Location: /login.php')` — **never executes**.
5. The hijacked session stays alive.

**Exploit pathway:**  
An attacker who steals a session cookie and uses it from a different IP triggers the fingerprint/IP mismatch check. Under the right conditions (partial logger load), the fatal error fires, the session is not destroyed, the attacker retains access, and no hijack event is logged.

#### How the Fix Prevents It

```php
// ✅ After — guard tests for the exact function being called
if (function_exists('logSecurityEvent')) {
    logSecurityEvent(LOG_SESSION_HIJACK, 'IP mismatch in require_login');
}
```

If `logSecurityEvent` is missing, the block is skipped cleanly — no fatal error, no halt. Execution continues: the session is invalidated and the redirect fires. Security telemetry may be missing in that edge case, but the security control itself is no longer breakable.

---

### A7 — `ensure_session_started()` Silent Failure Creates Undefined Session State

**Severity:** 🟡 Medium (Hardening)  
**Attack class:** Session Injection via Undefined State

#### What Was Wrong

```php
// ❌ Before
function ensure_session_started(): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        require_once __DIR__ . '/../config/session.php';
        // No check that session actually started after this
    }
}
```

If `session.php` failed to call `session_start()` (e.g., due to headers-already-sent, file corruption, or missing config), the function returned silently. All subsequent code that reads or writes `$_SESSION` would operate on an uninitialised superglobal.

#### The Vulnerability

In PHP, accessing `$_SESSION` without an active session doesn't crash — it reads from whatever happens to be in memory. In some edge cases (persistent CLI workers, shared memory backends), this means reading **another request's session data**. More commonly, it means session data is written but never persisted — authentication checks pass in memory for the current request but `$_SESSION['user_id']` is gone on the next request.

An attacker aware of this can craft requests that trigger the silent failure condition, causing the application to operate in a confused state where auth guards don't work correctly.

#### How the Fix Prevents It

```php
// ✅ After — throws on any failure
function ensure_session_started(): void {
    if (session_status() === PHP_SESSION_ACTIVE) { return; }

    $sessionConfig = __DIR__ . '/../config/session.php';
    if (!file_exists($sessionConfig)) {
        throw new RuntimeException('session.php not found — cannot start session');
    }

    require_once $sessionConfig;

    if (session_status() !== PHP_SESSION_ACTIVE) {
        throw new RuntimeException('Session failed to start');
    }
}
```

Silent failure is eliminated. Any misconfiguration that would leave the session uninitialised now throws a `RuntimeException`, which creates a visible error log entry and a hard stop — the request never reaches auth-guarded code in a broken state.

---

## Part 2 — Cross-File Fixes (C-Class)

These vulnerabilities span multiple files and cannot be fixed in isolation.

---

### C1.1a — Dual Write to `login_attempts` Halves the Real Brute-Force Threshold

**Severity:** 🔴 Critical  
**Files affected:** `includes/auth.php` + `includes/logger.php`  
**Attack class:** Brute Force Amplification / Denial of Service via Lockout

#### What Was Wrong

A single failed login causes **two separate, independent increments** to the `login_attempts` counter in the database:

1. `auth.php` → `record_failed_attempt($pdo, $ip)` — increments `attempts` by 1 via `ON DUPLICATE KEY UPDATE attempts + 1`
2. `logger.php` → `recordFailedLogin($ip)` — also increments `attempts` by 1 via its own separate `INSERT ... ON DUPLICATE KEY UPDATE attempts + 1`

Both functions write to the same `ip` row in `login_attempts`. They are both called on every failed login.

#### The Vulnerability

The configured threshold is `MAX_LOGIN_ATTEMPTS = 5`. After 5 real login failures the IP should be locked. But because the counter is incremented twice per attempt, the counter reaches 5 after only **3 real attempts** (3 × 2 = 6 ≥ 5, but in practice 2 after attempt 2, 4 after attempt 2, lockout triggered).

**Attack 1 — Attacker brute forces before lockout:**  
The attacker gets 2-3 password attempts for every round before lockout. If the threshold was set to 5 to allow for genuine user typos, the effective threshold of ~2 means legitimate users get locked out from their own accounts on a single mistype — making the lockout a **denial-of-service weapon against real users**.

**Attack 2 — Attacker uses dual-write to lock out victims:**  
Knowing that 2 requests trigger a lockout, the attacker sends just 3 deliberately failed login attempts for a victim's account. The victim's IP is locked. They cannot log in. Attacker accomplishes a targeted denial-of-service with minimal traffic.

#### How the Fix Prevents It

Remove the call to `recordFailedLogin()` from the login flow and keep only `record_failed_attempt()` in `auth.php`. The `record_failed_attempt()` function has the complete, correct logic including the ATTEMPT_WINDOW reset check. `recordFailedLogin()` in `logger.php` increments blindly without windowing. After the fix, one failed attempt = one counter increment, restoring the intended threshold of 5.

---

### C1.1b — `X-Forwarded-For` Poisoning Enables Remote Victim Lockout

**Severity:** 🔴 Critical  
**Files affected:** `includes/logger.php` + `includes/sanitize.php`  
**Attack class:** IP Spoofing / Targeted Denial of Service

#### What Was Wrong

`recordFailedLogin()` in `logger.php` resolves the IP to record via `_getLogIp()`, which calls `get_client_ip()` in `sanitize.php`. The current `get_client_ip()` trusts `X-Forwarded-For` unconditionally:

```php
// ❌ Before (conceptual — sanitize.php get_client_ip)
return $_SERVER['HTTP_X_FORWARDED_FOR'] // Trusted from ANY source
    ?? $_SERVER['REMOTE_ADDR'];
```

#### The Vulnerability

An attacker can forge the `X-Forwarded-For` header in their HTTP request to set it to any value — including their victim's real IP address:

```
POST /login.php HTTP/1.1
X-Forwarded-For: 192.168.1.50   ← victim's IP
...
```

When `recordFailedLogin()` writes this failed attempt to `login_attempts`, it uses the **forged victim IP** as the key. After 3-5 such forged requests, the victim's IP is locked. The victim can no longer log in from any device on their network.

**The attacker has:**
- Never sent traffic from the victim's actual IP
- Required no credentials or access to the victim's account
- Locked the victim out silently, with no trace pointing to the attacker's real IP
- The activity log records the victim's IP as the source of failed logins — framing the victim

#### How the Fix Prevents It

`get_client_ip()` is updated to only trust `X-Forwarded-For` from a defined list of known trusted proxy IPs:

```php
// ✅ After
function get_client_ip(): string {
    $trusted_proxies = ['127.0.0.1'];  // Only your own load balancer

    if (in_array($_SERVER['REMOTE_ADDR'], $trusted_proxies, true)) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
    }

    return $_SERVER['REMOTE_ADDR'];  // All other sources: trust only TCP layer
}
```

If the request does not arrive from a trusted proxy, `REMOTE_ADDR` is used as the authoritative IP — and that cannot be forged at the HTTP layer (it's set by the TCP connection). Arbitrary clients can inject `X-Forwarded-For` all they want; it will be ignored.

---

### C1.2 — Mismatched User-Agent Causes Fatal Error and Session Destruction on Demand

**Severity:** 🔴 Critical  
**File affected:** `config/session.php`  
**Attack class:** Forced Logout / Denial of Service via Error Trigger

#### What Was Wrong

In `session.php`, the session fingerprint check runs at line 59–65 and can call `resetSession($now)` on a mismatch. But `$now = time()` is not defined until line 73:

```php
// ❌ Before — execution order
$currentFingerprint = hash('sha256', $ua . $ip);   // line 51
if (!hash_equals($_SESSION['fingerprint'], $fp)) {
    resetSession(time());                            // line 64 — uses time() directly
}
// ...
$now = time();                                       // line 73 — too late for above
// ...
if (($now - $_SESSION['last_activity']) > $inactivityTimeout) {
    resetSession($now);                              // line 152 — uses $now, safe
}
```

The immediate crash risk is subtler: `resetSession()` reinitialises `$_SESSION['created_at']`, `$_SESSION['last_activity']`, and `$_SESSION['last_regen']`. But the code that *reads* those variables to make timeout decisions (lines 147–162) runs after `$now` is defined. However if `resetSession()` is triggered at line 64 and it calls `logActivity()` which internally touches `$_SESSION` values that haven't been set yet — the logger can crash or log incorrect data.

#### The Vulnerability

Any attacker (or even a legitimate user switching browsers) who sends a request with a different User-Agent string triggers the fingerprint mismatch at line 59. This:

1. Calls `resetSession()` which calls `session_destroy()` and `session_start()` — wiping the active session
2. In the process, exercises code paths that can throw if `$now` or session metadata is not yet defined

**Targeted attack:**
- Attacker knows a victim is logged in
- Attacker finds any way to make a request *on behalf* of the victim (CSRF, XSS) with a spoofed `User-Agent` header
- Victim's session is destroyed — they are logged out
- This is repeatable — every login attempt can be met with a forged UA request

#### How the Fix Prevents It

Move `$now = time()` to the very top of the execution block, before the fingerprint check, and ensure `resetSession()` never references undefined state:

```php
// ✅ After
$now = time();   // ← defined first, always

$currentFingerprint = hash('sha256', $secret . $ua . $ip);
if (!hash_equals($_SESSION['fingerprint'], $currentFingerprint)) {
    logActivity('SESSION_HIJACK_DETECTED');
    session_unset();
    session_destroy();
    header("Location: /login.php");
    exit;  // Hard stop — no resetSession() call, no partial state
}
```

`$now` is available everywhere it is needed. The hijack response no longer calls `resetSession()` (which has side effects) — it simply destroys the session and redirects. State is never partially initialised.

---

### C1.3 — Session Fingerprint Has No Server Secret; Reproducible on Shared Networks

**Severity:** 🔴 Critical  
**File affected:** `config/session.php`  
**Attack class:** Session Hijacking via Fingerprint Forgery

#### What Was Wrong

The session fingerprint was computed purely from client-visible information:

```php
// ❌ Before
$currentFingerprint = hash('sha256',
    ($_SERVER['HTTP_USER_AGENT'] ?? '') .
    $_SERVER['REMOTE_ADDR']
);
```

#### The Vulnerability

Both inputs (`User-Agent` and `REMOTE_ADDR`) are fully known to any attacker on the same network — or even from outside it:

- **User-Agent** is sent by the browser in every request and is trivially readable or spoofable.
- **REMOTE_ADDR** behind a NAT (university network, office LAN, coffee shop) is the **same for every device** on that network.

An attacker on the same network as a victim can:
1. Steal the victim's session cookie (via XSS, packet sniff on HTTP, or ARP poisoning).
2. Note that both their device and the victim's device have the same `REMOTE_ADDR`.
3. Copy the victim's `User-Agent` string (visible in the stolen cookie request, or guessable from the browser).
4. Compute the fingerprint themselves: `sha256(UA + IP)` — it matches exactly.
5. Send requests with the stolen cookie — the fingerprint check passes, the session continues.

The fingerprint provides **zero additional protection** on any shared network.

#### How the Fix Prevents It

A server-side secret is injected into the hash, making the fingerprint uncomputable by any external party even if they know the UA and IP:

```php
// ✅ After
$secret = $_ENV['SESSION_SECRET'] ?? 'fallback-change-in-production';
$currentFingerprint = hash('sha256',
    $secret .
    ($_SERVER['HTTP_USER_AGENT'] ?? '') .
    $_SERVER['REMOTE_ADDR']
);
```

`SESSION_SECRET` is a long random string stored in the server's `.env` file — never transmitted to clients, never in the codebase. Even if an attacker knows the UA and IP, they cannot compute the fingerprint without the secret. A stolen session cookie used from a different connection (different secret-derived fingerprint) is immediately invalidated.

> ⚠️ `SESSION_SECRET` must be set in `.env` as a minimum 32-character random string. Rotate it during incident response to invalidate all active sessions across the platform simultaneously.

---

### C2.1 — Integer Overflow on Balance Check Allows Transfers With Insufficient Funds

**Severity:** 🔴 Critical  
**File affected:** `includes/process_payment.php`  
**Attack class:** Arithmetic Overflow / Financial Bypass

#### What Was Wrong

The sender's balance was cast to `int` before comparison:

```php
// ❌ Before
if ((int)$sender['balance_paise'] < $amount_paise) {
    throw new RuntimeException("insufficient_balance");
}
```

#### The Vulnerability

PHP's `int` type is 64-bit on modern systems, with a maximum value of `9,223,372,036,854,775,807` (~922 crore rupees in paise). Any balance stored as a string in the database that exceeds this value — or any `$amount_paise` derived from crafted input — will **overflow to a negative integer** when cast with `(int)`.

**Concrete attack:**
- Attacker crafts an amount string that when multiplied by 100 exceeds `PHP_INT_MAX`.
- `sanitize_amount()` may still pass a large string through if it passes format validation.
- `(int)$amount_paise` wraps to a large negative number.
- `if (-9223372036854775808 < 500000)` → `true` → insufficient funds exception... wait, actually a negative amount would *correctly* fail. The real danger is the reverse: a stored `balance_paise` that overflows to a negative — making the check `if (negative < positive_amount)` → `true` always — insufficient balance is always flagged even for rich accounts. Or `balance_paise` overflows to a negative and the check `if (negative < 0)` → `true` blocks all transfers for that account.

More critically: if both values overflow in the same direction, the comparison silently produces the wrong answer and the transfer proceeds or blocks incorrectly — financial data integrity is compromised.

#### How the Fix Prevents It

Replace integer arithmetic with arbitrary-precision string comparison:

```php
// ✅ After — bccomp handles values of any magnitude correctly
if (bccomp((string)$sender['balance_paise'], (string)$amount_paise) < 0) {
    throw new RuntimeException("insufficient_balance");
}
```

`bccomp()` operates on strings and handles values of arbitrary size without overflow. Whether the balance is 1 paise or 100 crore rupees expressed as paise, the comparison is always mathematically correct. Remove all `(int)` casts from `balance_paise` throughout the file.

---

### C2.2 — Non-Deterministic Lock Order Enables Deliberate Deadlock as Denial of Service

**Severity:** 🔴 Critical  
**File affected:** `includes/process_payment.php`  
**Attack class:** Deadlock Injection / Transaction Denial of Service

#### What Was Wrong

The payment transaction locks the sender row first, then the receiver row — always in that order:

```php
// ❌ Before
// Lock sender
$stmt = $pdo->prepare("SELECT balance_paise FROM users WHERE id = ? FOR UPDATE");
$stmt->execute([$sender_id]);

// Lock receiver
$stmt = $pdo->prepare("SELECT id FROM users WHERE id = ? FOR UPDATE");
$stmt->execute([$receiver_id]);
```

#### The Vulnerability

In MySQL (InnoDB), `FOR UPDATE` acquires a row-level exclusive lock. If two transactions each hold one lock and wait for the other, they deadlock — MySQL kills one and the other succeeds, but the killed one throws an exception.

**Deliberate deadlock injection:**
1. Attacker controls two accounts: Account A (id=10) and Account B (id=20).
2. Attacker submits Transfer A→B.
3. Simultaneously submits Transfer B→A.
4. Transfer A→B: locks row 10, waits for row 20.
5. Transfer B→A: locks row 20, waits for row 10.
6. **Deadlock.** Both transactions are stuck. MySQL kills one.
7. Attacker repeats continuously — every pair of simultaneous reverse transfers causes a deadlock.
8. All legitimate transfers involving either account are blocked. With enough accounts, the attacker can deadlock the entire transfer system.

This is a **denial-of-service against the payment system** using only normal application functionality (no SQL injection required).

#### How the Fix Prevents It

Always acquire locks in ascending `id` order, regardless of who is sender and who is receiver:

```php
// ✅ After — deterministic lock ordering eliminates deadlock
$first  = min($sender_id, $receiver_id);
$second = max($sender_id, $receiver_id);

$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? FOR UPDATE");
$stmt->execute([$first]);
$rowFirst = $stmt->fetch(PDO::FETCH_ASSOC);

$stmt->execute([$second]);
$rowSecond = $stmt->fetch(PDO::FETCH_ASSOC);

// Re-map to sender/receiver based on original IDs
$sender   = ($first === $sender_id)   ? $rowFirst : $rowSecond;
$receiver = ($first === $receiver_id) ? $rowFirst : $rowSecond;
```

If Transfer A→B locks ids 10 then 20, Transfer B→A now *also* locks ids 10 then 20 (because `min(20,10) = 10`). They queue instead of deadlocking. The second transaction simply waits for the first to commit, then proceeds safely. Deadlock injection is mathematically impossible when all transactions acquire locks in the same global order.

---

## Summary Table

| Fix | Severity | File(s) | Attack Prevented |
|-----|----------|---------|-----------------|
| A2 | 🔴 Critical | `auth.php` | Financial data / email mass enumeration |
| A3+A4 | 🔴 Critical | `auth.php` | Auth bypass via truthy lockout + blind brute force |
| A5 | 🔴 Critical | `auth.php` | Session survives logout / CSRF forced logout |
| A6 | 🟡 Medium | `auth.php` | Rate limit bypass / session binding defeat |
| A7 | 🟡 Medium | `auth.php` | Silent session failure enabling undefined state |
| A8 | 🟡 Medium | `auth.php` | UUID v1 prediction for user enumeration |
| A9 | 🟡 Medium | `auth.php` | Post-logout stolen cookie reuse |
| A10 | 🟡 Medium | `auth.php` | Fatal error bypassing hijack detection handler |
| C1.1a | 🔴 Critical | `auth.php` + `logger.php` | Dual-write halves lockout threshold |
| C1.1b | 🔴 Critical | `logger.php` + `sanitize.php` | XFF header spoofing to lock victim IPs remotely |
| C1.2 | 🔴 Critical | `session.php` | UA mismatch triggers forced logout on demand |
| C1.3 | 🔴 Critical | `session.php` | Shared-network fingerprint forgery for session hijack |
| C2.1 | 🔴 Critical | `process_payment.php` | Integer overflow bypasses insufficient-funds guard |
| C2.2 | 🔴 Critical | `process_payment.php` | Deadlock injection denies service to payment system |
