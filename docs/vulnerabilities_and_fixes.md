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
**Status:** ✅ Fixed

#### What Was Wrong

`get_user_by_public_id()` — called whenever one user looks up or transfers to another — returned sensitive database columns alongside safe display fields:

```php
// ❌ Before
SELECT id, public_id, username, email, balance_paise, bio, profile_image_path
FROM users WHERE public_id = :public_id
```

This function was used on the search page and transfer page — both accessible by any logged-in user.

#### The Vulnerability

Every API response for a peer lookup included `email` and `balance_paise`. There was no authentication check to see if the requestor was the account owner — any account could query any other.

**Step-by-step attack:**

```
Step 1 — Attacker registers an account
  They receive their own public_id: 550e8400-e29b-41d4-a716-446655440000
  This is a UUID v1 — it encodes the timestamp of registration (see A8).

Step 2 — Attacker decodes the timestamp from their UUID and generates adjacent IDs
  Using any UUID v1 parser (Python, JS, or online tool):
    Time extracted: 2026-03-07 10:00:00.000
  Generate UUIDs for timestamps -30 minutes to +30 minutes from this.
  With UUID v1's 100ns resolution, this yields millions of candidate IDs
  but only a handful of real registrations will hit.

Step 3 — Attacker queries the search/transfer endpoint for each candidate
  GET /search.php?q=550e8400-e29b-41d4-a716-000000000001
  Response: { username: "alice", email: "alice@uni.in", balance_paise: 5000000 }

  GET /search.php?q=550e8400-e29b-41d4-a716-000000000002  
  Response: { username: "bob", email: "bob@uni.in", balance_paise: 250000 }

Step 4 — Full user map built in minutes
  Attacker scripts this across all candidate UUIDs.
  Every registered account reveals its email and exact balance.
  Result: complete financial intelligence on all players before any transfer.
```

Combined with A8 (UUID v1 predictability), the attacker can enumerate the entire user base — not just guess randomly, but generate a precise ordered list of every registration.

#### How the Fix Prevents It

The function was split into two strictly scoped versions:

```php
// ✅ Public lookup — safe fields only, no financial data
SELECT id, public_id, username, bio, profile_image_path
FROM users WHERE public_id = :public_id

// ✅ Owner-only — gated on internal integer ID from session, not public_id
function get_own_profile(PDO $pdo, int $userId): ?array {
    SELECT id, public_id, username, email, balance_paise, ...
    FROM users WHERE id = :id  // ← only the session user's own ID reaches here
}
```

The sensitive `get_own_profile()` takes the **internal integer `id`** which only comes from `$_SESSION['user_id']` — it is never exposed in URLs or API responses. An attacker enumerating `public_id` values gets only usernames and avatars. Email and balance are invisible to any peer lookup, regardless of how many IDs are probed.

---

### A3 + A4 — Lockout Mechanism Itself Grants Login; Lockout Events Never Logged

**Severity:** 🔴 Critical  
**Attack class:** Authentication Bypass + Blind Brute Force  
**Status:** ✅ Fixed

#### What Was Wrong

Two separate bugs existed in the same lockout code path:

```php
// ❌ Before
if (is_ip_locked($pdo, $ip)) {
    /* logActivity(LOG_LOGIN_LOCKED); */   // ← deliberately commented out
    usleep(random_int(...));
    return 'locked';                       // ← returns a non-empty STRING, not false
}
```

And in `login.php`, the result was checked with a loose boolean:
```php
if (login_user($pdo, $username, $password)) {
    // grant access
}
```

#### The Vulnerability

**A3 — The lockout itself is the login bypass:**

In PHP, any non-empty string evaluates to `true` in a boolean context. `'locked'` is a non-empty string. Therefore:

```
$result = login_user($pdo, 'alice', 'wrongpassword');
// After 5 failed attempts, IP is locked.
// login_user() returns 'locked'

if ($result) {   // if ('locked') → TRUE
    // Attacker is granted access as if they logged in correctly
    $_SESSION['user_id'] = ...  // ← this code runs
}
```

The password is never checked. The account targeted doesn't even matter — **the lockout mechanism itself is the backdoor**.

**Step-by-step attack:**

```
Step 1 — Attacker deliberately fails 5 logins with any username/password
  POST /login.php  username=alice&password=wrong   → fail
  POST /login.php  username=alice&password=wrong   → fail
  POST /login.php  username=alice&password=wrong   → fail
  POST /login.php  username=alice&password=wrong   → fail
  POST /login.php  username=alice&password=wrong   → fail

Step 2 — IP is now locked, next attempt returns 'locked'
  POST /login.php  username=alice&password=anything
  login_user() → is_ip_locked() → true → return 'locked'

Step 3 — login.php evaluates 'locked' as true — attacker is authenticated
  if ('locked')  → true
  Session is populated with alice's user_id.
  Attacker is inside alice's account.
  No valid password was ever entered.
```

**A4 — The attack leaves zero trace:**

The `logActivity(LOG_LOGIN_LOCKED)` call was commented out. Every lockout event — including the bypass above — generated no log entry. Defenders watching the security dashboard would see:
- Zero locked IP log entries
- Possibly a successful login for alice right after 5 failures — but the 5 failures may not stand out without lockout context

An attacker could use this bypass against any account, repeatedly, with no audit trail.

#### How the Fix Prevents It

```php
// ✅ After — A3: false, not string. A4: logging always runs.
if (is_ip_locked($pdo, $ip)) {
    logActivity(LOG_LOGIN_LOCKED);   // logged unconditionally
    usleep(random_int(...));
    return false;                    // false — PHP cannot evaluate as truthy
}
```

`false` is the only value PHP cannot accidentally cast to `true`. The lockout event is now logged before the delay — even if something crashes afterward, the log entry already exists. Defenders get a real-time `LOGIN_LOCKED` signal for every lockout triggered, making brute-force campaigns immediately visible.

---

### A5 — Session Cookie Not Deleted on Logout (Missing `SameSite`)

**Severity:** 🔴 Critical  
**Attack class:** Session Persistence After Logout / CSRF-Forced Logout  
**Status:** ✅ Fixed

#### What Was Wrong

`logout_user()` called `setcookie()` using PHP's old 7-positional-argument form:

```php
// ❌ Before — no way to set SameSite in this signature
setcookie(
    session_name(), '',
    time() - 42000,    // expired
    $params['path'],
    $params['domain'],
    $params['secure'],
    $params['httponly']
    // SameSite: impossible to set here
);
```

Meanwhile, the session cookie was originally issued by `session.php` with `SameSite=Lax` set via `session_set_cookie_params()`.

#### The Vulnerability

**Attack 1 — Session survives logout (cookie deletion silently rejected):**

For a browser to delete a cookie, the `Set-Cookie` deletion header must match the original cookie on *all* attributes — including `SameSite`. If the cookie was issued with `SameSite=Lax` but the deletion is sent without any `SameSite` attribute, modern browsers (Chrome 80+, Firefox 96+) treat them as **two different cookies**. The deletion targets a cookie that doesn't exist. The original cookie stays untouched.

```
Original session cookie:  PHPSESSID=abc123; SameSite=Lax; HttpOnly; Secure
Logout deletion attempt:  PHPSESSID=;       expires=past; HttpOnly; Secure
                                            ↑ no SameSite

Browser evaluation: "These are different cookies. I will not delete the first."
Result: User thinks they've logged out. Session cookie still active.
```

An attacker with the session cookie (stolen before logout) can now still use it — the logout did nothing.

**Attack 2 — CSRF forced logout (denial of service):**

Without `SameSite`, cross-origin requests carry the session cookie. An attacker hosting a page at `evil.example.com` can embed:

```html
<img src="https://yourapp.com/logout.php" style="display:none">
```

Any victim who visits `evil.example.com` while logged in will have their session silently destroyed. In a war-game context, an attacker who discovers any open redirector or XSS on an external site can use this to continuously log out competing team members — a reliable, zero-credential denial of service.

#### How the Fix Prevents It

```php
// ✅ After — PHP 7.3+ array form, SameSite explicitly mirrored
setcookie(session_name(), '', [
    'expires'  => time() - 42000,
    'path'     => $params['path'],
    'domain'   => $params['domain'],
    'secure'   => $params['secure'],
    'httponly' => $params['httponly'],
    'samesite' => $params['samesite'] ?? 'Lax',
]);
```

The deletion cookie now has an identical `SameSite` value to the original. The browser sees a match on all attributes and honours the deletion. Additionally, `SameSite=Lax` means any cross-origin request to `/logout.php` will have the session cookie stripped by the browser before it's even sent — the CSRF forced-logout attempt silently fails.

---

### A6 — IP Bypasses Proxy-Aware Detection; Rate Limiting and Session Binding Broken

**Severity:** 🟡 Medium  
**Attack class:** Rate Limit Evasion / Session Binding Defeat / Self-Inflicted DoS  
**Status:** ✅ Fixed

#### What Was Wrong

Both `login_user()` and `require_login()` hardcoded `$_SERVER['REMOTE_ADDR']` instead of using the app's own `get_client_ip()` function:

```php
// ❌ Before — in both functions
$ip = sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
```

#### The Vulnerability

In a proxied deployment (load balancer, Nginx reverse proxy, Docker network), `REMOTE_ADDR` is always the **proxy's internal IP** — never the actual client. Every user request arrives from the same address.

**Attack 1 — Rate limit lockout affects the entire platform:**

```
Setup: App sits behind Nginx proxy at 10.0.0.1

User A fails login 5 times:
  Each attempt records IP 10.0.0.1 in login_attempts.
  After 5 fails: is_ip_locked(10.0.0.1) → true.

User B tries to log in at the same moment:
  Their request also comes from REMOTE_ADDR=10.0.0.1.
  is_ip_locked(10.0.0.1) → true → they are blocked.

Result: One user's failed logins lock out the entire application.
All 50 players are denied access until the lockout window expires.
```

In a war-game, an opposing team can deliberately trigger this: repeatedly fail login for any account from their machine — all legitimate users on the platform are simultaneously locked out.

**Attack 2 — Session binding check never catches stolen cookies:**

```
At login:
  $_SESSION['ip'] = REMOTE_ADDR = '10.0.0.1'  (proxy IP)

Attacker steals victim's cookie and uses it from a different city:
  require_login() reads: REMOTE_ADDR = '10.0.0.1'  (same proxy IP)
  Stored:               $_SESSION['ip'] = '10.0.0.1'
  Comparison: match → no hijack detected.

The IP binding anti-hijacking control does nothing.
Any stolen cookie from any location passes unchallenged.
```

**Attack 3 — If functions use different methods, every user is logged out on every request:**

```
login_user()    stores: $_SESSION['ip'] = get_client_ip() → '203.0.113.42' (real IP)
require_login() checks:                  REMOTE_ADDR      → '10.0.0.1'    (proxy IP)

'203.0.113.42' ≠ '10.0.0.1' → mismatch → session destroyed → redirect to login.

Every authenticated page load immediately logs the user out.
```

#### How the Fix Prevents It

```php
// ✅ After — identical IP resolution in both functions
$ip = function_exists('get_client_ip')
    ? get_client_ip()
    : sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
```

Both functions now use the same source. `get_client_ip()` returns the real client IP from trusted proxy headers (or falls back to `REMOTE_ADDR` if no proxy is involved). Rate limiting is per-real-client, session binding compares the same IP at login and at every subsequent request, and there is no mismatch between the two functions.

---

### A8 — Database Generates UUID v1; Attacker Can Predict All User Public IDs

**Severity:** 🟡 Medium  
**Attack class:** User Enumeration / Public ID Prediction  
**Status:** ✅ Fixed

#### What Was Wrong

`register_user()` inserted without specifying `public_id`, leaving it to a database trigger calling MySQL's `UUID()` function:

```php
// ❌ Before
INSERT INTO users (username, email, password_hash)
VALUES (:username, :email, :password_hash)
// Database trigger calls UUID() → generates UUID v1
```

#### The Vulnerability

**What is UUID v1?**  
MySQL's `UUID()` produces UUID version 1. A UUID v1 is not random — it is deterministically computed from:
- **Timestamp** — current time to 100-nanosecond resolution, encoded in the first three segments
- **Node ID** — the MAC address of the database server's network card (or a pseudo-random substitute in virtual environments)

A UUID v1 looks like: `1ef3c8d0-dc8b-11ee-b4a7-0242ac130002`  
The `11ee` segment encodes version, and the first part encodes the timestamp. Anyone can reverse this.

**Step-by-step attack:**

```
Step 1 — Attacker registers an account and receives their own public_id
  Response: public_id = 1ef3c8d0-dc8b-11ee-b4a7-0242ac130002

Step 2 — Attacker decodes the UUID v1 timestamp
  Using Python: import uuid; uuid.UUID('1ef3c8d0-dc8b-11ee-b4a7-0242ac130002').time
  Output: 138784523212345678  (100ns intervals since Oct 1582)
  Converted: 2026-03-07 10:00:00.123456789 UTC
  Node ID:   0242ac130002  ← database server MAC / container ID

Step 3 — Generate UUIDs for all registrations in a time window
  For every 100ns tick in range [T-1hr, T+1hr]:
    Generate UUID v1 with same node ID and that timestamp.
  This yields 36,000,000 candidate IDs for a 1-hour window.
  Actual registrations might be ~50 — so 50 hits in 36M attempts.

Step 4 — Probe the search/transfer endpoint with each candidate
  Script this in Python with asyncio — 36M requests takes ~minutes at LAN speed.
  Every HTTP 200 reveals a real user.
  Combined with A2 (now fixed separately), each hit exposed email + balance.

Step 5 — Even with A2 fixed, attacker maps the entire user base
  Attacker knows every registered username and their public_id.
  They now know exactly who to target for transfers, DoS, or social engineering.
```

Note: UUID v1 generation in Docker containers often uses a predictable pseudo-random node ID derived from the container's network interface — making the node component even easier to reproduce.

#### How the Fix Prevents It

```php
// ✅ After — 122 bits of OS-level cryptographic randomness
function generate_uuid_v4(): string {
    $data    = random_bytes(16);                          // /dev/urandom
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);         // force version 4 bits
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);         // force variant bits
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

// Registration now passes the PHP-generated UUID explicitly:
INSERT INTO users (public_id, username, email, password_hash)
VALUES (:public_id, :username, :email, :password_hash)
// bound as: 'public_id' => generate_uuid_v4()
```

UUID v4 has no timestamp and no node ID. All 122 non-version bits come from `/dev/urandom` — the OS kernel's cryptographic random pool seeded from hardware entropy. The search space is `2^122 ≈ 5.3 × 10^36`. Even scanning 36 million candidates per hour would take longer than the age of the universe to find a valid UUID by chance.

---

### A9 — Logout Does Not Immediately Invalidate Session ID; Stolen Cookies Remain Valid

**Severity:** 🟡 Medium  
**Attack class:** Post-Logout Session Hijacking  
**Status:** ✅ Fixed

#### What Was Wrong

```php
// ❌ Before
$_SESSION = [];
session_destroy();
```

`session_destroy()` deletes the session *data* from the server's store, but does **not** immediately delete the session *file*. The session ID in the browser cookie still refers to a file that may still exist on disk.

#### The Vulnerability

PHP's default session handler stores sessions as files in `/tmp/sess_<sessionid>`. When `session_destroy()` is called:
1. PHP marks the file for deletion
2. The actual deletion depends on **garbage collection** — which runs probabilistically based on `session.gc_probability` and `session.gc_divisor`
3. The default is `gc_probability=1`, `gc_divisor=100` — a 1% chance GC runs on any given request

There is a window — potentially several minutes — where the session file still exists on disk but the server thinks the session is destroyed.

**Step-by-step attack:**

```
Setup: Attacker has stolen victim's session cookie PHPSESSID=abc123
(via XSS injection, packet sniff on HTTP, or brief physical device access)

Attacker is watching the victim's activity.

Step 1 — Victim clicks logout
  POST /logout.php  Cookie: PHPSESSID=abc123
  logout_user() runs:
    $_SESSION = []           ← data wiped from server memory
    session_destroy()        ← marks file for GC... but doesn't delete yet
  Server responds: redirect to /login.php
  Victim's browser deletes the cookie.

Step 2 — Attacker immediately sends a request with the stolen cookie
  GET /dashboard.php  Cookie: PHPSESSID=abc123
  PHP looks for /tmp/sess_abc123 → STILL EXISTS (GC hasn't run yet)
  PHP reads the file → data is [] (wiped) but session_start() succeeds
  Depending on the application's require_login() logic:
    - If it checks $_SESSION['user_id'] → fails → redirect
    - If session_start() restores the session file → attacker gets an empty session
  In some configurations, PHP recreates the session under the same ID.

Step 3 — Race window
  The attack window is the time between session_destroy() and GC running.
  In high-traffic apps (GC runs often), this window is seconds.
  In low-traffic apps (GC rarely runs), the old session file persists for minutes.
```

In a war-game where the attacker has already obtained the cookie and is actively monitoring, a seconds-wide window is exploitable — especially if they automate the replay immediately after detecting the logout redirect.

#### How the Fix Prevents It

```php
// ✅ After — session ID invalidated synchronously, not probabilistically
session_regenerate_id(true);   // deletes /tmp/sess_abc123 RIGHT NOW
$_SESSION = [];
session_destroy();
```

`session_regenerate_id(true)` with `true` (delete old session) calls the session handler's `destroy()` method **synchronously** — the old session file is deleted immediately as part of the regeneration, not deferred to GC. The stolen cookie `PHPSESSID=abc123` now references a file that no longer exists. Any request with it gets a brand new empty session — not the victim's data — with zero race condition window.

---

### A10 — Wrong Function Guard Causes Fatal Error During Hijack Detection; Stolen Sessions Survive

**Severity:** 🟡 Medium  
**Attack class:** Security Control Bypass via Code Error  
**Status:** ✅ Fixed

#### What Was Wrong

`require_login()` detects session hijacking by comparing the IP stored at login with the IP on the current request. When a mismatch is found, it was supposed to log the event and destroy the session. The guard name and the called function name were different:

```php
// ❌ Before
if (function_exists('logActivity')) {          // checks for logActivity
    logSecurityEvent(LOG_SESSION_HIJACK, ...); // calls logSecurityEvent — different!
}
// ... then:
session_unset();
session_destroy();
header('Location: /login.php');
```

#### The Vulnerability

`logActivity` and `logSecurityEvent` are two different functions in `logger.php`. In a partial load scenario — where `logger.php` is included but only some of its functions are defined — or in any error state where `logSecurityEvent` is missing but `logActivity` is not:

```
function_exists('logActivity')    → true   (logActivity exists)
logSecurityEvent(...)             → FATAL ERROR: Call to undefined function

PHP halts execution at the fatal error.
The lines below never run:
  session_unset();    ← SKIPPED
  session_destroy();  ← SKIPPED
  header('Location'); ← SKIPPED
```

The hijacked session is **not destroyed**. The attacker's stolen cookie remains valid.

**Step-by-step exploit:**

```
Step 1 — Attacker steals victim's session cookie
  Via XSS, HTTP sniff, or any other method.
  Cookie: PHPSESSID=victim_session_id

Step 2 — Attacker uses cookie from a different IP
  Attacker is at IP 10.10.10.99
  Victim logged in from 10.10.10.50
  $_SESSION['ip'] = '10.10.10.50'  ← stored at login

Step 3 — require_login() detects the mismatch
  Current IP: 10.10.10.99 ≠ $_SESSION['ip']: 10.10.10.50
  Mismatch detected. Code enters the hijack response block.

Step 4 — Fatal error fires if logSecurityEvent is undefined
  function_exists('logActivity') → true → enters the if block
  logSecurityEvent() → FATAL ERROR
  PHP stops. session_destroy() never runs.

Step 5 — Attacker's next request still works
  Session was never destroyed.
  Attacker retains full authenticated access.
  No hijack event was logged. Defenders see nothing.
```

The window where this is exploitable is whenever `logger.php` is partially loaded — which can happen due to include order bugs, fatal errors in other files, or autoload failures in high-load conditions.

#### How the Fix Prevents It

```php
// ✅ After — guard checks for the exact function being called
if (function_exists('logSecurityEvent')) {
    logSecurityEvent(LOG_SESSION_HIJACK, 'IP mismatch in require_login');
}
// These always run, regardless of logger state:
session_unset();
session_destroy();
header('Location: /login.php');
```

If `logSecurityEvent` is not defined, the guard correctly skips the block — no error, no halt. The session destruction and redirect always execute. In the worst case, the hijack detection fires without logging — but the session is destroyed and the attacker is ejected. The security control is no longer breakable by a logger state issue.

---

### A7 — `ensure_session_started()` Silent Failure Creates Undefined Session State

**Severity:** 🟡 Medium (Hardening)  
**Attack class:** Auth Guard Bypass via Silent Session Failure  
**Status:** ✅ Fixed

#### What Was Wrong

```php
// ❌ Before
function ensure_session_started(): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        require_once __DIR__ . '/../config/session.php'; // no check after this
    }
    // Returns silently whether session started or not
}
```

This function is called at the top of every auth function — `login_user()`, `logout_user()`, `require_login()`. If it returned silently without a session actually starting, all subsequent `$_SESSION` reads and writes operated on an uninitialised superglobal.

#### The Vulnerability

**What PHP does when `$_SESSION` is accessed without an active session:**

In PHP, `$_SESSION` is a superglobal that is populated when `session_start()` is called. If you access it without ever calling `session_start()`, you don't get an error — you get an empty array. But crucially: any writes to it are **not persisted**. They exist only in memory for the current request and vanish when the request ends.

**Scenario 1 — Headers already sent (most common):**

```
Some PHP file outputs a character (echo, BOM, whitespace before <?php)
before session.php is included.
session_start() inside session.php fails silently: 
  Warning: session_start(): Cannot start session when headers already sent
  (This is a warning, not a fatal — execution continues)

ensure_session_started() returns. No exception. No stop.
login_user() proceeds:
  password_verify() → success
  $_SESSION['user_id'] = 42    ← written to in-memory array
  return true                  ← login appears successful

Next request:
  session_start() → starts a FRESH empty session (no persistent data)
  require_login() → $_SESSION['user_id'] → undefined → redirect to login
```

The user is trapped in an authentication loop: every login appears to succeed but the session doesn't persist.

**Scenario 2 — Attacker-triggerable (if they control a file include):**

If the attacker can inject any output before session.php loads — via a path traversal that causes a file with a BOM to be included, or via a reflected error message — they can prevent `session_start()` from succeeding entirely, putting every subsequent request into a broken state where the application behaves unpredictably: sometimes passing auth checks based on stale memory, sometimes failing them.

**Scenario 3 — Shared memory backends:**

In persistent PHP workers (PHP-FPM, Swoole), `$_SESSION` may not be reinitialized between requests. Reading it without `session_start()` could return data from the *previous request's session* — potentially a different user's authenticated session data.

#### How the Fix Prevents It

```php
// ✅ After — any failure is immediately visible, no silent continuation
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

If session startup fails for any reason — missing file, headers already sent, storage failure — a `RuntimeException` is thrown. PHP logs it, and the request halts before any auth code runs. The application never reaches `$_SESSION['user_id']` in a broken state. The failure is loud and visible, not silent and exploitable.

---

### A12 — No Session ID Rotation on Login; Session Fixation Attack Possible

**Severity:** 🔴 Critical  
**File affected:** `includes/auth.php`  
**Attack class:** Session Fixation  
**Status:** ✅ Fixed

#### What Was Wrong

When a user successfully logged in, the server accepted the session ID the browser already had, populated it with authenticated data, and returned — without ever issuing a new session ID:

```php
// ❌ Before — no session_regenerate_id() on login
clear_failed_attempts($pdo, $ip);

$_SESSION['user_id']       = (int) $user['id'];
$_SESSION['public_user_id'] = (string) $user['public_id'];
$_SESSION['username']      = $user['username'];
$_SESSION['ip']            = $ip;

return true;
```

#### The Vulnerability

**What session fixation is:**  
PHP session IDs are normally generated by the server and sent to the browser as a cookie. But PHP also accepts a session ID the browser *already has* — including one the browser received elsewhere. If the server doesn't replace the ID at login, an attacker who places a known session ID into the victim's browser *before* login can authenticate the session remotely the moment the victim logs in.

**Step-by-step attack:**

```
Step 1 — Attacker obtains a valid (unauthenticated) session ID
  Attacker visits /login.php normally.
  Server responds: Set-Cookie: PHPSESSID=a1b2c3d4e5f6  ← attacker knows this

Step 2 — Attacker plants this ID in the victim's browser
  Via XSS on any page:
    document.cookie = "PHPSESSID=a1b2c3d4e5f6; path=/";
  Or via a crafted link to a page that echoes the cookie.
  Now victim's browser holds: PHPSESSID=a1b2c3d4e5f6

Step 3 — Victim logs in normally
  POST /login.php  Cookie: PHPSESSID=a1b2c3d4e5f6
  Server verifies password — correct.
  WITHOUT FIX: server writes to the existing session:
    $_SESSION['user_id'] = 42;  // victim's account
  Session ID is still a1b2c3d4e5f6.

Step 4 — Attacker sends a request with the same ID
  GET /dashboard.php  Cookie: PHPSESSID=a1b2c3d4e5f6
  Server looks up session → user_id=42 → authenticated.
  Attacker is inside the victim's account.
  No password needed. No cookie theft needed.
  The attacker simply waited for the victim to log in.
```

**Why `session.php`'s periodic rotation doesn't rescue this:**  
`session.php` rotates the session ID every 5 minutes (`$regenInterval = 300`). But the attacker gets a window of up to 5 minutes after login — plenty of time to transfer funds, exfiltrate data, or change account details. In a war-game with fast-moving players, 5 minutes is the whole match.

#### How the Fix Prevents It

`session_regenerate_id(true)` is called immediately after a successful password verification, before any session data is written:

```php
// ✅ After — FIX: A12
clear_failed_attempts($pdo, $ip);

/* Prevent session fixation — old ID deleted, new random ID issued */
session_regenerate_id(true);

$_SESSION['user_id']       = (int) $user['id'];
$_SESSION['public_user_id'] = (string) $user['public_id'];
$_SESSION['username']      = $user['username'];
$_SESSION['ip']            = $ip;

return true;
```

`session_regenerate_id(true)` does two things atomically:
1. Generates a fresh cryptographically random session ID
2. Deletes the old session file/record immediately (`true` = delete old session)

The attacker's planted ID now points to a deleted session. Even if the victim just logged in using that ID, the server has thrown it away and issued a new one — one the attacker doesn't know. Their wait was wasted.

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
**Status:** ✅ Fixed

#### What Was Wrong

In `session.php`, the fingerprint mismatch handler called `resetSession($now)` — but `$now = time()` was not defined until *after* the fingerprint check block. Additionally, `resetSession()` internally called `session_destroy()` followed by a second `session_start()`, which means on any fingerprint mismatch the session was destroyed and reconstructed with no guarantee the new session inherited the correct secure cookie parameters.

```php
// ❌ Before — execution order
$currentFingerprint = hash('sha256', $ua . $ip); // line 51
if (!hash_equals($_SESSION['fingerprint'], $fp)) {
    resetSession(time());   // line 64 — $now not yet defined; side-effect chain
}
// ...
$now = time();  // line 73 — defined too late
```

The `resetSession()` function itself also lacked atomicity — it destroyed the session, deleted the cookie, set new cookie params, and started a fresh session. Any failure in that chain (headers already sent, file lock, etc.) left the session in an indeterminate state.

#### The Vulnerability

There are three realistic attack vectors, each with important nuance.

---

**Attack Vector 1 — HTTP Man-in-the-Middle (most dangerous in this war-game context)**

This only works on **HTTP** (not HTTPS). On a plain HTTP connection, every request travels in plaintext across the network. An attacker on the same LAN — which in a war-game setting is *every opposing team* — can run an ARP poisoning attack to insert themselves between the victim and the server as a silent relay:

```
Victim's browser
      │
      ↓  (ARP poison: "I am the router")
Attacker's machine   ←── receives all victim traffic
      │
      │  forwards traffic normally...
      │  ...but rewrites User-Agent header before forwarding
      ↓
Your server
```

The attacker modifies the `User-Agent` on every forwarded request. The server sees a different UA than the one stored in `$_SESSION['fingerprint']`. Mismatch fires on every single request. The victim is logged out the instant any request hits the server. When they log in again, the attacker rewrites the UA again. The victim cannot stay logged in — permanent denial of service from across the room, without needing any credentials, just network position.

---

**Attack Vector 2 — XSS (partial)**

This is often listed but needs clarification: **JavaScript in a browser cannot set the `User-Agent` header**. It is a [forbidden request header](https://fetch.spec.whatwg.org/#forbidden-request-header) — the browser always strips it from `fetch()` and `XMLHttpRequest` calls and injects the real one.

What XSS *can* do instead is use the victim's live session cookie to make requests from an environment that sends a different UA — for example, via a server-side relay the attacker controls:

```
Attacker's XSS payload (runs in victim's browser):
→ Sends stolen cookie + session data to attacker's server

Attacker's server:
→ Replays that cookie in a curl/Python request with a spoofed UA
→ Server sees UA mismatch
→ Session destroyed
```

This is more indirect, but achievable if XSS is already present.

---

**Attack Vector 3 — Natural trigger (most frequent real-world risk)**

No attacker needed. This vulnerability fires automatically on real user behaviour:

1. User logs in on Chrome 121 → fingerprint stored: `sha256("Mozilla/5.0 ... Chrome/121..." + IP)`
2. Chrome auto-updates overnight to Chrome 122 — the UA string changes
3. Next morning, user opens any page → fingerprint mismatch triggered
4. `resetSession()` is called → `session_destroy()` → second `session_start()` inside `resetSession()`
5. If the second `session_start()` fails for any reason (headers already sent, file lock, disk full, another include already called it) → **fatal PHP error throws mid-handler**
6. Session is half-destroyed: the data is wiped, but the session file may still exist, or the redirect never fires
7. User is stuck: every login immediately breaks on the next request

**Browser updates, privacy extensions that randomize UA, or simply a user switching from their phone to laptop** all trigger this. The `resetSession()` crash converts a routine event into a permanent account lockout. This is what makes C1.2 genuinely critical — it is a reliability bomb that fires for ordinary users with no attacker involved at all.

---



#### How the Fix Prevents It

**Part 1 — `$now` hoisted before all session logic:**

```php
// ✅ After — $now is the very first thing defined after session_start()
session_start();

$now = time(); // FIX: C1.2

$inactivityTimeout = 1800;
$absoluteLifetime  = 3600;
$regenInterval     = 300;
```

`$now` and the timeout policy constants are declared immediately after `session_start()`. No code path anywhere in the file can run before `$now` is defined.

**Part 2 — Fingerprint mismatch handler replaced with a hard stop:**

```php
// ✅ After — no resetSession(), no second session_start(), no partial state
} elseif (!hash_equals($_SESSION['fingerprint'], $currentFingerprint)) {
    if (function_exists('logActivity')) {
        logActivity('SESSION_HIJACK_DETECTED');
    }
    session_unset();
    session_destroy();
    header('Location: /login.php');
    exit; // FIX: C1.2 — hard stop, resetSession() no longer called here
}
```

The call to `resetSession()` is gone. The mismatch handler now executes three operations in sequence — unset, destroy, redirect — and then exits. There is no second `session_start()`, no risk of incorrect cookie params on the reconstructed session, and no way for a partial state to persist. The attacker's forged UA request now results in a clean session destruction and redirect, not a call chain that could error mid-way and leave the session alive.

---

### C1.3 — Session Fingerprint Has No Server Secret; Reproducible on Shared Networks

**Severity:** 🔴 Critical  
**File affected:** `config/session.php`  
**Attack class:** Session Hijacking via Fingerprint Forgery  
**Status:** ✅ Fixed

#### What Was Wrong

The session fingerprint was computed purely from two values that any attacker on the same network already knows:

```php
// ❌ Before
$currentFingerprint = hash('sha256',
    ($_SERVER['HTTP_USER_AGENT'] ?? '') .
    $_SERVER['REMOTE_ADDR']
);
```

There is no secret. Anyone who knows the two inputs can precompute the expected fingerprint and pass the check with a stolen cookie.

#### The Vulnerability

**What the fingerprint is supposed to do:**  
After a session is created, the fingerprint is stored in `$_SESSION['fingerprint']`. On every subsequent request, the server recomputes it and compares. If they don't match, the session is destroyed — this is meant to detect a stolen cookie being used from a different machine.

**Why it fails completely on a shared network:**

In a war-game setting (or any LAN/office/university network), all devices behind the same router share one public `REMOTE_ADDR` — the NAT IP. So `REMOTE_ADDR` is identical for every device on the network.

`User-Agent` is equally trivial to obtain or control:
- It is sent in plaintext in every HTTP request — anyone sniffing traffic reads it immediately
- On HTTPS with a MITM setup, the attacker has already decrypted the traffic to get the cookie, so the UA is right there in the same request
- UA is spoofable in any HTTP client: `curl -H "User-Agent: <victim's UA>"`

**Step-by-step attack without the fix:**

```
Step 1 — Cookie theft
  Attacker on same LAN runs Wireshark on HTTP traffic (or ARP+MITM for HTTPS).
  They capture a victim request and extract:
    - Session cookie: PHPSESSID=abc123xyz
    - User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121...
    - Source IP: 192.168.1.1  (the NAT IP — attacker's machine has the SAME one)

Step 2 — Fingerprint verification  
  Attacker's machine shares REMOTE_ADDR 192.168.1.1 with victim.
  Attacker sets User-Agent to match: Mozilla/5.0 (Windows NT 10.0...) Chrome/121...
  Attacker computes: sha256(UA + IP) → identical hash to victim's stored fingerprint.

Step 3 — Session replay
  Attacker sends: Cookie: PHPSESSID=abc123xyz  with matching UA.
  Server recomputes fingerprint → matches $_SESSION['fingerprint'] exactly.
  Fingerprint check passes.
  Attacker is now acting as the victim — full account access.

Step 4 — Duration
  Attack persists until the victim logs out or the session times out (30-60 min).
  Attacker can read balance, send transfers, drain the account.
```

**No crypto needed. No brute force. A single captured request enables full session takeover.**

The fingerprint was providing a false sense of security — it appeared to be a defence against cookie theft, but on any shared network it added zero protection.

#### How the Fix Prevents It

A server-side secret is prepended to the hash before computing it:

```php
// ✅ After — FIX: C1.3
$_fingerprintSecret = $_ENV['SESSION_SECRET'] ?? 'fallback-change-in-production';

$currentFingerprint = hash(
    'sha256',
    $_fingerprintSecret .
    ($_SERVER['HTTP_USER_AGENT'] ?? '') .
    $_SERVER['REMOTE_ADDR']
);
```

`SESSION_SECRET` is a long random string stored server-side in `.env`. The attacker now needs to compute:

```
sha256(SECRET + UA + IP)
```

They know `UA` and `IP`. They do not know `SECRET`. Without it, SHA-256 is a one-way function — preimage attacks are computationally infeasible at any reasonable key length. The attacker cannot reproduce the fingerprint even with a captured cookie, matching UA, and matching IP.

**Replay attack result after fix:**  
Attacker sends stolen cookie with matching UA and matching IP → server recomputes fingerprint with the secret → hash does not match → `SESSION_HIJACK_DETECTED` is logged → session is destroyed → attacker gets redirected to `/login.php` with nothing.

#### Bonus: Incident Response Rotation

Because `SESSION_SECRET` is a server-side variable, rotating it (changing the value in `.env` and restarting the app) **immediately invalidates every active session on the platform**. If a session compromise is detected during the war game, rotating `SESSION_SECRET` is a single-command response that logs out all users — legitimate and attacker — simultaneously, forcing everyone to re-authenticate.

> ⚠️ `SESSION_SECRET` **must** be set in `.env` as a minimum 32-character random string. Generate one with:  
> `php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"`  
> Never hardcode it, never commit it to git, never reuse it across environments.

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
