# TRANSACTIWAR — Security Fix Prompt for Claude Sonnet 4.6

## CONTEXT

You are working on a PHP web application called **TRANSACTIWAR** — a payment/transaction war-game app. A security audit has been completed and **20 issues** (14 critical, 6 medium) have been identified across 6 files.

Your job is to **apply every fix listed below**, one file at a time, in full. Do not skip any fix. Do not summarise — actually rewrite the affected code.

The 6 files that need editing are:

1. `includes/auth.php`
2. `config/session.php`
3. `process_payment.php`
4. `index.php`
5. `logger.php`
6. `login.php`

---

## RULES BEFORE YOU START

- Read each fix carefully before touching code.
- Apply fixes in the order they appear within each file section.
- Where a fix conflicts with another (see A3 vs A4 below — a known tension), use the **reconciled version** provided.
- After each file, output the **complete rewritten file** — not just the changed lines.
- Add a short `// FIX: <ID>` inline comment at each changed line so fixes are traceable.
- Do not introduce new logic beyond what is described.

---

## ⚠️ IMPORTANT: Reconcile A3 vs A4

Fix A3 says: return `false` for locked accounts.
Fix A4 says: log `LOG_LOGIN_LOCKED` for locked accounts.

**Both should be applied together.** The correct reconciled code is:

```php
if (is_ip_locked($pdo, $ip)) {
    logActivity(LOG_LOGIN_LOCKED);                                    // FIX: A4
    usleep(random_int(LOGIN_DELAY_MIN_US, LOGIN_DELAY_MAX_US));
    return false;                                                      // FIX: A3
}
```

---

## FILE 1 — `includes/auth.php`

### A1 — Fix incorrect session.php path in `ensure_session_started()`

Find:
```php
require_once __DIR__ . '/session.php';
```
Replace with:
```php
require_once __DIR__ . '/../config/session.php'; // FIX: A1
```

---

### A2 — Remove sensitive fields from `get_user_by_public_id()`

Find the SELECT inside `get_user_by_public_id()`:
```sql
SELECT id, public_id, username, email, balance_paise, bio, profile_image_path
FROM users WHERE public_id = :public_id
```
Replace with:
```sql
SELECT id, public_id, username, bio, profile_image_path
FROM users WHERE public_id = :public_id
```
// FIX: A2 — email and balance_paise removed from public lookup

Then add this new function anywhere in the file:
```php
// FIX: A2 — owner-only profile fetch (includes sensitive fields)
function get_own_profile(PDO $pdo, int $userId): ?array
{
    $stmt = $pdo->prepare("
        SELECT id, public_id, username, email, balance_paise, bio, profile_image_path
        FROM users WHERE id = :id LIMIT 1
    ");
    $stmt->execute(['id' => $userId]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}
```

---

### A3 + A4 (reconciled) — Fix login lockout logic + restore logging

Inside `login_user()`, find the IP lock check and apply:
```php
if (is_ip_locked($pdo, $ip)) {
    logActivity(LOG_LOGIN_LOCKED);                                    // FIX: A4
    usleep(random_int(LOGIN_DELAY_MIN_US, LOGIN_DELAY_MAX_US));
    return false;                                                      // FIX: A3
}
```

---

### A5 — Fix cookie deletion (add SameSite to setcookie)

Find the old `setcookie()` call in the logout function that deletes the session cookie.
Replace it with:
```php
setcookie(                                                             // FIX: A5
    session_name(),
    '',
    [
        'expires'  => time() - 42000,
        'path'     => $params['path'],
        'domain'   => $params['domain'],
        'secure'   => $params['secure'],
        'httponly' => $params['httponly'],
        'samesite' => $params['samesite'] ?? 'Lax',
    ]
);
```

---

### A6 — Replace `$_SERVER['REMOTE_ADDR']` with `get_client_ip()`

In `login_user()` and `require_login()`, find every occurrence of:
```php
$_SERVER['REMOTE_ADDR']
```
Replace with:
```php
get_client_ip() // FIX: A6
```

---

### A7 — Harden `ensure_session_started()`

Replace the entire function body with:
```php
function ensure_session_started(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {        // FIX: A7
        return;
    }

    $sessionConfig = __DIR__ . '/../config/session.php';

    if (!file_exists($sessionConfig)) {
        throw new RuntimeException('session.php config missing'); // FIX: A7
    }

    require_once $sessionConfig;

    if (session_status() !== PHP_SESSION_ACTIVE) {
        throw new RuntimeException('Session failed to start');   // FIX: A7
    }
}
```

---

### A8 — Add UUID v4 generator (use PHP, not DB)

Add this new function to the file:
```php
// FIX: A8 — UUID v4 generated in PHP to avoid DB UUID v1 predictability
function generate_uuid_v4(): string {
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}
```
Anywhere in the codebase that calls `UUID()` via SQL or uses DB-generated UUIDs for `public_id`, replace with `generate_uuid_v4()`.

---

### A9 — Harden logout session invalidation

In the logout function, before `session_destroy()`, add:
```php
session_regenerate_id(true);  // FIX: A9
$_SESSION = [];               // FIX: A9
session_destroy();
```

---

### A10 — Fix logger function existence check

Find:
```php
if (function_exists('logActivity'))
```
Replace with:
```php
if (function_exists('logSecurityEvent')) // FIX: A10
```

---

### A11 — Remove dead commented-out code

Delete any old commented-out `require_login()` block. // FIX: A11

---

## FILE 2 — `config/session.php`

### S1 — Define `$now` before it is used (fixes crash)

Find the file's opening logic. Move this line to the **very top** of the file, before any call to `resetSession()`:
```php
$now = time(); // FIX: S1 — must be defined before resetSession() is called
```

---

### S2 — Add server-side secret salt to session fingerprint

Find where `$currentFingerprint` is computed. Replace it with:
```php
// FIX: S2 — adds server secret to prevent fingerprint prediction under shared NAT
$secret = $_ENV['SESSION_SECRET'] ?? 'fallback-secret';

$currentFingerprint = hash(
    'sha256',
    $secret .
    ($_SERVER['HTTP_USER_AGENT'] ?? '') .
    $_SERVER['REMOTE_ADDR']
);
```
Note: `SESSION_SECRET` must be set in your `.env` file as a long random string. Warn the team about this.

---

### S3 — Replace fingerprint-mismatch crash with secure logout

Find the fingerprint comparison block. Replace the crash/error behaviour with:
```php
// FIX: S3 — secure logout on fingerprint mismatch instead of fatal crash
if (!hash_equals($_SESSION['fingerprint'], $currentFingerprint)) {
    logActivity('SESSION_HIJACK_DETECTED');
    session_unset();
    session_destroy();
    header("Location: /login.php");
    exit;
}
```

---

## FILE 3 — `process_payment.php`

### P1 — Prevent integer overflow in balance check

Find where sender balance is checked against amount:
```php
(int)$sender['balance_paise']
```
Replace the comparison with:
```php
// FIX: P1 — use bccomp to avoid PHP_INT_MAX overflow on large paise values
if (bccomp($sender['balance_paise'], $amount_paise) < 0) {
    throw new Exception("Insufficient balance");
}
```
Remove any existing `(int)` cast from balance fields throughout this file.

---

### P2 — Prevent deadlocks by locking rows in deterministic order

Find the transaction block where sender and receiver rows are locked with `FOR UPDATE`. Replace with:
```php
// FIX: P2 — lock in ascending ID order to eliminate deadlock injection
$first  = min($sender_id, $receiver_id);
$second = max($sender_id, $receiver_id);

$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id FOR UPDATE");
$stmt->execute(['id' => $first]);
$rowFirst = $stmt->fetch(PDO::FETCH_ASSOC);

$stmt->execute(['id' => $second]);
$rowSecond = $stmt->fetch(PDO::FETCH_ASSOC);

// Re-assign to sender/receiver based on original IDs
$sender   = ($first === $sender_id)   ? $rowFirst : $rowSecond;
$receiver = ($first === $receiver_id) ? $rowFirst : $rowSecond;
```

---

## FILE 4 — `index.php`

### I1 — Gate diagnostic/schema output behind admin check

Find the public diagnostic block (the one that exposes DB schema). Wrap it:
```php
// FIX: I1 — diagnostic mode must never be publicly accessible
if (!isset($_SESSION['user_id']) || !is_admin()) {
    http_response_code(403);
    exit("Forbidden");
}
```
If the diagnostic block has no legitimate use in production, remove it entirely.

---

## FILE 5 — `logger.php`

### L1 — Stop trusting `X-Forwarded-For` unconditionally

Find the current `get_client_ip()` implementation. Replace it with:
```php
// FIX: L1 — only trust X-Forwarded-For from known trusted proxies
function get_client_ip(): string {
    $trusted_proxies = ['127.0.0.1'];

    if (in_array($_SERVER['REMOTE_ADDR'], $trusted_proxies, true)) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
    }

    return $_SERVER['REMOTE_ADDR'];
}
```

---

### L2 — Eliminate duplicate failed-login logging

Find where both `record_failed_attempt()` **and** `recordFailedLogin()` are called for the same event. Remove one of them.

Decide on a single canonical function — recommended: keep `record_failed_attempt()` if it handles rate limiting too, otherwise keep `recordFailedLogin()`. Remove every call to the discarded function. // FIX: L2

---

## FILE 6 — `login.php`

### LG1 — Use strict equality when checking login result

Find:
```php
if (login_user(...))
```
Replace with:
```php
// FIX: LG1 — strict check prevents truthy 'locked' string from bypassing auth
$result = login_user(...);

if ($result === true) {
    // Successful login — start session, redirect
}
elseif ($result === false && /* locked condition */ is_ip_locked($pdo, get_client_ip())) {
    // Account/IP is locked — show lockout message
}
else {
    // Invalid credentials — show error
}
```
Adjust the condition to match however your code detects the locked vs wrong-password distinction (e.g. a separate flag, session variable, or additional function call).

---

## AFTER ALL FIXES

1. Run `php -l` on every modified file to confirm no parse errors.
2. Confirm `SESSION_SECRET` is set in `.env`.
3. Search the entire codebase for any remaining `$_SERVER['REMOTE_ADDR']` that bypasses `get_client_ip()`.
4. Search for any remaining `UUID()` SQL calls that should now use `generate_uuid_v4()`.
5. Confirm no other page calls `get_user_by_public_id()` and then reads `email` or `balance_paise` from the result (those fields no longer exist in the return value).

---

## SUMMARY TABLE

| Fix ID | File                  | Severity | Description                              |
|--------|-----------------------|----------|------------------------------------------|
| A1     | auth.php              | Critical | Wrong session.php path                   |
| A2     | auth.php              | Critical | Email/balance exposed in public lookup   |
| A3     | auth.php              | Critical | Locked returns truthy string             |
| A4     | auth.php              | Critical | Security logging was commented out       |
| A5     | auth.php              | Critical | SameSite missing on cookie delete        |
| A6     | auth.php              | Medium   | REMOTE_ADDR instead of get_client_ip()   |
| A7     | auth.php              | Medium   | ensure_session_started() not hardened    |
| A8     | auth.php              | Medium   | DB UUID v1 used instead of PHP UUID v4   |
| A9     | auth.php              | Medium   | Logout doesn't regenerate session ID     |
| A10    | auth.php              | Medium   | Wrong logger function existence check    |
| A11    | auth.php              | Medium   | Dead commented code left in              |
| S1     | session.php           | Critical | $now used before defined (crash)         |
| S2     | session.php           | Critical | Fingerprint has no server secret salt    |
| S3     | session.php           | Critical | Fingerprint mismatch causes fatal crash  |
| P1     | process_payment.php   | Critical | Integer overflow in balance check        |
| P2     | process_payment.php   | Critical | Deadlock via non-deterministic row lock  |
| I1     | index.php             | Critical | DB schema exposed publicly               |
| L1     | logger.php            | Critical | XFF header trusted unconditionally       |
| L2     | logger.php            | Critical | Duplicate failed-login logging           |
| LG1    | login.php             | Critical | Truthy string bypasses login check       |
