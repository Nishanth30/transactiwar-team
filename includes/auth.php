<?php
require_once __DIR__ . '/sanitize.php';
require_once __DIR__ . '/../config/session.php';

/* |-------------------------------------------------------------------------- | Security constants |-------------------------------------------------------------------------- */
const LOGIN_DELAY_MIN_US = 250000; // 0.25s base random delay (always applied)
const LOGIN_DELAY_MAX_US = 400000; // 0.40s base random delay (always applied)
const MAX_LOGIN_ATTEMPTS = 20;     // hard lock threshold — only last resort
const LOCKOUT_SECONDS = 1800;      // 30 min hard lock — only after 20 attempts
const ATTEMPT_WINDOW = 900;        // reset counter after 15 min of inactivity
const BACKOFF_CAP_SECONDS = 30;    // max exponential backoff delay per attempt
const MAX_PASSWORD_CHANGE_ATTEMPTS = 5;
const PASSWORD_CHANGE_LOCKOUT_SECONDS = 900;
const PASSWORD_CHANGE_ATTEMPT_WINDOW = 900;
const PASSWORD_CHANGE_BACKOFF_CAP_SECONDS = 16;
const MAX_REGISTRATION_ATTEMPTS = 5;        // M5 FIX: hard lock after 5 attempts per IP
const REGISTRATION_LOCKOUT_SECONDS = 900;   // 15 min lockout
const REGISTRATION_ATTEMPT_WINDOW = 900;    // reset counter after 15 min inactivity
const MAX_SEARCH_ATTEMPTS = 30;             // L4 FIX: per-user search cap per window
const SEARCH_LOCKOUT_SECONDS = 300;         // 5 min cooldown
const SEARCH_ATTEMPT_WINDOW = 60;           // 30 searches per 60 seconds

/*
 * L1 FIX: Explicit bcrypt cost factor used by ALL password_hash calls and
 * the DUMMY_HASH below. The Docker php:8.2-apache image defaults to cost 10,
 * but PASSWORD_DEFAULT's cost can vary across PHP builds. Pinning it here
 * ensures DUMMY_HASH verification takes the same time as real user hashes,
 * eliminating the timing oracle that leaked user existence.
 */
const BCRYPT_COST = 10;

/*
 * Real bcrypt hash used when user is missing.
 * Prevents timing-based user enumeration.
 *
 * IMPORTANT: Must be generated at BCRYPT_COST with the pre-hash scheme:
 *   php -r "echo password_hash(base64_encode(hash('sha384', 'dummy_never_matches', true)), PASSWORD_BCRYPT, ['cost' => 10]);"
 * Never reuse a hash from the internet.
 */
const DUMMY_HASH =
    '$2y$10$WT6nLcra8kUAo6AAp0MJPOJesqh5NjBBySvOD8ogS6uIRaeinc6mi';

/*
 * M6 FIX: Pre-hash passwords with SHA-384 before bcrypt.
 *
 * bcrypt silently truncates input at 72 bytes. With MAX_PASSWORD_LEN = 128,
 * users can create passwords where only the first 72 bytes are hashed —
 * two passwords sharing the same 72-byte prefix are considered identical.
 *
 * SHA-384 produces 48 raw bytes (64 base64 chars), safely under bcrypt's
 * 72-byte limit, while ensuring the ENTIRE password — regardless of length
 * — contributes to the hash.
 *
 * NOTE: Existing password hashes (without pre-hash) must be migrated on
 * next login. See safe_password_verify() for the transparent upgrade path.
 */
function safe_password_hash(string $password): string
{
    $preHash = base64_encode(hash('sha384', $password, true));
    return password_hash($preHash, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
}

function safe_password_verify(string $password, string $hash): bool
{
    // Try the new pre-hash scheme first.
    $preHash = base64_encode(hash('sha384', $password, true));
    if (password_verify($preHash, $hash)) {
        return true;
    }

    // Fall back to legacy direct bcrypt for hashes that predate M6.
    // On successful legacy verify, the caller should rehash with
    // safe_password_hash() to migrate the stored hash.
    return password_verify($password, $hash);
}

function needs_rehash(string $hash): bool
{
    // If password_needs_rehash returns true, OR if the hash was created
    // without the pre-hash scheme (legacy), it needs upgrading.
    // We detect legacy hashes by checking if they verify with a pre-hashed
    // input — but that requires the plaintext, so the caller checks this
    // after a successful safe_password_verify() by attempting the pre-hash
    // path alone. If only the legacy path matched, rehash is needed.
    return password_needs_rehash($hash, PASSWORD_DEFAULT);
}

function ensure_session_version_support(PDO $pdo): void
{
    static $cached = null;

    if ($cached !== null) {
        if (!$cached) {
            throw new RuntimeException('users.session_version column is required');
        }
        return;
    }

    try {
        $stmt = $pdo->query("SHOW COLUMNS FROM users LIKE 'session_version'");
        $hasColumn = (bool) $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$hasColumn) {
            // Auto-heal legacy DB volumes that predate session_version.
            try {
                $pdo->exec("
                    ALTER TABLE users
                    ADD COLUMN session_version INT UNSIGNED NOT NULL DEFAULT 1
                    AFTER password_hash
                ");
            } catch (PDOException $e) {
                // Ignore concurrent add attempts from another request.
                $sqlState = (string) $e->getCode();
                $driverCode = (string) ($e->errorInfo[1] ?? '');
                $isDuplicateColumn = ($sqlState === '42S21' || $driverCode === '1060');
                if (!$isDuplicateColumn) {
                    throw $e;
                }
            }

            $stmt = $pdo->query("SHOW COLUMNS FROM users LIKE 'session_version'");
            $hasColumn = (bool) $stmt->fetch(PDO::FETCH_ASSOC);
        }

        $cached = $hasColumn;
    } catch (Throwable $e) {
        $cached = false;
        throw new RuntimeException(
            'Failed to validate users.session_version support: ' . $e->getMessage(),
            0,
            $e
        );
    }

    if (!$cached) {
        throw new RuntimeException('users.session_version column is required');
    }
}

function normalize_login_identifier(string $identifier): string
{
    return strtolower(trim($identifier));
}

function login_attempt_key(string $identifier, string $ip): string
{
    $identifierHash = substr(hash('sha256', normalize_login_identifier($identifier)), 0, 16);
    $ipHash = substr(hash('sha256', $ip), 0, 16);

    return 'li:' . $identifierHash . ':' . $ipHash;
}


/* |-------------------------------------------------------------------------- | Ensure session exists safely |-------------------------------------------------------------------------- */
function ensure_session_started(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $sessionConfig = __DIR__ . '/../config/session.php';
    if (!file_exists($sessionConfig)) {
        throw new RuntimeException('session.php not found — cannot start session');
    }

    require_once $sessionConfig;

    if (session_status() !== PHP_SESSION_ACTIVE) {
        throw new RuntimeException('Session failed to start');
    }
}


/* |-------------------------------------------------------------------------- | Login attempt throttling (DB-backed) | Keyed by identifier+IP hash - clearing cookies does NOT reset this. | | C2 FIX: gate_login_attempt() uses SELECT … FOR UPDATE to atomically | lock the row, check the lockout state, pre-increment the counter, and | compute the backoff delay — all inside one transaction. This prevents | concurrent requests from reading stale attempt counts and bypassing | the lockout threshold. On successful login the counter is cleared | by clear_failed_attempts() as before. |-------------------------------------------------------------------------- */

/*
 * Atomically gate a login attempt.
 *
 * Returns an associative array:
 *   ['status' => 'locked']                        — hard-locked, reject immediately
 *   ['status' => 'throttled', 'retry_after' => s] — backoff not yet elapsed, reject with 429
 *   ['status' => 'proceed']                       — proceed with password_verify
 *
 * The counter is pre-incremented BEFORE password_verify() runs, so every
 * concurrent request that makes it past the gate sees an accurate count.
 * On successful login, call clear_failed_attempts() to reset.
 */
function gate_login_attempt(PDO $pdo, string $attemptKey): array
{
    $now = time();

    $pdo->beginTransaction();
    try {
        // Lock the row so concurrent requests serialize here.
        $stmt = $pdo->prepare("
            SELECT attempts, locked_until, last_attempt
            FROM login_attempts
            WHERE ip = :ip
            FOR UPDATE
        ");
        $stmt->execute(['ip' => $attemptKey]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        // Hard-lock check (unchanged threshold: MAX_LOGIN_ATTEMPTS failures).
        if ($row && (int) $row['locked_until'] > $now) {
            $pdo->commit();
            return ['status' => 'locked'];
        }

        // Compute backoff from the state BEFORE this increment.
        // H1 FIX: Instead of returning a sleep duration that blocks a PHP-FPM
        // worker, enforce the delay via timestamp: if not enough time has
        // elapsed since last_attempt, reject immediately with retry_after.
        // The attacker still cannot retry faster — they get an instant 429.
        $priorAttempts = 0;
        $lastAttempt   = 0;
        if ($row) {
            $lastAttempt   = (int) $row['last_attempt'];
            $priorAttempts = ($lastAttempt < $now - ATTEMPT_WINDOW)
                ? 0
                : (int) $row['attempts'];
        }

        if ($priorAttempts > 0) {
            $backoff = (int) min(2 ** $priorAttempts, BACKOFF_CAP_SECONDS);
            $elapsed = $now - $lastAttempt;

            if ($elapsed < $backoff) {
                // Not enough time has passed — reject without blocking.
                // Do NOT increment counter: this is a premature retry, not
                // a new credential guess, so it should not accelerate lockout.
                $pdo->commit();
                return [
                    'status'      => 'throttled',
                    'retry_after' => $backoff - $elapsed,
                ];
            }
        }

        // Backoff elapsed (or first attempt). Pre-increment: record this
        // attempt NOW so the next concurrent request that acquires the lock
        // sees the updated counter.
        $pdo->prepare("
            INSERT INTO login_attempts (ip, attempts, locked_until, last_attempt)
            VALUES (:ip, 1, 0, :now)
            ON DUPLICATE KEY UPDATE
                attempts     = IF(last_attempt < :window, 1, attempts + 1),
                locked_until = IF(
                                 IF(last_attempt < :window, 1, attempts + 1) >= :max,
                                 :now + :lockout,
                                 locked_until
                               ),
                last_attempt = :now
        ")->execute([
            'ip'      => $attemptKey,
            'now'     => $now,
            'window'  => $now - ATTEMPT_WINDOW,
            'max'     => MAX_LOGIN_ATTEMPTS,
            'lockout' => LOCKOUT_SECONDS,
        ]);

        $pdo->commit();
        return ['status' => 'proceed'];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}

function clear_failed_attempts(PDO $pdo, string $attemptKey): void
{
    $pdo->prepare("
        DELETE FROM login_attempts WHERE ip = :ip
    ")->execute(['ip' => $attemptKey]);
}

function get_lockout_remaining(PDO $pdo, string $attemptKey): int
{
    $now = time();
    $stmt = $pdo->prepare("
        SELECT locked_until FROM login_attempts WHERE ip = :ip
    ");
    $stmt->execute(['ip' => $attemptKey]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || $row['locked_until'] <= $now) {
        return 0;
    }

    return $row['locked_until'] - $now;
}

function password_change_attempt_key(int $userId, string $ip): string
{
    $ipHash = substr(hash('sha256', $ip), 0, 16);
    return 'pwc:' . $userId . ':' . $ipHash;
}

function is_password_change_locked(PDO $pdo, int $userId, string $ip): bool
{
    $now = time();
    $attemptKey = password_change_attempt_key($userId, $ip);
    $stmt = $pdo->prepare("
        SELECT locked_until
        FROM login_attempts
        WHERE ip = :ip
        LIMIT 1
    ");
    $stmt->execute([
        'ip' => $attemptKey,
    ]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return $row && (int) $row['locked_until'] > $now;
}

function record_password_change_failed_attempt(PDO $pdo, int $userId, string $ip): void
{
    $now = time();
    $attemptKey = password_change_attempt_key($userId, $ip);

    $pdo->prepare("
        INSERT INTO login_attempts (ip, attempts, locked_until, last_attempt)
        VALUES (:ip, 1, 0, :now)
        ON DUPLICATE KEY UPDATE
            attempts     = IF(last_attempt < :window, 1, attempts + 1),
            locked_until = IF(
                             IF(last_attempt < :window, 1, attempts + 1) >= :max,
                             :now + :lockout,
                             locked_until
                           ),
            last_attempt = :now
    ")->execute([
        'ip' => $attemptKey,
        'now' => $now,
        'window' => $now - PASSWORD_CHANGE_ATTEMPT_WINDOW,
        'max' => MAX_PASSWORD_CHANGE_ATTEMPTS,
        'lockout' => PASSWORD_CHANGE_LOCKOUT_SECONDS,
    ]);
}

/*
 * Check whether the password-change backoff period has elapsed.
 * Returns 0 if the caller may proceed, or the remaining seconds to wait.
 * H1 FIX: Enforced via timestamp comparison instead of sleep().
 */
function get_password_change_retry_after(PDO $pdo, int $userId, string $ip): int
{
    $attemptKey = password_change_attempt_key($userId, $ip);
    $now = time();
    $stmt = $pdo->prepare("
        SELECT attempts, last_attempt
        FROM login_attempts
        WHERE ip = :ip
        LIMIT 1
    ");
    $stmt->execute([
        'ip' => $attemptKey,
    ]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || (int) $row['attempts'] === 0) {
        return 0;
    }

    $lastAttempt = (int) $row['last_attempt'];
    if ($lastAttempt < $now - PASSWORD_CHANGE_ATTEMPT_WINDOW) {
        return 0;
    }

    $backoff = (int) min(2 ** (int) $row['attempts'], PASSWORD_CHANGE_BACKOFF_CAP_SECONDS);
    $elapsed = $now - $lastAttempt;

    if ($elapsed < $backoff) {
        return $backoff - $elapsed; // seconds the caller must still wait
    }

    return 0;
}

function clear_password_change_failed_attempts(PDO $pdo, int $userId, string $ip): void
{
    $attemptKey = password_change_attempt_key($userId, $ip);
    $pdo->prepare("
        DELETE FROM login_attempts
        WHERE ip = :ip
    ")->execute([
        'ip' => $attemptKey,
    ]);
}

function get_password_change_lockout_remaining(PDO $pdo, int $userId, string $ip): int
{
    $now = time();
    $attemptKey = password_change_attempt_key($userId, $ip);
    $stmt = $pdo->prepare("
        SELECT locked_until
        FROM login_attempts
        WHERE ip = :ip
        LIMIT 1
    ");
    $stmt->execute([
        'ip' => $attemptKey,
    ]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || (int) $row['locked_until'] <= $now) {
        return 0;
    }

    return (int) $row['locked_until'] - $now;
}

/* |-------------------------------------------------------------------------- | M5 FIX: Registration attempt throttling (DB-backed, IP-keyed) | Reuses the login_attempts table with a 'reg:' prefix to rate-limit | registration attempts. Prevents username/email enumeration at scale, | spam account creation, and bcrypt CPU exhaustion. |-------------------------------------------------------------------------- */

function registration_attempt_key(string $ip): string
{
    return 'reg:' . substr(hash('sha256', $ip), 0, 16);
}

function is_registration_locked(PDO $pdo, string $ip): bool
{
    $now = time();
    $attemptKey = registration_attempt_key($ip);
    $stmt = $pdo->prepare("
        SELECT locked_until
        FROM login_attempts
        WHERE ip = :ip
        LIMIT 1
    ");
    $stmt->execute(['ip' => $attemptKey]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return $row && (int) $row['locked_until'] > $now;
}

function record_registration_attempt(PDO $pdo, string $ip): void
{
    $now = time();
    $attemptKey = registration_attempt_key($ip);

    $pdo->prepare("
        INSERT INTO login_attempts (ip, attempts, locked_until, last_attempt)
        VALUES (:ip, 1, 0, :now)
        ON DUPLICATE KEY UPDATE
            attempts     = IF(last_attempt < :window, 1, attempts + 1),
            locked_until = IF(
                             IF(last_attempt < :window, 1, attempts + 1) >= :max,
                             :now + :lockout,
                             locked_until
                           ),
            last_attempt = :now
    ")->execute([
        'ip'      => $attemptKey,
        'now'     => $now,
        'window'  => $now - REGISTRATION_ATTEMPT_WINDOW,
        'max'     => MAX_REGISTRATION_ATTEMPTS,
        'lockout' => REGISTRATION_LOCKOUT_SECONDS,
    ]);
}

function get_registration_lockout_remaining(PDO $pdo, string $ip): int
{
    $now = time();
    $attemptKey = registration_attempt_key($ip);
    $stmt = $pdo->prepare("
        SELECT locked_until
        FROM login_attempts
        WHERE ip = :ip
        LIMIT 1
    ");
    $stmt->execute(['ip' => $attemptKey]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || (int) $row['locked_until'] <= $now) {
        return 0;
    }

    return (int) $row['locked_until'] - $now;
}


/* |-------------------------------------------------------------------------- | L4 FIX: Search attempt throttling (DB-backed, user-keyed) | Prevents brute-force username enumeration via the exact-match search. | Keyed by user ID so attackers cannot evade by switching IPs. |-------------------------------------------------------------------------- */

function search_attempt_key(int $userId): string
{
    return 'search:' . $userId;
}

function is_search_locked(PDO $pdo, int $userId): bool
{
    $now = time();
    $attemptKey = search_attempt_key($userId);
    $stmt = $pdo->prepare("
        SELECT locked_until
        FROM login_attempts
        WHERE ip = :ip
        LIMIT 1
    ");
    $stmt->execute(['ip' => $attemptKey]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return $row && (int) $row['locked_until'] > $now;
}

function record_search_attempt(PDO $pdo, int $userId): void
{
    $now = time();
    $attemptKey = search_attempt_key($userId);

    $pdo->prepare("
        INSERT INTO login_attempts (ip, attempts, locked_until, last_attempt)
        VALUES (:ip, 1, 0, :now)
        ON DUPLICATE KEY UPDATE
            attempts     = IF(last_attempt < :window, 1, attempts + 1),
            locked_until = IF(
                             IF(last_attempt < :window, 1, attempts + 1) >= :max,
                             :now + :lockout,
                             locked_until
                           ),
            last_attempt = :now
    ")->execute([
        'ip'      => $attemptKey,
        'now'     => $now,
        'window'  => $now - SEARCH_ATTEMPT_WINDOW,
        'max'     => MAX_SEARCH_ATTEMPTS,
        'lockout' => SEARCH_LOCKOUT_SECONDS,
    ]);
}


/*
 * Change password for an authenticated user.
 *
 * Returns:
 *   true              -> success
 *   'locked'          -> temporary lockout active
 *   'throttled'       -> backoff not elapsed, caller should return 429
 *   'invalid_current' -> current password mismatch
 *   'same_password'   -> new password equals current
 *   false             -> unexpected failure
 */
function change_password_for_user(
    PDO $pdo,
    int $userId,
    string $currentPassword,
    string $newPassword,
    string $ip
): bool|string {
    if (is_password_change_locked($pdo, $userId, $ip)) {
        usleep(random_int(LOGIN_DELAY_MIN_US, LOGIN_DELAY_MAX_US));
        return 'locked';
    }

    // H1 FIX: Enforce backoff via timestamp, not sleep().
    $retryAfter = get_password_change_retry_after($pdo, $userId, $ip);
    if ($retryAfter > 0) {
        header('Retry-After: ' . $retryAfter);
        http_response_code(429);
        return 'throttled';
    }

    try {
        ensure_session_version_support($pdo);
        $pdo->beginTransaction();

        $stmt = $pdo->prepare("
            SELECT password_hash
            FROM users
            WHERE id = :id
            FOR UPDATE
        ");
        $stmt->execute(['id' => $userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || empty($user['password_hash'])) {
            $pdo->rollBack();
            return false;
        }

        $storedHash = (string) $user['password_hash'];
        $currentMatches = safe_password_verify($currentPassword, $storedHash);
        usleep(random_int(LOGIN_DELAY_MIN_US, LOGIN_DELAY_MAX_US));

        if (!$currentMatches) {
            $pdo->rollBack();
            record_password_change_failed_attempt($pdo, $userId, $ip);
            return 'invalid_current';
        }

        if (safe_password_verify($newPassword, $storedHash)) {
            $pdo->rollBack();
            return 'same_password';
        }

        $newHash = safe_password_hash($newPassword);
        $updateStmt = $pdo->prepare("
            UPDATE users
            SET password_hash = :password_hash,
                session_version = session_version + 1
            WHERE id = :id
            LIMIT 1
        ");

        $updateStmt->execute([
            'password_hash' => $newHash,
            'id' => $userId,
        ]);

        $pdo->commit();
        clear_password_change_failed_attempts($pdo, $userId, $ip);
        return true;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log('Password change failed: ' . get_class($e) . ' code=' . $e->getCode());
        return false;
    }
}


/* |-------------------------------------------------------------------------- | Register user |-------------------------------------------------------------------------- | Returns: |   true        -> success |   'duplicate' -> username/email exists |   false       -> validation or unexpected failure | | Duplicate detection is handled atomically by the DB UNIQUE constraint, | avoiding the TOCTOU race condition of a pre-check SELECT. |-------------------------------------------------------------------------- */
function generate_uuid_v4(): string
{
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function register_user(PDO $pdo, string $username, string $email, string $password): bool|string
{
    $username = trim($username);
    $email = normalize_email($email);

    if ($username === '' || $email === '' || $password === '') {
        return false;
    }

    if (
    !validate_username($username) ||
    !validate_email($email) ||
    !validate_password($password)
    ) {
        return false;
    }

    $hash = safe_password_hash($password);

    try {
        $stmt = $pdo->prepare("
            INSERT INTO users (public_id, username, email, password_hash)
            VALUES (:public_id, :username, :email, :password_hash)
        ");
        $stmt->execute([
            'public_id' => generate_uuid_v4(),
            'username' => $username,
            'email' => $email,
            'password_hash' => $hash
        ]);
        //Adding this
        if (function_exists('logActivity')) {
            logActivity(LOG_REGISTER);
        }


        return true;

    }
    catch (PDOException $e) {
        // SQLSTATE 23000 = integrity constraint violation (duplicate key)
        if ($e->getCode() === '23000') {
            // Adding this
            if (function_exists('logActivity')) {
                logActivity(LOG_INVALID_INPUT);
            }
            return 'duplicate';
        }

        error_log('Register failed: ' . get_class($e) . ' code=' . $e->getCode());
        return false;
    }
}


/* |-------------------------------------------------------------------------- | Login user |-------------------------------------------------------------------------- | Returns: |   true        -> success |   'locked'    -> identifier/IP hard-locked (MAX_LOGIN_ATTEMPTS exceeded) |   'throttled' -> backoff not elapsed, 429 + Retry-After already sent |   'system'    -> session subsystem unavailable |   false       -> invalid credentials | | Security: | - DB-backed identifier+IP throttling (cookie-clearing resistant) | - Anti-enumeration timing protection | - Randomized brute-force delay | - Session fixation prevention | - Session IP binding | - Backoff enforced via timestamp check, not sleep() (H1 fix) |-------------------------------------------------------------------------- */
function login_user(PDO $pdo, string $identifier, string $password): bool|string
{
    ensure_session_started();
    try {
        ensure_session_version_support($pdo);
    } catch (Throwable $e) {
        error_log('Session version support missing during login: ' . get_class($e) . ' code=' . $e->getCode());
        if (function_exists('logSecurityEvent')) {
            logSecurityEvent(LOG_SUSPICIOUS, 'session_version_unavailable_login');
        }
        return 'system';
    }

    $ip = function_exists('get_client_ip')
        ? get_client_ip()
        : sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    $identifier = trim($identifier);

    if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
        $sql = "
            SELECT id, public_id, username, password_hash, session_version
            FROM users
            WHERE email = :id
            LIMIT 1
        ";
        $identifier = normalize_email($identifier);
    } else {
        $sql = "
            SELECT id, public_id, username, password_hash, session_version
            FROM users
            WHERE username = :id
            LIMIT 1
        ";
    }

    $stmt = $pdo->prepare($sql);
    $stmt->execute(['id' => $identifier]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    $attemptKey = $user
        ? login_attempt_key('uid:' . (string) $user['id'], $ip)
        : login_attempt_key($identifier, $ip);

    // Atomic gate: SELECT … FOR UPDATE serializes concurrent attempts,
    // checks lockout, pre-increments counter, and computes backoff.
    // Counter is pre-incremented; cleared on success by clear_failed_attempts().
    $gate = gate_login_attempt($pdo, $attemptKey);

    if ($gate['status'] === 'locked') {
        if (function_exists('logActivity')) {
            logActivity(LOG_LOGIN_LOCKED);
        }
        usleep(random_int(LOGIN_DELAY_MIN_US, LOGIN_DELAY_MAX_US));
        return 'locked';
    }

    // H1 FIX: Backoff is now enforced by timestamp, not sleep().
    // If the required delay hasn't elapsed, reject instantly with retry_after
    // so the PHP-FPM worker is freed immediately (~50 concurrent requests
    // can no longer exhaust the pool by sleeping for 30s each).
    if ($gate['status'] === 'throttled') {
        if (function_exists('logActivity')) {
            logActivity(LOG_LOGIN_LOCKED);
        }
        header('Retry-After: ' . $gate['retry_after']);
        http_response_code(429);
        return 'throttled';
    }

    // Always verify against a real hash to resist timing-based user enumeration.
    $hashToCheck = $user['password_hash'] ?? DUMMY_HASH;
    $valid = safe_password_verify($password, $hashToCheck);

    usleep(random_int(LOGIN_DELAY_MIN_US, LOGIN_DELAY_MAX_US));

    if (!$user || !$valid) {
        // Counter already pre-incremented by gate_login_attempt().
        if (function_exists('logActivity')) {
            logActivity(LOG_LOGIN_FAIL);
        }
        return false;
    }

    // Successful login clears only this identifier+IP throttle key.
    clear_failed_attempts($pdo, $attemptKey);

    // M6: Transparently migrate legacy hashes (pre-M6, no SHA-384 pre-hash)
    // to the new scheme on successful login. The pre-hash path in
    // safe_password_verify tried first; if only the legacy fallback matched,
    // the hash needs upgrading.
    $preHash = base64_encode(hash('sha384', $password, true));
    if (!password_verify($preHash, $hashToCheck)) {
        // Legacy hash — upgrade it now while we have the plaintext.
        try {
            $pdo->prepare("
                UPDATE users SET password_hash = :hash WHERE id = :id LIMIT 1
            ")->execute([
                'hash' => safe_password_hash($password),
                'id'   => (int) $user['id'],
            ]);
        } catch (Throwable $e) {
            // Non-fatal: login succeeds, rehash retried next login.
            error_log('M6 rehash failed for user ' . (int) $user['id'] . ': code=' . $e->getCode());
        }
    }

    session_regenerate_id(true);

    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['public_user_id'] = (string)$user['public_id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['session_version'] = (int)($user['session_version'] ?? 1);

    // Bind session to client IP to reduce stolen-cookie reuse.
    $_SESSION['ip'] = $ip;
    if (function_exists('logActivity')) {
        logActivity(LOG_LOGIN_SUCCESS);
    }
    return true;
}
/* |-------------------------------------------------------------------------- | Require login |-------------------------------------------------------------------------- */
function require_login(): void
{
    ensure_session_started();


    if (!isset($_SESSION['user_id'])) {
        if (function_exists('logActivity')) {
            logActivity(LOG_ACCESS_DENIED); // who tried to access without login
        }
        header('Location: /login.php');
        exit;
    }

    /*
     * Session IP binding check.
     * Kills the session if the IP has changed - prevents cookie hijacking.
     */
    $ip = function_exists('get_client_ip')
        ? get_client_ip()
        : sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

    if (($_SESSION['ip'] ?? '') !== $ip) {
        // ADD THIS - on IP mismatch (Change 6)
        if (function_exists('logSecurityEvent')) {
            logSecurityEvent(LOG_SESSION_HIJACK, 'IP mismatch in require_login');
        }
        session_unset();
        session_destroy();

        header('Location: /login.php');
        exit;
    }

    try {
        $pdo = null;
        if (isset($GLOBALS['pdo']) && $GLOBALS['pdo'] instanceof PDO) {
            $pdo = $GLOBALS['pdo'];
        } else {
            require __DIR__ . '/../config/db.php';
            if (isset($pdo) && $pdo instanceof PDO) {
                $GLOBALS['pdo'] = $pdo;
            } elseif (isset($GLOBALS['pdo']) && $GLOBALS['pdo'] instanceof PDO) {
                $pdo = $GLOBALS['pdo'];
            }
        }

        if (!($pdo instanceof PDO)) {
            throw new RuntimeException('PDO not available in require_login');
        }

        ensure_session_version_support($pdo);

        if (!isset($_SESSION['session_version'])) {
            if (function_exists('logSecurityEvent')) {
                logSecurityEvent(LOG_SESSION_HIJACK, 'Missing session version');
            }
            session_unset();
            session_destroy();
            header('Location: /login.php');
            exit;
        }

        $stmt = $pdo->prepare("
            SELECT session_version
            FROM users
            WHERE id = :id
            LIMIT 1
        ");
        $stmt->execute(['id' => (int)$_SESSION['user_id']]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        $dbSessionVersion = (int)($row['session_version'] ?? 0);
        $sessionVersion = (int)$_SESSION['session_version'];

        if (!$row || $dbSessionVersion !== $sessionVersion) {
            if (function_exists('logSecurityEvent')) {
                logSecurityEvent(LOG_SESSION_HIJACK, 'Session version mismatch');
            }
            session_unset();
            session_destroy();
            header('Location: /login.php');
            exit;
        }
    } catch (Throwable $e) {
        error_log('require_login session version check failed: ' . get_class($e) . ' code=' . $e->getCode());
        session_unset();
        session_destroy();
        header('Location: /login.php');
        exit;
    }
}

/* |-------------------------------------------------------------------------- | Public ID helpers for search + transfer modules |-------------------------------------------------------------------------- */
function resolve_user_id_from_public_id(PDO $pdo, string $publicId): ?int
{
    // $publicId = sanitize_public_user_id($publicId);   Rename it - Change 7
    $publicId = sanitize_uuid($publicId);

    if ($publicId === null) {
        return null;
    }

    $stmt = $pdo->prepare("
        SELECT id
        FROM users
        WHERE public_id = :public_id
        LIMIT 1
    ");
    $stmt->execute(['public_id' => $publicId]);

    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        return null;
    }

    return (int)$row['id'];
}

function get_user_by_public_id(PDO $pdo, string $publicId): ?array
{
    // $publicId = sanitize_public_user_id($publicId);
    $publicId = sanitize_uuid($publicId);
    if ($publicId === null) {
        return null;
    }

    $stmt = $pdo->prepare("
        SELECT id, public_id, username, bio, profile_image_path
        FROM users
        WHERE public_id = :public_id
        LIMIT 1
    ");
    $stmt->execute(['public_id' => $publicId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return $row ?: null;
}

function get_own_profile(PDO $pdo, int $userId): ?array
{
    $stmt = $pdo->prepare("
        SELECT id, public_id, username, email, balance_paise, bio, profile_image_path
        FROM users WHERE id = :id LIMIT 1
    ");
    $stmt->execute(['id' => $userId]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}


//Adding logic for logout_user
function logout_user(): void
{
    ensure_session_started();

    // Log BEFORE destroying session
    // user_id still available here
    if (function_exists('logActivity')) {
        logActivity(LOG_LOGOUT);
    }

    session_regenerate_id(true);
    // Wipe session data
    $_SESSION = [];

    // Delete cookie from browser
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
        [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'] ?? 'Lax',
        ]
        );
    }

    // Destroy server side session
    session_destroy();
}
