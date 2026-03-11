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

/*
 * Real bcrypt hash used when user is missing.
 * Prevents timing-based user enumeration.
 *
 * IMPORTANT: Regenerate with password_hash('dummy', PASSWORD_DEFAULT)
 * and replace - never reuse a hash from the internet.
 */
const DUMMY_HASH =
    '$2y$12$KIXsvMrxRbLQn5oTMHuSPOY/hGKPSfLpFBG7GiKVcI5Fg2NeRRdYu';


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


/* |-------------------------------------------------------------------------- | IP-based rate limiting (DB-backed) | Keyed by IP - clearing cookies does NOT reset this. |-------------------------------------------------------------------------- */
function is_ip_locked(PDO $pdo, string $ip): bool
{
    $now = time();
    $stmt = $pdo->prepare("
        SELECT attempts, locked_until, last_attempt
        FROM login_attempts
        WHERE ip = :ip
    ");
    $stmt->execute(['ip' => $ip]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return false;
    }

    // Still within lockout window
    if ($row['locked_until'] > $now) {
        return true;
    }

    return false;
}

function record_failed_attempt(PDO $pdo, string $ip): void
{
    $now = time();

    /*
     * INSERT new record or UPDATE existing.
     * If last attempt was outside the activity window, reset counter.
     * locked_until is only set once MAX_LOGIN_ATTEMPTS (20) is reached
     * — the exponential backoff handles throttling before that point.
     */
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
        'ip' => $ip,
        'now' => $now,
        'window' => $now - ATTEMPT_WINDOW,
        'max' => MAX_LOGIN_ATTEMPTS,
        'lockout' => LOCKOUT_SECONDS,
    ]);
}

/*
 * Exponential backoff delay based on prior failed attempts.
 * Returns seconds of delay to apply BEFORE checking the password.
 *
 * Formula: 2^attempts seconds, capped at BACKOFF_CAP_SECONDS.
 * Loose cap (30s) is intentional — strong password rules already
 * make brute force impractical without aggressive lockout.
 *
 * Delay schedule:
 *   1 fail  →  2s
 *   2 fails →  4s
 *   3 fails →  8s
 *   4 fails → 16s
 *   5+ fails→ 30s (cap)
 */
function get_backoff_delay(PDO $pdo, string $ip): int
{
    $stmt = $pdo->prepare("
        SELECT attempts, last_attempt
        FROM login_attempts
        WHERE ip = :ip
    ");
    $stmt->execute(['ip' => $ip]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || $row['attempts'] === 0) {
        return 0;
    }

    // Reset if outside the activity window
    if ($row['last_attempt'] < time() - ATTEMPT_WINDOW) {
        return 0;
    }

    $delay = (int) min(2 ** $row['attempts'], BACKOFF_CAP_SECONDS);
    return $delay;
}

function clear_failed_attempts(PDO $pdo, string $ip): void
{
    $pdo->prepare("
        DELETE FROM login_attempts WHERE ip = :ip
    ")->execute(['ip' => $ip]);
}

function get_lockout_remaining(PDO $pdo, string $ip): int
{
    $now = time();
    $stmt = $pdo->prepare("
        SELECT locked_until FROM login_attempts WHERE ip = :ip
    ");
    $stmt->execute(['ip' => $ip]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || $row['locked_until'] <= $now) {
        return 0;
    }

    return $row['locked_until'] - $now;
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

    $hash = password_hash($password, PASSWORD_DEFAULT);

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

        error_log('Register failed: ' . $e->getMessage());
        return false;
    }
}


/* |-------------------------------------------------------------------------- | Login user |-------------------------------------------------------------------------- | Returns: |   true     -> success |   'locked' -> IP is rate-limited |   false    -> invalid credentials | | Security: | - DB-backed IP rate limiting (cookie-clearing resistant) | - Anti-enumeration timing protection | - Randomized brute-force delay | - Session fixation prevention | - Session IP binding |-------------------------------------------------------------------------- */
function login_user(PDO $pdo, string $identifier, string $password): bool|string
{
    ensure_session_started();

    $ip = function_exists('get_client_ip')
        ? get_client_ip()
        : sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

    // Hard lock check — only triggers after MAX_LOGIN_ATTEMPTS (20) failures
    if (is_ip_locked($pdo, $ip)) {
        if (function_exists('logActivity')) {
            logActivity(LOG_LOGIN_LOCKED);
        }
        usleep(random_int(LOGIN_DELAY_MIN_US, LOGIN_DELAY_MAX_US));
        return 'locked';
    }

    // Exponential backoff — server-side enforced sleep based on prior failures.
    // Applied BEFORE password_verify so even a correct guess is slowed down.
    $backoffSeconds = get_backoff_delay($pdo, $ip);
    if ($backoffSeconds > 0) {
        sleep($backoffSeconds);
    }

    $identifier = trim($identifier);

    /*
     * Split query to avoid username/email ambiguity -
     * prevents edge cases where a username looks like an email.
     */
    if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
        $sql = "
            SELECT id, public_id, username, password_hash
            FROM users
            WHERE email = :id
            LIMIT 1
        ";
    }
    else {
        $sql = "
            SELECT id, public_id, username, password_hash
            FROM users
            WHERE username = :id
            LIMIT 1
        ";
    }

    $stmt = $pdo->prepare($sql);
    $stmt->execute(['id' => $identifier]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    /*
     * Always run password_verify() even when user not found.
     * DUMMY_HASH is a real bcrypt hash so full computation always runs,
     * preventing timing-based user enumeration.
     */
    $hashToCheck = $user['password_hash'] ?? DUMMY_HASH;
    $valid = password_verify($password, $hashToCheck);

    // Random delay - slows brute force and hides timing differences
    usleep(random_int(LOGIN_DELAY_MIN_US, LOGIN_DELAY_MAX_US));

    if (!$user || !$valid) {

        record_failed_attempt($pdo, $ip);
        // ADD THIS
        if (function_exists('logActivity')) {
            logActivity(LOG_LOGIN_FAIL);
        }

        return false;
    }

    // Successful login - clear rate limit record for this IP
    clear_failed_attempts($pdo, $ip);

    /* Prevent session fixation */
    session_regenerate_id(true);

    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['public_user_id'] = (string)$user['public_id'];
    $_SESSION['username'] = $user['username'];

    /*
     * Bind session to client IP.
     * Invalidates stolen cookies used from a different IP.
     */
    $_SESSION['ip'] = $ip;
    // ADD THIS - on success (Change 5)
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
