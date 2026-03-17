<?php
// includes/logger.php
// Activity & Security Logger
// Requirement 4: Webpage, Username, Timestamp, Client IP
//
// Defends against: Undetected attacks, blind spots,
//                  brute force, CSRF, SQLi probing,
//                  unauthorized access attempts
//
// Design principles:
//   - NEVER crashes the main application
//   - Silent failure with DB-only logging
//   - Zero dependencies except db.php + sanitize.php
//   - Every attack leaves a trace

declare(strict_types=1);


// ══════════════════════════════════════════════════════════════════
//  CONSTANTS
// ══════════════════════════════════════════════════════════════════

// Brute force threshold
define('MAX_LOGIN_FAILS',   5);
define('BRUTE_WINDOW_SECS', 300);  // 5 minutes


// ══════════════════════════════════════════════════════════════════
//  EVENT TYPE CONSTANTS
//  Use these instead of raw strings — no typos
// ══════════════════════════════════════════════════════════════════

// Authentication events
define('LOG_REGISTER',          'USER_REGISTER');
define('LOG_LOGIN_SUCCESS',     'LOGIN_SUCCESS');
define('LOG_LOGIN_FAIL',        'LOGIN_FAIL');
define('LOG_LOGIN_LOCKED',      'LOGIN_LOCKED');
define('LOG_LOGOUT',            'LOGOUT');
define('LOG_PASSWORD_CHANGE_SUCCESS', 'PASSWORD_CHANGE_SUCCESS');
define('LOG_PASSWORD_CHANGE_FAIL',    'PASSWORD_CHANGE_FAIL');
define('LOG_PASSWORD_CHANGE_LOCKED',  'PASSWORD_CHANGE_LOCKED');

// Profile events
define('LOG_PROFILE_VIEW',      'PROFILE_VIEW');
define('LOG_PROFILE_UPDATE',    'PROFILE_UPDATE');
define('LOG_PROFILE_IMG',       'PROFILE_IMAGE_UPLOAD');
define('LOG_PROFILE_OTHER',     'PROFILE_VIEW_OTHER');

// Transfer events
define('LOG_TRANSFER_OK',       'TRANSFER_SUCCESS');
define('LOG_TRANSFER_FAIL',     'TRANSFER_FAIL');
define('LOG_TRANSFER_INVALID',  'TRANSFER_INVALID');

// Search events
define('LOG_SEARCH',            'USER_SEARCH');

// Security events — most important during war game
define('LOG_CSRF_FAIL',         'CSRF_FAIL');
define('LOG_ACCESS_DENIED',     'ACCESS_DENIED');
define('LOG_INVALID_INPUT',     'INVALID_INPUT');
define('LOG_BRUTE_FORCE',       'BRUTE_FORCE_DETECTED');
define('LOG_FILE_UPLOAD_FAIL',  'FILE_UPLOAD_FAIL');
define('LOG_SQLI_PROBE',        'SQLI_PROBE_DETECTED');
define('LOG_XSS_PROBE',         'XSS_PROBE_DETECTED');
define('LOG_PATH_TRAVERSAL',    'PATH_TRAVERSAL_DETECTED');
define('LOG_SUSPICIOUS',        'SUSPICIOUS_ACTIVITY');

// Navigation
define('LOG_PAGE_VIEW',         'PAGE_VIEW');

// Session events — triggered by session.php
define('LOG_SESSION_TIMEOUT',   'SESSION_TIMEOUT');
define('LOG_SESSION_ABSOLUTE',  'SESSION_TIMEOUT_ABSOLUTE');
define('LOG_SESSION_HIJACK',    'SESSION_HIJACK_DETECTED');

// ══════════════════════════════════════════════════════════════════
//  SECTION 1 — CORE LOGGING FUNCTION
//  This is what everyone calls
// ══════════════════════════════════════════════════════════════════

/**
 * Log any user activity or security event.
 *
 * Auto-reads from session:
 *   user_id, username
 *
 * Auto-reads:
 *   client IP  from get_client_ip() or REMOTE_ADDR
 *   webpage    from $event parameter
 *   timestamp  from MySQL CURRENT_TIMESTAMP
 *
 * NEVER throws exception — silent failure guaranteed.
 *
 * Usage — anywhere in the app:
 *   logActivity(LOG_LOGIN_SUCCESS);
 *   logActivity(LOG_TRANSFER_FAIL);
 *   logActivity(LOG_CSRF_FAIL);
 */
function logActivity(string $event, ?string $detail = null): void {
    try {
        // ── Collect data ─────────────────────────────────────────

        // User data from session
        $userId   = $_SESSION['user_id']  ?? null;
        $username = $_SESSION['username'] ?? null;

        // Sanitize event string — prevent log injection
        // Allow word chars plus forensic context chars (spaces, pipes, slashes,
        // equals, colons, dots, parens, commas) but strip control chars and
        // anything that could break DB or log parsers.
        $event = preg_replace('/[^\w\-:. |\/=@,()<>]/', '', $event);
        $event = substr($event, 0, 255);

        // Sanitize detail — preserve printable ASCII for forensics
        if ($detail !== null) {
            $detail = preg_replace_callback('/[^\x20-\x7E]/', static function (array $m): string {
                return '\\x' . bin2hex($m[0]);
            }, $detail);
            $detail = substr($detail, 0, 2000);
        }

        // Sanitize username snapshot
        if ($username !== null) {
            $username = preg_replace('/[^\w\-.]/', '', (string)$username);
            $username = substr($username, 0, 32);
        }

        // Get client IP
        $ip = _getLogIp();

        // ── Try DB first ─────────────────────────────────────────
        _logToDatabase($userId, $username, $event, $ip, $detail);

        // ── Discord alert for security events ────────────────────
        if (function_exists('discordAlert')) {
            // Pass detail for richer Discord embeds
            $discordEvent = $detail !== null ? $event . ':' . $detail : $event;
            discordAlert($discordEvent, $username, $ip);
        }

    } catch (Throwable $e) {
        // Never throw into business flow.
        // Fallback to syslog so events survive a DB outage and appear in docker logs.
        $safeEvent = preg_replace('/[^\w\-:.]/', '', $event ?? 'UNKNOWN');
        $safeUser  = preg_replace('/[^\w\-.]/', '', (string) ($username ?? 'guest'));
        $safeIp    = filter_var($ip ?? '0.0.0.0', FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';

        // L5 FIX: Sanitize the exception detail before writing to syslog.
        // getMessage() can contain user-influenced strings (e.g. constraint
        // violation text) with newlines or control chars that enable log
        // injection in syslog consumers. We strip non-printable ASCII and
        // truncate to prevent log flooding.
        $safeMsg = preg_replace('/[^\x20-\x7E]/', '', substr($e->getMessage(), 0, 200));

        openlog('transactiwar', LOG_PID | LOG_NDELAY, LOG_USER);
        syslog(LOG_WARNING, sprintf(
            '[%s] user=%s ip=%s (DB write failed: %s)',
            $safeEvent,
            $safeUser,
            $safeIp,
            $safeMsg
        ));
        closelog();

        error_log('Activity log DB write failed: ' . get_class($e) . ' code=' . $e->getCode());
    }
}

/**
 * Build a compact forensic context string from the current request.
 * Captures URI, method, origin, and user-agent for security logs.
 *
 * Returns something like:
 *   "POST /login.php origin=https://evil.com ua=curl/7.88"
 */
function _buildRequestContext(): string {
    $parts = [];

    $method = $_SERVER['REQUEST_METHOD'] ?? '?';
    $uri    = $_SERVER['REQUEST_URI']    ?? '?';
    // Truncate URI to avoid log bloat from long query strings
    $uri = substr($uri, 0, 80);
    $parts[] = $method . ' ' . $uri;

    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin !== '') {
        $parts[] = 'origin=' . substr($origin, 0, 60);
    }

    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    if ($referer !== '' && $origin === '') {
        $parts[] = 'ref=' . substr($referer, 0, 60);
    }

    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if ($ua !== '') {
        // Truncate UA to the product token (first space-delimited chunk)
        $uaShort = explode(' ', $ua)[0];
        $parts[] = 'ua=' . substr($uaShort, 0, 40);
    }

    return implode(' | ', $parts);
}

/**
 * Log a high-priority security event in DB.
 * Includes extra detail field for attack specifics.
 * Automatically appends request context (URI, origin, UA) for forensics.
 *
 * Usage:
 *   logSecurityEvent(LOG_CSRF_FAIL, 'transfer.php POST');
 *   logSecurityEvent(LOG_BRUTE_FORCE, 'user: admin, attempts: 10');
 */
function logSecurityEvent(string $event, string $detail = ''): void {
    // Auto-append request context for forensics
    $ctx = _buildRequestContext();
    if ($detail !== '') {
        $fullDetail = $detail . ' | ' . $ctx;
    } else {
        $fullDetail = $ctx;
    }

    // Security events store the full detail in the dedicated column
    // while keeping the event type clean and indexable in webpage.
    logActivity($event, $fullDetail);
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 2 — DB STORAGE
// ══════════════════════════════════════════════════════════════════

/**
 * Write log entry to activity_logs table.
 * Uses global $pdo — requires db.php loaded.
 *
 * @throws PDOException if DB insert fails
 */
function _logToDatabase(
    ?int    $userId,
    ?string $username,
    string  $event,
    string  $ip,
    ?string $detail = null
): void {
    $pdo = _getLoggerPdo();
    $userId = ($userId !== null && $userId > 0) ? $userId : null;

    $stmt = $pdo->prepare(
        'INSERT INTO activity_logs
            (user_id, username_snapshot, webpage, detail, client_ip)
         VALUES
            (?, ?, ?, ?, ?)'
    );

    try {
        $stmt->execute([
            $userId,    // NULL for guests
            $username,  // NULL for guests
            $event,     // event type (clean, indexable)
            $detail,    // full forensic payload (NULL for non-security events)
            $ip,        // client IP
        ]);
    } catch (PDOException $e) {
        $isForeignKeyError = $e->getCode() === '23000';
        if (!$isForeignKeyError) {
            // If the detail column doesn't exist yet (old schema), retry without it
            if (str_contains($e->getMessage(), 'detail')) {
                $stmtFallback = $pdo->prepare(
                    'INSERT INTO activity_logs
                        (user_id, username_snapshot, webpage, client_ip)
                     VALUES (?, ?, ?, ?)'
                );
                $stmtFallback->execute([$userId, $username, $event, $ip]);
                return;
            }
            throw $e;
        }

        // Session can occasionally hold a stale/deleted user_id.
        // Retry once with guest user semantics so the event still lands in DB.
        $stmt->execute([
            null,
            $username,
            $event,
            $detail,
            $ip,
        ]);
    }
}

/**
 * Resolve a PDO handle for logger writes.
 * Prefers existing global PDO; lazily boots DB connection as a fallback.
 */
function _getLoggerPdo(): PDO {
    global $pdo;

    if (isset($pdo) && $pdo instanceof PDO) {
        return $pdo;
    }

    $dbBootstrap = __DIR__ . '/../config/db.php';
    if (is_file($dbBootstrap)) {
        require $dbBootstrap;
    }

    if (isset($pdo) && $pdo instanceof PDO) {
        return $pdo;
    }

    throw new RuntimeException('PDO not available');
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 3 — IP HELPER
// ══════════════════════════════════════════════════════════════════

/**
 * Get validated client IP for logging.
 * Uses sanitize.php if loaded, falls back to REMOTE_ADDR.
 */
function _getLogIp(): string {
    // Use sanitize.php function if available
    if (function_exists('get_client_ip')) {
        return get_client_ip();
    }

    // Fallback — direct REMOTE_ADDR
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // Basic validation
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        return $ip;
    }

    return '0.0.0.0';
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 4 — BRUTE FORCE DETECTION
//  Used by auth.php (Member 1) to lock accounts
// ══════════════════════════════════════════════════════════════════

/**
 * Count failed login attempts from an IP in last N seconds.
 * Used to detect and block brute force attacks.
 *
 * Usage in auth.php (Member 1):
 *   $fails = countRecentFailedLogins($ip);
 *   if ($fails >= MAX_LOGIN_FAILS) {
 *       logActivity(LOG_LOGIN_LOCKED);
 *       $error = 'Too many attempts. Try again in 5 minutes.';
 *   }
 */



/**
 * Check if an IP is currently brute forcing.
 * Simple boolean check for use in login handler.
 *
 * Usage in login.php:
 *   if (isIpBruteForcing()) {
 *       logActivity(LOG_BRUTE_FORCE);
 *       die('Too many attempts.');
 *   }
 */



// ══════════════════════════════════════════════════════════════════
//  SECTION 5 — QUERY FUNCTIONS
//  For war game monitoring and attack investigation
// ══════════════════════════════════════════════════════════════════

/**
 * Get most recent log entries.
 * Use during war game to see what's happening live.
 *
 * Usage:
 *   $logs = getRecentLogs(50);
 *   foreach ($logs as $log) { ... }
 */
function getRecentLogs(int $limit = 50): array {
    global $pdo;

    if (!isset($pdo)) {
        return [];
    }

    try {
        $limit = max(1, min(500, $limit)); // clamp 1-500

        $stmt = $pdo->prepare(
            'SELECT
                id,
                user_id,
                username_snapshot,
                webpage,
                client_ip,
                created_at
             FROM activity_logs
             ORDER BY created_at DESC
             LIMIT ?'
        );

        $stmt->execute([$limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    } catch (Throwable $e) {
        error_log('getRecentLogs error: ' . get_class($e) . ' code=' . $e->getCode());
        return [];
    }
}

/**
 * Get all activity from a specific IP address.
 * Use during war game to track what an attacker is doing.
 *
 * Usage:
 *   $logs = getLogsByIp('10.0.0.5');
 */
function getLogsByIp(string $ip, int $limit = 100): array {
    global $pdo;

    if (!isset($pdo)) {
        return [];
    }

    try {
        // Validate IP first
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return [];
        }

        $limit = max(1, min(500, $limit));

        $stmt = $pdo->prepare(
            'SELECT
                id,
                user_id,
                username_snapshot,
                webpage,
                client_ip,
                created_at
             FROM activity_logs
             WHERE client_ip = ?
             ORDER BY created_at DESC
             LIMIT ?'
        );

        $stmt->execute([$ip, $limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    } catch (Throwable $e) {
        error_log('getLogsByIp error: ' . get_class($e) . ' code=' . $e->getCode());
        return [];
    }
}

/**
 * Get all security events only.
 * Filters for attack-related log entries.
 * Most useful query during war game.
 *
 * Usage:
 *   $attacks = getSecurityEvents(100);
 */
function getSecurityEvents(int $limit = 100): array {
    global $pdo;

    if (!isset($pdo)) {
        return [];
    }

    try {
        $limit = max(1, min(500, $limit));

        $stmt = $pdo->prepare(
            'SELECT
                id,
                user_id,
                username_snapshot,
                webpage,
                client_ip,
                created_at
             FROM activity_logs
             WHERE webpage IN (?, ?, ?, ?, ?, ?, ?, ?)
             OR    webpage LIKE "CSRF_FAIL%"
             OR    webpage LIKE "SQLI%"
             OR    webpage LIKE "XSS%"
             ORDER BY created_at DESC
             LIMIT ?'
        );

        $stmt->execute([
            LOG_CSRF_FAIL,
            LOG_ACCESS_DENIED,
            LOG_INVALID_INPUT,
            LOG_BRUTE_FORCE,
            LOG_FILE_UPLOAD_FAIL,
            LOG_SQLI_PROBE,
            LOG_XSS_PROBE,
            LOG_PATH_TRAVERSAL,
            $limit,
        ]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    } catch (Throwable $e) {
        error_log('getSecurityEvents error: ' . get_class($e) . ' code=' . $e->getCode());
        return [];
    }
}

/**
 * Get attack summary grouped by IP.
 * Shows which IPs are most aggressive.
 *
 * Usage during war game:
 *   $summary = getAttackSummaryByIp();
 *   // Shows: IP | attack_count | last_seen
 */
function getAttackSummaryByIp(): array {
    global $pdo;

    if (!isset($pdo)) {
        return [];
    }

    try {
        $stmt = $pdo->prepare(
            'SELECT
                client_ip,
                COUNT(*)        AS attack_count,
                MAX(created_at) AS last_seen,
                MIN(created_at) AS first_seen,
                GROUP_CONCAT(
                    DISTINCT webpage
                    ORDER BY created_at DESC
                    SEPARATOR ", "
                ) AS attack_types
             FROM activity_logs
             WHERE webpage IN (?, ?, ?, ?, ?, ?, ?, ?)
             OR    webpage LIKE "CSRF_FAIL%"
             GROUP BY client_ip
             ORDER BY attack_count DESC
             LIMIT 20'
        );

        $stmt->execute([
            LOG_CSRF_FAIL,
            LOG_ACCESS_DENIED,
            LOG_LOGIN_FAIL,
            LOG_INVALID_INPUT,
            LOG_BRUTE_FORCE,
            LOG_FILE_UPLOAD_FAIL,
            LOG_SQLI_PROBE,
            LOG_XSS_PROBE,
        ]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    } catch (Throwable $e) {
        error_log('getAttackSummaryByIp error: ' . get_class($e) . ' code=' . $e->getCode());
        return [];
    }
}

/**
 * Get login activity for a specific user.
 * Check if an account has been compromised.
 *
 * Usage:
 *   $history = getUserLoginHistory($userId, 20);
 */
function getUserLoginHistory(int $userId, int $limit = 20): array {
    global $pdo;

    if (!isset($pdo)) {
        return [];
    }

    try {
        $limit = max(1, min(100, $limit));

        $stmt = $pdo->prepare(
            'SELECT
                webpage,
                client_ip,
                created_at
             FROM activity_logs
             WHERE user_id = ?
             AND   webpage IN (?, ?)
             ORDER BY created_at DESC
             LIMIT ?'
        );

        $stmt->execute([
            $userId,
            LOG_LOGIN_SUCCESS,
            LOG_LOGIN_FAIL,
            $limit,
        ]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    } catch (Throwable $e) {
        error_log('getUserLoginHistory error: ' . get_class($e) . ' code=' . $e->getCode());
        return [];
    }
}

// REPLACE countRecentFailedLogins() and isIpBruteForcing()
// in logger.php with these updated versions

/**
 * Count failed login attempts from an IP.
 * Now uses M5's login_attempts table instead of activity_logs.
 *
 * Usage in auth.php (Member 1):
 *   $fails = countRecentFailedLogins($ip);
 */
function countRecentFailedLogins(string $ip): int {
    global $pdo;

    if (!isset($pdo)) {
        return 0;
    }

    try {
        // Validate IP first
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return 0;
        }

        $stmt = $pdo->prepare(
            'SELECT attempts, locked_until
             FROM login_attempts
             WHERE ip = ?'
        );
        $stmt->execute([$ip]);
        $row = $stmt->fetch();

        if (!$row) {
            return 0; // No record — never failed
        }

        // Check if lockout window has expired
        if ($row['locked_until'] > 0 && time() > $row['locked_until']) {
            // Lockout expired — reset counter
            _resetLoginAttempts($ip);
            return 0;
        }

        return (int)$row['attempts'];

    } catch (Throwable $e) {
        error_log('countRecentFailedLogins error: ' . get_class($e) . ' code=' . $e->getCode());
        return 0;
    }
}

/**
 * Record a failed login attempt for this IP.
 * Call this every time login fails.
 *
 * Usage in auth.php (Member 1):
 *   recordFailedLogin($ip);
 */
function recordFailedLogin(string $ip): void {
    global $pdo;

    if (!isset($pdo)) {
        return;
    }

    try {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }

        $now = time();

        // Insert or update — if IP exists increment, else create
        $stmt = $pdo->prepare(
            'INSERT INTO login_attempts (ip, attempts, last_attempt)
             VALUES (?, 1, ?)
             ON DUPLICATE KEY UPDATE
                attempts     = attempts + 1,
                last_attempt = ?'
        );
        $stmt->execute([$ip, $now, $now]);

        // Check if threshold crossed — set lockout
        $count = countRecentFailedLogins($ip);
        if ($count >= MAX_LOGIN_FAILS) {
            _lockIp($ip);
            logActivity(LOG_BRUTE_FORCE);
        }

    } catch (Throwable $e) {
        error_log('recordFailedLogin error: ' . get_class($e) . ' code=' . $e->getCode());
    }
}

/**
 * Lock an IP for BRUTE_WINDOW_SECS seconds.
 * Internal — called automatically by recordFailedLogin().
 */
function _lockIp(string $ip): void {
    global $pdo;

    if (!isset($pdo)) {
        return;
    }

    try {
        $lockedUntil = time() + BRUTE_WINDOW_SECS;

        $stmt = $pdo->prepare(
            'UPDATE login_attempts
             SET locked_until = ?
             WHERE ip = ?'
        );
        $stmt->execute([$lockedUntil, $ip]);

    } catch (Throwable $e) {
        error_log('_lockIp error: ' . get_class($e) . ' code=' . $e->getCode());
    }
}

/**
 * Reset login attempts for an IP after lockout expires.
 * Internal — called automatically.
 */
function _resetLoginAttempts(string $ip): void {
    global $pdo;

    if (!isset($pdo)) {
        return;
    }

    try {
        $stmt = $pdo->prepare(
            'UPDATE login_attempts
             SET attempts     = 0,
                 locked_until = 0
             WHERE ip = ?'
        );
        $stmt->execute([$ip]);

    } catch (Throwable $e) {
        error_log('_resetLoginAttempts error: ' . get_class($e) . ' code=' . $e->getCode());
    }
}

/**
 * Check if current IP is currently locked out.
 * Updated to use login_attempts table.
 *
 * Usage in login.php:
 *   if (isIpBruteForcing()) { die('Too many attempts'); }
 */
function isIpBruteForcing(): bool {
    global $pdo;

    $ip = _getLogIp();

    if (!isset($pdo)) {
        return false;
    }

    try {
        $stmt = $pdo->prepare(
            'SELECT locked_until
             FROM login_attempts
             WHERE ip = ?'
        );
        $stmt->execute([$ip]);
        $row = $stmt->fetch();

        if (!$row) {
            return false;
        }

        // Check if still within lockout window
        if ($row['locked_until'] > 0 && time() < $row['locked_until']) {
            return true; // Still locked
        }

        return false;

    } catch (Throwable $e) {
        error_log('isIpBruteForcing error: ' . get_class($e) . ' code=' . $e->getCode());
        return false;
    }
}

/**
 * Reset login attempts on successful login.
 * Call this in auth.php after successful login.
 *
 * Usage in auth.php (Member 1):
 *   clearLoginAttempts($ip);
 */
function clearLoginAttempts(string $ip): void {
    global $pdo;

    if (!isset($pdo)) {
        return;
    }

    try {
        $stmt = $pdo->prepare(
            'DELETE FROM login_attempts WHERE ip = ?'
        );
        $stmt->execute([$ip]);

    } catch (Throwable $e) {
        error_log('clearLoginAttempts error: ' . get_class($e) . ' code=' . $e->getCode());
    }
}

/**
 * Get activity in last N minutes.
 * Live feed for war game defense monitoring.
 *
 * Usage:
 *   $recent = getLiveActivity(5); // last 5 minutes
 */
function getLiveActivity(int $minutes = 5): array {
    global $pdo;

    if (!isset($pdo)) {
        return [];
    }

    try {
        $minutes = max(1, min(60, $minutes));

        $stmt = $pdo->prepare(
            'SELECT
                id,
                user_id,
                username_snapshot,
                webpage,
                client_ip,
                created_at
             FROM activity_logs
             WHERE created_at >= NOW() - INTERVAL ? MINUTE
             ORDER BY created_at DESC'
        );

        $stmt->execute([$minutes]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    } catch (Throwable $e) {
        error_log('getLiveActivity error: ' . get_class($e) . ' code=' . $e->getCode());
        return [];
    }
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 6 — WAR GAME MONITOR PAGE
//  Create public/monitor.php using these functions
//  Password protect it — only your team should see it
// ══════════════════════════════════════════════════════════════════

/**
 * Render a simple HTML monitoring dashboard.
 * Drop this output inside monitor.php during war game.
 *
 * Usage in public/monitor.php:
 *   <?php
 *   require '../includes/headers.php';
 *   send_security_headers();
 *   require '../config/db.php';
 *   require '../includes/logger.php';
 *
 *   // Password protect
 *   if ($_GET['key'] !== 'YOUR_SECRET_KEY') die('403');
 *
 *   renderMonitorDashboard();
 */
function renderMonitorDashboard(): void {
    $liveActivity  = getLiveActivity(10);
    $securityEvents = getSecurityEvents(50);
    $attacksByIp   = getAttackSummaryByIp();

    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="15"> <!-- auto refresh every 15s -->
        <title>Monitor Dashboard</title>
        <link rel="stylesheet" href="/assets/css/monitor.css">
    </head>
    <body>

    <h1>🛡️ War Game Monitor
        <small class="monitor-time">
            Auto-refresh: 15s | <?= date('H:i:s') ?>
        </small>
    </h1>

    <!-- Attack Summary by IP -->
    <h2>🚨 Attack Summary by IP</h2>
    <?php if (empty($attacksByIp)): ?>
        <p class="success">✅ No attacks detected yet</p>
    <?php else: ?>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Attack Count</th>
            <th>First Seen</th>
            <th>Last Seen</th>
            <th>Attack Types</th>
        </tr>
        <?php foreach ($attacksByIp as $row): ?>
        <tr class="attack">
            <td><strong><?= htmlspecialchars($row['client_ip']) ?></strong></td>
            <td><span class="badge red"><?= (int)$row['attack_count'] ?></span></td>
            <td><?= htmlspecialchars($row['first_seen']) ?></td>
            <td><?= htmlspecialchars($row['last_seen']) ?></td>
            <td><?= htmlspecialchars($row['attack_types']) ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
    <?php endif; ?>

    <!-- Recent Security Events -->
    <h2>🔴 Security Events (Last 50)</h2>
    <?php if (empty($securityEvents)): ?>
        <p class="success">✅ No security events</p>
    <?php else: ?>
    <table>
        <tr>
            <th>Time</th>
            <th>Event</th>
            <th>User</th>
            <th>IP</th>
        </tr>
        <?php foreach ($securityEvents as $row): ?>
        <tr>
            <td class="info"><?= htmlspecialchars($row['created_at']) ?></td>
            <td class="attack"><strong><?= htmlspecialchars($row['webpage']) ?></strong></td>
            <td><?= htmlspecialchars($row['username_snapshot'] ?? 'guest') ?></td>
            <td><?= htmlspecialchars($row['client_ip']) ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
    <?php endif; ?>

    <!-- Live Activity Feed -->
    <h2>📡 Live Activity (Last 10 Minutes)</h2>
    <table>
        <tr>
            <th>Time</th>
            <th>Event</th>
            <th>User</th>
            <th>IP</th>
        </tr>
        <?php foreach ($liveActivity as $row):
            $isAttack = str_contains($row['webpage'], 'FAIL') ||
                        str_contains($row['webpage'], 'DENIED') ||
                        str_contains($row['webpage'], 'PROBE') ||
                        str_contains($row['webpage'], 'BRUTE');
            $class = $isAttack ? 'attack' : 'success';
        ?>
        <tr>
            <td class="info"><?= htmlspecialchars($row['created_at']) ?></td>
            <td class="<?= $class ?>"><?= htmlspecialchars($row['webpage']) ?></td>
            <td><?= htmlspecialchars($row['username_snapshot'] ?? 'guest') ?></td>
            <td><?= htmlspecialchars($row['client_ip']) ?></td>
        </tr>
        <?php endforeach; ?>
    </table>

    </body>
    </html>
    <?php
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 7 — DISCORD WEBHOOK INTEGRATION
//  Auto-loads if the file exists. No-op if missing or unconfigured.
// ══════════════════════════════════════════════════════════════════

$_discordWebhookPath = __DIR__ . '/discord_webhook.php';
if (is_file($_discordWebhookPath)) {
    require_once $_discordWebhookPath;
}
unset($_discordWebhookPath);
