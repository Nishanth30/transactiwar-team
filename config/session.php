<?php

declare(strict_types=1);

// D3 FIX: Global rate limiter runs BEFORE session_start() to prevent
// session-flood DoS that fills the /tmp tmpfs with session files.
require_once __DIR__ . '/../includes/rate_limiter.php';
check_global_rate_limit();

require_once __DIR__ . '/../includes/request.php';

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.sid_length', '48');
ini_set('session.sid_bits_per_character', '6');

enforce_https();

$secure = is_secure_request();

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $secure,
    'httponly' => true,
    'samesite' => 'Strict',
]);

if (session_status() !== PHP_SESSION_ACTIVE && !session_start()) {
    throw new RuntimeException('Session failed to start');
}

$now = time();
$clientIp = get_request_client_ip();
$userAgent = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
$secret = (string) ($_ENV['SESSION_SECRET'] ?? getenv('SESSION_SECRET') ?: '');

if ($secret === '' || strlen($secret) < 32) {
    http_response_code(500);
    exit('Server misconfiguration: SESSION_SECRET not set.');
}

$currentFingerprint = hash_hmac('sha256', $userAgent . '|' . $clientIp, $secret);

function delete_session_cookie(): void
{
    if (!ini_get('session.use_cookies')) {
        return;
    }

    $params = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires' => time() - 42000,
        'path' => $params['path'],
        'domain' => $params['domain'],
        'secure' => $params['secure'],
        'httponly' => $params['httponly'],
        'samesite' => $params['samesite'] ?? 'Strict',
    ]);
}

function resetSession(int $now, string $fingerprint): void
{
    $_SESSION = [];
    delete_session_cookie();
    session_destroy();

    if (!session_start()) {
        throw new RuntimeException('Session failed to restart');
    }

    $_SESSION['fingerprint'] = $fingerprint;
    $_SESSION['created_at'] = $now;
    $_SESSION['last_activity'] = $now;
    $_SESSION['last_regen'] = $now;
}

if (!isset($_SESSION['fingerprint'])) {
    $_SESSION['fingerprint'] = $currentFingerprint;
} elseif (!hash_equals((string) $_SESSION['fingerprint'], $currentFingerprint)) {
    if (function_exists('logActivity')) {
        logActivity('SESSION_HIJACK_DETECTED');
    }

    $_SESSION = [];
    delete_session_cookie();
    session_destroy();
    header('Location: /login.php');
    exit;
}

$inactivityTimeout = 1800;
$absoluteLifetime = 3600;
$regenInterval = 300;

if (!isset($_SESSION['created_at'])) {
    $_SESSION['created_at'] = $now;
}
if (!isset($_SESSION['last_activity'])) {
    $_SESSION['last_activity'] = $now;
}
if (!isset($_SESSION['last_regen'])) {
    $_SESSION['last_regen'] = $now;
}

if (($now - (int) $_SESSION['last_activity']) > $inactivityTimeout) {
    if (function_exists('logActivity')) {
        logActivity('SESSION_TIMEOUT_INACTIVITY');
    }
    resetSession($now, $currentFingerprint);
}

if (($now - (int) $_SESSION['created_at']) > $absoluteLifetime) {
    if (function_exists('logActivity')) {
        logActivity('SESSION_TIMEOUT_ABSOLUTE');
    }
    resetSession($now, $currentFingerprint);
}

if (($now - (int) $_SESSION['last_regen']) > $regenInterval) {
    session_regenerate_id(true);
    $_SESSION['last_regen'] = $now;
}

$_SESSION['last_activity'] = $now;
