<?php
declare(strict_types=1);
/*
|--------------------------------------------------------------------------
| Hardened session bootstrap
|--------------------------------------------------------------------------
| Covers:
| - Secure cookie settings
| - Session fixation mitigation
| - Inactivity timeout
| - Absolute lifetime limit
| - Strict mode
| - Cookie-only sessions
| - Safe defaults for production
*/

/* ---------- Security-focused INI settings ---------- */
ini_set('session.use_strict_mode',       '1');
ini_set('session.use_only_cookies',      '1');
ini_set('session.cookie_httponly',       '1');
ini_set('session.cookie_samesite',       'Strict');
ini_set('session.sid_length',            '48');
ini_set('session.sid_bits_per_character','6');

/*
 * If running behind a proxy and HTTPS is terminated upstream,
 * set this to true explicitly in production.
 */
$secure = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
    (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) &&
     $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
);

/* ---------- Secure cookie parameters ---------- */
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => $secure,
    'httponly' => true,
    'samesite' => 'Strict',
]);

/* ---------- Start session ---------- */
session_start();

/* ---------- Timing policies ---------- */
$inactivityTimeout = 1800;   // 30 minutes inactivity
$absoluteLifetime  = 3600;   // 1 hour max session age
$regenInterval     = 300;    // rotate ID every 5 minutes

$now = time();

/* ---------- Helper — wipe and restart a clean session ---------- */
function resetSession(int $now): void {
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(), '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_destroy();
    session_start();

    $_SESSION['created_at']    = $now;
    $_SESSION['last_activity'] = $now;
    $_SESSION['last_regen']    = $now;
}

/* ---------- Initialize session metadata ---------- */
if (!isset($_SESSION['created_at']))    { $_SESSION['created_at']    = $now; }
if (!isset($_SESSION['last_activity'])) { $_SESSION['last_activity'] = $now; }
if (!isset($_SESSION['last_regen']))    { $_SESSION['last_regen']    = $now; }

/* ---------- Inactivity timeout ---------- */
if (($now - $_SESSION['last_activity']) > $inactivityTimeout) {
    resetSession($now);
}

/* ---------- Absolute lifetime enforcement ---------- */
if (($now - $_SESSION['created_at']) > $absoluteLifetime) {
    resetSession($now);
}

/* ---------- Periodic session ID rotation ---------- */
if (($now - $_SESSION['last_regen']) > $regenInterval) {
    session_regenerate_id(true);
    $_SESSION['last_regen'] = $now;
}

/* ---------- Update activity timestamp ---------- */
$_SESSION['last_activity'] = $now;

/*
|--------------------------------------------------------------------------
| IMPORTANT
|--------------------------------------------------------------------------
| On successful login, ALSO call:
|
|     session_regenerate_id(true);
|
| This file rotates IDs periodically, but login-time regeneration
| is still required to fully prevent session fixation.
*/