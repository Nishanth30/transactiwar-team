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
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.sid_length', '48');
ini_set('session.sid_bits_per_character', '6');

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
    'path' => '/',
    'domain' => '',
    'secure' => $secure,
    'httponly' => true,
    'samesite' => 'Strict',
]);

/* ---------- Start session ---------- */
session_start();

/* ---------- $now defined immediately — must precede ALL session logic ---------- */
$now = time(); // FIX: C1.2 — moved before fingerprint check

/* ---------- Timing policies ---------- */
$inactivityTimeout = 1800;   // 30 minutes inactivity
$absoluteLifetime = 3600;   // 1 hour max session age
$regenInterval = 300;    // rotate ID every 5 minutes

// Session fingerprint check — UA + IP binding
// FIX: C1.2 — mismatch now does hard destroy+redirect instead of resetSession()
//             to avoid referencing uninitialised session metadata mid-stream
// FIX: C1.3 — server secret makes fingerprint uncomputable by external parties
// even if they know the victim's User-Agent and IP (e.g. shared NAT / LAN)
// SESSION_SECRET must be set in .env as a long random string (min 32 chars)
$_fingerprintSecret = $_ENV['SESSION_SECRET'] ?? null;
if ($_fingerprintSecret === null || strlen($_fingerprintSecret) < 32) {
    // Hard fail — running without a session secret is a critical misconfiguration.
    // Set SESSION_SECRET in your .env file (min 32 random chars).
    http_response_code(500);
    die('Server misconfiguration: SESSION_SECRET not set.');
}

$currentFingerprint = hash(
    'sha256',
    $_fingerprintSecret .
    ($_SERVER['HTTP_USER_AGENT'] ?? '') .
    $_SERVER['REMOTE_ADDR']
);

if (!isset($_SESSION['fingerprint'])) {
    // First request — store fingerprint
    $_SESSION['fingerprint'] = $currentFingerprint;
} elseif (!hash_equals($_SESSION['fingerprint'], $currentFingerprint)) {
    // Fingerprint mismatch — destroy session completely and redirect
    if (function_exists('logActivity')) {
        logActivity('SESSION_HIJACK_DETECTED');
    }
    session_unset();
    session_destroy();
    header('Location: /login.php');
    exit; // FIX: C1.2 — hard stop, resetSession() no longer called here
}

/* ---------- Helper — wipe and restart a clean session ---------- */
/* Problem:                                                      
│   resetSession() calls session_destroy()                        
│   then session_start() again                                    
│   But session_start() uses the OLD cookie settings             
│   because session_set_cookie_params() was                       
│   called before the first session_start()                       
│   The second session_start() may not                          
│   inherit all secure settings correctly   */
function resetSession(int $now): void
{
    global $secure; // bring in the $secure variable

    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_destroy();

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    session_start();

    $_SESSION['created_at'] = $now;
    $_SESSION['last_activity'] = $now;
    $_SESSION['last_regen'] = $now;
}
// function resetSession(int $now): void {
//     $_SESSION = [];

//     if (ini_get('session.use_cookies')) {
//         $params = session_get_cookie_params();
//         setcookie(
//             session_name(), '',
//             time() - 42000,
//             $params['path'],
//             $params['domain'],
//             $params['secure'],
//             $params['httponly']
//         );
//     }

//     session_destroy();
//     session_start();

//     $_SESSION['created_at']    = $now;
//     $_SESSION['last_activity'] = $now;
//     $_SESSION['last_regen']    = $now;
// }

/* ---------- Initialize session metadata ---------- */
if (!isset($_SESSION['created_at'])) {
    $_SESSION['created_at'] = $now;
}
if (!isset($_SESSION['last_activity'])) {
    $_SESSION['last_activity'] = $now;
}
if (!isset($_SESSION['last_regen'])) {
    $_SESSION['last_regen'] = $now;
}

/* ---------- Inactivity timeout ---------- */
if (($now - $_SESSION['last_activity']) > $inactivityTimeout) {
    // Adding Log activity
    if (function_exists('logActivity')) {
        logActivity('SESSION_TIMEOUT_INACTIVITY');
    }
    resetSession($now);
}

/* ---------- Absolute lifetime enforcement ---------- */
if (($now - $_SESSION['created_at']) > $absoluteLifetime) {
    // Adding Log activity
    if (function_exists('logActivity')) {
        logActivity('SESSION_TIMEOUT_ABSOLUTE');
    }
    resetSession($now);
}

//Adding : No HTTPS Warning in Development
/* Problem:                                                      │
│   On localhost $secure = false                                  │
│   Cookie sent without Secure flag                               │
│   Fine for dev but risky if deployed                            │
│   without noticing      */
if (!$secure && getenv('APP_ENV') !== 'production') {
    error_log('WARNING: Session cookie is NOT secure.' .
        ' HTTPS not detected. OK for localhost only.');
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
