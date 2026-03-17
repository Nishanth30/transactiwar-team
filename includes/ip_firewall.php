<?php
// includes/ip_firewall.php
// IP Firewall — checks blocked_ips table on every request.
// Loaded at the very start of the request lifecycle via header.php.
//
// Design:
//   - Single lightweight SELECT per request
//   - Supports permanent blocks and time-limited cooldowns
//   - Auto-expires cooldowns (checked at query time)
//   - Sticky cache: blocked IPs are cached to tmpfs so they stay
//     blocked even during DB outages. Unknown IPs fail open.
//   - Logs blocked requests for forensics

declare(strict_types=1);

/**
 * Check if the current client IP is blocked.
 * Call this as early as possible in the request lifecycle.
 * Returns immediately if the table doesn't exist yet (graceful).
 */
function checkIpFirewall(): void {
    try {
        $ip = _firewallGetIp();

        if ($ip === '127.0.0.1' || $ip === '::1') {
            return; // Never block localhost
        }

        $pdo = _firewallGetPdo();
        if ($pdo === null) {
            // DB not available — check sticky cache for known-blocked IPs
            if (_firewallCheckCache($ip)) {
                _firewallDeny($ip, null);
            }
            return; // Unknown IPs fail open
        }

        $stmt = $pdo->prepare(
            'SELECT reason, blocked_by, expires_at
             FROM blocked_ips
             WHERE ip = ?
             AND (expires_at IS NULL OR expires_at > NOW())
             LIMIT 1'
        );
        $stmt->execute([$ip]);
        $block = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$block) {
            _firewallClearCache($ip); // Unblocked or expired — purge cache
            return;
        }

        // Cache this block to tmpfs so it survives DB outages
        _firewallCacheBlock($ip, $block['expires_at']);

        _firewallDeny($ip, $block['expires_at']);

    } catch (Throwable $e) {
        // DB error — check sticky cache before failing open
        error_log('ip_firewall check error: ' . $e->getMessage());
        if (_firewallCheckCache($ip)) {
            _firewallDeny($ip, null);
        }
        // Unknown IPs still fail open to preserve availability
    }
}

// ══════════════════════════════════════════════════════════════════
//  DENY RESPONSE
// ══════════════════════════════════════════════════════════════════

/**
 * Send the 403 block page and terminate the request.
 * @param string      $ip        The blocked IP (for logging/alerts)
 * @param string|null $expiresAt MySQL DATETIME string, or null for permanent
 * @return never
 */
function _firewallDeny(string $ip, ?string $expiresAt): void {
    // Log the blocked request
    if (function_exists('logSecurityEvent')) {
        logSecurityEvent('IP_BLOCKED', 'firewall_reject');
    }

    // Send Discord alert (rate-limited by the webhook module itself)
    if (function_exists('discordAlert')) {
        discordAlert('IP_BLOCKED:firewall_reject', null, $ip);
    }

    http_response_code(403);
    header('Content-Type: text/html; charset=UTF-8');
    header('Connection: close');

    if ($expiresAt !== null) {
        $remaining = max(0, strtotime($expiresAt) - time());
        $mins = (int) ceil($remaining / 60);
        $timeText = $mins > 60
            ? (int) ceil($mins / 60) . ' hour' . ($mins > 120 ? 's' : '')
            : $mins . ' minute' . ($mins !== 1 ? 's' : '');

        $messages = [
            "Don't abuse the site bro, come back in <b>$timeText</b>.",
            "Chill out for <b>$timeText</b>. We're watching.",
            "Nah fam, you're in timeout for <b>$timeText</b>.",
            "Touch grass for <b>$timeText</b> and try again.",
            "You've been benched for <b>$timeText</b>. Take a water break.",
            "Rate limited to 0 requests for <b>$timeText</b>. Skill issue?",
            "Sir this is a banking app, not a CTF... oh wait. Anyway, <b>$timeText</b> timeout.",
            "Bro thought he was slick. <b>$timeText</b> timeout.",
        ];
    } else {
        $timeText = 'forever';
        $messages = [
            "Permanently banned. That's tough.",
            "Gone. Reduced to atoms.",
            "Your IP has been escorted out of the building. Permanently.",
            "You've been yeeted into the shadow realm.",
            "404: Your access was not found. And never will be.",
        ];
    }

    $msg = $messages[array_rand($messages)];

    die('<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Denied</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0f0f1a; color: #c0caf5; font-family: "Segoe UI", system-ui, sans-serif;
    text-align: center; padding: 2rem;
  }
  .card {
    background: #1a1b2e; border: 1px solid #2a2b3e; border-radius: 16px;
    padding: 3rem; max-width: 500px; width: 100%;
    box-shadow: 0 0 60px rgba(247, 118, 142, 0.08);
  }
  .emoji { font-size: 4rem; margin-bottom: 1rem; }
  h1 { color: #f7768e; font-size: 1.5rem; margin-bottom: 1rem; }
  p { font-size: 1.1rem; line-height: 1.6; color: #a9b1d6; margin-bottom: 1.5rem; }
  .timer { color: #ff9e64; font-size: 0.95rem; font-family: monospace; }
  .footer { color: #565f89; font-size: 0.8rem; margin-top: 2rem; }
</style>
</head>
<body>
<div class="card">
  <div class="emoji">' . ($expiresAt !== null ? '&#x1F512;' : '&#x1F6AB;') . '</div>
  <h1>Access Denied</h1>
  <p>' . $msg . '</p>
  ' . ($expiresAt !== null ? '<p class="timer">Timeout expires in: ' . htmlspecialchars($timeText) . '</p>' : '') . '
  <p class="footer">TransactiWar Security</p>
</div>
</body>
</html>');
}

// ══════════════════════════════════════════════════════════════════
//  STICKY BLOCK CACHE (tmpfs-backed)
//  When an IP is confirmed blocked by the DB, we cache it to /tmp.
//  On DB failure, we check this cache so blocked IPs stay blocked.
// ══════════════════════════════════════════════════════════════════

/** Directory for cached block entries. */
define('_FW_CACHE_DIR', sys_get_temp_dir() . '/fw_blocked');

/**
 * Cache a confirmed block to tmpfs.
 * File contents = expiry Unix timestamp, or "0" for permanent.
 */
function _firewallCacheBlock(string $ip, ?string $expiresAt): void {
    $dir = _FW_CACHE_DIR;
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    $expiry = ($expiresAt !== null) ? (string) strtotime($expiresAt) : '0';
    @file_put_contents($dir . '/' . hash('xxh3', $ip), $expiry, LOCK_EX);
}

/**
 * Check if an IP has a cached block that is still active.
 * Returns true if the IP should be blocked, false otherwise.
 */
function _firewallCheckCache(string $ip): bool {
    $file = _FW_CACHE_DIR . '/' . hash('xxh3', $ip);
    if (!is_file($file)) {
        return false;
    }
    $expiry = (int) trim((string) @file_get_contents($file));
    if ($expiry === 0) {
        return true; // Permanent block
    }
    if ($expiry > time()) {
        return true; // Timed block still active
    }
    // Expired — clean up
    @unlink($file);
    return false;
}

/**
 * Remove cached block when it's no longer in the DB.
 */
function _firewallClearCache(string $ip): void {
    $file = _FW_CACHE_DIR . '/' . hash('xxh3', $ip);
    if (is_file($file)) {
        @unlink($file);
    }
}

/**
 * Get client IP for firewall check.
 */
function _firewallGetIp(): string {
    if (function_exists('get_client_ip')) {
        return get_client_ip();
    }
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

/**
 * Get PDO handle — tries global first, then boots DB if needed.
 */
function _firewallGetPdo(): ?PDO {
    global $pdo;
    if (isset($pdo) && $pdo instanceof PDO) {
        return $pdo;
    }

    $dbFile = __DIR__ . '/../config/db.php';
    if (is_file($dbFile)) {
        require_once $dbFile;
    }

    if (isset($pdo) && $pdo instanceof PDO) {
        return $pdo;
    }

    return null;
}
