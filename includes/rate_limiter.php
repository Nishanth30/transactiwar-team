<?php

declare(strict_types=1);

/**
 * D3 FIX: Pre-session global rate limiter.
 *
 * Runs BEFORE session_start() to prevent session-file creation for abusive
 * IPs. Uses a single shared file with flock() for atomic IP tracking —
 * no frameworks, no database, no external dependencies.
 *
 * Why file-based: The DB connection is established after session_start()
 * in most pages. This must fire first to prevent the session-flood DoS
 * that fills the /tmp tmpfs.
 */

require_once __DIR__ . '/request.php';

const RATE_LIMIT_FILE       = '/tmp/ip_rate_limits.dat';
const RATE_LIMIT_WINDOW     = 60;   // 1-minute sliding window
const RATE_LIMIT_MAX        = 120;  // max requests per IP per window
const RATE_LIMIT_PRUNE_PROB = 10;   // 10% chance to prune stale entries

/**
 * Check global rate limit for the current request IP.
 * Exits with 429 if the limit is exceeded.
 * Fails open if the rate-limit file cannot be accessed.
 */
function check_global_rate_limit(): void
{
    $ip = get_request_client_ip();
    if ($ip === '' || $ip === '0.0.0.0') {
        return;
    }

    $now = time();

    $fp = @fopen(RATE_LIMIT_FILE, 'c+');
    if ($fp === false) {
        return; // fail open — don't break the app
    }

    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        return;
    }

    $content = stream_get_contents($fp);
    $data = ($content !== '' && $content !== false)
        ? json_decode($content, true)
        : [];

    if (!is_array($data)) {
        $data = [];
    }

    // Probabilistic cleanup of expired entries to bound file size
    if (random_int(1, 100) <= RATE_LIMIT_PRUNE_PROB) {
        foreach ($data as $key => $entry) {
            if (($entry['t'] ?? 0) < $now - RATE_LIMIT_WINDOW) {
                unset($data[$key]);
            }
        }
    }

    // Hash the IP so raw addresses aren't stored on disk
    $ipKey = hash('sha256', $ip);
    $entry = $data[$ipKey] ?? ['c' => 0, 't' => $now];

    // Reset window if expired
    if (($entry['t'] ?? 0) < $now - RATE_LIMIT_WINDOW) {
        $entry = ['c' => 0, 't' => $now];
    }

    $entry['c']++;
    $data[$ipKey] = $entry;

    // Write back atomically
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    // Reject if over limit
    if ($entry['c'] > RATE_LIMIT_MAX) {
        $retryAfter = max(1, ($entry['t'] + RATE_LIMIT_WINDOW) - $now);
        http_response_code(429);
        header('Retry-After: ' . $retryAfter);
        header('Content-Type: text/plain; charset=UTF-8');
        exit('Rate limit exceeded. Try again later.');
    }
}
