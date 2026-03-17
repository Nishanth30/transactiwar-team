<?php
// includes/discord_webhook.php
// Discord Webhook Alerting for Security Events
//
// Sends real-time alerts to a Discord channel when suspicious
// activity is detected. Hooks into the existing logger system.
//
// Design principles:
//   - NEVER crashes the main application (fire-and-forget)
//   - Rate-limited to prevent Discord API abuse / webhook revocation
//   - Severity-based filtering (only alerts on security events)
//   - Non-blocking: uses short timeout so page loads aren't delayed

declare(strict_types=1);


// ══════════════════════════════════════════════════════════════════
//  CONFIGURATION
// ══════════════════════════════════════════════════════════════════

// Maximum alerts per minute to avoid Discord rate limits (30/min API limit)
define('DISCORD_RATE_LIMIT',      15);
define('DISCORD_RATE_WINDOW',     60);   // seconds
// HTTP timeout for webhook POST — keep low so it doesn't block the app
define('DISCORD_TIMEOUT_SECONDS', 2);


// ══════════════════════════════════════════════════════════════════
//  SEVERITY CLASSIFICATION
// ══════════════════════════════════════════════════════════════════

// Events that trigger Discord alerts, mapped to severity + color
// Discord embed colors: red=0xFF0000, orange=0xFF8C00, yellow=0xFFD700
function _getAlertConfig(): array {
    return [
        // ── CRITICAL (red) — immediate attention ────────────────
        'SESSION_HIJACK_DETECTED' => ['severity' => 'CRITICAL', 'color' => 0xFF0000, 'emoji' => "\xF0\x9F\x9A\xA8"],
        'BRUTE_FORCE_DETECTED'    => ['severity' => 'CRITICAL', 'color' => 0xFF0000, 'emoji' => "\xF0\x9F\x9A\xA8"],
        'SQLI_PROBE_DETECTED'     => ['severity' => 'CRITICAL', 'color' => 0xFF0000, 'emoji' => "\xF0\x9F\x9A\xA8"],
        'XSS_PROBE_DETECTED'      => ['severity' => 'CRITICAL', 'color' => 0xFF0000, 'emoji' => "\xF0\x9F\x9A\xA8"],
        'PATH_TRAVERSAL_DETECTED' => ['severity' => 'CRITICAL', 'color' => 0xFF0000, 'emoji' => "\xF0\x9F\x9A\xA8"],

        // ── HIGH (orange) — investigate soon ────────────────────
        'CSRF_FAIL'               => ['severity' => 'HIGH',     'color' => 0xFF8C00, 'emoji' => "\xE2\x9A\xA0\xEF\xB8\x8F"],
        'TRANSFER_FAIL'           => ['severity' => 'HIGH',     'color' => 0xFF8C00, 'emoji' => "\xE2\x9A\xA0\xEF\xB8\x8F"],
        'TRANSFER_INVALID'        => ['severity' => 'HIGH',     'color' => 0xFF8C00, 'emoji' => "\xE2\x9A\xA0\xEF\xB8\x8F"],
        'FILE_UPLOAD_FAIL'        => ['severity' => 'HIGH',     'color' => 0xFF8C00, 'emoji' => "\xE2\x9A\xA0\xEF\xB8\x8F"],
        'ACCESS_DENIED'           => ['severity' => 'HIGH',     'color' => 0xFF8C00, 'emoji' => "\xE2\x9A\xA0\xEF\xB8\x8F"],
        'SUSPICIOUS_ACTIVITY'     => ['severity' => 'HIGH',     'color' => 0xFF8C00, 'emoji' => "\xE2\x9A\xA0\xEF\xB8\x8F"],

        // ── MEDIUM (yellow) — worth monitoring ──────────────────
        'LOGIN_FAIL'              => ['severity' => 'MEDIUM',   'color' => 0xFFD700, 'emoji' => "\xF0\x9F\x94\xB8"],
        'LOGIN_LOCKED'            => ['severity' => 'MEDIUM',   'color' => 0xFFD700, 'emoji' => "\xF0\x9F\x94\xB8"],
        'PASSWORD_CHANGE_FAIL'    => ['severity' => 'MEDIUM',   'color' => 0xFFD700, 'emoji' => "\xF0\x9F\x94\xB8"],
        'PASSWORD_CHANGE_LOCKED'  => ['severity' => 'MEDIUM',   'color' => 0xFFD700, 'emoji' => "\xF0\x9F\x94\xB8"],
        'INVALID_INPUT'           => ['severity' => 'MEDIUM',   'color' => 0xFFD700, 'emoji' => "\xF0\x9F\x94\xB8"],
    ];
}


// ══════════════════════════════════════════════════════════════════
//  CORE FUNCTION — called from logActivity()
// ══════════════════════════════════════════════════════════════════

/**
 * Send a Discord alert if this event is security-relevant.
 *
 * Called from logActivity() after every DB log write.
 * Silently returns if:
 *   - DISCORD_WEBHOOK_URL is not configured
 *   - Event is not in the alert list
 *   - Rate limit exceeded
 *   - Any error occurs (never crashes the app)
 *
 * @param string      $event    The log event string (may include :detail suffix)
 * @param string|null $username The username from session (null for guests)
 * @param string      $ip       The client IP
 */
function discordAlert(string $event, ?string $username, string $ip): void {
    try {
        $webhookUrl = getenv('DISCORD_WEBHOOK_URL');
        if ($webhookUrl === false || $webhookUrl === '') {
            return; // Not configured — silent skip
        }

        // ── Match event to alert config ─────────────────────────
        // Events can have detail suffixes like "CSRF_FAIL:origin_mismatch"
        // so we match on the base event type
        $alertConfig = _getAlertConfig();
        $matchedConfig = null;
        $baseEvent = $event;

        foreach ($alertConfig as $pattern => $config) {
            if ($event === $pattern || str_starts_with($event, $pattern . ':')) {
                $matchedConfig = $config;
                $baseEvent = $pattern;
                break;
            }
        }

        if ($matchedConfig === null) {
            return; // Not a security event — no alert
        }

        // ── Rate limiting (in-memory per-request + session-based) ──
        if (!_discordRateLimitOk()) {
            return;
        }

        // ── Build Discord embed ─────────────────────────────────
        $detail = '';
        if (str_contains($event, ':')) {
            $detail = substr($event, strlen($baseEvent) + 1);
        }

        $embed = _buildDiscordEmbed(
            $matchedConfig,
            $baseEvent,
            $detail,
            $username,
            $ip
        );

        // ── Send (fire-and-forget with short timeout) ───────────
        _sendDiscordWebhook($webhookUrl, $embed);

    } catch (Throwable $e) {
        // Never crash the application for a notification failure
        error_log('Discord webhook error: ' . $e->getMessage());
    }
}


// ══════════════════════════════════════════════════════════════════
//  EMBED BUILDER
// ══════════════════════════════════════════════════════════════════

/**
 * Build a Discord embed payload for a security event.
 */
function _buildDiscordEmbed(
    array   $config,
    string  $baseEvent,
    string  $detail,
    ?string $username,
    string  $ip
): array {
    $severity = $config['severity'];
    $emoji    = $config['emoji'];

    $title = sprintf('%s [%s] %s', $emoji, $severity, $baseEvent);

    $fields = [
        [
            'name'   => 'Event',
            'value'  => '`' . $baseEvent . '`',
            'inline' => true,
        ],
        [
            'name'   => 'Severity',
            'value'  => '`' . $severity . '`',
            'inline' => true,
        ],
        [
            'name'   => 'Source IP',
            'value'  => '`' . $ip . '`',
            'inline' => true,
        ],
        [
            'name'   => 'User',
            'value'  => '`' . ($username ?? 'guest') . '`',
            'inline' => true,
        ],
        [
            'name'   => 'Timestamp',
            'value'  => '`' . gmdate('Y-m-d H:i:s') . ' UTC`',
            'inline' => true,
        ],
    ];

    if ($detail !== '') {
        $fields[] = [
            'name'   => 'Detail',
            'value'  => '```' . substr($detail, 0, 500) . '```',
            'inline' => false,
        ];
    }

    return [
        'embeds' => [
            [
                'title'     => $title,
                'color'     => $config['color'],
                'fields'    => $fields,
                'footer'    => [
                    'text' => 'TransactiWar Security Monitor',
                ],
            ],
        ],
    ];
}


// ══════════════════════════════════════════════════════════════════
//  HTTP SENDER
// ══════════════════════════════════════════════════════════════════

/**
 * POST JSON payload to Discord webhook URL.
 * Uses a short timeout to avoid blocking the request.
 */
function _sendDiscordWebhook(string $url, array $payload): void {
    // Validate URL is actually a Discord webhook to prevent SSRF
    // Discord webhooks always match this pattern
    if (!preg_match('#^https://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/.+#', $url)) {
        error_log('Discord webhook URL does not match expected Discord pattern — refusing to send');
        return;
    }

    $json = json_encode($payload, JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        return;
    }

    $ch = curl_init($url);
    if ($ch === false) {
        return;
    }

    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $json,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'Content-Length: ' . strlen($json),
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => DISCORD_TIMEOUT_SECONDS,
        CURLOPT_CONNECTTIMEOUT => DISCORD_TIMEOUT_SECONDS,
        // Don't follow redirects — Discord webhooks don't redirect
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS      => 0,
    ]);

    curl_exec($ch);

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($httpCode === 429) {
        // Rate limited by Discord — back off in-memory
        _discordRateLimitRecord(burst: true);
    }

    curl_close($ch);
}


// ══════════════════════════════════════════════════════════════════
//  RATE LIMITER (session-backed sliding window)
// ══════════════════════════════════════════════════════════════════

/**
 * Check if we're within rate limits.
 * Uses a simple file-based counter since this runs server-wide,
 * not per-session.
 */
function _discordRateLimitOk(): bool {
    $stateFile = sys_get_temp_dir() . '/transactiwar_discord_ratelimit.json';

    $state = _discordReadState($stateFile);
    $now = time();

    // Prune timestamps outside the window
    $state['timestamps'] = array_values(array_filter(
        $state['timestamps'] ?? [],
        static fn(int $ts): bool => ($now - $ts) < DISCORD_RATE_WINDOW
    ));

    if (count($state['timestamps']) >= DISCORD_RATE_LIMIT) {
        return false; // Over limit
    }

    return true;
}

/**
 * Record that we sent a webhook.
 */
function _discordRateLimitRecord(bool $burst = false): void {
    $stateFile = sys_get_temp_dir() . '/transactiwar_discord_ratelimit.json';

    $state = _discordReadState($stateFile);
    $now = time();

    // Prune old timestamps
    $state['timestamps'] = array_values(array_filter(
        $state['timestamps'] ?? [],
        static fn(int $ts): bool => ($now - $ts) < DISCORD_RATE_WINDOW
    ));

    // If Discord told us 429, add extra phantom entries to back off
    $entriesToAdd = $burst ? 5 : 1;
    for ($i = 0; $i < $entriesToAdd; $i++) {
        $state['timestamps'][] = $now;
    }

    _discordWriteState($stateFile, $state);
}

/**
 * Read rate limit state from temp file.
 */
function _discordReadState(string $path): array {
    if (!is_file($path)) {
        return ['timestamps' => []];
    }

    $raw = file_get_contents($path);
    if ($raw === false) {
        return ['timestamps' => []];
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return ['timestamps' => []];
    }

    return $data;
}

/**
 * Write rate limit state to temp file.
 */
function _discordWriteState(string $path, array $state): void {
    $json = json_encode($state);
    if ($json !== false) {
        file_put_contents($path, $json, LOCK_EX);
    }
}
