<?php
// public/csp-report.php
// CSP Violation Report Collector
//
// Receives Content-Security-Policy violation reports from browsers.
// Logs them as security events for forensic analysis.
// When an attacker's XSS attempt gets blocked by CSP, we see exactly what they tried.

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/logger.php';

// Only accept POST with JSON content
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(204);
    exit;
}

// ── Per-IP rate limiting (file-based, lives on tmpfs) ─────────
// Allows 10 reports per IP per 60-second window.
// Prevents log-flooding attacks against this unauthenticated endpoint.
$_cspRateDir = sys_get_temp_dir() . '/csp_ratelimit';
if (!is_dir($_cspRateDir)) {
    @mkdir($_cspRateDir, 0700, true);
}
$_cspIp = function_exists('get_client_ip') ? get_client_ip() : ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
$_cspRateFile = $_cspRateDir . '/' . hash('xxh3', $_cspIp) . '.json';
$_cspRateLimit = 10;
$_cspRateWindow = 60;
$_cspNow = time();

$_cspState = [];
if (is_file($_cspRateFile)) {
    $_cspState = json_decode((string) file_get_contents($_cspRateFile), true) ?: [];
}
// Prune timestamps outside the window
$_cspState = array_values(array_filter(
    $_cspState,
    static fn(int $ts): bool => ($_cspNow - $ts) < $_cspRateWindow
));
if (count($_cspState) >= $_cspRateLimit) {
    http_response_code(429);
    exit;
}
$_cspState[] = $_cspNow;
file_put_contents($_cspRateFile, json_encode($_cspState), LOCK_EX);
unset($_cspRateDir, $_cspIp, $_cspRateFile, $_cspRateLimit, $_cspRateWindow, $_cspNow, $_cspState);

$raw = file_get_contents('php://input');

// Reject oversized reports (prevent abuse)
if ($raw === false || strlen($raw) === 0 || strlen($raw) > 10000) {
    http_response_code(204);
    exit;
}

$report = json_decode($raw, true);
if (!is_array($report)) {
    http_response_code(204);
    exit;
}

// CSP reports come wrapped in {"csp-report": {...}} or {"body": {...}}
$violation = $report['csp-report'] ?? $report['body'] ?? $report;

$blockedUri    = substr((string) ($violation['blocked-uri']    ?? $violation['blockedURL']        ?? ''), 0, 200);
$violatedDir   = substr((string) ($violation['violated-directive'] ?? $violation['effectiveDirective'] ?? ''), 0, 100);
$documentUri   = substr((string) ($violation['document-uri']   ?? $violation['documentURL']       ?? ''), 0, 200);
$sourceFile    = substr((string) ($violation['source-file']    ?? $violation['sourceFile']         ?? ''), 0, 200);
$lineNumber    = (int) ($violation['line-number'] ?? $violation['lineNumber'] ?? 0);

// Build a concise detail string
$detail = "blocked=$blockedUri directive=$violatedDir";
if ($sourceFile !== '') {
    $detail .= " source=$sourceFile:$lineNumber";
}

// Log as security event — this goes to DB + Discord
if (function_exists('logSecurityEvent')) {
    logSecurityEvent('CSP_VIOLATION', $detail);
}

// Always return 204 No Content (spec requirement)
http_response_code(204);
