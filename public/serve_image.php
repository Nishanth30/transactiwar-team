<?php
// public/serve_image.php
// Secure image serving gatekeeper.
// Images are stored OUTSIDE the web root in storage/uploads/.
// This script validates the session, sanitizes the filename,
// and streams the file with correct headers.
// Direct URL access to /storage/uploads/ is blocked by .htaccess.

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';

// ── 1. Require login ─────────────────────────────────────────────
// Only authenticated users can view any profile image.
require_login();

// ── 2. Sanitize the requested filename ───────────────────────────
// Accept only a bare filename — no path components at all.
$requested = $_GET['file'] ?? '';

// Strip any directory separators — blocks path traversal attacks
// e.g. ?file=../../config/db.php
$filename = basename($requested);

// Allow only known-safe characters: alphanumeric, dot, hyphen, underscore
if (!preg_match('/^[a-zA-Z0-9._\-]+$/', $filename)) {
    http_response_code(400);
    exit('Invalid filename.');
}

// ── 3. Resolve and validate the physical path ────────────────────
// Files live in storage/uploads/ — outside the web root.
$storage_dir = realpath(__DIR__ . '/../storage/uploads');
$file_path = $storage_dir . DIRECTORY_SEPARATOR . $filename;

// realpath() returns false if the file does not exist —
// this also blocks symlink traversal attacks.
$real_file = realpath($file_path);

if ($real_file === false || strpos($real_file, $storage_dir) !== 0) {
    // Either file doesn't exist, or it escaped the storage directory.
    http_response_code(404);
    exit('Image not found.');
}

// ── 4. Validate it is actually an image (magic bytes check) ──────
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime_type = $finfo->file($real_file);

$allowed_mimes = [
    'image/jpeg' => 'jpg',
    'image/png' => 'png',
    'image/gif' => 'gif',
    'image/webp' => 'webp',
];

if (!array_key_exists($mime_type, $allowed_mimes)) {
    http_response_code(403);
    exit('Forbidden file type.');
}

// ── 5. Send secure headers and stream the file ───────────────────
// Disable execution / caching of sensitive assets.
header('Content-Type: ' . $mime_type);
header('X-Content-Type-Options: nosniff');
header('Content-Disposition: inline; filename="' . $filename . '"');
header('Cache-Control: private, max-age=3600'); // cache in browser, not CDN/proxy
header('Content-Length: ' . filesize($real_file));

// Prevent the browser from sniffing the response as HTML.
// Belt-and-suspenders alongside X-Content-Type-Options.
header('X-Frame-Options: DENY');

readfile($real_file);
exit;
