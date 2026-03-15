<?php
// public/serve_image.php
// Secure image serving gatekeeper.
// Images are stored outside the web root in storage/uploads/.
// This script validates the session, sanitizes the filename,
// and streams the file with correct headers.

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../includes/sanitize.php';

// Only authenticated users can view profile images.
require_login();

$requested = $_GET['file'] ?? '';
$filename = basename((string) $requested);

// Allow only safe filename characters.
if (!preg_match('/^[a-zA-Z0-9._\-]+$/', $filename)) {
    http_response_code(400);
    exit('Invalid filename.');
}

$storageDir = realpath(__DIR__ . '/../storage/uploads');
$defaultFilename = 'default_agent.png';

if ($storageDir === false) {
    http_response_code(500);
    exit('Image storage unavailable.');
}

$filePath = $storageDir . DIRECTORY_SEPARATOR . $filename;
$defaultPath = $storageDir . DIRECTORY_SEPARATOR . $defaultFilename;
$realFile = realpath($filePath);
$realDefault = realpath($defaultPath);

// If requested file is missing/stale, fall back to default avatar.
if (
    $realFile === false ||
    !str_starts_with($realFile, $storageDir . DIRECTORY_SEPARATOR) ||
    !is_file($realFile)
) {
    $realFile = $realDefault;
    $filename = $defaultFilename;
}

if (
    $realFile === false ||
    !str_starts_with($realFile, $storageDir . DIRECTORY_SEPARATOR) ||
    !is_file($realFile)
) {
    http_response_code(404);
    exit('Image not found.');
}

$finfo = new finfo(FILEINFO_MIME_TYPE);
$mimeType = $finfo->file($realFile);

$allowedMimes = [
    'image/jpeg' => 'jpg',
    'image/png' => 'png',
    'image/gif' => 'gif',
    'image/webp' => 'webp',
];

if (!array_key_exists($mimeType, $allowedMimes)) {
    http_response_code(403);
    exit('Forbidden file type.');
}

send_asset_headers($mimeType);
header('Content-Disposition: inline; filename="' . $filename . '"');
header('Cache-Control: private, max-age=3600');
header('Content-Length: ' . filesize($realFile));

readfile($realFile);
exit;
