<?php
declare(strict_types=1);

/*
 * Central PDO bootstrap used by all runtime entry points.
 * Keep this file side-effect free except creating `$pdo`,
 * so contributors can safely require it from any module.
 */

// Environment-driven DB config for Docker.
// All four variables are mandatory -- the app refuses to start without them
// to prevent silent fallback to root with an empty password.
$host = getenv('MYSQL_HOST');
$db   = getenv('MYSQL_DATABASE');
$user = getenv('MYSQL_USER');
$pass = getenv('MYSQL_PASSWORD');

if ($host === false || $db === false || $user === false || $pass === false) {
    http_response_code(500);
    error_log('FATAL: One or more required database environment variables are not set (MYSQL_HOST, MYSQL_DATABASE, MYSQL_USER, MYSQL_PASSWORD).');
    exit('Internal server error.');
}

$dsn = "mysql:host={$host};dbname={$db};charset=utf8mb4";

$options = [
    // Throw exceptions so callers can consistently handle DB failures.
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    // Return associative arrays by default to avoid numeric-index mixups.
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
];

$pdo = new PDO($dsn, $user, $pass, $options);
