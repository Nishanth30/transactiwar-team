<?php
declare(strict_types=1);

/*
 * Central PDO bootstrap used by all runtime entry points.
 * Keep this file side-effect free except creating `$pdo`,
 * so contributors can safely require it from any module.
 */

// Environment-driven DB config for Docker + local parity.
// Defaults exist for developer convenience but docker/.env should provide real values.
$host = getenv('MYSQL_HOST') ?: 'db';
$db   = getenv('MYSQL_DATABASE') ?: 'app_database';
$user = getenv('MYSQL_USER') ?: 'root';
$pass = getenv('MYSQL_PASSWORD') ?: '';

$dsn = "mysql:host={$host};dbname={$db};charset=utf8mb4";

$options = [
    // Throw exceptions so callers can consistently handle DB failures.
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    // Return associative arrays by default to avoid numeric-index mixups.
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
];

$pdo = new PDO($dsn, $user, $pass, $options);
