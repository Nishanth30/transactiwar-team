<?php
declare(strict_types=1);

header('Content-Type: text/plain; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
echo '<a href="/logout.php">Logout</a>' . "\n";
echo "PHP running\n";

function requireEnv(string $key): string
{
    $value = getenv($key);
    if ($value === false || $value === '') {
        http_response_code(500);
        echo "Missing required server configuration.\n";
        exit(1);
    }

    return $value;
}

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

if (getenv('APP_DIAGNOSTIC_MODE') !== '1') {
    echo "Diagnostic mode disabled.\n";
    exit(0);
}

$host = requireEnv('MYSQL_HOST');
$user = requireEnv('MYSQL_USER');
$pass = requireEnv('MYSQL_PASSWORD');
$dbName = requireEnv('MYSQL_DATABASE');

try {
    $mysqli = new mysqli($host, $user, $pass, $dbName);
    $mysqli->set_charset('utf8mb4');
    $result = $mysqli->query('SHOW TABLES');

    echo "Tables:\n";
    while ($row = $result->fetch_array(MYSQLI_NUM)) {
        $tableName = preg_replace('/[^A-Za-z0-9_]/', '?', (string) $row[0]);
        echo "- {$tableName}\n";
    }

    $result->free();
    $mysqli->close();
} catch (mysqli_sql_exception $exception) {
    error_log('Database operation failed: ' . $exception->getMessage());
    http_response_code(500);
    echo "Database operation failed.\n";
    exit(1);
}
