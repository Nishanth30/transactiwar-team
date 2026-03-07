<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/csrf.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrf();
    session_unset();
    session_destroy();
    header('Location: /login.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    header('Allow: GET, POST');
    http_response_code(405);
    echo 'Method Not Allowed';
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Confirm Logout</title>
</head>
<body>
<h2>Confirm Logout</h2>
<form method="POST" action="/logout.php">
    <?= csrfField() ?>
    <button type="submit">Logout</button>
</form>
</body>
</html>
