<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../config/db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrf();
    logout_user();  // session_regenerate_id(true) + cookie deletion + logging
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
    <title>Transactiwar | Confirm Logout</title>
    <?= csrfMeta() ?>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>

<body>
    <?php include("header.html"); ?>

    <div class="container auth-container">
        <div class="card" style="text-align: center;">
            <h2 class="text-glow">Confirm Logout</h2>
            <p class="text-muted mt-2 mb-4">Are you sure you want to securely end your session?</p>
            <form method="POST" action="/logout.php">
                <?= csrfField() ?>
                <button type="submit" class="btn-primary"
                    style="background: rgba(255,50,50,0.2) !important; color: #ff5555 !important; border-color: #ff5555 !important; box-shadow: 0 0 10px rgba(255, 50, 50, 0.4) !important;">Sign
                    Out</button>
                <a href="/index.php" class="btn btn-primary"
                    style="background: transparent !important; margin-left:1rem; text-decoration:none; display: inline-block;">Cancel</a>
            </form>
        </div>
    </div>

    <?php include("footer.html"); ?>
</body>

</html>