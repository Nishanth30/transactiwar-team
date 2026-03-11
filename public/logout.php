<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../config/db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Logout is a state-changing action, so we require a CSRF token.
    verifyCsrf();
    logout_user();
    header('Location: /login.php');
    exit;
}

// The GET route only renders a confirmation page.
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
    <?php render_page_head('Transactiwar | Confirm Logout', csrfMeta()); ?>
</head>
<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container auth-container">
        <div class="card" style="text-align: center;">
            <h2 class="text-glow">Confirm Logout</h2>
            <p class="text-muted mt-2 mb-4">Are you sure you want to securely end your session?</p>
            <form method="POST" action="/logout.php">
                <?= csrfField() ?>
                <button type="submit" class="btn-primary" style="background: rgba(255,50,50,0.2) !important; color: #ff5555 !important; border-color: #ff5555 !important; box-shadow: 0 0 10px rgba(255, 50, 50, 0.4) !important;">Sign Out</button>
                <a href="/index.php" class="btn btn-primary" style="background: transparent !important; margin-left:1rem; text-decoration:none; display: inline-block;">Cancel</a>
            </form>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>
</html>
