<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();
no_cache();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';

require_login();
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <?php render_page_head('Transactiwar | Confirm Logout'); ?>
</head>

<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container auth-container">
        <div class="card text-center logout-card container-confirm">
            <h2 class="text-glow text-danger-glow">Confirm Logout?</h2>

            <p class="text-muted logout-text">
                Are you sure you want to end your secure session?
            </p>

            <form action="/logout.php" method="POST" class="logout-actions">
                <?= csrfField() ?>
                <a href="/index.php" class="btn-primary btn-stay">Stay Connected</a>
                <button type="submit" class="btn-primary btn-leave">Confirm Logout</button>
            </form>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>

</html>