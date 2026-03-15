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

    <div class="tw-auth-wrap">
        <div class="tw-auth-card tw-tiny">
            <div class="card">
                <div class="card-body text-center py-5">
                    <h2 class="text-danger-glow mb-3">Confirm Logout?</h2>
                    <p class="text-muted mb-4">
                        Are you sure you want to end your session?
                    </p>

                    <form action="/logout.php" method="POST" class="d-flex gap-2">
                        <?= csrfField() ?>
                        <a href="/index.php" class="btn btn-outline-secondary flex-fill">Stay</a>
                        <button type="submit" class="btn btn-outline-danger flex-fill">Logout</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.php'; ?>
</body>
</html>
