<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/auth.php';

$error = '';
$successMessage = '';

if (isset($_SESSION['flash_success']) && is_string($_SESSION['flash_success'])) {
    $successMessage = $_SESSION['flash_success'];
    unset($_SESSION['flash_success']);
}

// Logged-in users should not reuse the login form.
if (isset($_SESSION['user_id'])) {
    header('Location: /index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Enforce anti-CSRF check before reading credentials.
    verifyCsrf();

    $usernameOrEmail = post_str('identifier');
    $password = (string) ($_POST['password'] ?? '');

    if ($usernameOrEmail === '' || $password === '') {
        $error = 'All fields are required.';
        logActivity(LOG_INVALID_INPUT);
    } elseif (strlen($usernameOrEmail) > MAX_EMAIL_LEN) {
        $error = 'Invalid credentials.';
        logActivity(LOG_INVALID_INPUT);
    } else {
        try {
            // All authentication hardening (rate limit, timing defense, session regen)
            // is handled inside login_user().
            $success = login_user($pdo, $usernameOrEmail, $password);

            if ($success === true) {
                header('Location: /index.php');
                exit;
            }

            $error = $success === 'locked'
                ? 'Account temporarily locked. Please try again later.'
                : 'Invalid credentials.';
        } catch (Throwable $e) {
            error_log($e->getMessage());
            $error = 'Login failed.';
            logActivity(LOG_INVALID_INPUT);
        }
    }
}

// Keep page-view analytics on GET only.
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    logActivity(LOG_PAGE_VIEW);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | Login', csrfMeta()); ?>
</head>
<body>
    <div class="container auth-container container-login">
        <div class="card">
            <h2 class="text-center text-glow">Login</h2>

            <?php if ($error !== ''): ?>
                <div class="error-msg">
                    <?= escape_output($error) ?>
                </div>
            <?php endif; ?>

            <?php if ($successMessage !== ''): ?>
                <div class="success-msg">
                    <?= escape_output($successMessage) ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="/login.php">
                <?= csrfField() ?>

                <div class="mt-2">
                    <label>Username or Email</label>
                    <input type="text" name="identifier" required>
                </div>

                <div class="mt-2">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>

                <button type="submit" class="btn-primary mt-4">Login</button>
            </form>
            <div class="text-center mt-4">
                <a href="/register.php" class="text-muted">Need an account? <span class="text-cyan">Register here</span></a>
            </div>
        </div>
    </div>
</body>
</html>
