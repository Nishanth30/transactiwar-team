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

if (isset($_SESSION['flash_error']) && is_string($_SESSION['flash_error'])) {
    $error = $_SESSION['flash_error'];
    unset($_SESSION['flash_error']);
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
    $flashError = '';

    if ($usernameOrEmail === '' || $password === '') {
        $flashError = 'All fields are required.';
        logActivity(LOG_INVALID_INPUT);
    } elseif (strlen($usernameOrEmail) > MAX_EMAIL_LEN) {
        $flashError = 'Invalid credentials.';
        logActivity(LOG_INVALID_INPUT);
    } else {
        try {
            $success = login_user($pdo, $usernameOrEmail, $password);

            if ($success === true) {
                header('Location: /index.php');
                exit;
            }

            if ($success === 'locked') {
                $flashError = 'Account temporarily locked. Please try again later.';
            } elseif ($success === 'throttled') {
                $flashError = 'Too many attempts. Please wait a moment before trying again.';
            } elseif ($success === 'system') {
                $flashError = 'Login is temporarily unavailable. Please try again in a minute.';
            } else {
                $flashError = 'Invalid credentials.';
            }
        } catch (Throwable $e) {
            error_log($e->getMessage());
            $flashError = 'Login failed.';
            logActivity(LOG_INVALID_INPUT);
        }
    }

    $_SESSION['flash_error'] = $flashError;
    header('Location: /login.php');
    exit;
}

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
    <div class="tw-auth-wrap">
        <div class="tw-auth-card tw-narrow">
            <div class="card">
                <div class="card-body">
                    <h2 class="text-center text-glow mb-4">Login</h2>

                    <?php if ($error !== ''): ?>
                        <div class="alert alert-danger" role="alert">
                            <?= escape_output($error) ?>
                        </div>
                    <?php endif; ?>

                    <?php if ($successMessage !== ''): ?>
                        <div class="alert alert-success" role="alert">
                            <?= escape_output($successMessage) ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" action="/login.php">
                        <?= csrfField() ?>

                        <div class="mb-3">
                            <label for="identifier" class="form-label">Username or Email</label>
                            <input type="text" class="form-control" id="identifier"
                                   name="identifier" required autocomplete="username">
                        </div>

                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password"
                                   name="password" required autocomplete="current-password">
                        </div>

                        <button type="submit" class="btn btn-primary w-100 mt-2">Login</button>
                    </form>

                    <div class="text-center mt-4">
                        <a href="/register.php" class="text-muted">
                            Need an account? <span class="text-cyan">Register here</span>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
