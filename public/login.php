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

/* Already logged in → redirect */
if (isset($_SESSION['user_id'])) {
    header('Location: /index.php');
    exit;
}

/* Handle login submit */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    verifyCsrf();

    $usernameOrEmail = post_str('identifier');
    $password = $_POST['password'] ?? '';

    if ($usernameOrEmail === '' || $password === '') {
        $error = 'All fields are required.';
        logActivity(LOG_INVALID_INPUT);

    } elseif (strlen($usernameOrEmail) > MAX_EMAIL_LEN) {
        $error = 'Invalid credentials.';
        logActivity(LOG_INVALID_INPUT);

    } else {
        try {
            $success = login_user($pdo, $usernameOrEmail, $password);

            if ($success === true) {
                header('Location: /index.php');
                exit;
            } elseif ($success === 'locked') {
                // Hard lock only triggers at 20 attempts (30 min timeout)
                $error = 'Account temporarily locked. Please try again later.';
            } else {
                $error = 'Invalid credentials.';
            }

        } catch (Throwable $e) {
            error_log($e->getMessage());
            $error = 'Login failed.';
            logActivity(LOG_INVALID_INPUT);
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    logActivity(LOG_PAGE_VIEW);
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Transactiwar | Login</title>
    <?= csrfMeta() ?>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>

<body>

    <div class="container auth-container">
        <div class="card">
            <h2 class="text-center text-glow">Login</h2>

            <?php if ($error !== ''): ?>
                <div class="error-msg">
                    <?= escape_output($error) ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="">
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
                <a href="/register.php" class="text-muted">Need an account? <span class="text-cyan">Register
                        here</span></a>
            </div>
        </div>
    </div>

</body>

</html>