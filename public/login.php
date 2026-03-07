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
    <title>Login</title>
    <?= csrfMeta() ?>
</head>

<body>

    <h2>Login</h2>

    <?php if ($error !== ''): ?>
        <p style="color:red;">
            <?= escape_output($error) ?>
        </p>
    <?php endif; ?>

    <form method="POST" action="">
        <?= csrfField() ?>

        <label>
            Username or Email:
            <input type="text" name="identifier" required>
        </label>
        <br><br>

        <label>
            Password:
            <input type="password" name="password" required>
        </label>
        <br><br>

        <button type="submit">Login</button>
    </form>

    <a href="/register.php">Go to Register</a>

</body>

</html>