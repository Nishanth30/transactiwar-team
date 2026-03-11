<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../config/db.php';

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/sanitize.php';

$error = '';
$success = '';

/* Already logged in */
if (isset($_SESSION['user_id'])) {
    header('Location: /index.php');
    exit;
}

/* Handle form submit */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    verifyCsrf();

    $username = post_str('username');
    $email = normalize_email(post_str('email'));
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    if ($username === '' || $email === '' || $password === '' || $confirmPassword === '') {
        $error = 'All fields are required.';
    } elseif (!validate_username($username)) {
        $error = 'Username must be 5-32 characters and contain only lowercase letters, numbers, dots, or underscores.';
    } elseif (!validate_email($email)) {
        $error = 'Invalid email address.';
    } elseif (!validate_password($password)) {
        $error = password_requirements();
    } elseif ($password !== $confirmPassword) {
        $error = 'Passwords do not match.';
    } else {
        try {
            $result = register_user($pdo, $username, $email, $password);

            if ($result === true) {
                $success = 'Registration successful. You can now login.';
            } elseif ($result === 'duplicate') {
                $error = 'Username or email already exists.';
            } else {
                $error = 'Registration failed.';
            }

        } catch (Throwable $e) {
            error_log($e->getMessage());
            $error = 'Registration failed.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Transactiwar | Register</title>
    <?= csrfMeta() ?>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>

<body>

    <div class="container auth-container">
        <div class="card">
            <h2 class="text-center text-glow">Register</h2>

            <?php if ($error !== ''): ?>
                <div class="error-msg">
                    <?= escape_output($error) ?>
                </div>
            <?php endif; ?>

            <?php if ($success !== ''): ?>
                <div class="success-msg">
                    <?= escape_output($success) ?>
                </div>
            <?php endif; ?>

            <form method="POST">
                <?= csrfField() ?>

                <div class="mt-2">
                    <label>Username</label>
                    <input type="text" name="username" required minlength="<?= MIN_USERNAME_LEN ?>"
                        maxlength="<?= MAX_USERNAME_LEN ?>">
                </div>

                <div class="mt-2">
                    <label>Email</label>
                    <input type="email" name="email" required maxlength="<?= MAX_EMAIL_LEN ?>">
                </div>

                <div class="mt-2">
                    <label>Password</label>
                    <input type="password" name="password" required minlength="<?= MIN_PASSWORD_LEN ?>"
                        maxlength="<?= MAX_PASSWORD_LEN ?>">
                </div>

                <div class="mt-2">
                    <label>Confirm Password</label>
                    <input type="password" name="confirm_password" required>
                </div>

                <small class="text-muted mt-2 d-flex"><?= escape_output(password_requirements()) ?></small>

                <button type="submit" class="btn-primary mt-4">Create Account</button>
            </form>

            <div class="text-center mt-4">
                <a href="/login.php" class="text-muted">Already have an account? <span
                        class="text-cyan">Login</span></a>
            </div>
        </div>
    </div>

</body>

</html>