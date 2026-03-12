<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/sanitize.php';

$error = '';
$success = '';

// Retrieve flash messages from the session if they exist
if (isset($_SESSION['flash_error'])) {
    $error = $_SESSION['flash_error'];
    unset($_SESSION['flash_error']);
}
if (isset($_SESSION['flash_success'])) {
    $success = $_SESSION['flash_success'];
    unset($_SESSION['flash_success']);
}

// Prevent already-authenticated users from creating extra accounts accidentally.
if (isset($_SESSION['user_id'])) {
    header('Location: /index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Registration mutates state; CSRF token is mandatory.
    verifyCsrf();

    $username = post_str('username');
    $email = normalize_email(post_str('email'));
    $password = (string) ($_POST['password'] ?? '');
    $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

    $flash_error = '';
    $flash_success = '';

    if ($username === '' || $email === '' || $password === '' || $confirmPassword === '') {
        $flash_error = 'All fields are required.';
    } elseif (!validate_username($username)) {
        $flash_error = 'Invalid username. Please check the requirements below.';
    } elseif (!validate_email($email)) {
        $flash_error = 'Invalid email address.';
    } elseif (!validate_password($password)) {
        $flash_error = password_requirements();
    } elseif ($password !== $confirmPassword) {
        $flash_error = 'Passwords do not match.';
    } else {
        try {
            // register_user() encapsulates DB uniqueness handling and password hashing.
            $result = register_user($pdo, $username, $email, $password);

            if ($result === true) {
                $flash_success = 'Registration successful. You can now login.';
            } elseif ($result === 'duplicate') {
                $flash_error = 'Username or email already exists.';
            } else {
                $flash_error = 'Registration failed.';
            }
        } catch (Throwable $e) {
            error_log($e->getMessage());
            $flash_error = 'Registration failed.';
        }
    }

    if ($flash_error !== '') {
        $_SESSION['flash_error'] = $flash_error;
    }
    if ($flash_success !== '') {
        $_SESSION['flash_success'] = $flash_success;
    }

    // PRG Pattern: Redirect back to GET request to prevent form resubmission on reload
    header('Location: /register.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | Register', csrfMeta()); ?>
</head>
<body>
    <div class="container auth-container container-register">
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

            <form method="POST" action="/register.php">
                <?= csrfField() ?>

                <div class="mt-2">
                    <label>Username</label>
                    <input type="text" name="username" required minlength="<?= MIN_USERNAME_LEN ?>" maxlength="<?= MAX_USERNAME_LEN ?>">
                </div>

                <div class="mt-2">
                    <label>Email</label>
                    <input type="email" name="email" required maxlength="<?= MAX_EMAIL_LEN ?>">
                </div>

                <div class="mt-2">
                    <label>Password</label>
                    <input type="password" name="password" required minlength="<?= MIN_PASSWORD_LEN ?>" maxlength="<?= MAX_PASSWORD_LEN ?>">
                </div>

                <div class="mt-2">
                    <label>Confirm Password</label>
                    <input type="password" name="confirm_password" required>
                </div>

                <button type="submit" class="btn-primary mt-4">Create Account</button>
            </form>

            <?php if ($error !== ''): ?>
            <div class="rules-box mt-4">
                <h4 class="rules-title">Account Requirements</h4>
                <div class="rules-section">
                    <strong>Username</strong>
                    <ul>
                        <li><?= MIN_USERNAME_LEN ?>–<?= MAX_USERNAME_LEN ?> characters</li>
                        <li>Only letters, numbers, underscores, and hyphens</li>
                        <li>Cannot start or end with underscore or hyphen</li>
                        <li>No spaces allowed</li>
                    </ul>
                </div>
                <div class="rules-section">
                    <strong>Email</strong>
                    <ul>
                        <li>Must be a valid email address</li>
                        <li>Maximum <?= MAX_EMAIL_LEN ?> characters</li>
                    </ul>
                </div>
                <div class="rules-section">
                    <strong>Password</strong>
                    <ul>
                        <li><?= MIN_PASSWORD_LEN ?>–<?= MAX_PASSWORD_LEN ?> characters</li>
                        <li>At least one uppercase letter (A–Z)</li>
                        <li>At least one lowercase letter (a–z)</li>
                        <li>At least one digit (0–9)</li>
                        <li>At least one special character (!@#$%^&* etc.)</li>
                    </ul>
                </div>
            </div>
            <?php endif; ?>

            <div class="text-center mt-4">
                <a href="/login.php" class="text-muted">Already have an account? <span class="text-cyan">Login</span></a>
            </div>
        </div>
    </div>
</body>
</html>
