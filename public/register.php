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

if (isset($_SESSION['flash_error'])) {
    $error = $_SESSION['flash_error'];
    unset($_SESSION['flash_error']);
}
if (isset($_SESSION['flash_success'])) {
    $success = $_SESSION['flash_success'];
    unset($_SESSION['flash_success']);
}

if (isset($_SESSION['user_id'])) {
    header('Location: /index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrf();

    // Honeypot — bots fill the invisible field, humans don't
    if (aiTrapTriggered()) {
        $_SESSION['flash_error'] = 'Registration failed.';
        header('Location: /register.php');
        exit;
    }

    // M5 FIX: Rate-limit registration by IP before any expensive work
    // (validation, bcrypt hashing, DB insert). Prevents enumeration,
    // spam account creation, and CPU exhaustion via bcrypt.
    $regIp = function_exists('get_client_ip')
        ? get_client_ip()
        : sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

    if (is_registration_locked($pdo, $regIp)) {
        $remaining = get_registration_lockout_remaining($pdo, $regIp);
        $minutes = max(1, (int) ceil($remaining / 60));
        $_SESSION['flash_error'] = 'Too many registration attempts. Please try again in ' . $minutes . ' minute(s).';
        logActivity(LOG_INVALID_INPUT);
        header('Location: /register.php');
        exit;
    }

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
            $result = register_user($pdo, $username, $email, $password);

            if ($result === true) {
                $flash_success = 'Registration successful. You can now login.';
            } elseif ($result === 'duplicate') {
                $flash_error = 'Username or email already exists.';
            } else {
                $flash_error = 'Registration failed.';
            }
        } catch (Throwable $e) {
            error_log('Registration handler error: ' . get_class($e) . ' code=' . $e->getCode());
            $flash_error = 'Registration failed.';
        }
    }

    // Count every POST attempt (success or failure) toward the rate limit.
    // This prevents an attacker from enumerating usernames/emails without
    // triggering the lockout by only sending valid registrations.
    record_registration_attempt($pdo, $regIp);

    if ($flash_error !== '') {
        $_SESSION['flash_error'] = $flash_error;
    }
    if ($flash_success !== '') {
        $_SESSION['flash_success'] = $flash_success;
    }

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
    <div class="tw-auth-wrap">
        <div class="tw-auth-card tw-medium">
            <div class="card">
                <div class="card-body">
                    <h2 class="text-center text-glow mb-4">Register</h2>

                    <?php if ($error !== ''): ?>
                        <div class="alert alert-danger" role="alert">
                            <?= escape_output($error) ?>
                        </div>
                    <?php endif; ?>

                    <?php if ($success !== ''): ?>
                        <div class="alert alert-success" role="alert">
                            <?= escape_output($success) ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" action="/register.php">
                        <?= csrfField() ?>
                        <?= aiTrapForm() ?>

                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username"
                                   required minlength="<?= MIN_USERNAME_LEN ?>"
                                   maxlength="<?= MAX_USERNAME_LEN ?>" autocomplete="username">
                        </div>

                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email"
                                   required maxlength="<?= MAX_EMAIL_LEN ?>" autocomplete="email">
                        </div>

                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password"
                                   required minlength="<?= MIN_PASSWORD_LEN ?>"
                                   maxlength="<?= MAX_PASSWORD_LEN ?>" autocomplete="new-password">
                        </div>

                        <div class="mb-3">
                            <label for="confirm_password" class="form-label">Confirm Password</label>
                            <input type="password" class="form-control" id="confirm_password"
                                   name="confirm_password" required autocomplete="new-password">
                        </div>

                        <button type="submit" class="btn btn-primary w-100 mt-2">Create Account</button>
                    </form>

                    <?php if ($error !== ''): ?>
                    <div class="tw-rules mt-4">
                        <h6>Account Requirements</h6>
                        <div class="mb-2">
                            <strong>Username</strong>
                            <ul>
                                <li><?= MIN_USERNAME_LEN ?>&ndash;<?= MAX_USERNAME_LEN ?> characters</li>
                                <li>Only letters, numbers, underscores, and hyphens</li>
                                <li>Cannot start or end with underscore or hyphen</li>
                            </ul>
                        </div>
                        <div class="mb-2">
                            <strong>Email</strong>
                            <ul>
                                <li>Must be a valid email address (max <?= MAX_EMAIL_LEN ?> chars)</li>
                            </ul>
                        </div>
                        <div>
                            <strong>Password</strong>
                            <ul>
                                <li><?= MIN_PASSWORD_LEN ?>&ndash;<?= MAX_PASSWORD_LEN ?> characters</li>
                                <li>At least one uppercase letter (A&ndash;Z)</li>
                                <li>At least one lowercase letter (a&ndash;z)</li>
                                <li>At least one digit (0&ndash;9)</li>
                                <li>At least one special character (!@#$%^&amp;* etc.)</li>
                            </ul>
                        </div>
                    </div>
                    <?php endif; ?>

                    <div class="text-center mt-4">
                        <a href="/login.php" class="text-muted">
                            Already have an account? <span class="text-cyan">Login</span>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
