<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../config/db.php';

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/sanitize.php';

$error   = '';
$success = '';

/* Already logged in */
if (isset($_SESSION['user_id'])) {
    header('Location: /index.php');
    exit;
}

/* Handle form submit */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    verifyCsrf();

    $username        = post_str('username');
    $email           = normalize_email(post_str('email'));
    $password        = $_POST['password']         ?? '';
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
    <title>Register</title>
    <?= csrfMeta() ?>
</head>
<body>

<h2>Register</h2>

<?php if ($error !== ''): ?>
    <p style="color:red;">
        <?= escape_output($error) ?>
    </p>
<?php endif; ?>

<?php if ($success !== ''): ?>
    <p style="color:green;">
        <?= escape_output($success) ?>
    </p>
<?php endif; ?>

<form method="POST">
    <?= csrfField() ?>

    <label>
        Username:
        <input type="text" name="username" required
               minlength="<?= MIN_USERNAME_LEN ?>" maxlength="<?= MAX_USERNAME_LEN ?>">
    </label>
    <br><br>

    <label>
        Email:
        <input type="email" name="email" required maxlength="<?= MAX_EMAIL_LEN ?>">
    </label>
    <br><br>

    <label>
        Password:
        <input type="password" name="password" required
               minlength="<?= MIN_PASSWORD_LEN ?>" maxlength="<?= MAX_PASSWORD_LEN ?>">
    </label>
    <br><br>

    <label>
        Confirm Password:
        <input type="password" name="confirm_password" required>
    </label>
    <br><br>

    <small><?= escape_output(password_requirements()) ?></small>
    <br><br>

    <button type="submit">Register</button>
</form>

<br>
<a href="/login.php">Go to Login</a>

</body>
</html>