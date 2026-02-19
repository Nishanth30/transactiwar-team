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

    /* CSRF validation */
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        http_response_code(400);
        $error = 'Invalid request.';
    } else {

        $username = clean_input($_POST['username'] ?? '');
        $email    = clean_input($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($username === '' || $email === '' || $password === '') {
            $error = 'All fields are required.';
        } else {

            try {

                $ok = register_user($pdo, $username, $email, $password);

                if ($ok) {
                    $success = 'Registration successful. You can now login.';
                } else {
                    $error = 'Username or email already exists.';
                }

            } catch (Throwable $e) {
                error_log($e->getMessage());
                $error = 'Registration failed.';
            }
        }
    }
}

/* Generate CSRF token */
$csrfToken = generate_csrf_token();
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Register</title>
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

    <input type="hidden"
           name="csrf_token"
           value="<?= escape_output($csrfToken) ?>">

    <label>
        Username:
        <input type="text" name="username" required>
    </label>
    <br><br>

    <label>
        Email:
        <input type="email" name="email" required>
    </label>
    <br><br>

    <label>
        Password:
        <input type="password" name="password" required>
    </label>
    <br><br>

    <button type="submit">Register</button>

</form>

<br>
<a href="/login.php">Go to Login</a>

</body>
</html>
