<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../config/db.php';

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/sanitize.php';

$error = '';

/* Already logged in → redirect */
if (isset($_SESSION['user_id'])) {
    header('Location: /index.php');
    exit;
}

/* Handle login submit */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CSRF protection
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        http_response_code(400);
        $error = 'Invalid request.';
    } else {

        $usernameOrEmail = clean_input($_POST['identifier'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($usernameOrEmail === '' || $password === '') {
            $error = 'All fields are required.';
        } else {

            try {
                $success = login_user($pdo, $usernameOrEmail, $password);

                if ($success) {
                    header('Location: /index.php');
                    exit;
                } else {
                    $error = 'Invalid credentials.';
                }

            } catch (Throwable $e) {
                error_log($e->getMessage());
                $error = 'Login failed.';
            }
        }
    }
}

/* Generate CSRF token for form */
$csrfToken = generate_csrf_token();

?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Login</title>
</head>
<body>

<h2>Login</h2>

<?php if ($error !== ''): ?>
<p style="color:red;">
    <?= escape_output($error) ?>
</p>
<?php endif; ?>

<form method="POST" action="">
    <input type="hidden" name="csrf_token"
           value="<?= escape_output($csrfToken) ?>">

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

</body>
</html>
