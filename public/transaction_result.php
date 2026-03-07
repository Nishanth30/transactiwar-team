<?php
require_once __DIR__ . '/../includes/header.php';
send_security_headers();
no_cache();
require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_login();

// Guard — 'transfer_result' is only set by process_payment.php immediately
// before redirecting here. Absent means direct navigation or refresh.
if (!isset($_SESSION['transfer_result'])) {
    header('Location: ' . sanitize_header('/index.php'));
    exit;
}

// Read and immediately consume both keys — neither can be replayed on refresh.
$result = $_SESSION['transfer_result'];  // "successful" | "fail"
$error  = $_SESSION['transfer_error'] ?? null;
unset($_SESSION['transfer_result'], $_SESSION['transfer_error']);

// Outcome is driven by transfer_result, not by whether transfer_error is set.
$is_success = ($result === 'successful');

include("header.html");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title><?= $is_success ? 'Transfer Successful' : 'Transfer Failed' ?></title>
</head>
<body>
<div>
<?php if ($is_success): ?>
    <h2>✅ Transaction Successful</h2>
    <p>Your transfer has been completed.</p>
<?php else: ?>
    <h2>❌ Transfer Failed</h2>
    <p><?= escape_output($error ?? 'Transfer failed. Please try again.') ?></p>
<?php endif; ?>
    <a href="index.php">Go Back to Home Page</a>
</div>
<?php include("footer.html"); ?>
</body>
</html>