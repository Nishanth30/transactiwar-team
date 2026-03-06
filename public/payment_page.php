<?php
require_once __DIR__ . '/../includes/header.php';
send_security_headers();
no_cache();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../config/db.php';

require_login();

// If form was submitted, hand off to backend processor
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    require_once __DIR__ . '/../includes/process_payment.php';
    exit; // process_payment.php will redirect, but exit here as safety net
}

// GET — show the payment form
$username = get_str('username');
$targetUuid = get_str('target_uuid');

$stmt = $pdo->prepare("SELECT id, balance_paise FROM users WHERE id = ? LIMIT 1");
$stmt->execute([$_SESSION['user_id']]);
$sender = $stmt->fetch(PDO::FETCH_ASSOC);
$balanceRupees = number_format($sender['balance_paise'] / 100, 2);

logActivity(LOG_PROFILE_OTHER);

include("header.html");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Pay <?php echo escape_output($username); ?></title>
</head>
<body>

<div>
    <h2>Pay <?php echo escape_output($username); ?></h2>
    <p>Your balance: <strong>₹<?php echo escape_output($balanceRupees); ?></strong></p>

    <form action="payment_page.php?username=<?php echo urlencode($username); ?>&target_uuid=<?php echo urlencode($targetUuid); ?>" method="POST">

        <?= csrfField(); ?>

        <input type="hidden" name="target_uuid" value="<?php echo escape_attr($targetUuid); ?>">
        <input type="hidden" name="username"    value="<?php echo escape_attr($username); ?>">

        <label>Amount (₹):</label><br>
        <input type="number" name="amount" min="1" step="0.01" required><br>
        <small>Minimum transfer: ₹1.00</small><br><br>

        <label>Remark:</label><br>
        <input type="text" name="remark" maxlength="500" placeholder="Optional note..."><br><br>

        <button type="submit">Confirm Payment</button>
    </form>
</div>

<?php include("footer.html"); ?>
</body>
</html>