<?php
require_once __DIR__ . '/../includes/header.php';
send_security_headers();
no_cache();
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/auth.php';

require_login();

// If form was submitted, hand off to backend processor
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_once __DIR__ . '/../includes/process_payment.php';
    exit;
}

// ── GET — validate UUID from URL ──────────────────────────────────
$targetUuid = sanitize_uuid(get_str('target_uuid'));

if ($targetUuid === null) {
    header('Location: ' . sanitize_header('/index.php'));
    exit;
}

// ── Fetch receiver from DB by UUID ───────────────────────────────
// Username is NEVER taken from the URL — only from the DB row the
// UUID resolves to. Spoofing &username=abc in the URL has no effect.
$stmt = $pdo->prepare(
    "SELECT id, username FROM users WHERE public_id = ? LIMIT 1"
);
$stmt->execute([$targetUuid]);
$receiver = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$receiver) {
    // UUID doesn't match any account — abort
    header('Location: ' . sanitize_header('/index.php'));
    exit;
}

$receiverUsername = $receiver['username'];   // authoritative, from DB

// ── Fetch sender balance ──────────────────────────────────────────
$stmt = $pdo->prepare(
    "SELECT balance_paise FROM users WHERE id = ? LIMIT 1"
);
$stmt->execute([$_SESSION['user_id']]);
$sender        = $stmt->fetch(PDO::FETCH_ASSOC);
$balanceRupees = number_format($sender['balance_paise'] / 100, 2);

logActivity(LOG_PROFILE_OTHER);

include __DIR__ . '/header.html';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Pay <?= escape_output($receiverUsername) ?></title>
</head>
<body>

<div>
    <h2>Pay <?= escape_output($receiverUsername) ?></h2>
    <p>Your balance: <strong>₹<?= escape_output($balanceRupees) ?></strong></p>

    <form action="/payment_page.php" method="POST">
        <?= csrfField() ?>

        <input type="hidden" name="target_uuid" value="<?= escape_attr($targetUuid) ?>">

        <label>Amount (₹):</label><br>
        <input type="number" name="amount" min="1" step="0.01" required><br>
        <small>Minimum transfer: ₹1.00</small><br><br>

        <label>Remark:</label><br>
        <input type="text" name="remark" maxlength="500" placeholder="Optional note..."><br><br>

        <button type="submit">Confirm Payment</button>
    </form>
</div>

<?php include __DIR__ . '/footer.html'; ?>
</body>
</html>