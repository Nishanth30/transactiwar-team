<?php

declare(strict_types=1);

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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_SESSION['transfer_complete'])) {
        $_SESSION['transfer_error'] = "This transfer has already been processed.";
        $_SESSION['transfer_result'] = "fail";
        header('Location: ' . sanitize_header('/transaction_result.php'));
        exit;
    }

    require_once __DIR__ . '/../includes/process_payment.php';
    exit;
}

$targetUuid = sanitize_uuid(get_str('target_uuid'));
if ($targetUuid === null) {
    logActivity(LOG_INVALID_INPUT);
    header('Location: ' . sanitize_header('/index.php'));
    exit;
}

$stmt = $pdo->prepare(
    "SELECT id, username FROM users WHERE public_id = ? LIMIT 1"
);
$stmt->execute([$targetUuid]);
$receiver = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$receiver) {
    logActivity(LOG_INVALID_INPUT);
    header('Location: ' . sanitize_header('/index.php'));
    exit;
}

$transferNonce = bin2hex(random_bytes(16));
$_SESSION['transfer_nonce'] = $transferNonce;

$receiverUsername = $receiver['username'];

$stmt = $pdo->prepare(
    "SELECT balance_paise FROM users WHERE id = ? LIMIT 1"
);
$stmt->execute([$_SESSION['user_id']]);
$sender = $stmt->fetch(PDO::FETCH_ASSOC);
$balanceRupees = number_format($sender['balance_paise'] / 100, 2);

logActivity(LOG_PAGE_VIEW);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | Pay ' . $receiverUsername); ?>
</head>
<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container py-4 tw-w-sm">
        <div class="card">
            <div class="card-body">
                <h2 class="text-glow text-center mb-4">Transfer Funds</h2>

                <div class="card tw-target-card mb-4">
                    <div class="card-body py-3">
                        <p class="text-muted small mb-1">Recipient</p>
                        <h4 class="text-cyan mb-3"><?= escape_output($receiverUsername) ?></h4>

                        <div class="tw-balance-box w-100">
                            <span class="tw-balance-label d-block mb-1">Your Balance</span>
                            <span class="tw-balance-amount font-mono tw-balance-inline">
                                &#8377;<?= escape_output($balanceRupees) ?>
                            </span>
                        </div>
                    </div>
                </div>

                <form action="/payment_page.php" method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="transfer_nonce" value="<?= escape_attr($transferNonce) ?>">
                    <input type="hidden" name="target_uuid" value="<?= escape_attr($targetUuid) ?>">

                    <div class="mb-3">
                        <label for="amount" class="form-label">Amount (&#8377;)</label>
                        <input type="number" class="form-control" id="amount" name="amount"
                               min="1" step="0.01" placeholder="0.00" required>
                        <div class="form-text">Minimum transfer: &#8377;1.00</div>
                    </div>

                    <div class="mb-3">
                        <label for="remark" class="form-label">Remark (optional)</label>
                        <input type="text" class="form-control" id="remark" name="remark"
                               maxlength="500" placeholder="Add a note&hellip;">
                    </div>

                    <button type="submit" class="btn btn-primary w-100 mt-2">Authorize Transfer</button>
                </form>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.php'; ?>
</body>
</html>
