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
    // If transfer_complete is set, this is a back-button resubmission
    // with a stale CSRF token — redirect safely before verifyCsrf() fires
    if (isset($_SESSION['transfer_complete'])) {
        $_SESSION['transfer_error'] = "This transfer has already been processed.";
        $_SESSION['transfer_result'] = "fail";
        header('Location: ' . sanitize_header('/transaction_result.php'));
        exit;
    }

    require_once __DIR__ . '/../includes/process_payment.php';
    exit;
}

// Receiver identity is always addressed via public UUID, never internal numeric ID.
$targetUuid = sanitize_uuid(get_str('target_uuid'));
if ($targetUuid === null) {
    logActivity(LOG_INVALID_INPUT);
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
    logActivity(LOG_INVALID_INPUT);
    header('Location: ' . sanitize_header('/index.php'));
    exit;
}

$transferNonce = bin2hex(random_bytes(16));
$_SESSION['transfer_nonce'] = $transferNonce;

$receiverUsername = $receiver['username'];   // authoritative, from DB

// ── Fetch sender balance ──────────────────────────────────────────
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

    <div class="container auth-container">
        <div class="card">
            <h2 class="text-glow text-center">Transfer Funds</h2>

            <div class="card" style="background: rgba(0,0,0,0.3); border: none; margin-bottom: 2rem; text-align: center; padding: 1.5rem;">
                <p class="text-muted" style="margin: 0; font-size: 0.9rem;">Target Agent</p>
                <h3 class="text-cyan" style="margin: 0.5rem 0 1.5rem 0;"><?= escape_output($receiverUsername) ?></h3>
                <div style="display: flex; justify-content: space-between; align-items: center; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.1);">
                    <span class="text-muted" style="font-size: 0.9rem;">Your secure balance:</span>
                    <strong class="text-success" style="font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace; font-size: 1.1rem; color: var(--success);">₹<?= escape_output($balanceRupees) ?></strong>
                </div>
            </div>

            <form action="/payment_page.php" method="POST">
                <?= csrfField() ?>
                <input type="hidden" name="transfer_nonce" value="<?= escape_attr($transferNonce) ?>">
                <input type="hidden" name="target_uuid" value="<?= escape_attr($targetUuid) ?>">

                <div class="mt-2">
                    <label>Transfer Amount (₹)</label>
                    <input type="number" name="amount" min="1" step="0.01" placeholder="0.00" required>
                    <small class="text-muted" style="display:block; margin-top:0.5rem;">Minimum transfer: ₹1.00</small>
                </div>

                <div class="mt-3">
                    <label>Operational Remark (Optional)</label>
                    <input type="text" name="remark" maxlength="500" placeholder="Enter secure note...">
                </div>

                <button type="submit" class="btn-primary mt-4" style="width: 100%;">Authorize Transfer</button>
            </form>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>
</html>
