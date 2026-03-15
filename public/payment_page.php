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

// M9 FIX: Clear the stale transfer_complete flag on new page loads.
// Previously it was only cleared by visiting index.php, so navigating
// directly to a new payment form after a successful transfer would
// incorrectly reject the next POST with "already been processed".
unset($_SESSION['transfer_complete']);

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

// H5 FIX: Key the nonce by target UUID so each tab gets its own slot.
// The old single-slot design meant Tab B overwrote Tab A's nonce, either
// causing a DoS (Tab A's form becomes invalid) or leaving the nonce unbound
// to a specific recipient.
$transferNonce = bin2hex(random_bytes(16));
$_SESSION['transfer_nonce_' . $targetUuid] = $transferNonce;

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

                <form id="transferForm" action="/payment_page.php" method="POST">
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

                    <button type="submit" class="btn btn-primary w-100 mt-2">
                        Authorize Transfer
                    </button>
                </form>
            </div>
        </div>
    </div>

    <!-- Confirmation Modal -->
    <div class="modal fade" id="confirmModal" tabindex="-1"
         aria-labelledby="confirmModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header border-0 pb-0">
                    <h5 class="modal-title text-glow" id="confirmModalLabel">Confirm Transfer</h5>
                    <button type="button" class="btn-close btn-close-white"
                            data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p class="text-muted mb-3">Please review the details before authorizing.</p>

                    <dl class="row mb-0">
                        <dt class="col-4 text-muted">To</dt>
                        <dd class="col-8 text-cyan fw-bold" id="confirmRecipient"></dd>

                        <dt class="col-4 text-muted">Amount</dt>
                        <dd class="col-8 font-mono fw-bold" id="confirmAmount"></dd>

                        <dt class="col-4 text-muted">Remark</dt>
                        <dd class="col-8" id="confirmRemark"></dd>
                    </dl>
                </div>
                <div class="modal-footer border-0 pt-0">
                    <button type="button" class="btn btn-outline-secondary"
                            data-bs-dismiss="modal">Go Back</button>
                    <button type="button" id="confirmBtn" class="btn btn-primary">
                        Authorize Transfer
                    </button>
                </div>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.php'; ?>

    <script nonce="<?= get_csp_nonce() ?>">
    (function () {
        var form = document.getElementById('transferForm');
        if (!form || typeof bootstrap === 'undefined') return;

        var confirmBtn = document.getElementById('confirmBtn');
        var modalEl = document.getElementById('confirmModal');
        var modal = new bootstrap.Modal(modalEl);
        var confirmed = false;

        var recipientName = <?= escape_js($receiverUsername) ?>;

        form.addEventListener('submit', function (e) {
            if (confirmed) return;
            e.preventDefault();

            var amount = form.elements['amount'].value;
            var remark = form.elements['remark'].value;

            document.getElementById('confirmRecipient').textContent = recipientName;
            document.getElementById('confirmAmount').textContent = '\u20B9' + parseFloat(amount).toFixed(2);
            document.getElementById('confirmRemark').textContent = remark || '\u2014';

            modal.show();
        });

        confirmBtn.addEventListener('click', function () {
            confirmed = true;
            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Processing\u2026';
            form.submit();
        });
    })();
    </script>
</body>
</html>
