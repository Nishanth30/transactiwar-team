<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();
no_cache();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';

require_login();

if (!isset($_SESSION['transfer_result'])) {
    header('Location: ' . sanitize_header('/index.php'));
    exit;
}

$result = $_SESSION['transfer_result'];
$error = $_SESSION['transfer_error'] ?? null;
unset($_SESSION['transfer_result'], $_SESSION['transfer_error']);

$isSuccess = ($result === 'successful');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | ' . ($isSuccess ? 'Transfer Successful' : 'Transfer Failed')); ?>
</head>
<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="tw-auth-wrap">
        <div class="tw-auth-card tw-narrow">
            <div class="card">
                <div class="card-body text-center py-5">
                    <?php if ($isSuccess): ?>
                        <div class="tw-result-icon tw-result-icon-ok" aria-hidden="true">&#10003;</div>
                        <h2 class="text-glow mt-3 mb-2 tw-text-success-glow">Transfer Successful</h2>
                        <p class="text-muted mb-4">Your transfer has been completed securely.</p>
                    <?php else: ?>
                        <div class="tw-result-icon tw-result-icon-err" aria-hidden="true">&#10007;</div>
                        <h2 class="text-danger-glow mt-3 mb-2">Transfer Failed</h2>
                        <p class="text-muted mb-4">
                            <?= escape_output($error ?? 'Transfer failed. Please try again.') ?>
                        </p>
                    <?php endif; ?>

                    <a href="/transaction_history.php" class="btn btn-primary px-4">View Ledger</a>
                </div>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.php'; ?>
</body>
</html>
