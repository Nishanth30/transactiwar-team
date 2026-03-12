<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();
no_cache();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';

require_login();

// Result page must only be reachable via transfer flow state.
if (!isset($_SESSION['transfer_result'])) {
    header('Location: ' . sanitize_header('/index.php'));
    exit;
}

$result = $_SESSION['transfer_result'];
$error = $_SESSION['transfer_error'] ?? null;
// Flash semantics: read once, then clear.
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

    <div class="container auth-container">
        <div class="card text-center result-card">
            <?php if ($isSuccess): ?>
                <div class="result-icon-success">✅</div>
                <h2 class="text-success text-glow">Transaction Successful</h2>
                <p class="text-muted result-text">Your transfer has been completed securely.</p>
            <?php else: ?>
                <div class="result-icon-error">❌</div>
                <h2 class="text-error text-glow">Transfer Failed</h2>
                <p class="text-muted result-text"><?= escape_output($error ?? 'Transfer failed. Please try again.') ?></p>
            <?php endif; ?>

            <a href="/transaction_history.php" class="btn-primary btn-ledger">View Ledger</a>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>
</html>
