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
        <div class="card text-center" style="padding: 3rem 2rem;">
            <?php if ($isSuccess): ?>
                <div style="font-size: 4rem; text-shadow: 0 0 20px rgba(16, 185, 129, 0.8); margin-bottom: 1rem;">✅</div>
                <h2 class="text-success text-glow" style="color: var(--success);">Transaction Successful</h2>
                <p class="text-muted" style="font-size: 1.1rem; margin-bottom: 2rem;">Your transfer has been completed securely.</p>
            <?php else: ?>
                <div style="font-size: 4rem; text-shadow: 0 0 20px rgba(239, 68, 68, 0.8); margin-bottom: 1rem;">❌</div>
                <h2 class="text-error text-glow" style="color: var(--error);">Transfer Failed</h2>
                <p class="text-muted" style="font-size: 1.1rem; margin-bottom: 2rem;"><?= escape_output($error ?? 'Transfer failed. Please try again.') ?></p>
            <?php endif; ?>

            <a href="/transaction_history.php" class="btn-primary" style="display:inline-block; font-size:1rem; padding: 0.8rem 2rem;">View Ledger</a>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>
</html>
