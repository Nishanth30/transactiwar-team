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
$error = $_SESSION['transfer_error'] ?? null;
unset($_SESSION['transfer_result'], $_SESSION['transfer_error']);

// Outcome is driven by transfer_result, not by whether transfer_error is set.
$is_success = ($result === 'successful');

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Transactiwar | <?= $is_success ? 'Transfer Successful' : 'Transfer Failed' ?></title>
</head>

<body>

    <?php include("header.html"); ?>

    <div class="container auth-container">
        <div class="card text-center" style="padding: 3rem 2rem;">
            <?php if ($is_success): ?>
                <div style="font-size: 4rem; text-shadow: 0 0 20px rgba(16, 185, 129, 0.8); margin-bottom: 1rem;">✅</div>
                <h2 class="text-success text-glow" style="color: var(--success);">Transaction Successful</h2>
                <p class="text-muted" style="font-size: 1.1rem; margin-bottom: 2rem;">Your transfer has been completed
                    securely.</p>
            <?php else: ?>
                <div style="font-size: 4rem; text-shadow: 0 0 20px rgba(239, 68, 68, 0.8); margin-bottom: 1rem;">❌</div>
                <h2 class="text-error text-glow" style="color: var(--error);">Transfer Failed</h2>
                <p class="text-muted" style="font-size: 1.1rem; margin-bottom: 2rem;">
                    <?= escape_output($error ?? 'Transfer failed. Please try again.') ?></p>
            <?php endif; ?>

            <a href="transaction_history.php" class="btn-primary"
                style="display:inline-block; font-size:1rem; padding: 0.8rem 2rem;">View Ledger</a>
        </div>
    </div>

    <?php include("footer.html"); ?>
</body>

</html>