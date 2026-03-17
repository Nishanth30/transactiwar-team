<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../config/db.php';

require_login();
unset($_SESSION['transfer_complete']);

if (empty($_SESSION['user_id'])) {
    logActivity(LOG_ACCESS_DENIED);
    header('Location: ' . sanitize_header('/login.php'));
    exit;
}

$uid = (int) $_SESSION['user_id'];
$perPage = 20;
$rawPage = get_int('page');
$page = ($rawPage !== null && $rawPage > 0) ? $rawPage : 1;
$offset = ($page - 1) * $perPage;

try {
    $countStmt = $pdo->prepare(
        'SELECT COUNT(*) FROM transactions WHERE sender_id = :uid OR receiver_id = :uid'
    );
    $countStmt->bindValue(':uid', $uid, PDO::PARAM_INT);
    $countStmt->execute();
    $total = (int) $countStmt->fetchColumn();
    $totalPages = max(1, (int) ceil($total / $perPage));

    // Clamp page to actual range — avoids pointless large-OFFSET queries
    $page = min($page, $totalPages);
    $offset = ($page - 1) * $perPage;

    $stmt = $pdo->prepare(
        'SELECT
            t.id,
            t.amount_paise,
            t.receiver_comment,
            t.created_at,
            CASE WHEN t.sender_id = :uid THEN "sent" ELSE "received" END AS direction,
            CASE WHEN t.sender_id = :uid THEN r.public_id ELSE s.public_id END AS counterparty_id,
            CASE WHEN t.sender_id = :uid THEN r.username ELSE s.username END AS counterparty_username
         FROM transactions t
         JOIN users s ON s.id = t.sender_id
         JOIN users r ON r.id = t.receiver_id
         WHERE t.sender_id = :uid OR t.receiver_id = :uid
         ORDER BY t.created_at DESC
         LIMIT :lim OFFSET :off'
    );
    $stmt->bindValue(':uid', $uid, PDO::PARAM_INT);
    $stmt->bindValue(':lim', $perPage, PDO::PARAM_INT);
    $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    logSecurityEvent(LOG_INVALID_INPUT, 'history_db:' . get_class($e));
    $rows = [];
    $total = 0;
    $totalPages = 1;
    $dbError = true;
}

logActivity(LOG_PAGE_VIEW . ':transaction_history');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | Transaction History'); ?>
</head>
<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container py-4">
        <div class="card">
            <div class="card-body">
                <h2 class="text-glow mb-4">Transaction History</h2>

                <?php if (!empty($dbError)): ?>
                    <div class="alert alert-danger" role="alert">
                        Error loading transactions. Please try again.
                    </div>
                <?php elseif (empty($rows)): ?>
                    <p class="text-muted text-center py-4">No transactions yet.</p>
                <?php else: ?>
                    <p class="text-muted small mb-3">
                        Showing <?= count($rows) ?> of <?= $total ?> transactions
                    </p>

                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Type</th>
                                    <th>Counterparty</th>
                                    <th>Amount</th>
                                    <th>Remark</th>
                                    <th>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($rows as $tx):
                                    $safeUuid = sanitize_uuid($tx['counterparty_id']);
                                    $profileHref = $safeUuid !== null
                                        ? escape_attr('/view_profile.php?id=' . $safeUuid)
                                        : '#';
                                    $isSent = $tx['direction'] === 'sent';
                                ?>
                                <tr>
                                    <td class="tx-id font-mono"><?= escape_output($tx['id']) ?></td>
                                    <td>
                                        <span class="tx-dir-badge <?= $isSent ? 'tx-dir-sent' : 'tx-dir-received' ?>">
                                            <?= escape_output($tx['direction']) ?>
                                        </span>
                                    </td>
                                    <td>
                                        <a href="<?= $profileHref ?>" class="tx-counterparty">
                                            <?= escape_output($tx['counterparty_username']) ?>
                                        </a>
                                        <br>
                                        <small class="text-muted font-mono">
                                            <?= escape_output($tx['counterparty_id']) ?>
                                        </small>
                                    </td>
                                    <td class="font-mono fw-bold text-nowrap">
                                        &#8377;<?= escape_output(number_format((int) $tx['amount_paise'] / 100, 2)) ?>
                                    </td>
                                    <td class="text-muted">
                                        <?= $tx['receiver_comment'] !== null ? escape_output($tx['receiver_comment']) : '&mdash;' ?>
                                    </td>
                                    <td class="text-muted text-nowrap">
                                        <?= escape_output($tx['created_at']) ?>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <div class="tw-pagination mt-4">
                        <span class="text-muted small">
                            Page <?= (int) $page ?> of <?= (int) $totalPages ?>
                        </span>
                        <div class="d-flex gap-2">
                            <?php if ($page > 1): ?>
                                <a href="<?= escape_attr('/transaction_history.php?page=' . ($page - 1)) ?>"
                                   class="btn btn-outline-secondary btn-sm">&larr; Prev</a>
                            <?php endif; ?>
                            <?php if ($page < $totalPages): ?>
                                <a href="<?= escape_attr('/transaction_history.php?page=' . ($page + 1)) ?>"
                                   class="btn btn-outline-secondary btn-sm">Next &rarr;</a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.php'; ?>
</body>
</html>
