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

// Pagination is server-side to keep memory predictable for large ledgers.
$uid = (int) $_SESSION['user_id'];
$perPage = 20;
$rawPage = get_int('page');
$page = ($rawPage !== null && $rawPage > 0) ? $rawPage : 1;
$offset = ($page - 1) * $perPage;

try {
    // Count + page query are separated so UI can render total pages cleanly.
    $countStmt = $pdo->prepare(
        'SELECT COUNT(*) FROM transactions WHERE sender_id = :uid OR receiver_id = :uid'
    );
    $countStmt->bindValue(':uid', $uid, PDO::PARAM_INT);
    $countStmt->execute();
    $total = (int) $countStmt->fetchColumn();
    $totalPages = max(1, (int) ceil($total / $perPage));

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
    // Keep UI generic; detailed diagnostics stay in server logs.
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

    <div class="container">
        <div class="card">
            <h2 class="text-glow">Transaction Ledger</h2>

            <?php if (!empty($dbError)): ?>
                <div class="error-msg">Error loading transactions. Please try again.</div>
            <?php elseif (empty($rows)): ?>
                <div class="text-muted empty-ledger">No operational transactions found.</div>
            <?php else: ?>
                <p class="text-muted">Showing <?= count($rows) ?> of <?= $total ?> transactions.</p>

                <div class="table-container mt-2">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Direction</th>
                                <th>Counterparty</th>
                                <th>Amount (₹)</th>
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
                                $dirColor = $tx['direction'] === 'sent' ? 'var(--error)' : 'var(--success)';
                                ?>
                                <tr>
                                    <td class="text-muted tx-table-id font-mono">
                                        <?= escape_output($tx['id']) ?>
                                    </td>
                                    <td class="tx-table-dir <?= $tx['direction'] === 'sent' ? 'tx-table-dir-sent' : 'tx-table-dir-received' ?>">
                                        <?= escape_output($tx['direction']) ?>
                                    </td>
                                    <td>
                                        <a href="<?= $profileHref ?>" class="tx-counterparty-link">
                                            <?= escape_output($tx['counterparty_username']) ?>
                                        </a>
                                        <br>
                                        <small class="text-muted font-mono" style="font-size: 0.75rem;">
                                            <?= escape_output($tx['counterparty_id']) ?>
                                        </small>
                                    </td>
                                    <td class="font-mono tx-table-amt">
                                        ₹<?= escape_output(number_format((int) $tx['amount_paise'] / 100, 2)) ?>
                                    </td>
                                    <td class="text-muted">
                                        <?= $tx['receiver_comment'] !== null ? escape_output($tx['receiver_comment']) : '—' ?>
                                    </td>
                                    <td class="text-muted tx-table-date">
                                        <?= escape_output($tx['created_at']) ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <div class="mt-4 pagination-controls">
                    <span class="text-muted">Page <?= (int) $page ?> of <?= (int) $totalPages ?></span>
                    <div>
                        <?php if ($page > 1): ?>
                            <a href="<?= escape_attr('/transaction_history.php?page=' . ($page - 1)) ?>" class="btn btn-sm">← Previous</a>
                        <?php endif; ?>
                        <?php if ($page < $totalPages): ?>
                            <a href="<?= escape_attr('/transaction_history.php?page=' . ($page + 1)) ?>" class="btn btn-sm ml-2">Next →</a>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>
</html>
