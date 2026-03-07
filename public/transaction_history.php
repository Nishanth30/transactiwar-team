<?php
// declare(strict_types=1);

declare(strict_types=1);
ini_set('display_errors', 1);
error_reporting(E_ALL);
require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../config/session.php';

require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../config/db.php';

require_login();

include("header.html");

// ── Auth gate ─────────────────────────────────────────────────────
if (empty($_SESSION['user_id'])) {
    logActivity(LOG_ACCESS_DENIED);
    header('Location: ' . sanitize_header('/login.php'));
    exit;
}

$uid = (int) $_SESSION['user_id'];

// ── Fetch transactions ────────────────────────────────────────────
// Direction (sent/received) derived in SQL — not in PHP.
// LIMIT/OFFSET bound as integers — never interpolated.

$per_page = 20;
$raw_page = get_int('page');
$page     = ($raw_page !== null && $raw_page > 0) ? $raw_page : 1;
$offset   = ($page - 1) * $per_page;

try {
    // Total count for pagination
    $count_stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM transactions
         WHERE sender_id = :uid OR receiver_id = :uid'
    );
    $count_stmt->bindValue(':uid', $uid, PDO::PARAM_INT);
    $count_stmt->execute();
    $total       = (int) $count_stmt->fetchColumn();
    $total_pages = (int) ceil($total / $per_page);

    $stmt = $pdo->prepare(
        'SELECT
            t.id,
            t.amount_paise,
            t.receiver_comment,
            t.created_at,
            CASE WHEN t.sender_id = :uid THEN "sent" ELSE "received" END AS direction,
            CASE WHEN t.sender_id = :uid THEN r.public_id ELSE s.public_id END AS counterparty_id
         FROM transactions t
         JOIN users s ON s.id = t.sender_id
         JOIN users r ON r.id = t.receiver_id
         WHERE t.sender_id = :uid OR t.receiver_id = :uid
         ORDER BY t.created_at DESC
         LIMIT :lim OFFSET :off'
    );
    $stmt->bindValue(':uid', $uid,      PDO::PARAM_INT);
    $stmt->bindValue(':lim', $per_page, PDO::PARAM_INT);
    $stmt->bindValue(':off', $offset,   PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (Throwable $e) {
    logSecurityEvent(LOG_INVALID_INPUT, 'history_db:' . get_class($e));
    $rows        = [];
    $total       = 0;
    $total_pages = 1;
    $db_error    = true;
}

logActivity(LOG_PAGE_VIEW);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Transaction History</title>
</head>
<body>

<h1>Transaction History</h1>

<?php if (!empty($db_error)): ?>
    <p>Error loading transactions. Please try again.</p>
<?php elseif (empty($rows)): ?>
    <p>No transactions found.</p>
<?php else: ?>
    <p>Showing <?= count($rows) ?> of <?= $total ?> transactions.</p>

    <table border="1" cellpadding="6">
        <thead>
            <tr>
                <th>Transaction ID</th>
                <th>Direction</th>
                <th>Counterparty</th>
                <th>Amount (₹)</th>
                <th>Remark</th>
                <th>Date</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($rows as $tx):
            // Re-validate UUID from DB before putting it in an href
            $safe_uuid    = sanitize_uuid($tx['counterparty_id']);
            $profile_href = $safe_uuid !== null
                ? escape_attr('/view_profile.php?id=' . $safe_uuid)
                : '#';
        ?>
            <tr>
                <td><?= escape_output($tx['id']) ?></td>
                <td><?= escape_output($tx['direction']) ?></td>
                <td>
                    <a href="<?= $profile_href ?>">
                        <?= escape_output($tx['counterparty_id']) ?>
                    </a>
                </td>
                <td><?= escape_output(number_format((int)$tx['amount_paise'] / 100, 2)) ?></td>
                <td><?= $tx['receiver_comment'] !== null ? escape_output($tx['receiver_comment']) : '—' ?></td>
                <td><?= escape_output($tx['created_at']) ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <!-- Pagination -->
    <p>
        Page <?= (int)$page ?> of <?= (int)$total_pages ?>
        <?php if ($page > 1): ?>
            &nbsp;<a href="<?= escape_attr('history.php?page=' . ($page - 1)) ?>">← Previous</a>
        <?php endif; ?>
        <?php if ($page < $total_pages): ?>
            &nbsp;<a href="<?= escape_attr('history.php?page=' . ($page + 1)) ?>">Next →</a>
        <?php endif; ?>
    </p>
<?php endif; ?>
<?php include("footer.html"); ?>
</body>
</html>