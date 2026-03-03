<?php

$sender_id    = $_SESSION['user_id'];
$target_uuid  = post_str('target_uuid');
$username     = post_str('username');
$comment      = sanitize_comment(post_str('remark'));
$raw_rupees   = post_str('amount');
$amount_paise = sanitize_amount((string) round((float)$raw_rupees * 100));

if ($amount_paise === null) {
    logActivity(LOG_TRANSFER_INVALID);
    $_SESSION['transfer_error'] = "Enter amount and try again";
    header("Location: /failure.php");
    exit;
}

if (is_empty_input($target_uuid)) {
    logActivity(LOG_TRANSFER_INVALID);
    $_SESSION['transfer_error'] = "Receiver User ID missing";
    header("Location: /failure.php");
    exit;
}

try {
    // Look up receiver by public UUID
    $stmt = $pdo->prepare("SELECT id FROM users WHERE public_id = ? LIMIT 1");
    $stmt->execute([$target_uuid]);
    $receiver = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$receiver) {
        logActivity(LOG_TRANSFER_INVALID);
        $_SESSION['transfer_error'] = "Receiver does not exist";
        header("Location: /failure.php");
        exit;
    }

    $receiver_id = $receiver['id'];

    if ((int)$receiver_id === (int)$sender_id) {
        logActivity(LOG_TRANSFER_INVALID);
        $_SESSION['transfer_error'] = "Cant send money to self";
        header("Location: /failure.php");
        exit;
    }

    // RULE 9: Wrap all DB writes in a transaction
    $pdo->beginTransaction();

    // Lock sender row and read live balance
    $stmt = $pdo->prepare("SELECT balance_paise FROM users WHERE id = ? FOR UPDATE");
    $stmt->execute([$sender_id]);
    $sender = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$sender) {
        throw new Exception("Sender account not found.");
    }

    if ($sender['balance_paise'] < $amount_paise) {
        logActivity(LOG_TRANSFER_FAIL);
        throw new Exception("Insufficient balance.");
    }

    // Lock receiver row
    $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ? FOR UPDATE");
    $stmt->execute([$receiver_id]);
    if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
        throw new Exception("Receiver account not found.");
    }

    // Deduct from sender
    $stmt = $pdo->prepare("UPDATE users SET balance_paise = balance_paise - ? WHERE id = ?");
    $stmt->execute([$amount_paise, $sender_id]);

    // Add to receiver
    $stmt = $pdo->prepare("UPDATE users SET balance_paise = balance_paise + ? WHERE id = ?");
    $stmt->execute([$amount_paise, $receiver_id]);

    // Record the transaction
    $stmt = $pdo->prepare("
        INSERT INTO transactions (sender_id, receiver_id, amount_paise, receiver_comment)
        VALUES (?, ?, ?, ?)
    ");
    $stmt->execute([$sender_id, $receiver_id, $amount_paise, $comment]);

    $pdo->commit();

    logActivity(LOG_TRANSFER_OK);

    header("Location: /success.php");
    exit;

} catch (Exception $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    logActivity(LOG_TRANSFER_FAIL);
    $_SESSION['transfer_error'] = $e->getMessage();
    header("Location: /failure.php");
    exit;
}