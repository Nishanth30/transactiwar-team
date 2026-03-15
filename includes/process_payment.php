<?php

// Headers are inherited from payment_page.php which includes this file on POST.

require_login();
verifyCsrf();


$nonce = post_str('transfer_nonce');
if (!$nonce || !isset($_SESSION['transfer_nonce']) || 
    !hash_equals($_SESSION['transfer_nonce'], $nonce)) {
    logActivity(LOG_TRANSFER_INVALID);
    $_SESSION['transfer_error'] = "Invalid or expired transfer session.";
    header("Location: " . sanitize_header("/transaction_result.php"));
    exit;
}
// Consume immediately — one use only
unset($_SESSION['transfer_nonce']);

$_SESSION['transfer_result'] = "fail";

$sender_id = (int) $_SESSION['user_id'];

// Validate UUID format — rejects anything that isn't a well-formed UUID.
// sanitize_uuid() returns null on malformed input, preventing junk DB lookups.
// post_str('username') intentionally removed — it was read but never used,
// creating a dead input that could mislead future readers.
$target_uuid = sanitize_uuid(post_str('target_uuid'));

// sanitize_comment() strips HTML, control chars, enforces 500-char limit.
$comment = sanitize_comment(post_str('remark'));

// ── Amount parsing ───────────────────────────────────────────────
// Reject the value at string level before any arithmetic.
// A raw float parse of user input can be manipulated via scientific
// notation (e.g. "1e5") or locale-dependent decimals.
// post_str() already strips null bytes and control characters.
$raw_rupees = post_str('amount');

// Only allow digits and a single decimal point — nothing else.
// This blocks "1e3", "1,000", "-1", " 1" and other bypass attempts
// before we do any arithmetic on the value.
if (!preg_match('/^\d+(\.\d{1,2})?$/', $raw_rupees)) {
    logActivity(LOG_TRANSFER_INVALID);
    $_SESSION['transfer_error'] = "Invalid amount format.";
    header("Location: " . sanitize_header("/transaction_result.php"));
    exit;
}

// Convert to paise as integer. round() is safe here because we have
// already validated the format above; no scientific notation can reach this.
$amount_paise = sanitize_amount((string) round((float)$raw_rupees * 100));

// ── Early-exit guards ────────────────────────────────────────────
if ($amount_paise === null) {
    logActivity(LOG_TRANSFER_INVALID);
    $_SESSION['transfer_error'] = "Minimum transfer amount is ₹1.00.";
    header("Location: " . sanitize_header("/transaction_result.php"));
    exit;
}

if ($target_uuid === null) {
    // Covers both missing and malformed UUIDs.
    logActivity(LOG_TRANSFER_INVALID);
    $_SESSION['transfer_error'] = "Invalid or missing receiver ID.";
    header("Location: " . sanitize_header("/transaction_result.php"));
    exit;
}

// ── Database work ────────────────────────────────────────────────

try {
    // Resolve UUID → internal ID before acquiring any locks.
    // Keeps the FOR UPDATE window as short as possible.
    $stmt = $pdo->prepare("SELECT id FROM users WHERE public_id = ? LIMIT 1");
    $stmt->execute([$target_uuid]);
    $receiver = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$receiver) {
        logActivity(LOG_TRANSFER_INVALID);
        $_SESSION['transfer_error'] = "Receiver does not exist.";
        header("Location: " . sanitize_header("/transaction_result.php"));
        exit;
    }

    $receiver_id = (int) $receiver['id'];

    // Strict integer equality — no type-juggling surprises.
    if ($receiver_id === $sender_id) {
        logActivity(LOG_TRANSFER_INVALID);
        $_SESSION['transfer_error'] = "You cannot send money to yourself.";
        header("Location: " . sanitize_header("/transaction_result.php"));
        exit;
    }

    // Open transaction only after all cheap checks have passed.
    $pdo->beginTransaction();

    // ── Deadlock prevention: always lock the lower ID first ──────────
    // If two concurrent transfers run between the same two accounts in
    // opposite directions (A→B and B→A), each would lock its own sender
    // row first and then wait for the other — classic deadlock.
    // Locking in a globally consistent order (lower id first) means both
    // transactions acquire locks in the same sequence, so neither blocks
    // the other from making forward progress.
    if ($sender_id < $receiver_id) {
        $first_id  = $sender_id;
        $second_id = $receiver_id;
    } else {
        $first_id  = $receiver_id;
        $second_id = $sender_id;
    }

    // Lock first row (lower id)
    $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ? FOR UPDATE");
    $stmt->execute([$first_id]);
    if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
        throw new RuntimeException("account_not_found");
    }

    // Lock second row (higher id)
    $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ? FOR UPDATE");
    $stmt->execute([$second_id]);
    if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
        throw new RuntimeException("account_not_found");
    }

    // Both rows are now locked — read sender balance separately.
    // The FOR UPDATE above already locked the row; this read is consistent.
    $stmt = $pdo->prepare("SELECT balance_paise FROM users WHERE id = ? FOR UPDATE");
    $stmt->execute([$sender_id]);
    $sender = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$sender) {
        throw new RuntimeException("sender_not_found");
    }

    if ((int)$sender['balance_paise'] < $amount_paise) {
        throw new RuntimeException("insufficient_balance");
    }

    // Deduct from sender — WHERE id = ? prevents updating wrong row.
    $stmt = $pdo->prepare(
        "UPDATE users SET balance_paise = balance_paise - ? WHERE id = ?"
    );
    $stmt->execute([$amount_paise, $sender_id]);

    // Credit receiver.
    $stmt = $pdo->prepare(
        "UPDATE users SET balance_paise = balance_paise + ? WHERE id = ?"
    );
    $stmt->execute([$amount_paise, $receiver_id]);

    // Audit trail — records both sides and the optional comment.
    $stmt = $pdo->prepare("
        INSERT INTO transactions (sender_id, receiver_id, amount_paise, receiver_comment)
        VALUES (?, ?, ?, ?)
    ");
    $stmt->execute([$sender_id, $receiver_id, $amount_paise, $comment]);

    $pdo->commit();

    logActivity(LOG_TRANSFER_OK);
    $_SESSION['transfer_result']   = "successful";
    $_SESSION['transfer_complete'] = true;  // ← survives transaction_result.php
    header("Location: " . sanitize_header("/transaction_result.php"));
    exit;

} catch (RuntimeException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    // Map internal codes to safe user-facing messages.
    // $e->getMessage() is NEVER shown to the user — it may contain
    // internal state that helps an attacker (account existence, balance hints).
    $userMessages = [
        "insufficient_balance" => "Insufficient balance.",
        "sender_not_found"     => "Your account could not be verified. Please log in again.",
        "receiver_not_found"   => "Receiver does not exist.",
    ];

    $code = $e->getMessage();
    $_SESSION['transfer_error'] = $userMessages[$code]
        ?? "Transfer failed. Please try again.";  // safe generic fallback

    // Log the raw code server-side so your team can investigate.
    logSecurityEvent(LOG_TRANSFER_FAIL, $code);

    header("Location: " . sanitize_header("/transaction_result.php"));
    exit;

} catch (Throwable $e) {
    // Catch unexpected DB/PDO errors separately — never leak stack traces.
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    logSecurityEvent(LOG_TRANSFER_FAIL, "unexpected:" . get_class($e));

    $_SESSION['transfer_error'] = "An unexpected error occurred. Please try again.";
    header("Location: " . sanitize_header("/transaction_result.php"));
    exit;
}