<?php


require_once __DIR__ . '/header.php';
send_security_headers();
no_cache();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/sanitize.php';
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/../config/db.php';
// TEMP DEBUG — remove after fixing

require_login();
// ── CSRF verification ────────────────────────────────────────────
// Must be the very first thing — before reading any POST data.
// Kills the request with 403 if token is missing, expired, or forged.
verifyCsrf();

// ── Collect and sanitize inputs ──────────────────────────────────

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
    header("Location: " . sanitize_header("/failure.php"));
    exit;
}

// Convert to paise as integer. round() is safe here because we have
// already validated the format above; no scientific notation can reach this.
$amount_paise = sanitize_amount((string) round((float)$raw_rupees * 100));

// ── Early-exit guards ────────────────────────────────────────────

if ($amount_paise === null) {
    logActivity(LOG_TRANSFER_INVALID);
    $_SESSION['transfer_error'] = "Minimum transfer amount is ₹1.00.";
    header("Location: " . sanitize_header("/failure.php"));
    exit;
}

if ($target_uuid === null) {
    // Covers both missing and malformed UUIDs.
    logActivity(LOG_TRANSFER_INVALID);
    $_SESSION['transfer_error'] = "Invalid or missing receiver ID.";
    header("Location: " . sanitize_header("/failure.php"));
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
        header("Location: " . sanitize_header("/failure.php"));
        exit;
    }

    $receiver_id = (int) $receiver['id'];

    // Strict integer equality — no type-juggling surprises.
    if ($receiver_id === $sender_id) {
        logActivity(LOG_TRANSFER_INVALID);
        $_SESSION['transfer_error'] = "You cannot send money to yourself.";
        header("Location: " . sanitize_header("/failure.php"));
        exit;
    }

    // Open transaction only after all cheap checks have passed.
    // FOR UPDATE locks both rows to prevent race conditions / double-spend.
    $pdo->beginTransaction();

    // Lock sender and read live balance atomically.
    $stmt = $pdo->prepare("SELECT balance_paise FROM users WHERE id = ? FOR UPDATE");
    $stmt->execute([$sender_id]);
    $sender = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$sender) {
        // Should never happen for a logged-in user, but fail safely.
        throw new RuntimeException("sender_not_found");
    }

    if ((int)$sender['balance_paise'] < $amount_paise) {
        // Log before throwing so the event is captured even if rollback fires.
        logActivity(LOG_TRANSFER_FAIL);
        throw new RuntimeException("insufficient_balance");
    }

    // Lock receiver row — prevents the account being deleted mid-transfer.
    $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ? FOR UPDATE");
    $stmt->execute([$receiver_id]);
    if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
        throw new RuntimeException("receiver_not_found");
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

    header("Location: " . sanitize_header("/success.php"));
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

    header("Location: " . sanitize_header("/failure.php"));
    exit;

} catch (Throwable $e) {
    // Catch unexpected DB/PDO errors separately — never leak stack traces.
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    logSecurityEvent(LOG_TRANSFER_FAIL, "unexpected:" . get_class($e));

    $_SESSION['transfer_error'] = "An unexpected error occurred. Please try again.";
    header("Location: " . sanitize_header("/failure.php"));
    exit;
}