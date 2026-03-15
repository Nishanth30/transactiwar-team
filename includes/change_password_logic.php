<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/logger.php';

require_login();
logActivity(LOG_PAGE_VIEW . ':change_password');

$userId = (int) ($_SESSION['user_id'] ?? 0);
$clientIp = function_exists('get_client_ip')
    ? get_client_ip()
    : sanitize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

$error_message = '';
$show_password_policy = false;

if (isset($_SESSION['flash_error']) && is_string($_SESSION['flash_error'])) {
    $error_message = $_SESSION['flash_error'];
    unset($_SESSION['flash_error']);
}

if (!empty($_SESSION['flash_show_password_policy'])) {
    $show_password_policy = true;
    unset($_SESSION['flash_show_password_policy']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrf();

    $currentPassword = (string) ($_POST['current_password'] ?? '');
    $newPassword = (string) ($_POST['new_password'] ?? '');
    $confirmPassword = (string) ($_POST['confirm_new_password'] ?? '');

    $flashError = '';
    $flashShowPolicy = false;

    if ($currentPassword === '' || $newPassword === '' || $confirmPassword === '') {
        $flashError = 'All fields are required.';
        logActivity(LOG_INVALID_INPUT);
    } elseif (is_password_change_locked($pdo, $userId, $clientIp)) {
        $remaining = get_password_change_lockout_remaining($pdo, $userId, $clientIp);
        $minutes = max(1, (int) ceil($remaining / 60));
        $flashError = 'Too many failed attempts. Try again in ' . $minutes . ' minute(s).';
        logSecurityEvent(LOG_PASSWORD_CHANGE_LOCKED, 'user_id:' . $userId);
    } elseif (!validate_password($newPassword)) {
        $flashError = password_requirements();
        $flashShowPolicy = true;
        logActivity(LOG_INVALID_INPUT);
    } elseif ($newPassword !== $confirmPassword) {
        $flashError = 'New password and confirmation do not match.';
        logActivity(LOG_INVALID_INPUT);
    } else {
        $result = change_password_for_user(
            $pdo,
            $userId,
            $currentPassword,
            $newPassword,
            $clientIp
        );

        if ($result === true) {
            logActivity(LOG_PASSWORD_CHANGE_SUCCESS);
            logout_user();

            if (session_status() !== PHP_SESSION_ACTIVE && !session_start()) {
                header('Location: /login.php');
                exit;
            }

            $_SESSION['flash_success'] = 'Password changed successfully. Please login again.';
            header('Location: /login.php');
            exit;
        }

        if ($result === 'locked') {
            $remaining = get_password_change_lockout_remaining($pdo, $userId, $clientIp);
            $minutes = max(1, (int) ceil($remaining / 60));
            $flashError = 'Too many failed attempts. Try again in ' . $minutes . ' minute(s).';
            logSecurityEvent(LOG_PASSWORD_CHANGE_LOCKED, 'user_id:' . $userId);
        } elseif ($result === 'throttled') {
            $flashError = 'Too many attempts. Please wait a moment before trying again.';
            logActivity(LOG_LOGIN_LOCKED);
        } elseif ($result === 'invalid_current') {
            $flashError = 'Current password is incorrect.';
            logSecurityEvent(LOG_PASSWORD_CHANGE_FAIL, 'current_password_mismatch');
        } elseif ($result === 'same_password') {
            $flashError = 'New password must be different from your current password.';
            logActivity(LOG_INVALID_INPUT);
        } else {
            $flashError = 'Password change failed. Please try again.';
            logSecurityEvent(LOG_PASSWORD_CHANGE_FAIL, 'unexpected_error');
        }
    }

    if ($flashError !== '') {
        $_SESSION['flash_error'] = $flashError;
        if ($flashShowPolicy) {
            $_SESSION['flash_show_password_policy'] = true;
        }
    }

    header('Location: /change_password.php');
    exit;
}
