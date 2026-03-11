<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/session.php';

unset($_SESSION['transfer_complete']);

if (!isset($_SESSION['user_id'])) {
    header('Location: /login.php');
    exit;
} else {
    header('Location: /view_profile.php');
    exit;
}