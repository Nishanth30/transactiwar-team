<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/logger.php';

require_once __DIR__ . '/../includes/csrf.php';

// If someone visits /logout.php via GET, redirect them to the confirmation page
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /confirm_logout.php');
    exit;
}

// POST request: Verify CSRF token before logging out
verifyCsrf();

// Immediate logout and redirect
logout_user();
header('Location: /login.php');
exit;
