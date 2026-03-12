<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';

// Immediate logout and redirect
logout_user();
header('Location: /login.php');
exit;
