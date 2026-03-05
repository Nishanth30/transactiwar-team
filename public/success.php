<?php
// =====================
// success.php
// =====================
require_once __DIR__ . '/../includes/header.php';
send_security_headers();
no_cache();
require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_login();
include("header.html");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Transfer Successful</title>
</head>
<body>
<div>
    <h2>✅ Transfer Successful</h2>
    <p>Your payment was completed successfully.</p>
    <a href="index.php">Back to Dashboard</a>
</div>
<?php include("footer.html"); ?>
</body>
</html>