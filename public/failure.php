<?php
// =====================
// failure.php
// =====================
require_once __DIR__ . '/../includes/header.php';
send_security_headers();
no_cache();
require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_login();
include("header.html");
// TEMPORARY DEBUG — remove before submission
if (isset($_SESSION['transfer_error'])) {
    echo "<p style='color:red;'>Error: " . escape_output($_SESSION['transfer_error']) . "</p>";
    unset($_SESSION['transfer_error']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Transfer Failed</title>
</head>
<body>
<div>
    <h2>❌ Transfer Failed</h2>
    <p>Something went wrong. Please try again.</p>
    <a href="javascript:history.back()">Go Back</a>
</div>
<?php include("footer.html"); ?>
</body>
</html>