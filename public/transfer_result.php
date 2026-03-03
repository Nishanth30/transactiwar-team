<?php
require_once __DIR__ . '/../includes/header.php';
send_security_headers();
no_cache();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/auth.php';

require_login();

$status  = get_str('status');
$message = get_str('msg');

include("header.html");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Transfer Result</title>
</head>
<body>

<div style="max-width:460px; margin:60px auto; font-family:sans-serif; text-align:center;">
    <?php if ($status === 'success'): ?>
        <div style="font-size:72px;">✅</div>
        <h2 style="color:#28a745;">Transfer Successful</h2>
    <?php else: ?>
        <div style="font-size:72px;">❌</div>
        <h2 style="color:#dc3545;">Transfer Failed</h2>
    <?php endif; ?>

    <p><?php echo escape_output($message); ?></p>
    <a href="dashboard.php">Back to Dashboard</a>
</div>

<?php include("footer.html"); ?>
</body>
</html>