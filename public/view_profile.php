<?php

// 1. Boot up the engine 
require_once __DIR__ . '/../includes/profile_view_logic.php';


// 2. Activate the HTTP Security Headers
if (file_exists(__DIR__ . '/../includes/header.php')) {
    require_once __DIR__ . '/../includes/header.php';
    send_security_headers();
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Transactiwar | Agent Profile</title>
</head>

<body>

    <?php include("header.html"); ?>

    <div class="container">
        <div class="card" style="text-align: center;">
            <h1 class="text-glow">Agent: <?php echo $profileData['username']; ?></h1>
            <p class="text-muted" style="font-family: 'Fira Code', monospace; margin-bottom: 1.5rem;">
                Public ID: <?php echo $profileData['uuid']; ?>
            </p>

            <img src="serve_image.php?file=<?php echo $profileData['image']; ?>" width="150"
                style="border-radius: 50%; border: 3px solid var(--primary-cyan); box-shadow: 0 0 15px rgba(0,240,255,0.4); margin-bottom: 2rem;"
                alt="Profile Pic">

            <div class="card" style="margin-top: 20px; text-align: left; background: rgba(0,0,0,0.3); border: none;">
                <h3 class="text-cyan mb-2">Operational Bio</h3>
                <p><?php echo nl2br($profileData['bio']); ?></p>
            </div>

            <?php if ($profileData['is_mine']): ?>

                <div class="mt-4"
                    style="padding: 1.5rem; background: rgba(16, 185, 129, 0.1); border-left: 4px solid var(--success); text-align: left; border-radius: 6px;">
                    <strong>Secure Funds:</strong> ₹<?php echo $profileData['balance_rupees']; ?>
                </div>

                <div class="mt-4">
                    <a href="profile.php" class="btn btn-primary"
                        style="text-decoration: none; padding: 0.8rem 1.5rem; display: inline-block;">Edit My Profile</a>
                </div>

            <?php else: ?>

                <div class="mt-4">
                    <a href="payment_page.php?target_uuid=<?php echo $profileData['uuid']; ?>" class="btn btn-primary"
                        style="text-decoration:none; padding: 0.8rem 1.5rem; display: inline-block;">Initiate Transfer to
                        Agent</a>
                </div>

            <?php endif; ?>

        </div>
    </div>

    <?php include("footer.html"); ?>
</body>

</html>