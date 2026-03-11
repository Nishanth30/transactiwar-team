<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

// profile_view_logic.php enforces auth + lookup + output-safe payload creation.
require_once __DIR__ . '/../includes/profile_view_logic.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | Agent Profile'); ?>
</head>
<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container">
        <div class="card" style="text-align: center;">
            <h1 class="text-glow">Agent: <?= $profileData['username'] ?></h1>
            <p class="text-muted" style="font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace; margin-bottom: 1.5rem;">
                Public ID: <?= $profileData['uuid'] ?>
            </p>

            <img src="/serve_image.php?file=<?= $profileData['image'] ?>" width="150" style="border-radius: 50%; border: 3px solid var(--primary-cyan); box-shadow: 0 0 15px rgba(0,240,255,0.4); margin-bottom: 2rem;" alt="Profile Pic">

            <div class="card" style="margin-top: 20px; text-align: left; background: rgba(0,0,0,0.3); border: none;">
                <h3 class="text-cyan mb-2">Operational Bio</h3>
                <p><?= nl2br($profileData['bio']) ?></p>
            </div>

            <?php if ($profileData['is_mine']): ?>
                <div class="mt-4" style="padding: 1.5rem; background: rgba(16, 185, 129, 0.1); border-left: 4px solid var(--success); text-align: left; border-radius: 6px;">
                    <strong>Secure Funds:</strong> ₹<?= $profileData['balance_rupees'] ?>
                </div>

                <div class="mt-4">
                    <a href="/profile.php" class="btn btn-primary" style="text-decoration: none; padding: 0.8rem 1.5rem; display: inline-block;">Edit My Profile</a>
                </div>
            <?php else: ?>
                <div class="mt-4">
                    <a href="/payment_page.php?target_uuid=<?= $profileData['uuid'] ?>" class="btn btn-primary" style="text-decoration:none; padding: 0.8rem 1.5rem; display: inline-block;">Initiate Transfer to Agent</a>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>
</html>
