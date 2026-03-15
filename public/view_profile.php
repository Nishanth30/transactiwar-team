<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

require_once __DIR__ . '/../includes/profile_view_logic.php';
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <?php render_page_head('Transactiwar | Agent Profile'); ?>
</head>

<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container mt-5">
        <div class="card p-5 shadow-lg">
            <h1 class="text-glow mb-2">Agent: <?= $profileData['username'] ?></h1>
            <p class="text-muted font-monospace mb-4">
                Public ID: <?= $profileData['uuid'] ?>
            </p>

            <?php if ($profileData['is_mine']): ?>
                <div class="profile-main-grid">
                    <div class="profile-left-column">
                        <div class="mb-4">
                            <img src="/serve_image.php?file=<?= $profileData['image'] ?>" width="150" height="150"
                                class="rounded-circle avatar-glow" alt="Profile Pic">
                        </div>

                        <div class="card bg-dark border-secondary text-start p-4 mx-auto mb-4 profile-bio-box">
                            <h3 class="text-cyan mb-3 border-bottom border-secondary pb-2">Operational Bio</h3>
                            <p class="text-light m-0 profile-bio-text"><?= nl2br($profileData['bio']) ?></p>
                        </div>
                    </div>

                    <div class="profile-right-column">
                        <div class="profile-funds-box text-start mb-4">
                            <p class="profile-funds-label mb-2">Your balance</p>
                            <strong class="font-monospace profile-balance-large profile-balance-emphasis">
                                ₹<?= escape_output($profileData['balance_rupees']) ?>
                            </strong>
                        </div>

                        <div>
                            <a href="/profile.php" class="btn btn-primary px-4 py-2">Edit My Profile</a>
                        </div>
                    </div>
                </div>
            <?php else: ?>
                <div class="mb-4">
                    <img src="/serve_image.php?file=<?= $profileData['image'] ?>" width="150" height="150"
                        class="rounded-circle avatar-glow" alt="Profile Pic">
                </div>

                <div class="card bg-dark border-secondary text-start p-4 mx-auto mb-4 profile-bio-box">
                    <h3 class="text-cyan mb-3 border-bottom border-secondary pb-2">Operational Bio</h3>
                    <p class="text-light m-0 profile-bio-text"><?= nl2br($profileData['bio']) ?></p>
                </div>

                <div>
                    <a href="/payment_page.php?target_uuid=<?= $profileData['uuid'] ?>"
                        class="btn btn-primary px-4 py-2">Initiate Transfer to Agent</a>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>

</html>