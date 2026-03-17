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

    <div class="container py-4 tw-w-xl">
        <div class="card">
            <div class="card-body">
                <h2 class="text-glow mb-1"><?= $profileData['username'] ?></h2>
                <p class="text-muted font-mono small mb-4">
                    <?= $profileData['uuid'] ?>
                </p>

                <?php if ($profileData['is_mine']): ?>
                    <div class="tw-profile-grid">
                        <div>
                            <div class="mb-4">
                                <img src="/serve_image.php?file=<?= $profileData['image'] ?>"
                                     width="120" height="120" alt="Profile picture"
                                     class="rounded-circle tw-avatar">
                            </div>

                            <div class="card tw-bio-card">
                                <div class="card-body">
                                    <h6 class="text-cyan text-uppercase small fw-bold mb-2">Bio</h6>
                                    <p class="mb-0 tw-lh-relaxed">
                                        <?= nl2br($profileData['bio'], false) ?>
                                    </p>
                                </div>
                            </div>
                        </div>

                        <div>
                            <div class="tw-balance-box w-100 text-center mb-4">
                                <span class="tw-balance-label d-block mb-1">Your Balance</span>
                                <span class="tw-balance-amount font-mono">
                                    &#8377;<?= escape_output($profileData['balance_rupees']) ?>
                                </span>
                            </div>

                            <a href="/profile.php" class="btn btn-primary w-100">Edit Profile</a>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="mb-4">
                        <img src="/serve_image.php?file=<?= $profileData['image'] ?>"
                             width="120" height="120" alt="Profile picture"
                             class="rounded-circle tw-avatar">
                    </div>

                    <div class="card tw-bio-card mb-4">
                        <div class="card-body">
                            <h6 class="text-cyan text-uppercase small fw-bold mb-2">Bio</h6>
                            <p class="mb-0 tw-lh-relaxed">
                                <?= nl2br($profileData['bio'], false) ?>
                            </p>
                        </div>
                    </div>

                    <a href="/payment_page.php?target_uuid=<?= $profileData['uuid'] ?>"
                       class="btn btn-primary">Initiate Transfer</a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.php'; ?>
</body>
</html>
