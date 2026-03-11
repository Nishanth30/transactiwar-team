<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

require_once __DIR__ . '/../includes/profile_update_logic.php';

$flash_success_message = '';
if (isset($_SESSION['flash_success']) && is_string($_SESSION['flash_success'])) {
    $flash_success_message = $_SESSION['flash_success'];
    unset($_SESSION['flash_success']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | Edit Profile'); ?>
</head>
<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container auth-container mt-5">
        <div class="card p-4 shadow-lg">
            <h2 class="text-glow text-center mb-4">Update Operational Profile</h2>

            <?php if ($flash_success_message !== ''): ?>
                <div class="alert alert-success">
                    <?= escape_output($flash_success_message) ?> <a href="/view_profile.php" class="text-cyan fw-bold">View Profile</a>
                </div>
            <?php endif; ?>

            <?php if ($error_message): ?>
                <div class="alert alert-danger">
                    <?= escape_output($error_message) ?>
                </div>
            <?php endif; ?>

            <div class="text-center mb-4">
                <p class="text-muted font-monospace mb-2">Current Operational Avatar</p>
                <div class="avatar-wrapper d-inline-block">
                    <img src="/serve_image.php?file=<?= $display_image ?>" width="120" height="120" class="rounded-circle avatar-glow" alt="Current Profile Picture">
                </div>
            </div>

            <form action="/profile.php" method="POST" enctype="multipart/form-data">
                <?= csrfField() ?>

                <div class="mb-4">
                    <label class="form-label text-cyan fw-bold">Update Credentials Image</label>
                    <input type="file" name="profile_image" class="form-control bg-dark text-light border-info" accept=".jpg,.jpeg,.png,.gif,.webp">
                    <div class="form-text text-muted">Accepted formats: JPG, PNG, WEBP (Max 2MB)</div>
                </div>

                <div class="mb-4">
                    <label class="form-label text-cyan fw-bold">Operational Bio</label>
                    <textarea name="bio" class="form-control bg-dark text-light border-info" rows="4" placeholder="Enter your background and mission details..."><?= $display_bio ?></textarea>
                </div>

                <div class="d-flex gap-3 mt-4">
                    <button type="submit" class="btn btn-primary w-50">Deploy Changes</button>
                    <a href="/view_profile.php" class="btn btn-outline-secondary w-50">Abort</a>
                </div>
            </form>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>
</html>
