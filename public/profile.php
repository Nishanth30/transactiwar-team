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

$error_message = '';
if (isset($_SESSION['flash_error']) && is_string($_SESSION['flash_error'])) {
    $error_message = $_SESSION['flash_error'];
    unset($_SESSION['flash_error']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | Edit Profile'); ?>
</head>
<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container py-4 tw-w-lg">
        <div class="card">
            <div class="card-body">
                <h2 class="text-glow mb-4">Edit Profile</h2>

                <?php if ($flash_success_message !== ''): ?>
                    <div class="alert alert-success" role="alert">
                        <?= escape_output($flash_success_message) ?>
                        <a href="/view_profile.php" class="text-cyan fw-bold ms-1">View Profile</a>
                    </div>
                <?php endif; ?>

                <?php if ($error_message): ?>
                    <div class="alert alert-danger" role="alert">
                        <?= escape_output($error_message) ?>
                    </div>
                <?php endif; ?>

                <div class="mb-4">
                    <p class="form-label mb-2">Current Avatar</p>
                    <img src="/serve_image.php?file=<?= $display_image ?>"
                         width="100" height="100" alt="Current profile picture"
                         class="rounded-circle tw-avatar">
                </div>

                <form action="/profile.php" method="POST" enctype="multipart/form-data">
                    <?= csrfField() ?>

                    <div class="mb-3">
                        <label for="profile_image" class="form-label">Profile Image</label>
                        <input type="file" class="form-control" id="profile_image"
                               name="profile_image" accept=".jpg,.jpeg,.png,.gif,.webp">
                        <div class="form-text">JPG, PNG, GIF, or WEBP &mdash; max 2 MB</div>
                    </div>

                    <div class="mb-3">
                        <label for="bio" class="form-label">Bio</label>
                        <textarea class="form-control" id="bio" name="bio" rows="3"
                                  placeholder="Tell us about yourself&hellip;"><?= $display_bio ?></textarea>
                    </div>

                    <div class="d-flex gap-2 mt-2">
                        <button type="submit" class="btn btn-primary flex-fill">Save Changes</button>
                        <a href="/view_profile.php" class="btn btn-outline-secondary flex-fill">Cancel</a>
                    </div>
                </form>

                <hr class="tw-divider my-4">

                <h5 class="text-cyan mb-3">Account Security</h5>
                <a href="/change_password.php" class="btn btn-outline-secondary w-100">Change Password</a>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.php'; ?>
</body>
</html>
