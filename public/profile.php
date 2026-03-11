<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

// profile_update_logic.php owns both:
// - POST processing + DB update
// - read-safe display variables for this template
require_once __DIR__ . '/../includes/profile_update_logic.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | Edit Profile'); ?>
</head>
<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container auth-container">
        <div class="card">
            <h2 class="text-glow text-center">Update Operational Profile</h2>

            <?php if ($update_success): ?>
                <div class="success-msg">
                    Profile updated successfully! <a href="/view_profile.php" class="text-cyan">View Profile</a>
                </div>
            <?php endif; ?>

            <?php if ($error_message): ?>
                <div class="error-msg">
                    <?= escape_output($error_message) ?>
                </div>
            <?php endif; ?>

            <div class="text-center mb-4">
                <p class="text-muted" style="margin-bottom: 1rem; font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace;">Current Operational Avatar</p>
                <div style="position: relative; display: inline-block;">
                    <img src="/serve_image.php?file=<?= $display_image ?>" width="120" style="border-radius: 50%; border: 3px solid var(--primary-cyan); box-shadow: 0 0 20px rgba(0,240,255,0.3); transition: all 0.3s ease;" alt="Current Profile Picture">
                </div>
            </div>

            <form action="/profile.php" method="POST" enctype="multipart/form-data">
                <?= csrfField() ?>

                <div class="mt-4">
                    <label class="mb-2">Update Credentials Image</label>
                    <div class="file-input-wrapper">
                        <div class="file-label">
                            <span class="text-cyan">Click to upload</span> or drag and drop
                            <br>
                            <small class="text-muted">JPG, PNG, WEBP (Max 2MB)</small>
                        </div>
                        <input type="file" name="profile_image" accept=".jpg,.jpeg,.png,.gif,.webp">
                    </div>
                </div>

                <div class="mt-4">
                    <label class="mb-2">Operational Bio</label>
                    <textarea name="bio" class="custom-textarea" placeholder="Enter your background and mission details..."><?= $display_bio ?></textarea>
                </div>

                <div class="mt-4 d-flex gap-2">
                    <button type="submit" class="btn-primary" style="flex: 1; margin: 0;">Deploy Changes</button>
                    <a href="/view_profile.php" class="btn" style="flex: 1; display: flex; align-items: center; justify-content: center;">Abort</a>
                </div>
            </form>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>
</html>
