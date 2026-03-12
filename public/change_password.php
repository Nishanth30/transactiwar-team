<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();
no_cache();

require_once __DIR__ . '/../includes/change_password_logic.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | Change Password', csrfMeta()); ?>
</head>
<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container auth-container container-password">
        <div class="card">
            <h2 class="text-center text-glow">Change Password</h2>

            <?php if ($error_message !== ''): ?>
                <div class="error-msg">
                    <?= escape_output($error_message) ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="/change_password.php">
                <?= csrfField() ?>

                <div class="mt-2">
                    <label>Current Password</label>
                    <input type="password" name="current_password" required autocomplete="current-password">
                </div>

                <div class="mt-2">
                    <label>New Password</label>
                    <input
                        type="password"
                        name="new_password"
                        required
                        minlength="<?= MIN_PASSWORD_LEN ?>"
                        maxlength="<?= MAX_PASSWORD_LEN ?>"
                        autocomplete="new-password"
                    >
                </div>

                <div class="mt-2">
                    <label>Confirm New Password</label>
                    <input type="password" name="confirm_new_password" required autocomplete="new-password">
                </div>

                <button type="submit" class="btn-primary mt-4">Update Password</button>
            </form>

            <?php if ($show_password_policy): ?>
            <div class="rules-box mt-4">
                <h4 class="rules-title">Password Policy</h4>
                <div class="rules-section">
                    <strong>Password</strong>
                    <ul>
                        <li><?= MIN_PASSWORD_LEN ?>-<?= MAX_PASSWORD_LEN ?> characters</li>
                        <li>At least one uppercase letter (A-Z)</li>
                        <li>At least one lowercase letter (a-z)</li>
                        <li>At least one digit (0-9)</li>
                        <li>At least one special character (!@#$%^&* etc.)</li>
                    </ul>
                </div>
            </div>
            <?php endif; ?>

            <div class="text-center mt-4">
                <a href="/profile.php" class="text-muted">Back to <span class="text-cyan">Edit Profile</span></a>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>
</html>
