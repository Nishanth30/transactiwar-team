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

    <div class="tw-auth-wrap">
        <div class="tw-auth-card tw-medium">
            <div class="card">
                <div class="card-body">
                    <h2 class="text-center text-glow mb-4">Change Password</h2>

                    <?php if ($error_message !== ''): ?>
                        <div class="alert alert-danger" role="alert">
                            <?= escape_output($error_message) ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" action="/change_password.php">
                        <?= csrfField() ?>

                        <div class="mb-3">
                            <label for="current_password" class="form-label">Current Password</label>
                            <input type="password" class="form-control" id="current_password"
                                   name="current_password" required autocomplete="current-password">
                        </div>

                        <div class="mb-3">
                            <label for="new_password" class="form-label">New Password</label>
                            <input type="password" class="form-control" id="new_password"
                                   name="new_password" required
                                   minlength="<?= MIN_PASSWORD_LEN ?>"
                                   maxlength="<?= MAX_PASSWORD_LEN ?>"
                                   autocomplete="new-password">
                        </div>

                        <div class="mb-3">
                            <label for="confirm_new_password" class="form-label">Confirm New Password</label>
                            <input type="password" class="form-control" id="confirm_new_password"
                                   name="confirm_new_password" required autocomplete="new-password">
                        </div>

                        <button type="submit" class="btn btn-primary w-100 mt-2">Update Password</button>
                    </form>

                    <?php if ($show_password_policy): ?>
                    <div class="tw-rules mt-4">
                        <h6>Password Policy</h6>
                        <div>
                            <strong>Requirements</strong>
                            <ul>
                                <li><?= MIN_PASSWORD_LEN ?>&ndash;<?= MAX_PASSWORD_LEN ?> characters</li>
                                <li>At least one uppercase letter (A&ndash;Z)</li>
                                <li>At least one lowercase letter (a&ndash;z)</li>
                                <li>At least one digit (0&ndash;9)</li>
                                <li>At least one special character (!@#$%^&amp;* etc.)</li>
                            </ul>
                        </div>
                    </div>
                    <?php endif; ?>

                    <div class="text-center mt-4">
                        <a href="/profile.php" class="text-muted">
                            Back to <span class="text-cyan">Edit Profile</span>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.php'; ?>
</body>
</html>
