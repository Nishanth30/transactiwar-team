<?php
// 1. Load the backend logic
require_once __DIR__ . '/../includes/profile_update_logic.php';

// 2. Activate the HTTP Security Headers
if (file_exists(__DIR__ . '/../includes/header.php')) {
    require_once __DIR__ . '/../includes/header.php';
    send_security_headers();
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <title>Transactiwar | Edit Profile</title>
</head>

<body>

    <?php include("header.html"); ?>

    <div class="container auth-container">
        <div class="card">
            <h2 class="text-glow text-center">Update Operational Profile</h2>

            <?php if ($update_success): ?>
                <div class="success-msg">
                    Profile updated successfully! <a href="view_profile.php" class="text-cyan">View Profile</a>
                </div>
            <?php endif; ?>

            <?php if ($error_message): ?>
                <div class="error-msg">
                    <?php echo escape_output($error_message); ?>
                </div>
            <?php endif; ?>

            <div class="text-center mb-4">
                <p class="text-muted" style="margin-bottom: 1rem; font-family: 'Fira Code', monospace;">Current
                    Operational Avatar</p>
                <div style="position: relative; display: inline-block;">
                    <img src="serve_image.php?file=<?php echo $display_image; ?>" width="120"
                        style="border-radius: 50%; border: 3px solid var(--primary-cyan); box-shadow: 0 0 20px rgba(0,240,255,0.3); transition: all 0.3s ease;"
                        alt="Current Profile Picture">
                </div>
            </div>

            <form action="profile.php" method="POST" enctype="multipart/form-data">

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
                    <textarea name="bio" class="custom-textarea"
                        placeholder="Enter your background and mission details..."><?php echo $display_bio; ?></textarea>
                </div>

                <div class="mt-4 d-flex gap-2">
                    <button type="submit" class="btn-primary" style="flex: 1; margin: 0;">Deploy Changes</button>
                    <a href="view_profile.php" class="btn"
                        style="flex: 1; display: flex; align-items: center; justify-content: center;">Abort</a>
                </div>
            </form>
        </div>
    </div>

    <?php include("footer.html"); ?>
</body>

</html>