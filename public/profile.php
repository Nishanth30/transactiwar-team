<?php 
require_once __DIR__ . '/../includes/profile_update_logic.php'; 

if (file_exists(__DIR__ . '/../includes/header.php')) {
    require_once __DIR__ . '/../includes/header.php';
} else {
    echo "<!DOCTYPE html><html><head><title>Edit Profile</title></head><body>";
}
?>

<div style="max-width: 600px; margin: 40px auto; font-family: sans-serif;">
    <h2>Update Operational Profile</h2>
    
    <?php if ($update_success): ?>
        <div style="padding: 10px; background: #d4edda; color: #155724; border-radius: 5px; margin-bottom: 20px;">
            Profile updated successfully! <a href="view_profile.php">View Profile</a>
        </div>
    <?php endif; ?>

    <?php if ($error_message): ?>
        <div style="padding: 10px; background: #f8d7da; color: #721c24; border-radius: 5px; margin-bottom: 20px;">
            <?php echo escape_output($error_message); ?>
        </div>
    <?php endif; ?>

    <div style="margin-bottom: 20px;">
        <p style="margin-bottom: 5px; font-weight: bold;">Current Avatar:</p>
        <img src="uploads/<?php echo $display_image; ?>" width="100" style="border-radius: 8px; border: 1px solid #ccc;" alt="Current Profile Picture">
    </div>

    <form action="profile.php" method="POST" enctype="multipart/form-data" style="background: #f9f9f9; padding: 20px; border-radius: 8px; border: 1px solid #eee;">
        
        <?= csrfField() ?>

        <div style="margin-bottom: 20px;">
            <label style="display: block; font-weight: bold; margin-bottom: 5px;">Upload New Avatar (Max 2MB, JPG/PNG/WEBP):</label>
            <input type="file" name="profile_image" accept=".jpg,.jpeg,.png,.gif,.webp" style="display: block; width: 100%;">
        </div>

        <div style="margin-bottom: 20px;">
            <label style="display: block; font-weight: bold; margin-bottom: 5px;">Operational Bio (No HTML allowed):</label>
            <textarea name="bio" rows="5" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; box-sizing: border-box;"><?php echo $display_bio; ?></textarea>
        </div>

        <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">Save Changes</button>
        <a href="view_profile.php" style="margin-left: 15px; text-decoration: none; color: #007bff;">Cancel / Go Back</a>
    </form>
</div>

</body>
</html>