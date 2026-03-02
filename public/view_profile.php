<?php 
// 1. Boot up the engine 
require_once __DIR__ . '/../includes/profile_view_logic.php'; 

// 2. Inject Beaver's Header
if (file_exists(__DIR__ . '/../includes/header.php')) {
    require_once __DIR__ . '/../includes/header.php';
} else {
    echo "<!DOCTYPE html><html><head><title>Agent Profile</title></head><body>";
}
?>

<div style="max-width: 600px; margin: 40px auto; font-family: sans-serif;">
    
    <h1>Agent: <?php echo $profileData['username']; ?></h1>
    <p style="color: gray; font-family: monospace;">
        Public Agent ID: <?php echo $profileData['uuid']; ?>
    </p>
    <img src="uploads/<?php echo $profileData['image']; ?>" width="150" style="border-radius: 8px;" alt="Profile Pic">
    
    <div style="margin-top: 20px; padding: 15px; background: #f4f4f4; border-radius: 5px;">
        <h3>Operational Bio</h3>
        <p><?php echo $profileData['bio']; ?></p>
    </div>

    <hr style="margin: 30px 0;">
    
    <?php if ($profileData['is_mine']): ?>
        
        <div style="padding: 15px; background: #e8f4f8; border-left: 4px solid #007bff; margin-bottom: 20px;">
            <strong>Secure Funds:</strong> ₹<?php echo $profileData['balance_rupees']; ?>
        </div>
        
        <a href="profile.php" style="padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px;">Edit My Profile</a>
        
    <?php else: ?>
        
        <a href="transfer.php?target_uuid=<?php echo $profileData['uuid']; ?>" style="padding: 10px 20px; background: #dc3545; color: white; text-decoration: none; border-radius: 4px;">Initiate Transfer to Agent</a>
        
    <?php endif; ?>

</div>

</body>
</html>