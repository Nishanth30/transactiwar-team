<?php
// includes/profile_view_logic.php

// 1. EXACT TEAM INTEGRATIONS
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/logger.php'; // 🆕 ADDED: The new Logger framework

// 2. BEAVER'S AUTHENTICATION
// This single function handles session_start, checks if logged in, 
// AND does Beaver's IP-binding security check. If it fails, Beaver kills the script.
require_login();


// If require_login() passes, we are mathematically guaranteed to have this:
$viewer_internal_id = $_SESSION['user_id'];
$sampleUsernames = [
    'nishanth',
    'tejas',
    'divyansh',
    'harshavardhan',
    'vrishin',
    'trudy',
];


// 3. RESOLUTION WATERFALL (Using Dog's Sanitizers)
$target_uuid = sanitize_public_user_id($_GET['id'] ?? null);

$target_username = clean_input($_GET['username'] ?? '');
if ($target_username !== '' && !validate_username($target_username)) {
    logSecurityEvent(LOG_INVALID_INPUT, 'Invalid profile username parameter');
    $target_username = '';
}

$sql = "";
$bind_val = "";

// 🆕 RED TEAM FIX (E4): Database-Level Privacy Gate. 
// We only select the balance if the row's ID matches the viewer's ID. Otherwise, it returns NULL.
$base_select = "SELECT id, public_id, username, bio, profile_image_path, 
                CASE WHEN id = :viewer_id THEN balance_paise ELSE NULL END as balance_paise 
                FROM users ";

if ($target_uuid) {
    // Search by UUID
    $sql = $base_select . "WHERE public_id = :val LIMIT 1";
    $bind_val = $target_uuid;
}
elseif ($target_username) {
    // Search by Username
    $sql = $base_select . "WHERE username = :val LIMIT 1";
    $bind_val = $target_username;
}
else {
    // Default to Self
    $sql = $base_select . "WHERE id = :val LIMIT 1";
    $bind_val = $viewer_internal_id;
}

// 4. SECURE EXECUTION
try {
    $stmt = $pdo->prepare($sql);
    // 🆕 RED TEAM FIX (E4): We now pass the viewer's ID to the query so MySQL can check ownership
    $stmt->execute([
        ':val' => $bind_val,
        ':viewer_id' => $viewer_internal_id
    ]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
}
catch (PDOException $e) {
    // 🆕 UPGRADED: Log the system failure via the framework before dying
    error_log("Profile View DB Error: " . $e->getMessage());
    logSecurityEvent(LOG_SUSPICIOUS, "Database error on profile view");
    die("A system error occurred. Our engineers have been notified.");
}

// 🆕 RED TEAM FIX (V1): Stop execution and log the probe if the profile doesn't exist
if (!$user) {
    logSecurityEvent(LOG_INVALID_INPUT, "Profile probe: " . substr((string)$bind_val, 0, 64));
    http_response_code(404);
    die("Agent not found or does not exist.");
}

$targetUserId = (int) ($user['id'] ?? 0);
$targetUsername = strtolower((string) ($user['username'] ?? ''));
$isOwnProfile = ($viewer_internal_id === $targetUserId);
$isSampleProfile = in_array($targetUsername, $sampleUsernames, true);

if (!$isOwnProfile && !$isSampleProfile) {
    logSecurityEvent(LOG_ACCESS_DENIED, "Non-sample profile access blocked: " . $targetUsername);
    http_response_code(404);
    die("Agent not found or does not exist.");
}
// 5. IRONCLAD DATA PACKAGING
// We prep the data so the UI dev literally cannot cause an XSS attack.
$profileData = [
    'username' => escape_output($user['username']),
    'bio' => escape_output($user['bio'] ?? 'No operational biography provided.'),
    'image' => escape_output(basename((string)($user['profile_image_path'] ?? 'default_agent.png'))),
    'uuid' => escape_output($user['public_id']),
    'is_mine' => $isOwnProfile

];

// 6. BALANCE PRIVACY GATE
if ($profileData['is_mine']) {
    $profileData['balance_rupees'] = number_format($user['balance_paise'] / 100, 2);
}

// 7. SECURITY AUDIT LOGGING (Using the framework)
// 🆕 UPGRADED: Determine if they are viewing themselves or snooping on someone else
if ($profileData['is_mine']) {
    logActivity(LOG_PROFILE_VIEW);
}
else {
    // Strip newlines — prevents log injection (username with \n could forge log entries)
    $safeForLog = preg_replace('/[\r\n\t]/', '_', $profileData['username']);
    logActivity(LOG_PROFILE_OTHER . ':' . $safeForLog);
}

unset($user);

?>
