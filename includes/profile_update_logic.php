<?php
// includes/profile_update_logic.php

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/logger.php'; // 🆕 ADDED: The Logger

// 1. IDENTITY VERIFICATION (Kills IDOR)
require_login();
$user_id = $_SESSION['user_id'];
$public_id = $_SESSION['public_user_id'];

// 2. FETCH CURRENT DATA (We do this first so we know what to delete later)
$stmt = $pdo->prepare("SELECT bio, profile_image_path FROM users WHERE id = :id LIMIT 1");
$stmt->execute([':id' => $user_id]);
$current_user = $stmt->fetch(PDO::FETCH_ASSOC);

$old_image_path = $current_user['profile_image_path'] ?? null;
$update_success = false;
$error_message = '';

// 3. THE POST REQUEST HANDLER (When they click "Save")
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // A. CSRF DEFENSE: Kills forged requests instantly
    verifyCsrf();

    // B. BIO SANITIZATION: Kills XSS and Null Bytes
    $new_bio = sanitize_bio($_POST['bio'] ?? '');

    // C. FILE UPLOAD DEFENSE MATRIX (The RCE Killer)
    $image_path_query = "";
    $bind_params = [':bio' => $new_bio, ':id' => $user_id];
    $new_file_destination = null;

    if (isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] === UPLOAD_ERR_OK) {
        $file = $_FILES['profile_image'];

        // Defense 1: Hard Size Limit (2MB max) to prevent DOS
        if ($file['size'] > 2097152) {
            $error_message = "File is too large. Maximum size is 2MB.";
            // 🆕 ADDED: Ring the alarm for oversized files
            logSecurityEvent(LOG_FILE_UPLOAD_FAIL, "File exceeded 2MB limit"); 
        } else {
            // Defense 2: True MIME Type Check (Don't trust the browser)
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime_type = $finfo->file($file['tmp_name']);
            $allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

            if (!in_array($mime_type, $allowed_mimes, true)) {
                $error_message = "Invalid file format. Only JPG, PNG, GIF, and WEBP are allowed.";
                // 🆕 ADDED: Ring the alarm for hacking attempts (fake images)
                logSecurityEvent(LOG_FILE_UPLOAD_FAIL, "Invalid MIME type: " . $mime_type); 
            } else {
                // Defense 3: Secure Extension & Filename (Kills Directory Traversal)
                $safe_filename = sanitize_filename($file['name']);
                
                // Defense 4: Obfuscated Storage Name (Kills Data Enumeration)
                $final_filename = 'avatar_' . time() . '_' . rand(1000, 9999) . '_' . $safe_filename;
                
                $upload_dir = __DIR__ . '/../public/uploads/';
                if (!is_dir($upload_dir)) {
                    mkdir($upload_dir, 0755, true);
                }

                $new_file_destination = $upload_dir . $final_filename;

                // Move the file out of temporary storage
                if (move_uploaded_file($file['tmp_name'], $new_file_destination)) {
                    $image_path_query = ", profile_image_path = :img";
                    $bind_params[':img'] = $final_filename;
                } else {
                    $error_message = "System error: Failed to save the image.";
                }
            }
        }
    }

    // D. DATABASE UPDATE & STORAGE CLEANUP
    if (empty($error_message)) {
        try {
            $sql = "UPDATE users SET bio = :bio" . $image_path_query . " WHERE id = :id";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($bind_params);
            $update_success = true;

            // 🆕 ADDED: Log the successful profile update for the audit trail
            logActivity(LOG_PROFILE_UPDATE); 

            // Defense 5: Storage Exhaustion Cleanup
            if ($new_file_destination !== null && $old_image_path !== null) {
                $old_file_full_path = __DIR__ . '/../public/uploads/' . basename($old_image_path);
                if (file_exists($old_file_full_path) && is_file($old_file_full_path)) {
                    unlink($old_file_full_path); 
                }
            }

            // Refresh the current data so the UI updates immediately
            $stmt = $pdo->prepare("SELECT bio, profile_image_path FROM users WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $user_id]);
            $current_user = $stmt->fetch(PDO::FETCH_ASSOC);

        } catch (PDOException $e) {
            // Info Disclosure Defense: Log the real error, show a generic one
            error_log("Profile Update Error: " . $e->getMessage());
            $error_message = "A database error occurred while saving your profile.";
            
            // If the DB failed but we moved the file, delete the orphaned file
            if ($new_file_destination !== null && file_exists($new_file_destination)) {
                unlink($new_file_destination);
            }
        }
    }
}

// 4. PREPARE SAFE UI DATA
$display_bio = escape_output($current_user['bio'] ?? '');
$display_image = escape_output(basename((string)($current_user['profile_image_path'] ?? 'default_agent.png')));
?>