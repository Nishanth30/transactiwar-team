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
    // 🆕 RED TEAM FIX (E1): Decode HTML entities back to raw text before saving to prevent infinite double-encoding corruption.
    $raw_input_bio = htmlspecialchars_decode($_POST['bio'] ?? '', ENT_QUOTES);
    $new_bio = sanitize_bio($raw_input_bio);

    // C. FILE UPLOAD DEFENSE MATRIX (The RCE & Bomb Killer)
    $image_path_query = "";
    $bind_params = [':bio' => $new_bio, ':id' => $user_id];
    $new_file_destination = null;

    if (isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] === UPLOAD_ERR_OK) {
        $file = $_FILES['profile_image'];

        if ($file['size'] > 2097152) {
            $error_message = "File is too large. Maximum size is 2MB.";
            logSecurityEvent(LOG_FILE_UPLOAD_FAIL, "File exceeded 2MB limit"); 
        } else {
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime_type = $finfo->file($file['tmp_name']);
            $allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

            if (!in_array($mime_type, $allowed_mimes, true)) {
                $error_message = "Invalid file format.";
                logSecurityEvent(LOG_FILE_UPLOAD_FAIL, "Invalid MIME type: " . $mime_type); 
            } else {
                // 🆕 RED TEAM FIX (C3): The Decompression Bomb Check
                // Read the image dimensions BEFORE loading it into RAM
                $image_info = @getimagesize($file['tmp_name']);
                if ($image_info === false || $image_info[0] > 4000 || $image_info[1] > 4000) {
                    $error_message = "Image dimensions too large. Max 4000x4000 pixels.";
                    logSecurityEvent(LOG_FILE_UPLOAD_FAIL, "Decompression bomb prevented");
                } else {
                    $safe_filename = sanitize_filename($file['name']);
                    $final_filename = 'avatar_' . bin2hex(random_bytes(16)) . '_' . $safe_filename;
                    $upload_dir = __DIR__ . '/../public/uploads/';
                    if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }
                    $new_file_destination = $upload_dir . $final_filename;

                    if (move_uploaded_file($file['tmp_name'], $new_file_destination)) {
                        // Safe to re-process now that we know dimensions are small
                        $reprocess_success = false;
                        if ($mime_type === 'image/jpeg') {
                            $img = @imagecreatefromjpeg($new_file_destination);
                            if ($img) { $reprocess_success = imagejpeg($img, $new_file_destination, 90); imagedestroy($img); }
                        } elseif ($mime_type === 'image/png') {
                            $img = @imagecreatefrompng($new_file_destination);
                            if ($img) { $reprocess_success = imagepng($img, $new_file_destination); imagedestroy($img); }
                        } elseif ($mime_type === 'image/gif') {
                            $img = @imagecreatefromgif($new_file_destination);
                            if ($img) { $reprocess_success = imagegif($img, $new_file_destination); imagedestroy($img); }
                        } elseif ($mime_type === 'image/webp') {
                            $img = @imagecreatefromwebp($new_file_destination);
                            if ($img) { $reprocess_success = imagewebp($img, $new_file_destination, 90); imagedestroy($img); }
                        }

                        if ($reprocess_success) {
                            $image_path_query = ", profile_image_path = :img";
                            $bind_params[':img'] = $final_filename;
                        } else {
                            unlink($new_file_destination); 
                            $error_message = "System error: Failed to process secure image.";
                        }
                    } else {
                        $error_message = "System error: Failed to save the image.";
                    }
                }
            }
        }
    }

    // D. DATABASE UPDATE & STRICT STORAGE CLEANUP
    if (empty($error_message)) {
        try {
            $pdo->beginTransaction();

            // Lock the row to prevent the race condition
            $lock_stmt = $pdo->prepare("SELECT profile_image_path FROM users WHERE id = :id FOR UPDATE");
            $lock_stmt->execute([':id' => $user_id]);
            $real_old_image = $lock_stmt->fetchColumn();

            // Execute the update
            $sql = "UPDATE users SET bio = :bio" . $image_path_query . " WHERE id = :id";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($bind_params);
            
            // 🆕 RED TEAM FIX (C1): Delete the old file WHILE the database is locked.
            // This guarantees no other thread can sneak in and orphan a file.
            if ($new_file_destination !== null && $real_old_image) {
                $old_file_full_path = __DIR__ . '/../public/uploads/' . basename($real_old_image);
                if (file_exists($old_file_full_path) && is_file($old_file_full_path)) {
                    unlink($old_file_full_path); 
                }
            }

            // Now release the lock
            $pdo->commit();
            $update_success = true;
            logActivity(LOG_PROFILE_UPDATE); 

            $stmt = $pdo->prepare("SELECT bio, profile_image_path FROM users WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $user_id]);
            $current_user = $stmt->fetch(PDO::FETCH_ASSOC);

        } catch (PDOException $e) {
            if ($pdo->inTransaction()) { $pdo->rollBack(); }
            error_log("Profile Update Error: " . $e->getMessage());
            $error_message = "A database error occurred while saving your profile.";
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