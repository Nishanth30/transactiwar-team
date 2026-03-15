<?php
// includes/profile_update_logic.php

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/logger.php'; // 🆕 ADDED: The Logger

// 1. IDENTITY VERIFICATION (Kills IDOR)
require_login();
logActivity(LOG_PAGE_VIEW . ':profile_edit');
$user_id = $_SESSION['user_id'];
$public_id = $_SESSION['public_user_id'];

// 2. FETCH CURRENT DATA (We do this first so we know what to delete later)
$stmt = $pdo->prepare("SELECT bio, profile_image_path FROM users WHERE id = :id LIMIT 1");
$stmt->execute([':id' => $user_id]);
$current_user = $stmt->fetch(PDO::FETCH_ASSOC);

$old_image_path = $current_user['profile_image_path'] ?? null;
$update_success = false;
$error_message = '';

function ensure_profile_upload_dir(): ?string
{
    $upload_dir = __DIR__ . '/../storage/uploads/';

    if (!is_dir($upload_dir) && !mkdir($upload_dir, 0770, true) && !is_dir($upload_dir)) {
        error_log('profile_update_logic.php: failed to create upload directory: ' . $upload_dir);
        return null;
    }

    if (!is_writable($upload_dir)) {
        error_log('profile_update_logic.php: upload directory is not writable: ' . $upload_dir);
        return null;
    }

    return $upload_dir;
}

// 3. THE POST REQUEST HANDLER (When they click "Save")
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // A. CSRF DEFENSE: Kills forged requests instantly
    verifyCsrf();

    // B. BIO SANITIZATION: Kills XSS and Null Bytes
    $new_bio = '';
    $raw_input_bio = (string) ($_POST['bio'] ?? '');

    // Reject massive input BEFORE expensive sanitization
    if (mb_strlen($raw_input_bio, 'UTF-8') > 3000) {
        $error_message = "Your biography is too long. Please limit it to 3,000 characters.";
        logSecurityEvent(LOG_INVALID_INPUT, "Bio exceeded 3000 chars");
    }
    else {
        $new_bio = sanitize_bio($raw_input_bio);
    }

    // C. FILE UPLOAD DEFENSE MATRIX (The RCE & Bomb Killer)
    $image_path_query = "";
    $bind_params = [':bio' => $new_bio, ':id' => $user_id];
    $new_file_destination = null;

    if (empty($error_message) && isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] === UPLOAD_ERR_OK) {
        $file = $_FILES['profile_image'];

        if (!is_uploaded_file((string) ($file['tmp_name'] ?? ''))) {
            $error_message = "Invalid upload source.";
            logSecurityEvent(LOG_FILE_UPLOAD_FAIL, "tmp_name was not an uploaded file");
        }
        elseif ($file['size'] > 2097152) {
            $error_message = "File is too large. Maximum size is 2MB.";
            logSecurityEvent(LOG_FILE_UPLOAD_FAIL, "File exceeded 2MB limit");
        }
        else {
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime_type = $finfo->file($file['tmp_name']);
            $allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

            if (!in_array($mime_type, $allowed_mimes, true)) {
                $error_message = "Invalid file format.";
                logSecurityEvent(LOG_FILE_UPLOAD_FAIL, "Invalid MIME type: " . $mime_type);
            }
            else {
                // 🆕 RED TEAM FIX (C3): The Decompression Bomb Check
                // Read the image dimensions BEFORE loading it into RAM
                $image_info = @getimagesize($file['tmp_name']);
                if ($image_info === false || $image_info[0] > 1200 || $image_info[1] > 1200) {
                    $error_message = "Image dimensions too large. Max 1200x1200 pixels.";
                    logSecurityEvent(LOG_FILE_UPLOAD_FAIL, "image exceeded safe dimensions");
                }
                else {
                    $safe_filename = sanitize_filename($file['name']);
                    $final_filename = 'avatar_' . bin2hex(random_bytes(16)) . '_' . $safe_filename;
                    // Store OUTSIDE the web root — serve via serve_image.php only
                    $upload_dir = ensure_profile_upload_dir();
                    if ($upload_dir === null) {
                        $error_message = "System error: Upload storage is unavailable.";
                        logSecurityEvent(LOG_FILE_UPLOAD_FAIL, "upload directory unavailable or not writable");
                    }
                    else {
                        $new_file_destination = $upload_dir . $final_filename;
                    }

                    if (empty($error_message) && $new_file_destination !== null && move_uploaded_file($file['tmp_name'], $new_file_destination)) {
                        // Safe to re-process now that we know dimensions are small
                        $reprocess_success = false;
                        if ($mime_type === 'image/jpeg') {
                            $img = @imagecreatefromjpeg($new_file_destination);
                            if ($img) {
                                $reprocess_success = imagejpeg($img, $new_file_destination, 90);
                                imagedestroy($img);
                            }
                        }
                        elseif ($mime_type === 'image/png') {
                            $img = @imagecreatefrompng($new_file_destination);
                            if ($img) {
                                $reprocess_success = imagepng($img, $new_file_destination);
                                imagedestroy($img);
                            }
                        }
                        elseif ($mime_type === 'image/gif') {
                            // M4 FIX: GD's imagegif() preserves GIF89a comment
                            // extension blocks, which can carry PHP polyglot
                            // payloads that survive a round-trip. Converting to
                            // PNG strips all GIF-specific metadata completely.
                            $img = @imagecreatefromgif($new_file_destination);
                            if ($img) {
                                $png_dest = preg_replace('/\.gif$/i', '.png', $new_file_destination);
                                $reprocess_success = imagepng($img, $png_dest);
                                imagedestroy($img);
                                if ($reprocess_success) {
                                    unlink($new_file_destination);
                                    $new_file_destination = $png_dest;
                                    $final_filename = preg_replace('/\.gif$/i', '.png', $final_filename);
                                }
                            }
                        }
                        elseif ($mime_type === 'image/webp') {
                            $img = @imagecreatefromwebp($new_file_destination);
                            if ($img) {
                                $reprocess_success = imagewebp($img, $new_file_destination, 90);
                                imagedestroy($img);
                            }
                        }

                        if ($reprocess_success) {
                            $image_path_query = ", profile_image_path = :img";
                            $bind_params[':img'] = $final_filename;
                        }
                        else {
                            unlink($new_file_destination);
                            $error_message = "System error: Failed to process secure image.";
                        }
                    }
                    elseif (empty($error_message)) {
                        error_log('profile_update_logic.php: move_uploaded_file failed for destination ' . (string) $new_file_destination);
                        $error_message = "System error: Failed to save the image.";
                    }
                }
            }
        }
    } elseif (empty($error_message) && isset($_FILES['profile_image']) && (int) ($_FILES['profile_image']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
        $error_message = "Image upload failed before processing.";
        logSecurityEvent(
            LOG_FILE_UPLOAD_FAIL,
            'php upload error code: ' . (string) ((int) ($_FILES['profile_image']['error'] ?? -1))
        );
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
                $old_file_full_path = __DIR__ . '/../storage/uploads/' . basename($real_old_image);
                if (file_exists($old_file_full_path) && is_file($old_file_full_path)) {
                    unlink($old_file_full_path);
                }
            }

            // Now release the lock
            $pdo->commit();
            logActivity(LOG_PROFILE_UPDATE);

            // Session flash — more secure than ?updated=1 in URL
            // (doesn't appear in browser history, logs, or Referer headers)
            $_SESSION['flash_success'] = 'Profile updated successfully!';

            // PRG — redirect after POST so refresh doesn't re-submit the form
            header('Location: /profile.php');
            exit;

        }
        catch (PDOException $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log("Profile Update Error: " . $e->getMessage());
            $error_message = "A database error occurred while saving your profile.";
            if ($new_file_destination !== null && file_exists($new_file_destination)) {
                unlink($new_file_destination);
            }
        }
    }

    // PRG Pattern: If there are any errors, store them in the session and redirect
    if (!empty($error_message)) {
        $_SESSION['flash_error'] = $error_message;
        header('Location: /profile.php');
        exit;
    }
}

// 4. PREPARE SAFE UI DATA
$display_bio = escape_output($current_user['bio'] ?? '');
$display_image = escape_output(basename((string)($current_user['profile_image_path'] ?? 'default_agent.png')));
?>
