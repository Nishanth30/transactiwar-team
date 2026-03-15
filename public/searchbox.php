<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/header.php';
send_security_headers();

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../config/db.php';

require_login();

unset($_SESSION['transfer_complete']);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php render_page_head('Transactiwar | Search Users'); ?>
</head>
<body>
    <?php include __DIR__ . '/header.html'; ?>

    <div class="container py-4 tw-w-md">
        <div class="card">
            <div class="card-body">
                <h2 class="text-glow mb-4">Search Users</h2>

                <form method="GET" action="/searchbox.php" class="d-flex gap-2 mb-2">
                    <input type="text" class="form-control" name="q" id="searchbar"
                           placeholder="Enter username or user ID&hellip;"
                           aria-label="Search users">
                    <button type="submit" class="btn btn-primary text-nowrap">Search</button>
                </form>
                <p class="form-text mb-4">Search by exact username or public user ID (UUID)</p>

                <?php
                $query = sanitize_search(get_str('q'));
                $searchTerm = trim($query);

                if ($searchTerm !== '') {
                    logActivity(LOG_SEARCH);
                }

                if (!isset($pdo) || $pdo === null) {
                    // L3 FIX: Generic message — the old text confirmed which
                    // infrastructure component was down, aiding attacker recon.
                    echo '<div class="alert alert-danger" role="alert">An unexpected error occurred. Please try again later.</div>';
                    goto search_end;
                }

                // L4 FIX: Rate-limit searches per authenticated user to prevent
                // brute-force username enumeration. Keyed by user ID, not IP.
                $searchUserId = (int) ($_SESSION['user_id'] ?? 0);
                if ($searchTerm !== '' && is_search_locked($pdo, $searchUserId)) {
                    echo '<div class="alert alert-danger" role="alert">Too many searches. Please wait a moment before trying again.</div>';
                    goto search_end;
                }

                $isUuid = ($searchTerm !== '' && sanitize_uuid($searchTerm) !== null);
                $searchLooksValid = true;

                if ($searchTerm !== '' && !$isUuid) {
                    $searchLooksValid = validate_username($searchTerm);
                }

                $rows = [];
                if ($searchTerm !== '' && $searchLooksValid) {
                    if ($isUuid) {
                        $stmt = $pdo->prepare(
                            "SELECT username FROM users WHERE public_id = :search_val LIMIT 1"
                        );
                        $stmt->execute([':search_val' => sanitize_uuid($searchTerm)]);
                    } else {
                        $stmt = $pdo->prepare(
                            "SELECT username FROM users WHERE username = :search_val LIMIT 1"
                        );
                        $stmt->execute([':search_val' => $searchTerm]);
                    }
                    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    record_search_attempt($pdo, $searchUserId);
                } elseif ($searchTerm !== '' && !$searchLooksValid) {
                    logActivity(LOG_INVALID_INPUT);
                }

                if (count($rows) === 0) {
                    if ($searchTerm !== '' && !$searchLooksValid) {
                        echo '<div class="alert alert-danger" role="alert">Invalid search query.</div>';
                    } elseif ($searchTerm !== '') {
                        echo '<div class="alert alert-danger" role="alert">No matching user found.</div>';
                    } else {
                        echo '<p class="text-muted text-center py-3">Enter a username or user ID to search.</p>';
                    }
                } else {
                    foreach ($rows as $row) {
                        $safeUsername = escape_output($row['username']);
                        $urlUsername = urlencode($row['username']);
                        $safeProfileHref = escape_attr("view_profile.php?username=" . $urlUsername);

                        echo '<a href="' . $safeProfileHref . '" class="tw-search-result">';
                        echo '<div class="card mb-2">';
                        echo '<div class="card-body py-3 text-center">';
                        echo '<h5 class="text-cyan mb-0">' . $safeUsername . '</h5>';
                        echo '</div></div></a>';
                    }
                }
                search_end:
                ?>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.php'; ?>
</body>
</html>
