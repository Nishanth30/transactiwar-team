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

    <div class="container">
        <div class="card">
            <h2 class="text-glow">Search Users</h2>


            <form method="GET" action="/searchbox.php" class="search-form">
                <div class="search-input-wrapper">
                    <input type="text" name="q" id="searchbar" placeholder="Enter username or user ID...">
                </div>
                <button type="submit" class="btn-primary btn-search">Search</button>
            </form>
            <p class="text-muted mt-2">Search by exact username or public user ID (UUID)</p>
            <div class="results-container mt-4">
                <?php
                $query = sanitize_search(get_str('q'));
                $searchTerm = trim($query);

                if ($searchTerm !== '') {
                    logActivity(LOG_SEARCH);
                }

                if (!isset($pdo) || $pdo === null) {
                    die("<p class='error-msg'>Database connection failed.</p>");
                }

                // Determine if input is a UUID or a username
                $isUuid = ($searchTerm !== '' && sanitize_uuid($searchTerm) !== null);
                $searchLooksValid = true;

                if ($searchTerm !== '' && !$isUuid) {
                    $searchLooksValid = validate_username($searchTerm);
                }

                $rows = [];
                if ($searchTerm !== '' && $searchLooksValid) {
                    if ($isUuid) {
                        // Search by public user ID (UUID) — exact match
                        $stmt = $pdo->prepare(
                            "SELECT username FROM users WHERE public_id = :search_val LIMIT 1"
                        );
                        $stmt->execute([':search_val' => sanitize_uuid($searchTerm)]);
                    } else {
                        // Search by username — exact match
                        $stmt = $pdo->prepare(
                            "SELECT username FROM users WHERE username = :search_val LIMIT 1"
                        );
                        $stmt->execute([':search_val' => $searchTerm]);
                    }
                    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
                } elseif ($searchTerm !== '' && !$searchLooksValid) {
                    logActivity(LOG_INVALID_INPUT);
                }

                if (count($rows) === 0) {
                    if ($searchTerm !== '' && !$searchLooksValid) {
                        echo "<p class='error-msg'>Invalid search query.</p>";
                    } elseif ($searchTerm !== '') {
                        echo "<p class='error-msg'>No matching user found.</p>";
                    } else {
                        echo "<p class='error-msg'>Enter a username or user ID to search.</p>";
                    }
                } else {
                    foreach ($rows as $row) {
                        $safeUsername = escape_output($row['username']);
                        $urlUsername = urlencode($row['username']);
                        $safeProfileHref = escape_attr("view_profile.php?username=" . $urlUsername);

                        echo '<a href="' . $safeProfileHref . '" class="search-result-link">';
                        echo '<div class="card search-result-card">';
                        echo '<h3 class="text-cyan search-result-title">' . $safeUsername . '</h3>';
                        echo '</div>';
                        echo '</a>';
                    }
                }
                ?>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>

</html>