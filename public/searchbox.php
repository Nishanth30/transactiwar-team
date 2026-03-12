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
            <p class="text-muted mt-2">Only sample users are shown on this page.</p>

            <form method="GET" action="/searchbox.php" class="search-form">
                <div class="search-input-wrapper">
                    <input type="text" name="q" id="searchbar" placeholder="Enter sample username...">
                </div>
                <button type="submit" class="btn-primary btn-search">Search</button>
            </form>

            <div class="results-container mt-4">
                <?php
                $sampleUsernames = [
                    'nishanth',
                    'tejas',
                    'divyansh',
                    'harshavardhan',
                    'vrishin',
                    'trudy',
                ];

                $query = sanitize_search(get_str('q'));
                $searchTerm = trim($query);

                if ($searchTerm !== '') {
                    logActivity(LOG_SEARCH);
                }

                if (!isset($pdo) || $pdo === null) {
                    die("<p class='error-msg'>Database connection failed.</p>");
                }

                $searchLooksValid = true;
                if ($searchTerm !== '') {
                    $searchLooksValid = validate_username($searchTerm);
                }

                $rows = [];
                if ($searchLooksValid) {
                    $usernameFilterParams = [];
                    $usernameFilterPlaceholders = [];
                    foreach ($sampleUsernames as $idx => $username) {
                        $nameKey = ':sample_' . $idx;
                        $usernameFilterPlaceholders[] = $nameKey;
                        $usernameFilterParams[$nameKey] = $username;
                    }

                    $orderByCaseParts = [];
                    $orderParams = [];
                    foreach ($sampleUsernames as $idx => $username) {
                        $orderKey = ':order_' . $idx;
                        $orderByCaseParts[] = "WHEN {$orderKey} THEN {$idx}";
                        $orderParams[$orderKey] = $username;
                    }

                    $sql = "
                        SELECT username
                        FROM users
                        WHERE username IN (" . implode(', ', $usernameFilterPlaceholders) . ")
                    ";

                    $executeParams = array_merge($usernameFilterParams, $orderParams);
                    if ($searchTerm !== '') {
                        $sql .= " AND username = :search_username";
                        $executeParams[':search_username'] = $searchTerm;
                    }

                    $sql .= "
                        ORDER BY CASE username
                            " . implode(' ', $orderByCaseParts) . "
                            ELSE 999
                        END
                        LIMIT 6
                    ";

                    $stmt = $pdo->prepare($sql);
                    $stmt->execute($executeParams);
                    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
                } elseif ($searchTerm !== '') {
                    logActivity(LOG_INVALID_INPUT);
                }

                if (count($rows) === 0) {
                    if ($searchTerm !== '' && !$searchLooksValid) {
                        echo "<p class='error-msg'>Use a valid sample username.</p>";
                    } elseif ($searchTerm !== '') {
                        echo "<p class='error-msg'>No matching sample users found.</p>";
                    } else {
                        echo "<p class='error-msg'>Sample users are not available right now.</p>";
                    }
                } else {
                    $leftColumnRows = array_slice($rows, 0, 3);
                    $rightColumnRows = array_slice($rows, 3, 3);

                    echo '<div class="sample-users-grid">';
                    echo '<div class="sample-users-column">';
                    foreach ($leftColumnRows as $row) {
                        $safeUsername = escape_output($row['username']);
                        $urlUsername = urlencode($row['username']);
                        $safeProfileHref = escape_attr("view_profile.php?username=" . $urlUsername);

                        echo '<a href="' . $safeProfileHref . '" class="search-result-link">';
                        echo '<div class="card search-result-card">';
                        echo '<h3 class="text-cyan search-result-title">' . $safeUsername . '</h3>';
                        echo '</div>';
                        echo '</a>';
                    }

                    echo '</div>';
                    echo '<div class="sample-users-column">';

                    foreach ($rightColumnRows as $row) {
                        $safeUsername = escape_output($row['username']);
                        $urlUsername = urlencode($row['username']);
                        $safeProfileHref = escape_attr("view_profile.php?username=" . $urlUsername);

                        echo '<a href="' . $safeProfileHref . '" class="search-result-link">';
                        echo '<div class="card search-result-card">';
                        echo '<h3 class="text-cyan search-result-title">' . $safeUsername . '</h3>';
                        echo '</div>';
                        echo '</a>';
                    }

                    echo '</div>';
                    echo '</div>';
                }
                ?>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/footer.html'; ?>
</body>
</html>
