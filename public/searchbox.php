<?php

require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../config/session.php';

require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../config/db.php';

require_login();

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Transactiwar | Search Users</title>
</head>

<body>

    <?php include("header.html"); ?>

    <div class="container">
        <div class="card">
            <h2 class="text-glow">Search Users</h2>

            <form method="GET" action="" style="flex-direction: row; align-items: flex-end;">
                <!-- No CSRF token on GET forms — tokens in URLs leak via logs/history/Referer -->
                <div style="flex: 1;">
                    <input type="text" name="q" id="searchbar" placeholder="Enter username...">
                </div>
                <button type="submit" class="btn-primary" style="margin-top:0;">Search</button>
            </form>

            <div class="results-container mt-4">
                <?php


                $query = sanitize_search(get_str('q'));

                if (!is_empty_input($query)) {
                    logActivity(LOG_SEARCH);

                    // $searchTerm = "%" . $query . "%";
                    $searchTerm = $query;

                    // Check PDO is available
                    if (!isset($pdo) || $pdo === null) {
                        die("<p class='error-msg'>Database connection failed.</p>");
                    }

                    $stmt = $pdo->prepare("
                SELECT username, public_id 
                FROM users 
                WHERE username = :search1 OR public_id = :search2
                LIMIT 32
            ");


                    if (!$stmt) {
                        die("<p class='error-msg'>Query prepare failed.</p>");
                    }

                    // $stmt->execute(['search' => $searchTerm]);
                    $stmt->execute([
                        ':search1' => $searchTerm,
                        ':search2' => $searchTerm,
                    ]);
                    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

                    if (count($rows) === 0) {
                        echo "<p class='error-msg'>No users found.</p>";
                    } else {
                        echo '<div class="bento-grid">';
                        foreach ($rows as $row) {
                            $safeUsername = escape_output($row['username']);
                            $safePublicId = escape_output($row['public_id']);

                            $urlUsername = urlencode($row['username']);
                            $urlPublicId = urlencode($row['public_id']);

                            $safeUsernameHref = escape_attr("view_profile.php?username=" . $urlUsername);
                            $safePublicIdHref = escape_attr("view_profile.php?id=" . $urlPublicId);

                            echo '<a href="' . $safePublicIdHref . '" style="text-decoration:none;">';
                            echo '<div class="card" style="padding: 1.5rem; text-align:center; transition: all 0.3s ease;">';
                            echo '<h3 class="text-cyan" style="margin:0;">' . $safeUsername . '</h3>';
                            echo '<p class="text-muted" style="margin-top:0.5rem; font-size: 0.8rem;">ID: ' . $safePublicId . '</p>';
                            echo '</div>';
                            echo '</a>';
                        }
                        echo '</div>';
                    }
                }
                ?>
            </div>
        </div>
    </div>

    <?php include("footer.html"); ?>
</body>

</html>