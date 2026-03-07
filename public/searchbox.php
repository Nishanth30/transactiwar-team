<?php

require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../config/session.php';

require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/sanitize.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../config/db.php';

require_login();

include("header.html");
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Search Users</title>
    <style>
        body {
            font-family: Arial, sans-serif;
        }

        #searchbar {
            width: 300px;
            padding: 8px;
            font-size: 16px;
        }

        .results-container {
            margin-top: 20px;
            width: 300px;
            border: 1px solid #ccc;
        }

        .result-item {
            display: block;
            padding: 8px;
            border-top: 1px solid #eee;
            text-decoration: none;
            color: black;
        }

        .result-item:hover {
            background-color: #f2f2f2;
        }
    </style>
</head>

<body>

    <h2>Search Users</h2>

    <form method="GET" action="">
        <?= csrfField(); ?>
        <input type="text" name="q" id="searchbar" placeholder="Search users...">
        <button type="submit">Search</button>
    </form>

    <div class="results-container">
        <?php

        $query = sanitize_search(get_str('q'));

        if (!is_empty_input($query)) {
            logActivity(LOG_SEARCH);


            // Check PDO is available
            if (!isset($pdo) || $pdo === null) {
                die("<p style='color:red;'>Database connection failed.</p>");
            }

            $stmt = $pdo->prepare("
        SELECT username, public_id 
        FROM users 
        WHERE username = :search OR public_id = :search
        LIMIT 1
    ");

            if (!$stmt) {
                die("<p style='color:red;'>Query prepare failed.</p>");
            }

            $stmt->execute(['search' => $query]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (count($rows) === 0) {
                echo "<p style='color:red;'>No users found.</p>";
            }

            foreach ($rows as $row) {
                $safeUsername = escape_output($row['username']);
                $safePublicId = escape_output($row['public_id']);

                $urlUsername = urlencode($row['username']);
                $urlPublicId = urlencode($row['public_id']);

                $safeUsernameHref = escape_attr("view_profile.php?username=" . $urlUsername);
                $safePublicIdHref = escape_attr("view_profile.php?id=" . $urlPublicId);

                echo '<div class="result-item">';
                echo '<a href="' . $safePublicIdHref . '">' . $safeUsername . '</a>';
                echo '</div>';
            }
        }
        ?>
    </div>

    <?php include("footer.html"); ?>
</body>

</html>