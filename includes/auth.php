<?php
declare(strict_types=1);

function register_user(PDO $pdo, string $username, string $email, string $password): bool
{
    $hash = password_hash($password, PASSWORD_DEFAULT);

    $sql = "
        INSERT INTO users (username, email, password_hash)
        VALUES (:username, :email, :password_hash)
    ";

    try {
        $stmt = $pdo->prepare($sql);

        return $stmt->execute([
            'username' => $username,
            'email' => $email,
            'password_hash' => $hash
        ]);

    } catch (PDOException $e) {
        return false;
    }
}


function login_user(PDO $pdo, string $identifier, string $password): bool
{
    $sql = "
        SELECT id, username, password_hash
        FROM users
        WHERE username = :id OR email = :id
        LIMIT 1
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute(['id' => $identifier]);

    $user = $stmt->fetch();

    if (!$user) {
        return false;
    }

    if (!password_verify($password, $user['password_hash'])) {
        return false;
    }

    /* Prevent session fixation */
    session_regenerate_id(true);

    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['username'] = $user['username'];

    return true;
}

function require_login(): void
{
    if (!isset($_SESSION['user_id'])) {
        header('Location: /login.php');
        exit;
    }
}
