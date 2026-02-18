CREATE DATABASE IF NOT EXISTS app_database
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;
USE app_database;

-- 1) Users
CREATE TABLE users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(32) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    email VARCHAR(254) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    balance_paise BIGINT UNSIGNED NOT NULL DEFAULT 10000, -- ₹100.00
    bio TEXT NULL,                                         -- long bio
    profile_image_path VARCHAR(512) NULL,                  -- image path/key/url
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT uq_users_username UNIQUE (username),
    CONSTRAINT uq_users_email UNIQUE (email),
    CONSTRAINT chk_users_balance_nonnegative CHECK (balance_paise >= 0)
) ENGINE=InnoDB;

-- 2) Money transfers
CREATE TABLE transactions (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sender_id INT UNSIGNED NOT NULL,
    receiver_id INT UNSIGNED NOT NULL,
    amount_paise BIGINT UNSIGNED NOT NULL,
    receiver_comment VARCHAR(500) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_transactions_sender
      FOREIGN KEY (sender_id) REFERENCES users(id)
      ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_transactions_receiver
      FOREIGN KEY (receiver_id) REFERENCES users(id)
      ON UPDATE RESTRICT ON DELETE RESTRICT,

    CONSTRAINT chk_transactions_amount_min_1_rupee CHECK (amount_paise >= 100), -- min ₹1.00
    CONSTRAINT chk_transactions_not_self CHECK (sender_id <> receiver_id),

    INDEX idx_transactions_sender_time (sender_id, created_at),
    INDEX idx_transactions_receiver_time (receiver_id, created_at)
) ENGINE=InnoDB;

-- 3) Activity logs
CREATE TABLE activity_logs (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NULL,                              -- NULL for unauthenticated events
    username_snapshot VARCHAR(32) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
    webpage VARCHAR(255) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,                         -- IPv4/IPv6
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_activity_logs_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON UPDATE RESTRICT ON DELETE SET NULL,

    INDEX idx_activity_logs_user_time (user_id, created_at),
    INDEX idx_activity_logs_username_time (username_snapshot, created_at)
) ENGINE=InnoDB;

-- 4) Enforce: profile updates allowed except username
DELIMITER //
CREATE TRIGGER trg_users_username_immutable
BEFORE UPDATE ON users
FOR EACH ROW
BEGIN
    IF NEW.username <> OLD.username THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Username cannot be changed';
    END IF;
END//
DELIMITER ;
