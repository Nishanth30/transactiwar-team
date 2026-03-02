# TransactiWar — Database Schema Walkthrough

---

## Step 0: Database Creation

```sql
CREATE DATABASE IF NOT EXISTS app_database
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;
USE app_database;
```

Before any tables, we set up the database itself with two properties.

**`utf8mb4`** is MySQL's full Unicode encoding. MySQL's older `utf8` is a 3-byte subset and
cannot store emoji or many non-Latin characters. `utf8mb4` is 4-byte and handles the full
Unicode range — important for bio text and comments where users may type anything.

**`utf8mb4_0900_ai_ci`** is the collation — the ruleset MySQL uses to compare and sort
strings. `0900` refers to the Unicode 9.0 standard. `ai` means accent-insensitive (`e` and
`é` are treated as equal). `ci` means case-insensitive (`Alice` and `alice` are equal). This
is the modern default and a sensible choice for general text.

---

## Step 1: The `users` Table

```sql
CREATE TABLE users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT (UUID()),
    ...
) ENGINE=InnoDB;
```

### Primary Key

```sql
id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY
```

`INT UNSIGNED` ranges from 0 to 4,294,967,295. The `UNSIGNED` matters — plain `INT` is
signed and would allow negative IDs, which are nonsensical for an auto-incremented surrogate
key. `AUTO_INCREMENT` means MySQL assigns the next available integer on each insert; you
never set this manually.

### Public ID (Opaque External Identifier)

```sql
public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT (UUID())
```

This field is the externally exposed identifier for user search and transfer. It is UUID-based
and non-sequential, which prevents trivial enumeration attacks against user records. The
internal numeric `id` remains the primary key for joins and FK performance; `public_id` is
used at API/UI boundaries.

### Username and Email

```sql
username VARCHAR(32) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
email    VARCHAR(254) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
```

Both fields override the database-level `utf8mb4` with `ascii`. This is intentional.
Usernames and emails only ever contain standard ASCII characters (letters, digits, `@`, `.`,
`-`, `_`). Restricting the column to ASCII means any non-ASCII byte — including Cyrillic or
Greek characters that look visually identical to Latin ones — is rejected at the column level.
This blocks Unicode homograph attacks where an attacker registers `аdmin` (Cyrillic `а`)
to impersonate `admin`.

`VARCHAR(254)` for email is the RFC 5321 maximum. The common shortcut of `VARCHAR(100)`
silently truncates valid addresses. `VARCHAR(32)` for username is a reasonable practical cap.

`ascii_general_ci` is case-insensitive, so `Alice` and `alice` are treated as the same
username — which is the expected behaviour for a login system.

### Password

```sql
password_hash VARCHAR(255) NOT NULL,
```

Passwords are never stored in plain text. This column stores the output of a hashing function
(bcrypt, Argon2, etc.). `VARCHAR(255)` is wide enough for any modern hash format including
the `$2y$...` bcrypt format (60 chars) and Argon2id hashes. The column is `NOT NULL` — an
account without a password hash must never exist.

### Balance

```sql
balance_paise BIGINT UNSIGNED NOT NULL DEFAULT 10000,  -- Rs.100.00
```

Balance is stored in **paise** (1 rupee = 100 paise), so `10000` paise = Rs.100.00. This is
deliberate — integer arithmetic is exact, whereas `DECIMAL` arithmetic requires careful
handling of rounding rules that are easy to get wrong in application code. `BIGINT UNSIGNED`
ensures the value can never be negative at the type level, even before the `CHECK` constraint
fires.

`DEFAULT 10000` satisfies the spec requirement that every new user starts with Rs.100.

### Profile Fields

```sql
bio                TEXT NULL,
profile_image_path VARCHAR(512) NULL,
```

`bio` is `TEXT` — this is MySQL's variable-length large-text type, suitable for long
biographies with no practical length limit for this use case. `NULL` means the field is
optional; a user who hasn't written a bio simply has `NULL` here rather than an empty string.

`profile_image_path` stores a file path, object storage key, or URL — not the image data
itself. Storing binary image data in the database is an anti-pattern: it bloats the DB,
makes backups slow, and defeats caching. `VARCHAR(512)` is wide enough for long cloud storage
URLs.

### Timestamps

```sql
created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
```

`created_at` is set once on insert and never changes. `updated_at` is set on insert and
automatically updated by MySQL whenever any field in the row changes — no application code
required. Both are `NOT NULL`; a row without timestamps is an anomaly.

### Constraints

```sql
CONSTRAINT uq_users_public_id UNIQUE (public_id),
CONSTRAINT uq_users_username UNIQUE (username),
CONSTRAINT uq_users_email    UNIQUE (email),
CONSTRAINT chk_users_balance_nonnegative CHECK (balance_paise >= 0),
CONSTRAINT chk_users_public_id_uuid_format CHECK (
  public_id REGEXP '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)
```

The `UNIQUE` constraints ensure no two users share `public_id`, `username`, or `email`.
MySQL automatically creates indexes for these constraints, so they also serve as fast lookup
indexes for login and external-id operations.

The `CHECK` constraint is the database-level guarantee that a balance can never go below zero.
Application code checks balance before a transfer, but the `CHECK` is the backstop — even if
a bug in the PHP logic attempts to push the balance negative, MySQL will reject the `UPDATE`
outright.

---

## Step 2: The `transactions` Table

```sql
CREATE TABLE transactions (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sender_id    INT UNSIGNED NOT NULL,
    receiver_id  INT UNSIGNED NOT NULL,
    amount_paise BIGINT UNSIGNED NOT NULL,
    receiver_comment VARCHAR(500) NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ...
) ENGINE=InnoDB;
```

### Foreign Keys

```sql
CONSTRAINT fk_transactions_sender
  FOREIGN KEY (sender_id) REFERENCES users(id)
  ON UPDATE RESTRICT ON DELETE RESTRICT,
CONSTRAINT fk_transactions_receiver
  FOREIGN KEY (receiver_id) REFERENCES users(id)
  ON UPDATE RESTRICT ON DELETE RESTRICT,
```

Both `sender_id` and `receiver_id` reference `users(id)`. `RESTRICT` on both update and
delete means:

- You cannot delete a user who has any transaction record. Financial history is permanent.
- You cannot change a user's primary key while transactions reference it (moot since `id` is
  auto-incremented and never updated, but explicit is safer).

`CASCADE` was not used here. Deleting a user and silently wiping their entire transaction
history is not acceptable for a financial application.

### Validation Constraints

```sql
CONSTRAINT chk_transactions_amount_min_1_rupee CHECK (amount_paise >= 100),
CONSTRAINT chk_transactions_not_self        CHECK (sender_id <> receiver_id),
```

`amount_paise >= 100` enforces a minimum transfer of Rs.1.00. Since `amount_paise` is
stored in paise, `100` means 1 rupee exactly.

`sender_id <> receiver_id` blocks self-transfers. Without this, a user could send money to
themselves, which is semantically meaningless and could be used to game transaction history
displays.

### Indexes

```sql
INDEX idx_transactions_sender_time   (sender_id,   created_at),
INDEX idx_transactions_receiver_time (receiver_id, created_at)
```

The most common query is "show all transactions for user X, newest first." A compound index
on `(user_id, created_at)` lets MySQL seek directly to that user's rows and read them in
time order — no full table scan, no separate sort. Two indexes are needed because a user
appears as either sender or receiver, and a single index cannot efficiently serve both queries
simultaneously.

### Why No `updated_at` Here?

Transactions are immutable records. A transfer that happened is a fact — it should never be
edited. There is no `updated_at` because there should never be an update to a transaction row.

---

## Step 3: The `activity_logs` Table

```sql
CREATE TABLE activity_logs (
    id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id           INT UNSIGNED NULL,
    username_snapshot VARCHAR(32) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
    webpage           VARCHAR(255) NOT NULL,
    client_ip         VARCHAR(45)  NOT NULL,
    created_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ...
) ENGINE=InnoDB;
```

This table is the most nuanced of the three.

### Nullable `user_id`

```sql
user_id INT UNSIGNED NULL,  -- NULL for unauthenticated events
```

`user_id` is nullable. This is intentional — it allows logging events that happen before a
user authenticates: failed login attempts, access to protected pages by unauthenticated
visitors, or probing of the registration endpoint. These pre-authentication events are often
the most security-relevant. `NULL` here means "no authenticated user was associated with this
request."

### `username_snapshot`

```sql
username_snapshot VARCHAR(32) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
```

This is a literal copy of the username at the time the log row was written. It answers the
forensic question: if a user account is later deleted (setting `user_id` to `NULL`), the log
row still contains an identity. Without this, deleted-user log rows become permanently
anonymous. With it, you can still reconstruct "user `alice` visited `/transfer` at 14:32 from
10.0.0.5" long after the `alice` account is gone.

It also means the username lookup does not require a join — the data is already in the row.

### FK with `SET NULL`

```sql
CONSTRAINT fk_activity_logs_user
  FOREIGN KEY (user_id) REFERENCES users(id)
  ON UPDATE RESTRICT ON DELETE SET NULL,
```

`ON DELETE SET NULL` is the key difference from the transactions table. When a user is
deleted:

- In `transactions`: deletion is **blocked** (`RESTRICT`) — financial records are permanent.
- In `activity_logs`: deletion is **allowed**, and `user_id` is set to `NULL` — the log rows
  survive without referencing the now-deleted user.

This distinction reflects the different nature of the two tables. Financial records have legal
permanence. Activity logs are an audit trail that should survive account deletion, but do not
need to block it.

### `client_ip VARCHAR(45)`

```sql
client_ip VARCHAR(45) NOT NULL,
```

`VARCHAR(45)` is wide enough for both IPv4 (`255.255.255.255` — 15 chars) and IPv6
(`2001:0db8:85a3:0000:0000:8a2e:0370:7334` — 39 chars), including the longest possible IPv6
representation. `NOT NULL` because an IP address is always available from the HTTP connection;
there is no legitimate reason for it to be absent.

### Indexes

```sql
INDEX idx_activity_logs_user_time     (user_id,           created_at),
INDEX idx_activity_logs_username_time (username_snapshot, created_at)
```

Two compound indexes serve two different query patterns:

- "Show all activity for user ID X" — served by `(user_id, created_at)`
- "Show all activity by username `alice`" — served by `(username_snapshot, created_at)`,
  useful when querying by name after the user account is deleted and `user_id` is NULL

---

## Step 4: The Username Immutability Trigger

```sql
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
```

### What it does

This trigger fires **before** any `UPDATE` on the `users` table, for each row being updated.
`NEW.username` is the value being written; `OLD.username` is the current value. If they
differ, the trigger raises a SQL error (`SQLSTATE '45000'` is the generic user-defined error
state) and aborts the update entirely. The row is not changed.

### Why a trigger and not just PHP

The spec says users can update any profile field except their username. PHP code can enforce
this by never including `username` in the `UPDATE` query. But:

1. A second developer adds a new profile endpoint and forgets to exclude `username`.
2. A direct SQL call during debugging accidentally updates it.
3. Any bug in the PHP logic lets it slip through.

In all three cases, the trigger catches it. The rule is enforced unconditionally at the
database layer, not just in whatever PHP path happens to run.

### Why it matters beyond just the spec

The `username_snapshot` column in `activity_logs` depends on usernames being stable. A
snapshot taken when a user logs in at 9am would misidentify the user if they renamed
themselves at 10am. The trigger ensures this can never happen — usernames are immutable from
the moment of registration, so every snapshot in the log is permanently accurate.

### `DELIMITER //`

MySQL's command-line client uses `;` to detect the end of a statement. A trigger body
contains `;` characters internally (after `SIGNAL` and `END`), which would confuse the
parser. `DELIMITER //` temporarily changes the statement terminator to `//` so the entire
trigger body is sent as one unit. After the trigger is created, `DELIMITER ;` restores
normal behaviour. This is only needed in scripts and the CLI; application code using prepared
statements is unaffected.

---

## Step 5: The `login_attempts` Table

```sql
CREATE TABLE login_attempts (
    ip           VARCHAR(45)  NOT NULL,
    attempts     INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until INT UNSIGNED NOT NULL DEFAULT 0,
    last_attempt INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (ip)
) ENGINE=InnoDB;
```

This table backs IP-based login throttling. It stores attempt counters and lockout windows
per source IP so brute-force retries cannot be reset by clearing browser cookies or starting
new sessions.

---

## Summary: What Each Table Is Responsible For

| Table | Responsibility | Key Design Choice |
|---|---|---|
| `users` | Identity, credentials, balance | Dual-ID model (`id` internal + UUID `public_id` external), paise integer, ASCII collation |
| `transactions` | Financial history | RESTRICT FKs, immutable rows, compound indexes |
| `activity_logs` | Audit trail | Nullable user_id, username_snapshot, SET NULL FK |
| `login_attempts` | Brute-force control state | IP-keyed lockout counters for auth throttling |
| Trigger | Username immutability | DB-level rule, protects snapshot accuracy |
