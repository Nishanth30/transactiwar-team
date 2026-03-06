#!/bin/sh
set -eu

require_env() {
  var_name="$1"
  eval "var_value=\${$var_name:-}"
  if [ -z "$var_value" ]; then
    echo "[setup] Missing required env var: $var_name" >&2
    exit 1
  fi
  printf "%s" "$var_value"
}

MYSQL_HOST="$(require_env MYSQL_HOST)"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_DATABASE="$(require_env MYSQL_DATABASE)"
MYSQL_USER="$(require_env MYSQL_USER)"
MYSQL_PASSWORD="$(require_env MYSQL_PASSWORD)"
DB_WAIT_ATTEMPTS="${DB_WAIT_ATTEMPTS:-60}"
DB_WAIT_SLEEP_SECONDS="${DB_WAIT_SLEEP_SECONDS:-2}"

case "$MYSQL_DATABASE" in
  *[!a-zA-Z0-9_]* | "")
    echo "[setup] MYSQL_DATABASE must contain only letters, numbers, and underscores." >&2
    exit 1
    ;;
esac

export MYSQL_PWD="$MYSQL_PASSWORD"

echo "[setup] Waiting for MySQL at ${MYSQL_HOST}:${MYSQL_PORT}..."
attempt=0
until mysqladmin --protocol=tcp --connect-timeout=2 ping \
  -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" --silent >/dev/null 2>&1
do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge "$DB_WAIT_ATTEMPTS" ]; then
    echo "[setup] MySQL did not become ready in time." >&2
    exit 1
  fi
  sleep "$DB_WAIT_SLEEP_SECONDS"
done
echo "[setup] MySQL is reachable."

echo "[setup] Waiting for users table bootstrap..."
attempt=0
until [ "$(mysql --protocol=tcp --connect-timeout=2 -N -s \
  -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" "$MYSQL_DATABASE" \
  -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${MYSQL_DATABASE}' AND table_name='users';" \
  2>/dev/null || true)" = "1" ]
do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge "$DB_WAIT_ATTEMPTS" ]; then
    db_exists="$(mysql --protocol=tcp --connect-timeout=2 -N -s \
      -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" \
      -e "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='${MYSQL_DATABASE}';" \
      2>/dev/null || true)"
    db_exists="$(printf "%s" "$db_exists" | tr -d '[:space:]')"

    if [ "$db_exists" = "1" ]; then
      echo "[setup] users table was not found in database '${MYSQL_DATABASE}' within timeout." >&2
      echo "[setup] Verify database/init.sql is mounted to /docker-entrypoint-initdb.d/init.sql and uses CREATE TABLE statements only." >&2
    else
      echo "[setup] Database '${MYSQL_DATABASE}' does not exist for this initialized MySQL volume." >&2
      echo "[setup] This commonly happens when MYSQL_DATABASE changes after mysql_data was created." >&2
      echo "[setup] Recreate state: docker compose --env-file docker/.env -f docker/docker-compose.yml down -v && docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build" >&2
    fi
    exit 1
  fi
  sleep "$DB_WAIT_SLEEP_SECONDS"
done
echo "[setup] Schema detected; seeding test users."

echo "[setup] Ensuring secure public user IDs are present..."
mysql --protocol=tcp --connect-timeout=5 \
  -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" "$MYSQL_DATABASE" <<'SQL'
SET @has_public_id_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'users'
    AND column_name = 'public_id'
);
SET @add_public_id_col_sql := IF(
  @has_public_id_col = 0,
  'ALTER TABLE users ADD COLUMN public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER id',
  'DO 0'
);
PREPARE stmt_add_col FROM @add_public_id_col_sql;
EXECUTE stmt_add_col;
DEALLOCATE PREPARE stmt_add_col;

UPDATE users
SET public_id = UUID()
WHERE public_id IS NULL OR public_id = '';

SET @has_public_id_idx := (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'users'
    AND index_name = 'uq_users_public_id'
);
SET @add_public_id_idx_sql := IF(
  @has_public_id_idx = 0,
  'ALTER TABLE users ADD CONSTRAINT uq_users_public_id UNIQUE (public_id)',
  'DO 0'
);
PREPARE stmt_add_idx FROM @add_public_id_idx_sql;
EXECUTE stmt_add_idx;
DEALLOCATE PREPARE stmt_add_idx;

ALTER TABLE users
  MODIFY public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT (UUID());

SET @has_login_attempts := (
  SELECT COUNT(*)
  FROM information_schema.tables
  WHERE table_schema = DATABASE()
    AND table_name = 'login_attempts'
);
SET @create_login_attempts_sql := IF(
  @has_login_attempts = 0,
  'CREATE TABLE login_attempts (ip VARCHAR(45) NOT NULL, attempts INT UNSIGNED NOT NULL DEFAULT 0, locked_until INT UNSIGNED NOT NULL DEFAULT 0, last_attempt INT UNSIGNED NOT NULL DEFAULT 0, PRIMARY KEY (ip)) ENGINE=InnoDB',
  'DO 0'
);
PREPARE stmt_login_table FROM @create_login_attempts_sql;
EXECUTE stmt_login_table;
DEALLOCATE PREPARE stmt_login_table;
SQL

mysql --protocol=tcp --connect-timeout=5 \
  -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" "$MYSQL_DATABASE" <<'SQL'
INSERT INTO users (username, email, password_hash, balance_paise, bio)
VALUES
  ('nishanth', 'nishanth@iith.in', '$2y$10$p9hl/NUNL7WTExKoI34aqOfd5Rgv2hUinHSCfolpjjZof.QZOrisu', 10000, 'Seed account for integration checks'),
  ('tejas', 'tejas@iith.in', '$2y$10$miUlmBgo7bFZgnj3Ph22w.AmhEAyIcb.Cw.YcVBlZapBIuUJ0YQd6', 10000, 'Seed account for integration checks'),
  ('divyansh', 'divyansh@iith.in', '$2y$10$ff/5fhtDPygb5U2PhsEGy.FXxct6vPUPi4yJLE3NOxNvSB2tKGqVa', 10000, 'Seed account for integration checks'),
  ('harshavardhan', 'harshavardhan@iith.in', '$2y$10$lLQeJjGDNBfCE/AsDEwFPetpWRt6Ot2bJYE18Bd1LhFMi/ro9EvCe', 10000, 'Seed account for integration checks'),
  ('vrishin', 'vrishin@iith.in', '$2y$10$DoJz/154CEIrIsElX12TcuN7i/tMlfL5XSSO0ag5sjLlFE8RnS6/6', 10000, 'Seed account for integration checks'),
  ('trudy', 'trudy@iith.in', '$2y$10$3l/mqAXHfk6lahCx6Kwq5.lj/DD6mIrOQmVQOpy9RXS8ax90dEOzy', 10000, 'Seed account for integration checks')
ON DUPLICATE KEY UPDATE
  email = VALUES(email),
  password_hash = VALUES(password_hash),
  bio = VALUES(bio),
  updated_at = CURRENT_TIMESTAMP;
SQL

seeded_count="$(mysql --protocol=tcp --connect-timeout=2 -N -s \
  -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" "$MYSQL_DATABASE" \
  -e "SELECT COUNT(*) FROM users WHERE username IN ('nishanth','tejas','divyansh','harshavardhan','vrishin','trudy');")"
seeded_count="$(printf "%s" "$seeded_count" | tr -d '[:space:]')"

if [ "$seeded_count" -lt 6 ]; then
  echo "[setup] Seed verification failed. Expected 6 users, got ${seeded_count}." >&2
  exit 1
fi

echo "[setup] Seeded ${seeded_count} test users successfully."
