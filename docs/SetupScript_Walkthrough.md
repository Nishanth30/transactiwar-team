# TransactiWar - Setup Script Walkthrough

---

## Purpose

`docker/setup.sh` is a one-shot bootstrap script executed by the `setup` service.

Its job is to:

1. Wait for MySQL to become reachable
2. Wait for schema bootstrap (`users` table) to exist
3. Ensure secure external user IDs (`users.public_id`) exist and are constrained
4. Insert 6 deterministic test accounts with hashed passwords
5. Verify seed success and fail fast if anything is wrong

This script is idempotent and safe to run multiple times.

---

## Execution Context

The script runs inside the `setup` container with:

- `read_only: true`
- `tmpfs: /tmp`
- `no-new-privileges:true`
- only private `backend` network access

It uses MySQL CLI tools from `mysql:8.4` image.

---

## Step-by-Step Behavior

### 1) Validate Required Environment

The script enforces presence of:

- `MYSQL_HOST`
- `MYSQL_DATABASE`
- `MYSQL_USER`
- `MYSQL_PASSWORD`

If any are missing, it exits immediately with a clear error.

### 2) Basic Identifier Guard

`MYSQL_DATABASE` is restricted to letters, numbers, and underscore.

This prevents malformed DB names from being injected into the schema existence query.

### 3) Handle Password Securely for CLI Calls

The script exports:

```sh
MYSQL_PWD="$MYSQL_PASSWORD"
```

Then uses `mysql`/`mysqladmin` without `-p...` in command arguments.

This avoids exposing DB passwords in process command-line arguments.

### 4) Wait for MySQL Readiness

It loops on:

```sh
mysqladmin --protocol=tcp ping ... --silent
```

with bounded retries controlled by:

- `DB_WAIT_ATTEMPTS` (default `60`)
- `DB_WAIT_SLEEP_SECONDS` (default `2`)

If readiness never arrives, script exits non-zero.

### 5) Wait for `users` Table

After server readiness, schema might still be unavailable on fresh volume initialization.

The script polls `information_schema.tables` until:

- table `users` exists in `${MYSQL_DATABASE}`

This guarantees inserts happen only after `init.sql` has completed.
If timeout is reached, the script emits targeted diagnostics:

- DB missing: likely `MYSQL_DATABASE` changed after volume creation (requires `down -v`)
- DB exists but no `users` table: schema bootstrap (`init.sql`) was not applied correctly

### 6) Seed Test Users (Idempotent)

The script inserts 6 users into `users` with precomputed bcrypt hashes:

- `test_alice`
- `test_bob`
- `test_carol`
- `test_dave`
- `test_erin`
- `test_frank`

It uses:

```sql
ON DUPLICATE KEY UPDATE
```

so reruns do not fail and keep records synchronized.

### 6.5) Secure ID Migration Guard (Self-Improving)

Before seeding, the script performs safe in-place schema hardening for older DB volumes:

- Adds `users.public_id` if missing
- Backfills existing rows with `UUID()`
- Adds `UNIQUE` constraint `uq_users_public_id`
- Forces `public_id` to `NOT NULL DEFAULT (UUID())`
- Creates `login_attempts` if missing (required by auth rate limiting)

This keeps old contributor volumes compatible without requiring `down -v`.

### 7) Verify Post-Condition

It checks count of seeded usernames and requires at least 6.

If count is lower, it exits non-zero so Compose marks setup as failed.

---

## Test Account Credentials (Local Dev)

These passwords were used to generate the stored bcrypt hashes:

| Username | Password |
|---|---|
| `test_alice` | `TwaTest!2026#1` |
| `test_bob` | `TwaTest!2026#2` |
| `test_carol` | `TwaTest!2026#3` |
| `test_dave` | `TwaTest!2026#4` |
| `test_erin` | `TwaTest!2026#5` |
| `test_frank` | `TwaTest!2026#6` |

These are for local development only. Do not reuse in shared/production environments.

---

## Why This Improves Onboarding

Without this script, every contributor must manually seed test users.

With this script:

- first-time setup is fully automatic
- data seed is deterministic across machines
- app startup happens only after seeding success
- failures are explicit and visible in `setup` logs

---

## Verification Commands

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml logs --no-color setup
```

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" \
  -e "SELECT username,public_id,email,balance_paise FROM users WHERE username LIKE 'test_%' ORDER BY username;"
```
