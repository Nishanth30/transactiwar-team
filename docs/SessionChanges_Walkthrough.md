# TransactiWar - Session Changes Walkthrough

---

## Context

This walkthrough documents what was implemented in the current session to satisfy the requested Docker + DB bootstrap tasks and improve contributor onboarding.

---

## Requirements to Implementation Mapping

### 1) Define services in compose file, secure by design

Implemented in `docker/docker-compose.yml`:

- `db` service (MySQL 8.4)
- `setup` service (one-shot seed job)
- `app` service (PHP + Apache)

Security-oriented decisions included:

- `no-new-privileges:true` on all services
- DB not exposed via host port
- app exposed only on loopback: `127.0.0.1:${APP_PORT}:80`
- read-only mounts for immutable inputs (`init.sql`, `setup.sh`, app code)
- `setup` service with read-only root FS + `tmpfs`
- internal network for backend traffic isolation

### 2) Add volume for DB persistence

Implemented:

- named volume `mysql_data` mounted at `/var/lib/mysql`

Result:

- DB state persists across container recreation unless `down -v` is used.

### 3) Add auto DB init

Implemented:

- `../database/init.sql` mounted to `/docker-entrypoint-initdb.d/init.sql:ro`

Result:

- schema auto-creates on fresh volume creation.

### 4) Add service dependency

Implemented:

- `setup` depends on `db` being healthy
- `app` depends on `db` healthy
- `app` depends on `setup` completed successfully

Result:

- deterministic startup ordering and no race conditions.

### 5) Verify DB auto-initialization

Executed:

- `docker compose down -v --remove-orphans`
- `docker compose up -d --build`
- setup log checks

Observed in logs:

- MySQL became reachable
- schema detected
- seed completed successfully

### 6) Verify tables

Executed SQL check:

- `SHOW TABLES;`

Observed tables:

- `activity_logs`
- `transactions`
- `users`

### 7) `setup.sh` (auto-create 5+ test accounts)

Implemented in `docker/setup.sh`:

- DB readiness loop using `mysqladmin ping`
- schema readiness loop for `users` table
- direct MySQL CLI insert of 6 test accounts
- `ON DUPLICATE KEY UPDATE` for idempotence
- post-seed verification count check

### 8) Integrate `setup.sh` with Docker

Implemented:

- `setup` compose service with entrypoint `/bin/sh /setup.sh`
- mounted script read-only from repo
- network + env wiring for DB access

---

## Production-Style Reliability Fix Applied During Validation

### Issue discovered

`curl` and browser access to `http://localhost:8080` failed even though app container was running.

### Root cause

`app` had been attached only to `backend`, and `backend` was `internal: true`.

With only an internal network, host port publishing was configured but not actually reachable.

### Fix

Added a second network:

- `frontend` (non-internal)

Attached `app` to both:

- `backend` for DB communication
- `frontend` for host reachability

Result:

- `curl http://127.0.0.1:8080` succeeds
- browser access to `http://localhost:8080` works

---

## Additional Hardening Applied Before Final Commit

### Issue discovered

App container had a broad read-only repo mount (`../:/var/www/html:ro`), which included `docker/.env`.

If app code execution was compromised, attacker could read DB root password from that file.

### Fix

Added file-level override mount in `docker/docker-compose.yml`:

- `./.env.example:/var/www/html/docker/.env:ro`

This keeps app source mount behavior while masking real secrets file path with non-secret example content.

---

## Files Changed

- `docker/docker-compose.yml`
- `docker/setup.sh`
- `README.md`
- `docs/DockerCompose_Walkthrough.md`
- `docs/SetupScript_Walkthrough.md`
- `docs/SessionChanges_Walkthrough.md`

---

## Validation Snapshot

After clean startup:

- `db`: healthy
- `setup`: exited successfully
- `app`: running and reachable on `127.0.0.1:8080`

App response confirmed:

- `PHP running`
- table listing present (with diagnostic mode enabled)

Seed verification confirmed six accounts:

- `test_alice` through `test_frank`

---

## Suggested Contributor Verification Flow

1. `docker compose down -v --remove-orphans`
2. `docker compose up -d --build`
3. `docker compose logs --no-color setup`
4. `curl http://127.0.0.1:8080`
5. SQL checks for tables and test users

This flow is now documented in `README.md` and linked walkthroughs for friction-free onboarding.
