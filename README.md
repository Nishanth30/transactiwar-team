# transactiwar-team

Secure-by-default local stack for TransactiWar (`PHP + Apache + MySQL + Docker Compose`).

## Quick Start (Friction-Free Onboarding)

Run from project root:

```bash
cd <repo-root>
```

1. Copy env template:

```bash
cp docker/.env.example docker/.env
```

2. Edit `docker/.env` with local values.

Required:

- `MYSQL_ROOT_PASSWORD`
- `MYSQL_DATABASE`
- `MYSQL_USER`
- `MYSQL_PASSWORD`
- `APP_PORT`
- `APP_DIAGNOSTIC_MODE`

3. Start everything:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

Important:

- The first run initializes MySQL users/passwords from your current `docker/.env`.
- If you later change `MYSQL_ROOT_PASSWORD`, `MYSQL_USER`, or `MYSQL_PASSWORD`, reset DB volume once:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down -v
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

4. Confirm service status:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml ps
```

Expected:

- `db` is `healthy`
- `setup` is `Exited (0)`
- `app` is `Up`

5. Open app in browser:

```bash
APP_PORT_VAL="$(awk -F= '/^APP_PORT=/{print $2}' docker/.env | tail -n1)"
echo "http://localhost:${APP_PORT_VAL}"
```

## Startup Pipeline

Startup order is enforced in compose:

- `db` (healthy) -> `setup` (seed users) -> `app`

This removes DB/seed race conditions during onboarding.

## Verification Checklist

1. Check setup service output:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml logs --no-color setup
```

Expected lines include:

- `MySQL is reachable`
- `Schema detected; seeding test users`
- `Ensuring secure public user IDs are present...`
- `Seeded 6 test users successfully`

2. Check app endpoint:

```bash
APP_PORT_VAL="$(awk -F= '/^APP_PORT=/{print $2}' docker/.env | tail -n1)"
curl -s "http://127.0.0.1:${APP_PORT_VAL}"
```

Expected output includes:

- `PHP running`

3. Verify schema tables:

```bash
set -a; source docker/.env; set +a
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" -e "SHOW TABLES;"
```

Expected tables:

- `users`
- `transactions`
- `activity_logs`
- `login_attempts`

4. Verify seeded test users:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" \
  -e "SELECT username,public_id,email,balance_paise FROM users WHERE username LIKE 'test_%' ORDER BY username;"
```

Expected rows:

- `test_alice`, `test_bob`, `test_carol`, `test_dave`, `test_erin`, `test_frank`

5. Verify secure public IDs exist and are unique:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" \
  -e "SHOW INDEX FROM users; SELECT username,public_id FROM users ORDER BY id LIMIT 10;"
```

Expected:

- unique index `uq_users_public_id` is present
- every user row has a non-null UUID-like `public_id`

## DB Persistence Check

To confirm DB persistence works:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" -e "SELECT COUNT(*) FROM users;"
```

If data is still present, named volume persistence is working.

## Day-to-Day Commands

Start services:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d
```

Stop services:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down
```

Tail logs:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml logs -f app db setup
```

Open app container shell:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec app sh
```

Open DB container shell:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec db sh
```

Reset DB (destructive):

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down -v
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

## Common Troubleshooting

App not reachable in browser/curl:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --force-recreate app
docker compose --env-file docker/.env -f docker/docker-compose.yml ps
```

Confirm `app` shows `127.0.0.1:<APP_PORT>->80/tcp` in `PORTS`.

Access denied for DB user after env changes:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down -v
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

Why this happens:

- MySQL credentials from `docker/.env` are applied only when `mysql_data` volume is created.
- Existing volumes keep old credentials until you recreate the volume.

## Walkthrough Docs

- `docs/DockerCompose_Walkthrough.md` - service-by-service compose design and security reasoning
- `docs/SetupScript_Walkthrough.md` - detailed behavior of `docker/setup.sh`
- `docs/SessionChanges_Walkthrough.md` - implementation/verification mapping for this session
- `docs/DBSchema_Walkthrough.md` - database schema rationale
- `docs/IndexPHP_Walkthrough.md` - entrypoint and secure PHP behavior
- `docs/INTEROPERABILITY.md` - team ownership and change contract

## Team Ownership

| Member | Role | Core responsibility |
|---|---|---|
| Beaver | Member 1 | Auth and session management |
| Spider | Member 2 | Profile management and file upload |
| Cat | Member 3 | Search and money transfer |
| Dog | Member 4 | Security hardening and cross-cutting |
| Capybara | Member 5 | Infrastructure, Docker and DB |

## Contributor Rules

- Commit `docker/.env.example`; never commit `docker/.env`.
- App container is intentionally prevented from reading real `docker/.env` (masked with `.env.example`).
- Use app DB user (`MYSQL_USER`) in application code, not root.
- For breaking DB changes, update docs and provide reset instructions in the PR.
