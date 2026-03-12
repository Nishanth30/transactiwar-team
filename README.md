# transactiwar-team

TransactiWar assignment project (`PHP + Apache + MySQL + Docker Compose`).

## Project Scope

This repository is focused on the assignment application itself:

- authentication and session management
- profile and image upload
- user search
- transfers and transaction history
- security controls (CSRF, validation, prepared statements, safe output)

## Documentation Map

- Contributor workflow: `docs/CONTRIBUTOR_GUIDE.md`
- Team ownership and module contracts: `docs/INTEROPERABILITY.md`
- Branching workflow: `docs/BRANCHING_AND_DEPLOYMENT.md`
- Docker architecture walkthrough: `docs/DockerCompose_Walkthrough.md`

## Prerequisites

- Docker and Docker Compose
- Git

## Environment Setup

Create `docker/.env` from the tracked template:

```bash
cp docker/.env.example docker/.env
```

Required values in `docker/.env`:

- `MYSQL_ROOT_PASSWORD`
- `MYSQL_DATABASE`
- `MYSQL_USER`
- `MYSQL_PASSWORD`
- `APP_PORT`
- `CSRF_ALLOWED_ORIGIN`
- `APP_DIAGNOSTIC_MODE`
- `SESSION_SECRET`
- `TRUSTED_PROXIES` (optional, comma-separated proxy IPs allowed to set `X-Forwarded-Proto`)

Generate a session secret (minimum 32 random characters):

```bash
openssl rand -hex 32
```

Recommended local default:

```dotenv
APP_PORT=8080
CSRF_ALLOWED_ORIGIN=http://localhost:8080
TRUSTED_PROXIES=
```

If you run using `127.0.0.1`, set:

```dotenv
CSRF_ALLOWED_ORIGIN=http://127.0.0.1:8080
```

Use your real HTTPS origin in production (for example `https://app.example.com`).
If TLS is terminated at a reverse proxy, set `TRUSTED_PROXIES` to the proxy IP(s), for example:

```dotenv
TRUSTED_PROXIES=172.20.0.10,172.20.0.11
```

## Start the Project

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

Check status:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml ps
```

Expected:

- `db` is `healthy`
- `setup` exits successfully
- `app` is `Up`

Open the app:

```bash
echo "http://127.0.0.1:$(awk -F= '/^APP_PORT=/{print $2}' docker/.env | tail -n1)/"
```

## Smoke Test

After startup, verify core flows manually:

1. register
2. login
3. view/edit profile
4. upload avatar
5. search users
6. transfer funds
7. check transaction history
8. logout

Useful checks:

```bash
curl -kisS http://127.0.0.1:8080/login.php | sed -n '1,40p'
curl -kisS http://127.0.0.1:8080/assets/css/style.css | sed -n '1,20p'
```

## Verification Checklist

Check setup service output:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml logs --no-color setup
```

Expected lines include:

- `MySQL is reachable`
- `Schema detected; seeding test users`
- `Ensuring secure public user IDs are present...`
- `Seeded 6 test users successfully`

Check app endpoint:

```bash
APP_PORT_VAL="$(awk -F= '/^APP_PORT=/{print $2}' docker/.env | tail -n1)"
curl -s "http://127.0.0.1:${APP_PORT_VAL}"
```

Verify schema tables:

```bash
set -a; source docker/.env; set +a
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" -e "SHOW TABLES;"
```

Verify seeded test users:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" \
  -e "SELECT username,public_id,email,balance_paise FROM users WHERE username LIKE 'test_%' ORDER BY username;"
```

Verify secure public IDs and unique index:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" \
  -e "SHOW INDEX FROM users; SELECT username,public_id FROM users ORDER BY id LIMIT 10;"
```

## Database Notes

Startup order is enforced by compose:

- `db (healthy) -> setup (seed) -> app`

If DB credentials or DB name change after first run, recreate volumes:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down -v
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

The setup job ensures:

- schema exists
- `public_id` values exist and are unique
- `login_attempts` exists
- assignment seed users are present

## Useful Commands

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

Open app shell:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec app sh
```

Open DB shell:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec db sh
```

DB persistence check:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" -e "SELECT COUNT(*) FROM users;"
```

## Common Troubleshooting

App not reachable:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --force-recreate app
docker compose --env-file docker/.env -f docker/docker-compose.yml ps
```

Access denied for DB user after env changes:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down -v
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

`setup` exits with `users table was not found`:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml logs --no-color setup
docker compose --env-file docker/.env -f docker/docker-compose.yml down -v
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

## Contributor Rules

- Commit `docker/.env.example`, not `docker/.env`.
- Do not commit private keys or machine-specific secrets.
- Use application DB credentials (`MYSQL_USER`) from code, not root.
- Update documentation in the same PR when contracts or behavior change.
