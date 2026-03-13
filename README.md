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

## Quick Start

1. Copy `docker/.env.example` to `docker/.env`.
2. Set `MYSQL_ROOT_PASSWORD`, `MYSQL_USER`, `MYSQL_PASSWORD`, and `SESSION_SECRET`.
3. Choose an HTTPS port in `APP_PORT`.
4. Set `CSRF_ALLOWED_ORIGIN` to match that exact HTTPS URL.
5. Start the stack with Docker Compose.
6. Open `https://localhost:<APP_PORT>/` in your browser.

Example local URL choices:

- `APP_PORT=8443` -> `https://localhost:8443/`
- `APP_PORT=8080` -> `https://localhost:8080/`

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
- `ENFORCE_HTTPS`
- `GENERATE_SELF_SIGNED_TLS`
- `TLS_CERT_CN`
- `TLS_CERT_SAN`
- `TLS_SELF_SIGNED_DAYS`

Generate a session secret (minimum 32 random characters):

```bash
openssl rand -hex 32
```

If `openssl` is not installed, generate any 64-hex-character random string using another tool and place it in `SESSION_SECRET`.

Recommended local default:

```dotenv
APP_PORT=8443
CSRF_ALLOWED_ORIGIN=https://localhost:8443
TRUSTED_PROXIES=
ENFORCE_HTTPS=1
GENERATE_SELF_SIGNED_TLS=1
TLS_CERT_CN=localhost
TLS_CERT_SAN=DNS:localhost,IP:127.0.0.1,IP:::1
TLS_SELF_SIGNED_DAYS=30
```

If you run using `127.0.0.1`, set:

```dotenv
CSRF_ALLOWED_ORIGIN=https://127.0.0.1:8443
```

If you prefer port `8080`, set:

```dotenv
APP_PORT=8080
CSRF_ALLOWED_ORIGIN=https://localhost:8080
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
docker compose --env-file docker/.env -f docker/docker-compose.yml ps -a
```

Expected:

- `db` is `healthy`
- `setup` is `Exited (0)`
- `app` is `Up`

Open the app:

```bash
echo "https://localhost:$(awk -F= '/^APP_PORT=/{gsub(/\r/, \"\", $2); print $2}' docker/.env | tail -n1)/"
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
APP_PORT_VAL="$(awk -F= '/^APP_PORT=/{gsub(/\r/, \"\", $2); print $2}' docker/.env | tail -n1)"
curl -kisS "https://localhost:${APP_PORT_VAL}/login.php" | sed -n '1,40p'
curl -kisS "https://localhost:${APP_PORT_VAL}/assets/css/style.css" | sed -n '1,20p'
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
APP_PORT_VAL="$(awk -F= '/^APP_PORT=/{gsub(/\r/, \"\", $2); print $2}' docker/.env | tail -n1)"
curl -sk "https://localhost:${APP_PORT_VAL}"
```

Verify schema tables:

```bash
set -a; source <(tr -d '\r' < docker/.env); set +a
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" -e "SHOW TABLES;"
```

Verify seeded users:

```bash
set -a; source <(tr -d '\r' < docker/.env); set +a
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" \
  -e "SELECT username,public_id,email,balance_paise FROM users WHERE username IN ('nishanth','tejas','divyansh','harshavardhan','vrishin','trudy') ORDER BY username;"
```

Verify secure public IDs and unique index:

```bash
set -a; source <(tr -d '\r' < docker/.env); set +a
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

## Automatic Account Creation

Automatic account creation is handled by the Docker bootstrap script:

- Script: `docker/setup.sh`
- Trigger: runs automatically as the `setup` service during `docker compose up`
- Purpose:
  - waits for MySQL to become healthy
  - verifies that the schema exists
  - creates or repairs required supporting structures
  - inserts the assignment seed accounts if they are missing

The seeded accounts currently created by the script are:

- `nishanth`
- `tejas`
- `divyansh`
- `harshavardhan`
- `vrishin`
- `trudy`

You do not need to create these accounts manually when starting from a fresh Docker volume.

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

Local browser warns about the certificate:

The default container boot path generates a self-signed certificate in `docker/certs/`, so browsers will show a trust warning until you replace it with a certificate issued by a CA your machine trusts. For local CLI checks, use `curl -k`.

App redirects unexpectedly or login/CSRF fails:

Make sure `CSRF_ALLOWED_ORIGIN` exactly matches the browser URL, including:

- `https`
- hostname (`localhost` vs `127.0.0.1`)
- port (`8080`, `8443`, etc.)

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

## Resources

The following references were used while implementing and validating the application:

- [PHP manual: password_hash](https://www.php.net/manual/en/function.password-hash.php)
- [PHP manual: password_verify](https://www.php.net/manual/en/function.password-verify.php)
- [PHP manual: random_bytes](https://www.php.net/manual/en/function.random-bytes.php)
- [PHP manual: session_set_cookie_params](https://www.php.net/manual/en/function.session-set-cookie-params.php)
- [PHP manual: PDO prepared statements](https://www.php.net/manual/en/pdo.prepare.php)
- [PHP manual: filter_var](https://www.php.net/manual/en/function.filter-var.php)
- [Apache HTTP Server documentation](https://httpd.apache.org/docs/)
- [Apache mod_ssl documentation](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html)
- [Docker documentation](https://docs.docker.com/)
- [Docker Compose documentation](https://docs.docker.com/compose/)
- [MySQL 8.4 Reference Manual](https://dev.mysql.com/doc/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [MDN Web Docs: HTTP headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

AI assistants were also used as implementation aides during development and review:

- [ChatGPT](https://chat.openai.com/)
- [Claude](https://claude.ai/)
- [Gemini](https://gemini.google.com/)
