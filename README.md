# transactiwar-team

Secure-by-default PHP + MySQL local stack for team development.

## Team ownership

| Member | Role | Core responsibility |
|---|---|---|
| Beaver | Member 1 | Auth and session management |
| Spider | Member 2 | Profile management and file upload |
| Cat | Member 3 | Search and money transfer |
| Dog | Member 4 | Security hardening and cross-cutting |
| Capybara | Member 5 | Infrastructure, Docker and DB |

Detailed role boundaries and interface contracts:

- `docs/INTEROPERABILITY.md`

## Repo map

- `docker/`: Docker build and compose setup
- `database/`: DB bootstrap SQL (`init.sql`)
- `public/`: web root served by Apache (`/var/www/html/public`)
- `includes/`: shared PHP modules
- `storage/`: runtime writable data and logs
- `docs/`: project docs and references

## Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin)

## First-time setup

1. Copy environment template:

```bash
cp docker/.env.example docker/.env
```

1. Edit `docker/.env` and set local values.

Required values:

- `MYSQL_ROOT_PASSWORD`
- `MYSQL_DATABASE`
- `MYSQL_USER`
- `MYSQL_PASSWORD`
- `APP_PORT`
- `APP_DIAGNOSTIC_MODE`

## Start services

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

Web app:

- `http://localhost:${APP_PORT}` (default `http://localhost:8080`)

## Verify app and DB

Default response:

- `PHP running`
- `Diagnostic mode disabled.`

To show DB table names (diagnostic only), set:

```env
APP_DIAGNOSTIC_MODE=1
```

Then run:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d
```

## Access MySQL

Load env vars in your shell:

```bash
set -a; source docker/.env; set +a
```

Connect as app user:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"
```

Connect as root:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec db \
  mysql -uroot -p"$MYSQL_ROOT_PASSWORD"
```

Quick table check:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T db \
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -D "$MYSQL_DATABASE" -e "SHOW TABLES;"
```

## Access containers and logs

App shell:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec app sh
```

DB shell:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml exec db sh
```

Tail logs:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml logs -f app db
```

## Stop services

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down
```

## Reset DB (destructive)

This removes MySQL volume and re-runs `database/init.sql`.

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down -v
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

## Interoperability

- Team contract and change rules are documented in `docs/INTEROPERABILITY.md`.
- Commit `docker/.env.example`; never commit `docker/.env`.

## Common troubleshooting

Access denied for DB user:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml down -v
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
```

Port in use:

- Change `APP_PORT` in `docker/.env` and restart.
