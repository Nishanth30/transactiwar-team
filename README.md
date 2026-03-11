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
- `APP_DIAGNOSTIC_MODE`
- `SESSION_SECRET`

Generate a session secret (minimum 32 random characters):

```bash
openssl rand -hex 32
```

Recommended local default:

```dotenv
APP_PORT=8080
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

## Contributor Rules

- Commit `docker/.env.example`, not `docker/.env`.
- Do not commit private keys or machine-specific secrets.
- Use application DB credentials (`MYSQL_USER`) from code, not root.
- Update documentation in the same PR when contracts or behavior change.
