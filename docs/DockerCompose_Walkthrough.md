# TransactiWar - Docker Compose Walkthrough

---

## Top-Level Structure

The compose file now defines three services and two networks:

- `db`: MySQL 8.4 with persistent storage and schema auto-init
- `setup`: one-shot initializer that waits for DB readiness and seeds test users
- `app`: PHP + Apache web app

It also defines:

- named volume: `mysql_data`
- internal network: `backend` (private service-to-service traffic)
- normal network: `frontend` (required so host port publishing actually works)

The final startup flow is:

`db (healthy) -> setup (success) -> app (start)`

---

## The `db` Service (MySQL)

### Image and Core Runtime

```yaml
image: mysql:8.4
restart: unless-stopped
init: true
```

- `mysql:8.4` pins the major version.
- `unless-stopped` auto-recovers after reboot/crash.
- `init: true` provides a tiny init process to reap zombies and forward signals correctly.

### Hardened Startup Flags

```yaml
command: ["mysqld", "--local-infile=0", "--skip-name-resolve"]
```

- `--local-infile=0`: disables `LOAD DATA LOCAL INFILE`.
- `--skip-name-resolve`: avoids DNS/reverse-DNS dependency and connection delays.

### Least-Privilege Runtime Setting

```yaml
security_opt:
  - no-new-privileges:true
```

Prevents privilege escalation by child processes inside the container.

### Environment Variables

```yaml
environment:
  MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD:?Set MYSQL_ROOT_PASSWORD in docker/.env}
  MYSQL_DATABASE: ${MYSQL_DATABASE:-app_database}
  MYSQL_USER: ${MYSQL_USER:?Set MYSQL_USER in docker/.env}
  MYSQL_PASSWORD: ${MYSQL_PASSWORD:?Set MYSQL_PASSWORD in docker/.env}
```

- `:?` fails fast if required secret env vars are missing.
- `:-app_database` provides a safe non-secret default.

### Volume Mounts

```yaml
volumes:
  - mysql_data:/var/lib/mysql
  - ../database/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
```

- `mysql_data` persists DB files across container recreation.
- `init.sql` is auto-executed only when the data directory is empty.
- `:ro` protects host SQL file from container-side modification.
- `init.sql` must be database-agnostic: no `CREATE DATABASE` and no `USE`.
  Docker chooses the active DB from `MYSQL_DATABASE` and runs init there.

### Health Check

```yaml
healthcheck:
  test:
    ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -uroot -p\"$${MYSQL_ROOT_PASSWORD}\" --silent"]
  interval: 5s
  timeout: 3s
  retries: 20
```

This confirms MySQL is accepting connections, not just that the process exists.

### Network Placement

```yaml
networks:
  - backend
```

`db` is only on the private internal network. No host `ports` mapping is defined.

---

## The `setup` Service (One-Shot Seeder)

### Why This Service Exists

The MySQL image can create schema from `init.sql`, but team onboarding also needs deterministic test users. The `setup` service does that safely and automatically.

### Runtime Shape

```yaml
image: mysql:8.4
restart: "no"
init: true
read_only: true
tmpfs:
  - /tmp
security_opt:
  - no-new-privileges:true
```

Security choices:

- `restart: "no"`: one-shot job, not long-running.
- `read_only: true`: immutable container filesystem.
- `tmpfs: /tmp`: writable temp area without persistent disk writes.
- `no-new-privileges:true`: same hardening as other services.

### Dependency + Entry Point

```yaml
depends_on:
  db:
    condition: service_healthy
entrypoint: ["/bin/sh", "/setup.sh"]
volumes:
  - ./setup.sh:/setup.sh:ro
```

It runs only after `db` is healthy and executes a repo-owned script mounted read-only.

### Network Placement

```yaml
networks:
  - backend
```

`setup` reaches MySQL privately and has no host exposure.

---

## The `app` Service (PHP + Apache)

### Build + Runtime

```yaml
build:
  context: ..
  dockerfile: docker/Dockerfile
restart: unless-stopped
init: true
security_opt:
  - no-new-privileges:true
```

### Startup Dependencies

```yaml
depends_on:
  db:
    condition: service_healthy
  setup:
    condition: service_completed_successfully
```

This prevents race conditions:

- app does not start before DB is ready
- app does not start before seed users are inserted

### Port Mapping

```yaml
ports:
  - "127.0.0.1:${APP_PORT:-8080}:80"
```

The app is reachable only from local machine (loopback), not from all interfaces.

### Code + Data Mounts

```yaml
volumes:
  - ../:/var/www/html:ro
  - ./.env.example:/var/www/html/docker/.env:ro
  - ../public/uploads:/var/www/html/public/uploads
  - ../storage:/var/www/html/storage
```

- project code is read-only
- only uploads/storage are writable
- real `docker/.env` secrets are masked inside app container by mounting `docker/.env.example` at `/var/www/html/docker/.env`

### Network Placement (Important)

```yaml
networks:
  - backend
  - frontend
```

- `backend`: app-to-db traffic
- `frontend`: enables host port publishing

If app is only on an `internal: true` network, published ports can appear configured but still fail from browser/curl. Attaching `app` to `frontend` resolves this while keeping DB isolated.

---

## Network Design

```yaml
networks:
  backend:
    internal: true
  frontend:
```

- `backend` blocks external routing and keeps DB/setup traffic private.
- `frontend` allows only app's explicit loopback-published port to be reachable.

---

## Named Volume

```yaml
volumes:
  mysql_data:
```

Persistent DB storage survives `docker compose down` and container recreation.
Use `docker compose down -v` only when intentionally resetting DB state.
If `MYSQL_DATABASE` is changed after first boot, run `down -v` once so MySQL
can reinitialize the target database cleanly.

---

## Security and Reliability Summary

| Concern | Control in Compose |
|---|---|
| DB data persistence | Named volume `mysql_data` |
| Schema auto-init | `init.sql` mounted under `docker-entrypoint-initdb.d` |
| Deterministic seed users | One-shot `setup` service + `setup.sh` |
| Startup race prevention | Health-based + completion-based `depends_on` |
| DB isolation | No DB ports + `backend` internal network |
| App host exposure scope | `127.0.0.1:${APP_PORT}:80` only |
| Runtime privilege control | `no-new-privileges:true` on all services |
| Writable filesystem minimization | Read-only `setup` + read-only app code mount |
| App-side secret file exposure reduced | `docker/.env` path in app container is overridden with `.env.example` |
| Signal/zombie handling | `init: true` on long-running and one-shot services |
