# TransactiWar — Docker Compose Walkthrough

---

## Top-Level Structure

The file defines two services (`db` and `app`) and one named volume (`mysql_data`). The
services communicate over Docker's default bridge network that Compose creates automatically
— `db` is reachable from `app` at the hostname `db`, but is not reachable from the host
machine or the internet because it has no `ports` mapping.

---

## The `db` Service (MySQL)

### Image and Restart Policy

```yaml
image: mysql:8.4
restart: unless-stopped
```

`mysql:8.4` pins to a specific major version. This avoids surprise upgrades if the image is
pulled again later. `unless-stopped` means the container restarts automatically after a crash
or a host reboot, but stays stopped if you explicitly ran `docker compose stop`.

### Hardened Startup Flags

```yaml
command: ["mysqld", "--local-infile=0", "--skip-name-resolve"]
```

These two flags override MySQL's defaults at startup.

`--local-infile=0` disables the `LOAD DATA LOCAL INFILE` command. This command allows
reading arbitrary files from the client's filesystem and has a long history of being
exploited when enabled. Disabling it at the server level means no connection can enable it,
regardless of user privileges.

`--skip-name-resolve` tells MySQL to skip reverse DNS lookups when a client connects. By
default MySQL resolves client hostnames, which adds latency and can fail silently in
environments without reliable DNS. With this flag, MySQL uses IP addresses only — faster and
more predictable inside Docker.

### No New Privileges

```yaml
security_opt:
  - no-new-privileges:true
```

This Linux security option prevents the MySQL process and any child processes from gaining
privileges beyond what the container started with — even if a binary inside the container has
the `setuid` bit set. It limits the blast radius if the container is somehow compromised.
Applied to both services.

### Environment Variables

```yaml
environment:
  MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD:?Set MYSQL_ROOT_PASSWORD in docker/.env}
  MYSQL_DATABASE:      ${MYSQL_DATABASE:-app_database}
  MYSQL_USER:          ${MYSQL_USER:?Set MYSQL_USER in docker/.env}
  MYSQL_PASSWORD:      ${MYSQL_PASSWORD:?Set MYSQL_PASSWORD in docker/.env}
```

Two syntax patterns are in use here:

`:?message` — if the variable is unset or empty, Docker Compose **aborts immediately** and
prints the message. This is used for `MYSQL_ROOT_PASSWORD`, `MYSQL_USER`, and
`MYSQL_PASSWORD` — secrets that must never have a default value baked into the file.

`:-default` — if the variable is unset, use the default. This is used for `MYSQL_DATABASE`
where `app_database` is a safe, non-secret fallback.

This pattern means you can never accidentally start the stack with a blank root password —
the compose command fails fast and tells you exactly what to set and where.

### Volumes

```yaml
volumes:
  - mysql_data:/var/lib/mysql
  - ../database/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
```

`mysql_data` is a named Docker volume (defined at the bottom of the file). MySQL stores its
data files at `/var/lib/mysql` inside the container. Mounting a named volume here means data
persists across container restarts and rebuilds — without it, the database would be wiped
every time the container stopped.

`init.sql` is mounted into `/docker-entrypoint-initdb.d/`. The official MySQL Docker image
automatically runs any `.sql` files in that directory on first startup (when the data
directory is empty). This is how the schema is created without any manual steps. The `:ro`
flag means the container can read the file but cannot modify it — your schema file on the
host stays untouched.

### Health Check

```yaml
healthcheck:
  test:
    [
      "CMD-SHELL",
      "mysqladmin ping -h 127.0.0.1 -uroot -p\"$${MYSQL_ROOT_PASSWORD}\" --silent",
    ]
  interval: 5s
  timeout: 3s
  retries: 20
```

`mysqladmin ping` asks the MySQL server if it is ready to accept connections. This is a
stronger check than just "is the process running?" — MySQL takes several seconds to
initialise its data directory on first start, and a process check would incorrectly report
healthy during that window.

`$$` is Docker Compose's escape for a literal `$` — without it, Compose would try to
interpolate `${MYSQL_ROOT_PASSWORD}` at parse time rather than letting the shell inside the
container expand it at runtime.

`interval: 5s` — check every 5 seconds. `timeout: 3s` — if the command doesn't finish in
3 seconds, count it as a failure. `retries: 20` — allow up to 20 consecutive failures (100
seconds total) before marking the container as unhealthy. This is generous because the first
start includes schema initialisation, which takes longer than subsequent starts.

---

## The `app` Service (PHP + Apache)

### Build

```yaml
build:
  context: ..
  dockerfile: docker/Dockerfile
```

Instead of pulling a pre-built image, Compose builds one from `docker/Dockerfile`. The build
context is the parent directory (`..`) — meaning the Dockerfile can `COPY` any file from the
project root. The Dockerfile itself lives inside the `docker/` subdirectory to keep project
structure clean.

### Depends On with Health Condition

```yaml
depends_on:
  db:
    condition: service_healthy
```

The `app` container will not start until the `db` container passes its health check. Without
this, the app would start immediately and crash because MySQL isn't ready yet. `service_healthy`
is stronger than the default `service_started` — it waits for the health check to pass, not
just for the container process to exist.

### Port Binding

```yaml
ports:
  - "127.0.0.1:${APP_PORT:-8080}:80"
```

This binds port 80 inside the container to port 8080 (or whatever `APP_PORT` is set to) on
the host — but **only on the loopback interface** (`127.0.0.1`). This is the critical
difference from `0.0.0.0:8080:80`. With `0.0.0.0`, the port is exposed on every network
interface, including the public one — anyone on the internet could reach it directly. With
`127.0.0.1`, only processes on the same machine (like a reverse proxy such as nginx) can
reach it.

The `db` service has no `ports` mapping at all, so MySQL is completely unreachable from
outside Docker. Only the `app` container can talk to it.

### Environment Variables

```yaml
environment:
  MYSQL_HOST:          db
  MYSQL_USER:          ${MYSQL_USER:?Set MYSQL_USER in docker/.env}
  MYSQL_PASSWORD:      ${MYSQL_PASSWORD:?Set MYSQL_PASSWORD in docker/.env}
  MYSQL_DATABASE:      ${MYSQL_DATABASE:-app_database}
  APP_DIAGNOSTIC_MODE: ${APP_DIAGNOSTIC_MODE:-0}
```

`MYSQL_HOST: db` — inside Docker's network, the `db` container is reachable at the hostname
`db` (the service name). Your PHP code uses this hostname when opening a database connection.

The database credentials use the same `:?` pattern as the `db` service — they must match,
and both fail loudly if unset.

`APP_DIAGNOSTIC_MODE` defaults to `0` (off). This is a safety net: detailed error output is
useful in development but leaks internal structure to attackers in production. By defaulting
to off and requiring an explicit opt-in, you avoid accidentally shipping a diagnostic-enabled
deployment.

### Volumes

```yaml
volumes:
  - ../:/var/www/html:ro
  - ../public/uploads:/var/www/html/public/uploads
  - ../storage:/var/www/html/storage
```

The entire project codebase is mounted read-only (`ro`) into the web root. The container
cannot modify your source files, configuration, or SQL schema — even if PHP code is somehow
exploited to write files.

The two subsequent mounts override specific subdirectories with read-write mounts:

`public/uploads` — where uploaded profile images are saved. The app must be able to write
here.

`storage` — where application-level files (logs, temporary data, etc.) are written.

Docker evaluates volume mounts in order and more specific paths take precedence, so these two
directories are effectively carved out of the read-only mount and given write access. Only
these two directories on your host filesystem can be modified from inside the container.

---

## The Named Volume

```yaml
volumes:
  mysql_data:
```

Declaring `mysql_data` here registers it as a Docker-managed named volume. Docker stores it
in its own managed location on the host (not as a directory you can easily browse). Named
volumes persist independently of the container lifecycle — you can `docker compose down` and
bring everything back up, and the database will still have all its data. To wipe the database
and start fresh, you must explicitly run `docker compose down -v`.

---

## Summary

| Concern | How It Is Handled |
|---|---|
| Secrets never have defaults | `:?` syntax aborts on missing vars |
| App waits for DB to be ready | `condition: service_healthy` |
| DB unreachable from outside | No `ports` mapping on `db` |
| App not exposed to internet | Port bound to `127.0.0.1` only |
| Source code cannot be modified | Codebase mounted `:ro` |
| Writable directories are explicit | Only `uploads` and `storage` get RW mounts |
| Privilege escalation blocked | `no-new-privileges:true` on both services |
| Dangerous MySQL features off | `--local-infile=0` at startup |
| Schema auto-applied on first run | `init.sql` in `docker-entrypoint-initdb.d/` |
| Data survives container restarts | Named volume for MySQL data directory |
