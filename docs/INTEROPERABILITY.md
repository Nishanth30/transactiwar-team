# Interoperability Contract

This document defines team boundaries, shared interfaces, and change rules so all members can work in parallel without breaking each other.

## Team ownership

| Member | Role | Owns | Must coordinate before changing |
|---|---|---|---|
| Beaver | Auth and Session | login/logout/session behavior | anything that changes session keys, auth middleware behavior, or login response contract |
| Spider | Profile and Upload | profile update flows and file upload behavior | file path conventions, upload validation rules, profile payload shape |
| Cat | Search and Transfer | search endpoints and transfer logic | transfer transaction model, transfer validation contract, search query params |
| Dog | Security and Cross-cutting | shared security controls and review gates | security headers, validation standards, error handling policy, authz checks |
| Capybara | Infra, Docker and DB | Docker, runtime envs, DB bootstrap and schema process | env var names, compose services, DB schema bootstrap conventions |

## Source-of-truth locations

- Runtime bootstrap: `docker/docker-compose.yml`
- Image hardening and web root: `docker/Dockerfile`
- Environment template: `docker/.env.example`
- Database bootstrap schema: `database/init.sql`
- Web entrypoint: `public/index.php`
- Team runbook: `README.md`

## Shared runtime contract

All members must use these runtime assumptions:

- App is served from `public/` (`/var/www/html/public` inside container).
- MySQL schema is auto-loaded from `database/init.sql` on fresh DB volume creation.
- Startup order is enforced as `db (healthy) -> setup (seed) -> app`.
- Team-local secrets are in `docker/.env`; never commit that file.
- Required env vars:
`MYSQL_ROOT_PASSWORD`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`, `APP_PORT`, `APP_DIAGNOSTIC_MODE`
- Optional setup tuning vars:
`DB_WAIT_ATTEMPTS`, `DB_WAIT_SLEEP_SECONDS`
- Default app exposure is localhost only (`127.0.0.1` binding).

## Data and DB contract

- `database/init.sql` must remain idempotent for fresh setup.
- Schema changes require review from Capybara and Dog before merge.
- If a schema change is not backward compatible, PR must include:
`breaking-change` label and explicit local reset instructions.
- Use app DB user (`MYSQL_USER`) from application code, not root.

## HTTP and module contract

When adding or changing endpoints/modules:

1. Keep stable request and response shapes unless coordinated.
2. For breaking API changes, update:
`README.md` and this file in the same PR.
3. Use consistent status code semantics:
- `2xx`: success
- `4xx`: client input/authz/authn issues
- `5xx`: server/runtime issues
4. Do not expose internal stack traces or raw SQL errors in responses.

## Security baseline contract

All roles follow these minimum rules:

- Validate and normalize all external input.
- Enforce authorization checks at business-action boundaries.
- Avoid direct trust in client-provided IDs or roles.
- Keep sensitive data out of logs.
- Keep security headers and safe defaults enabled unless explicitly reviewed by Dog.

## File upload contract (Spider + Dog + Capybara)

- Accept only allowlisted MIME/extensions.
- Store uploads under team-defined upload directories only.
- Never execute uploaded content as code.
- Enforce max file size and filename sanitization.

## Transfer contract (Cat + Beaver + Dog)

- Transfer operations must be atomic at DB level.
- Validate sender/receiver constraints and amount constraints server-side.
- Record auditable transfer events without leaking secrets.

## Session contract (Beaver + Dog)

- Session identifiers must be regenerated on login.
- Session cookies must remain `HttpOnly`.
- Session key names used across modules must be versioned/documented when changed.

## Change-management workflow

Before merge:

1. Confirm ownership reviewer approved.
2. Confirm no undocumented contract changes.
3. Confirm local Docker setup still starts from clean checkout.
4. Confirm DB bootstrap still works from `down -v` followed by `up -d --build`.

## Pull request checklist

- Scope: role owner listed in PR description.
- Contracts: any changed contract documented.
- Security: Dog reviewed cross-cutting risk.
- Infra/DB: Capybara reviewed env/schema/runtime implications.
- Repro: startup commands and verification steps included.

## Conflict resolution rule

If two streams touch the same contract surface, merge order is:

1. Security and data integrity constraints
2. Runtime/bootstrap compatibility
3. Feature behavior details

Then update this contract doc immediately after resolving.
