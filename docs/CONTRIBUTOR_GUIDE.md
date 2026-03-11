# TransactiWar Contributor Guide

This guide is the day-to-day playbook for contributors working on the PHP/MySQL/Docker codebase.

## 1) Working Agreements

- Preserve security controls by default. Do not remove CSRF checks, auth guards, prepared statements, or output encoding.
- Keep changes incremental. Prefer focused PRs over large rewrites.
- Update documentation in the same PR when behavior, security assumptions, or deployment flow changes.
- Never commit `docker/.env`, private keys, or machine-specific secrets.

## 2) Code Commenting Standard

Use comments to explain intent and security rationale, not obvious syntax.

Good comment examples:

- why a lock order exists in transfers
- why an error message is intentionally generic
- why an input is validated before DB access

Avoid comments that repeat code literally (for example: "assigns X to Y").

## 3) PHP Coding Expectations

- Start files with `declare(strict_types=1);`.
- Use shared helpers from `includes/sanitize.php`, `includes/auth.php`, `includes/csrf.php`, and `includes/header.php`.
- Use prepared statements for all database access.
- Escape untrusted output with `escape_output()` or `escape_attr()` before rendering.
- Keep state-changing routes behind `verifyCsrf()`.

## 4) Security Baseline Checklist (Before PR)

- Authentication paths still call `require_login()` where required.
- All POST handlers still verify CSRF.
- No new direct SQL string interpolation.
- No sensitive details leaked in user-facing error responses.
- File upload and image handling remain allowlist-based.
- Transfer logic remains transactional and atomic.

## 5) Testing Flow

Run these before opening a PR:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d --build
docker compose --env-file docker/.env -f docker/docker-compose.yml ps
```

Then verify:

1. register and login
2. profile view and update
3. image upload
4. search
5. transfer and transaction history
6. logout and session behavior

## 6) Ownership and Coordination

Use `docs/INTEROPERABILITY.md` as source of truth for team ownership and module boundaries.

- Beaver: auth/session
- Spider: profile/upload
- Cat: search/transfer
- Dog: security cross-cutting
- Capybara: Docker/DB/runtime

If your change crosses another member's ownership boundary, coordinate before merge.

