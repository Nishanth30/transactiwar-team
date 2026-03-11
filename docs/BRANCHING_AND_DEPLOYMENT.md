# Branching and Delivery Guide

This document defines a clean branching workflow for assignment development and submission.

## 1) Branch Roles

- `main`: stable integration branch.
- `feature/<name>`: focused implementation branches.
- `fix/<name>`: targeted bugfix branches.

## 2) Why This Workflow

This keeps code review and testing predictable:

- each branch has a single purpose
- reviewers can validate smaller changes
- regressions are easier to isolate and revert

## 3) Initial Setup

```bash
git checkout main
git pull --ff-only
git checkout -b feature/<short-name>
```

## 4) Delivery Workflow

1. implement and test in your feature branch
2. keep commits focused and descriptive
3. open PR into `main`
4. merge only after review + verification

## 5) Verification Checklist (Before Merge)

1. `docker compose ... up -d --build` succeeds
2. `db` is healthy and `setup` completed
3. register/login/profile/upload/search/transfer/history/logout flows pass
4. no secrets are committed
5. docs are updated if contracts changed

## 6) Conflict Handling Rule

When branches conflict on the same file, resolve in this order:

1. security and data integrity constraints
2. runtime/bootstrap compatibility
3. feature behavior details

Then update `README.md` and relevant docs in the same PR.
