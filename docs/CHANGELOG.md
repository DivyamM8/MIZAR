# Changelog

## Unreleased

### Phase 0 — foundation (2026-10-29)
- Backend package skeleton (FastAPI, SQLAlchemy Core, Alembic).
- Configuration via `MIZAR_*` environment variables; non-loopback binds refused.
- Error taxonomy and standard API error envelope (DESIGN.md §14).
- Local-access guard: Host allowlist, Origin check, per-launch API token for
  state-changing requests, security headers, internal errors without stack traces.
- SQLite with WAL and foreign keys; UTC-only datetime column type that refuses
  naive datetimes.
- Initial migration: `cases`, `jobs`.
- Stable ID scheme (DESIGN.md §3.1).
- Tooling: pytest, ruff, mypy (strict).
