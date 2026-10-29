# Changelog

## Unreleased

### Phase 1 — cases, evidence intake, jobs (2026-10-29)
- Cases: create, list, get, update, delete. Deletion requires the exact case
  name, is refused while a job runs, and removes records, exports and evidence
  blobs (blobs shared with another case are kept).
- Evidence store: single-pass SHA-256 while streaming uploads, read-only
  content-addressed blobs, re-verification on duplicate upload, free-space
  floor, cross-process lock for commit/delete.
- Upload API: raw body per file; per-file and per-case size limits enforced
  while streaming; timezone/year hints and format override validated.
- Archives: zip, tar, gzip, bzip2, xz, nested up to 3 levels. Path traversal,
  absolute paths, symlinks, devices, encrypted members, compression bombs,
  member-count and case-budget limits are reported per member. Truncated
  compressed data is recovered with a warning.
- Format detection by content for all v1 formats, with scored candidates;
  generic fallback flagged as a coverage gap; corrupt-EVTX hint.
- Background worker process with persistent job queue: atomic claim,
  heartbeats, cancellation, crash recovery with bounded retries, restart by
  `mizar serve`, graceful requeue on shutdown.
- Evidence verification job: re-hashes every blob and records the result.

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
