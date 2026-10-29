# Changelog

## Unreleased

### Phase 2 — event schema, parsers, events API (2026-10-29)
- Normalized event schema v1.0.0 as JSON Schema (`mizar/schemas/event.v1.json`)
  with generated documentation (`docs/event-schema.md`).
- Parsers: traditional/rsyslog syslog, RFC 5424, journald JSON, auditd
  (multi-record grouping, hex decoding, ENRICHED format), native EVTX, EVTX
  XML/JSON/CSV exports, Apache/Nginx access, Zeek TSV/JSON, CEF, LEEF, Squid,
  and generic text/JSON-lines fallbacks. Message parsers for sshd, PAM, sudo,
  su, account management, cron and netfilter/UFW.
- Timezone policy implemented: UTC only from explicit offsets, format-defined
  UTC, or analyst hints; year hints with flagged rollover; DST-ambiguous and
  nonexistent local times are not guessed.
- Parse jobs queued automatically after detection; re-parse with new hints or
  format override; parse results with statistics and file-level problems
  (e.g. unreadable EVTX chunks); failures keep records parsed so far.
- Duplicate groups across source files without removing any record.
- Events API: filtered search, event detail with the raw record read back from
  the evidence file and verified against its hash.
- Deterministic synthetic scenario generator with ground truth
  (`fixtures/generator`), and Apache-2.0 EVTX samples.
- Property-based tests: parsers never crash on arbitrary input and every line
  stays traceable to its exact bytes.

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
