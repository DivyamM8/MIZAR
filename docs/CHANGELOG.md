# Changelog

## Unreleased

### Phase 7 — hardening, performance, packaging, user guide (2026-11-05)
- Background jobs have a time limit (`MIZAR_JOB_TIMEOUT_SECONDS`, default 6 h):
  a job past it is recorded as `JOB_TIMEOUT` and not retried, and the worker
  restarts, so input that hangs a parser can no longer block the queue.
- State-changing API requests other than uploads are limited to 1 MiB.
- A warning at start-up when the data directory is readable by other users.
- Stopping `mizar serve` mid-parse no longer deletes the partial events first;
  the requeued parse does that when it restarts, so shutdown is quick.
- Dependency audit (`pip-audit`, `npm audit`): no known vulnerabilities.
- Faster loading of large cases: events are written in batches of 50,000 over
  one connection with a larger cache, and files of 64 MiB or more load without
  the random-key event indexes, which are rebuilt afterwards. A 2 GB case
  (13.7M events) now parses and indexes in 25 min instead of 61, writing 51 GB
  to disk instead of 269. The event ID becomes a unique index (migration 0007).
- Fixed: an analysis run with more than about 32,000 findings failed while
  carrying over analyst statuses ("too many SQL variables").
- Analysis memory no longer grows with the number of events: findings keep
  their evidence as event IDs and fetch the events when built, threshold rules
  find bursts in one pass, and reports stream their events. Peak memory on a
  2.8M-event case fell from 2.0 GB to 0.58 GB.
- At most 1,000 findings per rule are kept per run (highest severity and
  confidence, then earliest), and the run, the Findings page and the report
  say when a rule was capped and which parameters narrow it.
- AUTH-007 (2.0.0) reports one finding per user, listing that user's new
  source addresses, instead of one per user and address.
- Installable package with the web UI inside: `scripts/install.sh`
  (`scripts/build.sh` builds the wheel); `mizar --version`.
- User guide (`docs/USER_GUIDE.md`).

### Phase 6 — reports and exports (2026-11-04)
- PDF investigation report: cover with Draft/Final marking and run hashes,
  executive summary generated from the data, scope and evidence with hashes
  and parse statistics, methodology, one section per finding with every field
  and its supporting events, timeline, entities, limitations and the run
  manifest. Footer with case, run and page numbers; a small MIZAR mark in the
  page corners.
- JSON export with the full run manifest, findings and referenced events with
  their original records (hash-checked); optional NDJSON of all events.
- CSV export (ZIP) with findings, events and source files, protected against
  spreadsheet formula injection.
- Filters by status and minimum severity; exports run as background jobs,
  are written atomically, and record their size and SHA-256.
- PDF reports draw Cyrillic, Greek and other non-Western-European text with a
  bundled DejaVu Sans font; text it cannot show correctly stays escaped.
- Reports page in the UI: choose a run, format and filters; download, cancel
  or delete exports.
- Fixed: alternative explanations and verification steps now have their
  placeholders filled in (they showed `{source_ip}` and similar).
- Fixed: stopping `mizar serve` with SIGTERM left the worker process running;
  the worker now also stops if the server is killed.

### Phase 5 — web UI (2026-11-04)
- React + TypeScript web UI served by `mizar serve`: cases (create, edit,
  delete with typed confirmation), case overview, evidence (multi-file upload
  with progress and hints, file tree with hashes, detection, parse statistics,
  messages, re-parse), findings (prioritized, filtered by run, severity and
  status), finding detail (rationale, hypothesis, alternatives, verification,
  sources with hashes, chained findings, evidence events, analyst review),
  timeline (histogram, filters, lanes, finding markers, cursor paging), event
  search, entities, sessions, runs (manifest viewer, overrides, comparison
  by fingerprint) and the rule catalogue.
- Event drawer with normalized fields, the raw record and whether it still
  matches its hash, sessions and duplicates, documented links and related events.
- The backend serves the built UI with the per-launch token in a meta tag; the
  app shell is the fallback for client-side routes, and API 404s stay JSON.
- Checks: strict type checking, unit tests, and a browser tour over every page
  that fails on console errors.

### Phase 4 — correlation and timeline (2026-11-04)
- Case index job after parsing: entities (hosts, users, IPs with source and
  destination counts), sessions from shared logon/session IDs, and documented
  Sysmon process links; duplicates counted once.
- Timeline API with keyset paging in both directions, a separate lane for
  events without reliable UTC time, shared filters, finding markers, and
  filters by finding or minimum severity; histogram with readable bucket sizes.
- Entity list and detail with the findings that name each entity; session list
  and detail; on-demand related events labeled as shared attributes, not
  causation; documented links in event detail.
- Long rebuilds no longer hold the database write lock; writers wait up to
  30 s instead of failing.
- Windows log-cleared events (1102/104) now carry the logon ID, so they join
  the session that cleared the log.

### Phase 3 — detection, findings, analysis runs (2026-11-04)
- Rule engine with five rule types (match, threshold, sequence, first-seen,
  correlation), a filter language with list-aware operators and RE2 regexes,
  and SQL prefiltering on indexed columns.
- 32 rules as YAML files validated against a JSON Schema and semantic checks
  (parameters, fields, regexes, Critical only in correlations, wording rules);
  generated catalogue in `docs/rules.md`.
- Findings with severity, confidence and evidence strength kept separate,
  each with its rationale, ATT&CK techniques, entities, observed evidence,
  interpretation, alternative explanations, verification steps, linked
  evidence events and source files with hashes.
- Analysis runs: evidence re-verified first, manifest of inputs, parser and
  rule versions, parameters and configuration, inputs fingerprint for
  reproducibility, coverage gaps and rule notes; one failing rule does not stop
  a run.
- Analyst status and notes per finding, carried to later runs by fingerprint.
- Ground-truth tests on all planted scenarios, including benign look-alikes,
  plus positive and negative cases per rule.

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
