# MIZAR — Design Document

| | |
|---|---|
| Status | **Approved for implementation** |
| Document version | 0.6.0 |
| Licence | Apache-2.0 |
| Date | 2026-10-29 |
| Event schema version | 1.0.0 (proposed) |
| Rule format version | 1.0.0 (proposed) |

MIZAR is a local web application for cybersecurity investigators. An analyst
creates a case, uploads one or more log files, and MIZAR preserves the
originals as evidence, parses and normalizes their records, detects suspicious
patterns, correlates related events into a timeline, prioritizes findings, lets
the analyst inspect the supporting evidence, and exports a professional PDF
report (plus JSON/CSV).

**Primary users:** SOC analysts, incident responders, digital forensic
investigators. **Secondary:** CTF participants and learners.

---

## 1. Scope

### 1.1 In scope for v1

- Cases, multi-file upload, archives (`.zip`, `.gz`, `.tar`, `.tar.gz`).
- Evidence handling: SHA-256, immutable content-addressed storage, hash
  re-verification before every analysis run.
- Parsers for three format families (§7):
  1. Linux: `auth.log`/`secure`, syslog RFC 3164 and RFC 5424, journald JSON
     export, auditd.
  2. Windows: native `.evtx` (Security, System, Sysmon, PowerShell) and EVTX
     exported to XML / JSON / CSV.
  3. Web and network: Apache/Nginx access logs (common/combined), Zeek
     (TSV and JSON), iptables/UFW, CEF, LEEF, Squid access log.
- Generic fallback parser for anything unrecognized (§7.4).
- Versioned normalized event schema (§5).
- Rule-based detection: authentication attacks, privilege & persistence, web
  & network (§9).
- Correlation, event linking, and a unified timeline (§10).
- Findings with severity, confidence, and evidence strength kept separate,
  with ATT&CK mapping and analyst status workflow (§11).
- Reproducible analysis runs (§12).
- Export: PDF report, JSON, CSV (§13).
- Hardening against hostile log content (§15).

### 1.2 Explicit non-goals for v1

- Not a SIEM: no live ingestion, agents, forwarding, or retention management.
- Not an EDR: no endpoint telemetry or response actions.
- No packet capture analysis (PCAP). Zeek *logs* are supported; packets are not.
- No outbound network calls by default (no threat-intel lookups, no telemetry,
  no CDN assets).
- No multi-user accounts or authentication (single analyst, localhost).
- No ML/anomaly models. Rarity checks are limited to "first seen within this
  case's data" and labelled as such.
- No Sigma import (the rule format is designed so a Sigma subset can be mapped
  later).
- macOS unified log and generic JSON/CSV field mapping: deferred. Such files
  go through the generic fallback parser.
- Defense-evasion/execution detections (encoded PowerShell, Sysmon process
  chains): deferred. Exception: the log-cleared rule DEF-001 is in v1 (§9.2).

### 1.3 Decisions record

| # | Decision | Choice | Rationale |
|---|---|---|---|
| D1 | Stack | Python 3 + FastAPI backend; React + TypeScript (Vite) frontend | Python has the best forensic parsing ecosystem; React gives an interactive timeline and evidence view |
| D2 | Target scale | ~2 GB / ~10M events per case on one workstation | Typical IR triage. Drives SQLite + streaming + background worker |
| D3 | Storage | SQLite (WAL mode) via SQLAlchemy 2.x Core + Alembic migrations | Zero-admin, single file, fast enough at D2 scale with batch inserts and indexes |
| D4 | Deployment | Binds to `127.0.0.1` only, no login; native (venv + npm build) or Podman/Docker compose | Single analyst. Analyst name entered per case for attribution |
| D5 | EVTX library | `evtx` (Rust-backed `pyevtx-rs`) with `python-evtx` as fallback | `python-evtx` is pure Python and too slow for multi-GB files |
| D6 | PDF engine | ReportLab (Platypus) | Pure-Python wheels, no native deps. Unlike HTML-to-PDF engines it never fetches URLs, so hostile log content cannot cause SSRF or local file reads in the renderer |
| D7 | Raw record storage (revised in Phase 2) | Line-framed UTF-8 records are read back from the immutable evidence file by byte offset and verified against `record_hash` on every view. A stored copy is kept only where the locator cannot be read back cheaply (EVTX renderings, XML/JSON/CSV items, UTF-16 text), zlib-compressed only when that makes it smaller | Measured: per-record zlib did not shrink short lines (97 vs 96 bytes) and a second copy cost ~16% of the database. Reading from the evidence file also proves the shown bytes still match the original |
| D8 | Job execution | One separate worker process polling a persistent `jobs` table | Keeps the API responsive (GIL). No Redis/Celery needed for a single analyst |
| D9 | Analyst action audit log | **Not in v1** (by request). Findings keep `status`, `analyst_notes`, `updated_by`, `updated_at` | The analysis-run record (§12) is still required and kept |
| D10 | Test data | Synthetic fixture generator with planted scenarios and a ground-truth manifest | Detections are tested against known answers |
| D11 | Limits | 2 GiB per file, 20 GiB uncompressed per case, 10,000 archive members | Confirmed in review |
| D12 | Port | `127.0.0.1:8730` | Confirmed in review |
| D13 | Native EVTX test data | Openly licensed public samples first; analyst-generated Windows samples later | Licence of each sample set is checked and recorded in `fixtures/THIRD_PARTY.md` before use |
| D14 | Report branding | Neutral; small "MIZAR" watermark in the page corners | Confirmed in review |
| D15 | Case deletion | Deletes everything belonging to the case (DB rows, exports, evidence blobs) after typed-name confirmation | Blobs shared with another case (same content hash) are kept until no case references them |
| D16 | Licence | Apache-2.0 | Dependencies must be Apache-2.0-compatible (no GPL in the shipped backend/frontend) |
| D17 | Archive nesting depth | 3 container levels (was 2) | A `.tar.gz` collection holding rotated `auth.log.2.gz` files is three levels and is common |
| D18 | Upload transport | One raw-body request per file instead of multipart | Single-pass hashing straight into the evidence store; no second copy in a temp directory; early size-limit rejection; per-file errors. The UI sends several requests for a multi-file selection |
| D19 | Store concurrency | A cross-process `flock` on the evidence store is held while a blob is committed together with its database row, and while deletion checks references | Prevents a blob being deleted between being stored and being referenced (API and worker are separate processes) |
| D20 | Truncated compressed data | Recovered bytes are kept as the member, with an `ARCHIVE_TRUNCATED` warning | Partial logs from a damaged rotation file are still evidence |
| D21 | EVTX test data | Samples from the `evtx` Rust project (Apache-2.0), pinned to a commit, in `fixtures/third_party/evtx` | EVTX-ATTACK-SAMPLES is GPL-3.0, incompatible with D16 |
| D22 | XML parsing | Python stdlib ElementTree, with DOCTYPE/ENTITY declarations refused | Python 3.14's expat resists entity expansion and never fetches external entities; no extra dependency |
| D23 | Windows exports without field names | Get-WinEvent JSON (positional `Properties`) and Event Viewer CSV (rendered message only) map the event ID's meaning but leave account/IP fields null, marked `partial` | Guessing which positional value is the username would produce misleading data |
| D24 | Per-parse constants | `schema_version`, `parser_version`, `ingestion_time` are stored once per parse result and joined into every event by the API | Same schema to clients, ~40 bytes less per stored event |
| D25 | Query planning | Selective filters (IP, user, host, file, event type) write the case condition as `+case_id` so SQLite uses the selective index; `PRAGMA optimize` runs after each parse | Measured: case-scoped IP lookup on 1M events 469 ms → 0.1 ms |
| D26 | Rule parameters | Declared once in a `params` block (type, default, minimum, description) and referenced by name | The run manifest lists exactly which values were tunable and which were used |
| D27 | Finding granularity | One finding per rule per grouping key; threshold bursts are listed inside it | Stable fingerprints, so analyst status and notes carry over between runs even when thresholds change |
| D28 | Correlation rules | `correlation` rules chain base-rule findings (and optionally events) by a join field and time window; they cannot chain other correlations | Reuses base detections instead of re-detecting; keeps chains explainable |
| D29 | First-seen rules | Only values first seen *after a baseline period* of the case's data are flagged; if the data is shorter than the baseline the run notes it | Without a baseline, everything is "first seen" once |
| D30 | Evidence links | `finding_events` has no foreign key to events. Links follow original records: re-parsing the same bytes keeps the IDs, and links to records that no longer exist are shown as not present | Old runs stay reviewable after re-parsing |
| D31 | Regex engine | RE2 (linear time, no backreferences) for all rule regexes | A hostile log line cannot stall a rule |
| D32 | Event links | Only source-documented links are stored (Sysmon `ProcessGuid`: parent→child process, process→its activity). "Related by IP/user/host within ±window" is computed on request and labeled as shared attributes | Materializing same-actor links is quadratic (every failure from one IP linked to every other) and would suggest causation |
| D33 | Sessions | Duplicate-free events sharing (`hostname`, `session_id`) form a session group, split when consecutive events are more than 8 h apart; Windows shared logon IDs (0x3e7, 0x3e4, 0x3e5, 0x0) and one-event sessions are excluded | sshd PIDs and auditd session numbers are reused over time; SYSTEM would otherwise be one giant session |
| D34 | Case index | Entities, sessions and process links are rebuilt for the whole case by one background job, queued after parsing (at most one waiting per case) | Always consistent with the current events; cost ≈ 12–15 s per 1M events |
| D35 | Short write transactions | Heavy rebuilds compute in read transactions and swap results in one short write; SQLite waits up to 30 s for the write lock | Measured: 148 API writes during a 1M-event index rebuild, 0 errors (worst wait 5.6 s); before, writers failed after 5 s |

---

## 2. Architecture

```
 Browser (React SPA, served locally)
        │  HTTP/JSON on 127.0.0.1:8730
        ▼
 ┌──────────────────────── FastAPI process ────────────────────────┐
 │ api/        REST endpoints, request validation, error envelope   │
 │ cases/      case CRUD                                            │
 │ evidence/   upload streaming, hashing, evidence store, verify    │
 │ reporting/  PDF / JSON / CSV export (streamed)                   │
 └───────────────┬───────────────────────────────┬──────────────────┘
                 │ enqueue job                   │ read
                 ▼                               ▼
          ┌─────────────┐   SQLite (WAL)  ┌─────────────────┐
          │ jobs table  │◄───────────────►│ mizar.db        │
          └─────┬───────┘                 └─────────────────┘
                │ poll / claim                    ▲
                ▼                                 │ batch writes
 ┌──────────────────────── Worker process ─────────┴────────────────┐
 │ ingest/       archive expansion, format detection                │
 │ parsers/      streaming parsers → normalized events              │
 │ detection/    rule engine → findings                             │
 │ correlation/  dedup groups, entity links, sessions, timeline     │
 └──────────────────────────────────────────────────────────────────┘
                 │ read-only
                 ▼
          data/evidence/sha256/ab/cd/<sha256>   (immutable originals)
```

### 2.1 Repository layout

```
MIZAR/
├── backend/
│   ├── pyproject.toml
│   ├── mizar/
│   │   ├── api/            routers, error handlers, schemas (pydantic)
│   │   ├── core/           config, logging, errors, ids, time utilities
│   │   ├── db/             tables, migrations (alembic), repositories
│   │   ├── evidence/       store, hashing, verification, archive safety
│   │   ├── ingest/         format detection, ingestion jobs
│   │   ├── parsers/        one module per parser + registry + generic
│   │   ├── detection/      rule loader, engine, evaluators
│   │   ├── correlation/    dedup, entity extraction, linking, timeline
│   │   ├── reporting/      pdf/, json, csv
│   │   └── worker.py
│   ├── rules/              YAML detection rules (versioned)
│   ├── schemas/            event.v1.json (JSON Schema), rule.v1.json
│   └── tests/
├── frontend/               React + TS + Vite
├── fixtures/
│   ├── generator/          synthetic scenario generator
│   └── scenarios/          generated logs + ground_truth.json
├── deploy/                 compose file, Containerfile
└── docs/
    ├── DESIGN.md           this document
    ├── event-schema.md     field reference (generated from JSON Schema)
    ├── rules.md            rule catalogue (generated from rules/)
    └── CHANGELOG.md
```

### 2.2 Data directory

Configurable via `MIZAR_DATA_DIR` (default `~/.local/share/mizar`):

```
data/
├── mizar.db                     SQLite database
├── evidence/sha256/ab/cd/<hash> immutable originals and extracted archive members
├── staging/                     in-progress uploads (cleaned on startup)
└── exports/                     generated reports
```

---

## 3. Domain model

```
Case 1───* SourceFile 1───* Event *───* EventGroup (dedup / session / chain)
  │            │ (parent_file_id for archive members)
  │            └──* ParseResult
  ├───* AnalysisRun 1───* Finding *───* Event   (finding_events, with role)
  │                          │
  │                          └── fingerprint (matches findings across runs)
  └───* Job
```

| Entity | Purpose |
|---|---|
| `Case` | Investigation container. Fields: `case_id`, `name`, `reference` (external ticket), `analyst_name`, `description`, `default_timezone_hint`, `created_at` |
| `SourceFile` | One input file, or one member extracted from an archive (§6.1) |
| `ParseResult` | Outcome of parsing one source file with one parser version |
| `Event` | One normalized record (§5) |
| `RawRecord` | Compressed raw bytes/text for an event (D7) |
| `EventGroup` | Typed grouping that never deletes members: `duplicate`, `session`, `chain` |
| `AnalysisRun` | One execution of detection + correlation, with full manifest (§12) |
| `Finding` | Output of a rule in a run (§11) |
| `FindingEvent` | Link table: `finding_id`, `event_id`, `role` (`trigger`, `context`, `outcome`) |
| `Job` | Background task state: `queued`, `running`, `succeeded`, `failed`, `cancelled`, with progress and error |

### 3.1 Identifiers

All IDs are stable and deterministic where the inputs permit it:

| ID | Format | Derivation |
|---|---|---|
| `case_id` | `CASE-<ULID>` | Random at creation |
| `source_file_id` | `SF-<ULID>` | Random. Each file also has a per-case display `sequence` (#1, #2, …). Re-uploading identical bytes into the same case creates a new record flagged `DUPLICATE_UPLOAD`. Event IDs do not depend on this ID (they use the content hash) |
| `event_id` | UUIDv5(`MIZAR_NS`, `case_id \| source_file_id \| source_file_sha256 \| record_locator`) | Re-parsing the same source file always yields the same event IDs. `source_file_id` is included because one case can hold the same content twice (a duplicate upload); those are distinct records, linked by duplicate groups |
| `run_id` | `RUN-<ULID>` | Random per run |
| `finding_id` | `<run_id>-F<4-digit sequence>` | Sequence assigned after deterministic sort (§12.2) |
| `finding_fingerprint` | SHA-256 of `rule_id \| rule_major_version \| grouping key values` | Same pattern across re-runs gets the same fingerprint, so analyst status and notes carry forward |

---

## 4. Timestamp and timezone policy

This is a correctness requirement. MIZAR never invents timezone information.

1. `timestamp_original` always stores the exact timestamp text from the record,
   unmodified.
2. `timestamp_utc` is populated **only** when conversion is reliable:
   - the record carries an explicit offset (`2026-10-29T12:00:00+05:30`,
     RFC 5424, journald `__REALTIME_TIMESTAMP`, EVTX `SystemTime`, Zeek epoch
     `ts`, Apache `[29/Oct/2026:12:00:00 +0000]`); or
   - the analyst supplied a timezone hint for that source file at upload.
3. `timezone_assumption` records which basis was used:

   | Value | Meaning |
   |---|---|
   | `explicit` | Offset or zone present in the record |
   | `format_defined_utc` | Format specification defines UTC (EVTX SystemTime, epoch seconds) |
   | `analyst_hint:<IANA zone>` | Analyst-supplied, e.g. `analyst_hint:Asia/Kolkata` |
   | `none` | No reliable basis; `timestamp_utc` is `null` |

4. Formats without a year (RFC 3164 `Oct 29 12:00:01`): the year must come
   from an analyst-supplied **year hint** (the year of the file's first
   record). If the timestamps go backwards across
   a month boundary (Dec → Jan) the year is incremented and the warning
   `year_rollover_inferred` is attached to the affected events. Without a year
   hint, `timestamp_utc` is `null`.
5. Ambiguous or nonexistent local times (DST fold or gap) are not resolved by
   guessing. `timestamp_utc` is `null` and the warning `dst_ambiguous` or
   `dst_nonexistent` is attached.
6. Unparseable timestamps: `timestamp_utc = null`, `parsing_status = partial`,
   warning `timestamp_unparsed`. The record is still ingested.
7. Events with `timestamp_utc = null` appear in a separate **"Unplaced"** lane
   of the timeline, ordered by file position. They are never interleaved by
   guesswork.
8. Precision is recorded (`timestamp_precision`: `s`, `ms`, `us`, `ns`) so
   ordering ties are not over-interpreted.
9. Clock skew between hosts is not corrected in v1. The report states this
   limitation. A per-source clock offset correction is a candidate for v2 and
   would be recorded as an explicit assumption.

---

## 5. Normalized event schema v1.0.0

The schema is defined as JSON Schema in `backend/mizar/schemas/event.v1.json`
(source of truth; Python reads its enumerations from it).
[docs/event-schema.md](event-schema.md) is generated from it, and a test fails
if it is stale. Every event the API returns carries `schema_version` (stored
once per parse result, D24).

**Versioning rules (SemVer):** MAJOR = field removed, renamed, or changed in
meaning or type. MINOR = new nullable field. PATCH = documentation only.
Migrations are written in Alembic; old exports remain readable because each
export embeds its schema version.

### 5.1 Fields

| Field | Type | Null | Description |
|---|---|---|---|
| `event_id` | UUID | no | Stable ID (§3.1) |
| `schema_version` | string | no | e.g. `1.0.0` |
| `case_id` | string | no | Owning case |
| `source_file_id` | string | no | Source file the record came from |
| `source_type` | enum | no | `linux_auth`, `syslog`, `journald`, `auditd`, `windows_evtx`, `windows_evtx_export`, `web_access`, `zeek`, `firewall`, `cef`, `leef`, `proxy`, `generic` |
| `parser_name` | string | no | e.g. `linux.sshd` |
| `parser_version` | string | no | SemVer of the parser |
| `original_record_reference` | object | no | Locator: `{kind: "line", line: 1043, byte_offset: 88123, byte_length: 142}` or `{kind: "evtx_record", record_id: 5521, chunk: 3}` or `{kind: "json_line", line: 7}` |
| `record_hash` | hex | no | SHA-256 of the raw record bytes (used for duplicate detection, §8) |
| `timestamp_original` | string | yes | Exact source text |
| `timestamp_utc` | datetime (UTC) | yes | §4 |
| `timestamp_precision` | enum | yes | `s`/`ms`/`us`/`ns` |
| `timezone_assumption` | string | no | §4 |
| `hostname` | string | yes | Host that generated the record |
| `username` | string | yes | Primary subject/target user, as written in the source (case preserved) |
| `user_domain` | string | yes | Windows domain or realm |
| `source_ip` | string | yes | Validated IPv4/IPv6. Invalid values are left null and kept in `extra` with a warning |
| `destination_ip` | string | yes | As above |
| `source_port` | int | yes | 0–65535, validated |
| `destination_port` | int | yes | 0–65535, validated |
| `protocol` | string | yes | Lowercase, e.g. `tcp`, `ssh`, `http` |
| `event_category` | enum | yes | `authentication`, `account_management`, `privilege`, `process`, `service`, `scheduled_task`, `file`, `network`, `web`, `system`, `other` |
| `event_type` | string | yes | Normalized action, e.g. `logon`, `logon_failed`, `user_created`, `group_member_added`, `http_request`, `connection_denied` |
| `event_outcome` | enum | yes | `success`, `failure`, `unknown`. Null when not applicable |
| `event_code` | string | yes | Native code: Windows EventID, HTTP status, auditd type |
| `process_name` | string | yes | e.g. `sshd`, `sudo`, `C:\Windows\System32\svchost.exe` |
| `process_id` | int | yes | |
| `session_id` | string | yes | Linking key: Windows `TargetLogonId`, sshd PID session, Zeek `uid`, auditd `ses` |
| `message` | string | yes | Human-readable message as in the source (not rewritten) |
| `extra` | JSON object | yes | Source-specific fields not in the core schema, e.g. `LogonType`, `user_agent`, `http_method`, `url`, `status` |
| `record_index` | int | no | 0-based position of the record within its file, in parse order |
| `parsing_status` | enum | no | `parsed`, `partial` (some fields failed), `unparsed` (stored as raw only, generic fallback) |
| `parse_warnings` | string[] | yes | Machine-readable codes, e.g. `timestamp_unparsed`, `invalid_ip`, `year_rollover_inferred`, `truncated_record` |
| `ingestion_time` | datetime (UTC) | no | When MIZAR created the event |

Rules for parsers:
- Never coerce invalid data into plausible-looking values. An invalid IP becomes
  `null` with a warning, not `0.0.0.0`. An out-of-range port becomes `null`,
  not clamped.
- `message` and `raw_record` are kept verbatim. Normalization only adds fields.
- Field values are stored as written. Comparisons in rules may be
  case-insensitive (declared per rule), but stored data is not lowercased.

### 5.2 Indexing (SQLite)

Indexes on `(case_id, timestamp_utc)`, `source_ip`, `destination_ip`,
`username`, `hostname`, `session_id`, `event_type`, `event_code`,
`record_hash`, and `(source_file_id, record_index)` (unique). See D25 for how
queries use them. Message search is a substring match in v1; an FTS5 index is
deferred until the search UI (Phase 5) shows it is needed, because keeping it
in sync costs ingestion speed.

---

## 6. Evidence and provenance

### 6.1 Ingestion of a file

1. Stream the upload to `staging/` in 1 MiB chunks, computing SHA-256 while
   writing (one pass, constant memory). Enforce size limits (§15).
2. Move it atomically to `evidence/sha256/ab/cd/<sha256>` and set it read-only
   (`0444`). If identical content already exists, reuse the stored blob; the
   new `SourceFile` row still records this upload separately.
3. Record in `source_files`: `source_file_id`, `case_id`,
   `original_filename` (as supplied, sanitized for display only),
   `size_bytes`, `sha256`, `ingestion_time` (UTC), `uploaded_by`,
   `detected_format`, `detection_confidence`, `format_override` (if the
   analyst chose one), `timezone_hint`, `year_hint`, `parent_file_id`,
   `archive_member_path`, `validation_status`, `validation_messages`.
4. Archives: each member is extracted (with the guards in §15) into the
   evidence store as its own `SourceFile`, with its own hash and
   `parent_file_id` and `archive_member_path` pointing back to the archive.
   Record locators always refer to the extracted member, so a raw record can
   be re-read without decompressing the whole archive. `.gz` is treated as a
   one-member archive.
5. Format detection reads the first 64 KiB. Each parser's `detect()` returns a
   score from 0 to 1, and the highest score above 0.5 wins. All candidate
   scores are stored so the analyst can see why a format was chosen and
   override it.
6. Parse in a background job (§7), writing a `ParseResult`: `parser_name`,
   `parser_version`, `started_at`, `finished_at`, `records_total`,
   `records_parsed`, `records_partial`, `records_unparsed`, `warnings_by_code`
   (counts), `first_timestamp_utc`, `last_timestamp_utc`, `status`
   (`succeeded`, `succeeded_with_warnings`, `failed`), `error`.

The original file is never modified, re-encoded, or rewritten.

### 6.2 Verification

Before every analysis run, and on demand from the Evidence page, every input
blob is re-hashed. A mismatch:
- blocks the run with error `EVIDENCE_INTEGRITY_MISMATCH`,
- marks the source file `integrity_failed`, which is shown prominently in the
  UI and in any report.

---

## 7. Parsers

### 7.1 Parser contract

```python
class Parser(Protocol):
    name: str            # "linux.sshd"
    version: str         # "1.0.0"
    source_type: str
    def detect(self, head: bytes, filename: str) -> float: ...
    def parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[ParsedRecord]: ...
```

- Streaming only: memory stays bounded regardless of file size. Events are
  written in batches of 5,000 per transaction.
- A bad record never aborts the file. It produces an event with
  `parsing_status = partial` or `unparsed` and a warning code.
- File-level errors (corrupt EVTX header, wrong encoding throughout) fail the
  `ParseResult` with a typed error and keep every record parsed up to that
  point. Partial ingestion is reported, never hidden.
- Encoding: UTF-8 is tried first, then UTF-16 with BOM. Undecodable bytes are
  replaced for display, but the raw bytes are preserved, and the warning
  `encoding_replaced` is attached.
- Line length limit 1 MiB. Longer lines are kept raw and flagged
  `truncated_record` (truncated for parsing only).

### 7.2 v1 parser set

| Parser | Inputs | Notes |
|---|---|---|
| `linux.syslog3164` | `syslog`, `messages`, `auth.log`, `secure` | Needs year and timezone hints. Dispatches to message sub-parsers below |
| `linux.syslog5424` | RFC 5424 | Explicit timestamps |
| sub: `linux.sshd` | sshd messages | Failed/Accepted password/publickey, Invalid user, disconnects, PAM. Extracts user, IP, port, method |
| sub: `linux.sudo` / `linux.su` | sudo/su | Command, target user, TTY, failures, "NOT in sudoers" |
| sub: `linux.accounts` | useradd, usermod, groupadd, gpasswd, passwd | Account and group changes |
| sub: `linux.cron` | CRON/crond | Job execution, crontab edits |
| `linux.journald_json` | `journalctl -o json` / `json-seq` | `__REALTIME_TIMESTAMP` is UTC µs. Reuses message sub-parsers |
| `linux.auditd` | `audit.log` | Groups multi-line events by `msg=audit(ts:serial)`. Decodes hex-encoded fields, keeping the original |
| `windows.evtx` | `.evtx` | Via `evtx` (D5). Field mapping for Security (4624/4625/4634/4648/4672/4688/4697/4698/4720/4728/4732/4740/4756/1102), System (7045, 104), Sysmon (1, 3, 11, 13), PowerShell (4103/4104). All EventData kept in `extra` |
| `windows.evtx_xml` / `_json` / `_csv` | Exports from wevtutil, Get-WinEvent, Event Viewer CSV | Event Viewer CSV has local, offset-less times and needs a timezone hint |
| `web.access` | Apache/Nginx common and combined | Explicit offset. Extracts method, URL (raw plus decoded copy), status, bytes, referrer, user agent |
| `network.zeek` | `conn`, `dns`, `http`, `ssl`, `ssh`, `notice` in TSV (`#fields` header) or JSON | Epoch timestamps (UTC). `uid` → `session_id` |
| `network.iptables` | Kernel/UFW lines in syslog | Usually nested in syslog; detected by the `SRC= DST= PROTO=` pattern |
| `network.cef` / `network.leef` | CEF / LEEF | Header plus extension parsing with escaping per spec |
| `proxy.squid` | Squid native access log | Epoch timestamps |
| `generic` | Anything else | §7.4 |

### 7.3 Python version risk

The machine has Python 3.14. Phase 0 verifies that wheels exist for `evtx`,
`pydantic-core`, and `reportlab` on 3.14. If one is missing, the backend pins
3.13 (also used in the container image).

### 7.4 Generic fallback parser

One event per line (or per JSON object, for JSON-lines). It tries a list of
common timestamp patterns (ISO 8601, RFC 3164, epoch) and IPv4/IPv6
extraction. `parsing_status` is `partial` when a timestamp was found and
`unparsed` otherwise. Its events take part in keyword search and the timeline,
but only rules marked `applies_to: generic` run on them (none in v1 beyond IP
extraction for the entity view). The report lists every file handled by the
fallback parser as a **coverage gap**.

---

## 8. Deduplication and grouping

Nothing is deleted or merged destructively.

- **Exact duplicates:** records with identical raw bytes (`record_hash`) in
  *different* source files of a case, typically the same log collected twice
  (e.g. `auth.log` and an overlapping `auth.log.1`). Identical lines within one
  file are distinct records and are never grouped. If a record occurs k times
  in file A and k times in file B, the n-th occurrence in A is grouped with the
  n-th in B. They form an `EventGroup(type=duplicate)` that lists every
  member event and its source file. Groups are rebuilt after each parse that
  touches shared records.
- **Limitation:** formats whose lines do not name the host (web access logs)
  can produce identical lines on two different servers in the same second.
  Those would be grouped as duplicates. The group is visible and
  non-destructive, and the report states this limitation. The UI shows one row with a "×N sources"
  badge and can expand it. Rules count a duplicate group **once** (configurable),
  so collecting the same log twice does not inflate brute-force counts. The
  finding still lists every member event as evidence.
- Identical messages from **different** hosts or different times are not
  duplicates.
- **Session groups** and **chain groups** (§10) are additive overlays. An event
  can belong to several groups.

---

## 9. Detection

### 9.1 Rule format (YAML, `mizar/schemas/rule.v1.json`)

One file per rule in `backend/mizar/rules/<ID>.yaml`; the catalogue is
generated as [docs/rules.md](rules.md). Example (abridged from `AUTH-001`):

```yaml
id: AUTH-001
version: 1.0.0
status: stable
title: Possible SSH brute force from {source_ip} against {hostname}
description: >
  {count} failed SSH authentication attempts from {source_ip} to {hostname} ...
attack: [T1110.001]
applies_to: [linux_auth]          # optional: source types
type: threshold
filter:
  all:
    - {field: event_type, op: eq, value: logon_failed}
    - {field: process_name, op: in, value: [sshd, sshd-session]}
group_by: [source_ip, hostname]
params:
  min_failures: {type: integer, default: 20, minimum: 2, description: ...}
  window: {type: duration, default: 10m, description: ...}
threshold: {count: min_failures, window: window, count_duplicates_once: true}
severity:
  base: medium
  reason: Repeated password guessing is an attack attempt with unknown outcome.
confidence:
  base: medium
  reason: ...
  modifiers:
    - when: {count_gte: 100}
      raise: 1
      reason: The volume is far above what a mistyping user produces.
evidence_strength: direct
interpretation: >
  The address {source_ip} made repeated failed SSH logon attempts ...
alternative_explanations: [...]
verification_steps: [...]
```

Templates use `{field}`, `{distinct.field}`, `{params.name}`, `{count}`,
`{first}`, `{last}` and `{a|b}` (first of several that has a value). They are
filled by dictionary lookup only.

Modifier conditions: `count_gte`, `distinct_gte {field, value}`,
`any_event <filter>`, `all_events <filter>`, `all_events_parsed`,
`includes_rules [IDs]` (correlation). Actions: `set`, `raise`, `lower`.
Confidence is also lowered automatically when supporting records are only
partially parsed, and for multi-source sequences that rely on analyst
timezone hints.

Rule types:
- `match`: single-event condition (e.g. user added to an admin group). With
  `group_by`, matching events of one key form one finding; otherwise each event
  is its own finding.
- `threshold`: count, or distinct count, per `group_by` in a sliding window.
  rsyslog "message repeated N times" lines count N times; the same record
  collected in two files counts once.
- `sequence`: a `first` step (with `min_count`) followed by a `then` step that
  share `join` fields within a window (e.g. failures then success from the same
  IP).
- `first_seen`: the first occurrence of a value combination **within this
  case's data**, after a baseline period (D29).
- `correlation`: findings of base rules (or events) chained by a join field
  within a window (D28).

Events without a reliable UTC time cannot be placed in windows. Time-based rules
skip them and the run notes how many were skipped.

Operators: `eq`, `neq`, `in`, `contains`, `startswith`, `endswith`, `regex`
(RE2, D31), `cidr`, `exists`, `gte`, `lte`. String comparisons ignore case
unless `ignore_case: false`. When a field holds a list (e.g. auditd paths), a
condition matches if any element matches.

Every rule declares its tunable `params`. Effective values are the rule
default or a per-run override; the run manifest records them.

Rule validation runs when rules load and in the tests: schema check, file name
matches ID, unique IDs, SemVer, `attack` IDs well-formed, declared parameters,
known fields, RE2-compatible regexes, Critical only in correlation rules, and
the wording rules of §11.4. Tests cover every rule with planted scenarios or
dedicated positive and negative cases.

### 9.2 v1 rule catalogue

| ID | Title (draft) | Type | ATT&CK | Base sev. |
|---|---|---|---|---|
| AUTH-001 | Possible SSH brute force from a single source | threshold | T1110.001 | Medium |
| AUTH-002 | Possible password spraying (one source, ≥ 10 accounts by default) | threshold (distinct users) | T1110.003 | Medium |
| AUTH-003 | Successful logon after repeated failures | sequence | T1110, T1078 | High |
| AUTH-004 | Windows logon failure burst (4625) | threshold | T1110 | Medium |
| AUTH-005 | Account lockout (4740) | match | T1110 | Low |
| AUTH-006 | Attempts against non-existent accounts | threshold | T1110 | Low |
| AUTH-007 | Successful logon from a source first seen in this case's data | first_seen | T1078 | Low |
| AUTH-008 | Remote interactive logon (4624 type 10) from public IP | match | T1021.001 | Medium |
| AUTH-009 | Logon with explicit credentials (4648) to a remote host | match | T1078, T1021 | Low |
| PRIV-001 | sudo attempt by a user not in sudoers | match | T1548.003 | Medium |
| PRIV-002 | Repeated sudo authentication failures | threshold | T1548.003 | Low |
| PRIV-003 | User added to a privileged group (4728/4732/4756; `usermod -aG sudo/wheel`) | match | T1098 | High |
| PRIV-004 | Special privileges assigned at logon to a rarely seen account (4672) | first_seen | T1078.002 | Low |
| PRIV-005 | Access to credential files (`/etc/shadow`, auditd) | match | T1003.008 | Medium |
| PERS-001 | Local account created (4720; useradd) | match | T1136.001 | Medium |
| PERS-002 | Service installed (7045 / 4697) | match | T1543.003 | Medium |
| PERS-003 | Scheduled task created (4698) | match | T1053.005 | Medium |
| PERS-004 | Crontab modified | match | T1053.003 | Low |
| PERS-005 | SSH `authorized_keys` modified (auditd) | match | T1098.004 | Medium |
| WEB-001 | Known scanner or attack-tool user agent | threshold | T1595.002 | Low |
| WEB-002 | SQL injection patterns in request | match + threshold | T1190 | Medium |
| WEB-003 | Path traversal / local file inclusion patterns | match | T1190 | Medium |
| WEB-004 | Cross-site scripting patterns | match | T1190 | Low |
| WEB-005 | Possible web shell interaction (successful requests to script files with command-like parameters) | match | T1505.003 | High |
| WEB-006 | 404 burst from one client (content discovery) | threshold | T1595.003 | Low |
| WEB-007 | Attack pattern request answered with HTTP 200 | match | T1190 | High |
| NET-001 | Possible port scan (one source, many destination ports or hosts) | threshold (distinct) | T1046 | Medium |
| NET-002 | Denied connection burst | threshold | T1046 | Low |
| NET-003 | Zeek notice passthrough | match | (per notice) | Informational |
| DEF-001 | Security or audit log cleared (Security 1102 / System 104) | match | T1070.001 | High |
| CORR-001 | Web attack activity followed by successful authentication from the same source | sequence (cross-source) | T1190, T1078 | High |
| CORR-002 | Account created or privileged soon after a suspicious logon on the same host | sequence (cross-source) | T1136, T1098 | High |

Severity **rationale** in each finding is generated from the base severity plus
every modifier that fired, each with its `reason`. Confidence works the same
way.

---

## 10. Correlation, linking, and timeline

### 10.1 Entities

Hosts, users and IP addresses are extracted from events into an entity index
(`entity_type`, `value`, `event_count`, `unplaced_count`, `first_seen_utc`,
`last_seen_utc`, `source_file_ids`; for IPs also `as_source` /
`as_destination`). A record collected twice counts once. The API adds the
findings of a run (latest successful by default) that name each entity, by
severity, and an entity detail lists those findings and the entity's
sessions. Values are kept as written; Windows account names that differ only
in case are separate entities.

### 10.2 Sessions and links

**Sessions** (D33) are event groups: events sharing `hostname` and
`session_id` (Windows logon ID, `sshd[PID]`, auditd `ses`, Zeek `uid`). The
summary lists start and end, accounts and addresses seen, event types, and
whether a closing event (logoff, session closed) was recorded. Session
membership shows in the event detail.

**Documented links** (D32) are stored only where the source defines them:

| Link type | Basis | Example |
|---|---|---|
| `parent_process_of` | Sysmon `ParentProcessGuid` → `ProcessGuid` | cmd.exe started by a web server process |
| `process_performed` | Sysmon `ProcessGuid` on network, file, registry and DNS events | The process that made a connection |

**Related events** are computed on request: events sharing `source_ip`,
`destination_ip`, `username` or `hostname` with the selected event within
±window (default 30 min). The response states the basis and that a shared
attribute and time does not show causation.

Duplicate groups (§8) complete the set of relationships.

### 10.3 Timeline

- One unified UTC timeline across all sources, filterable by host, user, IP,
  source file, category, event type, message text, time range, a finding, or
  a minimum severity of linked findings.
- Each row shows UTC time, the original timestamp text, the timezone
  assumption, source file, host, user, addresses, event type and outcome, a
  message preview, and **finding markers** (rule, severity, role) from a run.
- Paging uses a keyset cursor on (`timestamp_utc`, `source_file_id`,
  `record_index`), covered by one index, in both directions: every page costs
  the same (measured ≈ 5 ms deep into 1M events).
- The **unplaced lane** holds events without a reliable UTC time (§4.7), in file
  order, with its own cursor; it is never interleaved with placed events.
- A histogram endpoint returns counts per bucket (bucket sizes rounded to
  readable steps from 1 s to 30 days) and how many of those events are
  finding evidence, plus the unplaced count.
- Session view: a session's events in order (logon → activity → logoff).

---

## 11. Findings

### 11.1 Fields

| Field | Notes |
|---|---|
| `finding_id` | §3.1 |
| `fingerprint` | Matches the same finding across runs |
| `run_id` | |
| `rule_id`, `rule_version` | |
| `title`, `description` | Rendered from the rule template with the finding's values (escaped) |
| `severity` | `informational` · `low` · `medium` · `high` · `critical` |
| `severity_rationale` | List of reasons (base + fired modifiers) |
| `confidence` | `low` · `medium` · `high` |
| `confidence_rationale` | List of reasons |
| `evidence_strength` | `direct` · `corroborated` · `circumstantial` · `inferred` (§11.3) |
| `attack_techniques` | e.g. `["T1110.001"]` |
| `first_observed_utc`, `last_observed_utc` | Nullable if supporting events lack UTC times |
| `related_event_ids` | Via `finding_events`, with role |
| `source_file_ids` | Derived from related events, with file hash |
| `observed_evidence` | Structured facts: counts, distinct values, key fields, sample records (pointers to events, not copies) |
| `interpretation` | Hypothesis wording (§11.4) |
| `alternative_explanations` | From the rule, with instance-specific additions |
| `verification_steps` | From the rule |
| `status` | `open` · `investigating` · `confirmed` · `false_positive` · `resolved` |
| `analyst_notes` | Free text |
| `updated_by`, `updated_at` | |

### 11.2 Severity vs confidence vs evidence strength

These three ratings are kept separate and never merged into one score.

- **Severity:** how bad the activity would be *if the interpretation is
  correct*.
  - Critical: activity consistent with active compromise of privileged
    access or broad impact.
  - High: likely unauthorized access or privilege change.
  - Medium: attack activity with an unknown outcome.
  - Low: reconnaissance or a weak signal.
  - Informational: context only.
- **Confidence:** how likely the interpretation is correct given the data.
  It is lowered when supporting events are `partial`, when timestamps rely on
  analyst hints, or when the pattern has common benign causes.
- **Evidence strength:** what kind of evidence supports the finding.
  - `direct`: the records themselves show the behavior (e.g. 4720 account
    created).
  - `corroborated`: multiple independent sources agree.
  - `circumstantial`: shared attributes or timing only.
  - `inferred`: derived from absence or rarity (e.g. first-seen).

**Prioritization** (Findings list default sort): severity, then confidence,
then evidence strength, then `first_observed_utc`. The sort order is shown in
the UI and the report, not hidden behind a single opaque score.

### 11.3 Critical severity

No v1 rule has base severity Critical. Critical is reached only through
modifiers with direct evidence of both an access outcome and a privilege or
persistence outcome. Example: CORR-002 where the account privileged is
`root`/`Administrator`/`Domain Admins` *and* the preceding logon followed a
brute force. Even then the wording stays a hypothesis.

### 11.4 Language rules

Enforced by a lint test over all rule templates:
- Use: "consistent with", "possible", "indicates an attempt", "was observed".
- Never generate: "compromised", "attacker succeeded", "malicious user",
  "confirmed breach". The exception is the analyst's own notes and the
  `confirmed` status, which is the analyst's judgment and is labelled as such
  in the report.
- Outcomes are stated only as the log shows them: "A successful logon for
  `alice` from 203.0.113.5 was recorded at …", not "the attacker logged in".

### 11.5 Status across re-runs

When a new run produces a finding with a fingerprint seen before, the latest
analyst `status` and `analyst_notes` are carried forward and marked "carried
from `<run_id>`". Findings that disappear in a new run (e.g. after a threshold
change) remain visible in the old run and are listed as "not reproduced" in the
run comparison.

---

## 12. Analysis runs and reproducibility

### 12.1 Run record (`analysis_runs`)

- `run_id`, `case_id`, `started_at`, `finished_at`, `status`,
  `triggered_by`
- `mizar_version`, `event_schema_version`, `rule_format_version`
- `inputs`: list of `{source_file_id, sha256, verified_at, parser_name,
  parser_version, parse_result_id}`
- `rules`: list of `{rule_id, rule_version, rule_file_sha256}`
- `config`: effective parameters per rule, global settings (dedup policy,
  link windows), and timezone and year hints in effect
- `results`: finding counts by severity and rule, events evaluated, rule
  errors, duration
- `manifest_sha256`: hash of the canonical JSON of all the above

### 12.2 Determinism

- Events are processed in a stable order: `timestamp_utc NULLS LAST`, then
  `source_file_id`, then record locator.
- Findings are sorted by `(rule_id, first_observed_utc, fingerprint)` before
  sequence IDs are assigned.
- No randomness or wall-clock dependency in detection logic. Windows are
  anchored to event time, not run time.
- Same inputs, same software versions, and same config give identical findings
  (apart from `run_id` and run timestamps). A regression test asserts this.

---

## 13. Reporting and export

### 13.1 PDF report (ReportLab)

1. Cover: case name and reference, analyst, generation time (UTC), MIZAR
   version, run ID, manifest hash, a "Draft / Final" marking chosen at export.
2. Executive summary: counts by severity and status, top findings, time span
   covered, and key limitations. Text is generated from the data without
   overstatement.
3. Scope and evidence: table of source files (name, size, SHA-256, format,
   parser and version, ingestion time, verification result, parse stats) and
   coverage gaps (generic-parsed files, unplaced events, integrity failures).
4. Methodology: rule set and versions, thresholds, timezone assumptions,
   dedup policy, link windows.
5. Findings, ordered by priority. One section per finding with every §11.1
   field, plus an evidence table of supporting events (UTC time, original
   timestamp, host, user, IPs, message), with long evidence lists truncated to
   N events and the full list noted as available in the JSON export.
6. Timeline of finding-related events.
7. Entities: top hosts, users, and IPs involved in findings.
8. Limitations and assumptions.
9. Appendix: run manifest.

Export filters: include or exclude statuses (e.g. hide `false_positive`),
minimum severity. Every page shows a footer with the case ID, run ID, and page
number, and a small, low-contrast "MIZAR" watermark in the page corners (no
other branding). The PDF metadata records the generator version.

### 13.2 JSON and CSV

- JSON: one document with case, run manifest, source files, findings (full),
  and the referenced events (optionally all events, streamed as NDJSON for
  large cases). It embeds `event_schema_version`.
- CSV: `findings.csv`, `events.csv` (filtered view), `source_files.csv`.
  Formula-injection protection: cells starting with `= + - @ \t \r` are
  prefixed with `'`.

---

## 14. Error handling

### 14.1 Error taxonomy

Every error has a stable code, a human message, and optional details.

| Layer | Examples (codes) | Behavior |
|---|---|---|
| Request | `VALIDATION_ERROR`, `CASE_NOT_FOUND`, `FILE_TOO_LARGE`, `UNSUPPORTED_ARCHIVE` | 4xx with error envelope; nothing persisted |
| Evidence | `EVIDENCE_INTEGRITY_MISMATCH`, `STORAGE_FULL`, `HASH_IO_ERROR` | Upload rolled back (staging file removed). Integrity mismatches block runs |
| Archive | `ARCHIVE_PATH_TRAVERSAL`, `ARCHIVE_BOMB_SUSPECTED`, `ARCHIVE_MEMBER_LIMIT`, `ARCHIVE_ENCRYPTED` | Offending member skipped and recorded; other members continue |
| Parse – file | `FORMAT_UNDETECTED` (→ generic parser), `EVTX_CORRUPT_HEADER`, `ENCODING_UNSUPPORTED` | `ParseResult.status = failed`, records parsed so far kept |
| Parse – record | warning codes (§5.1) | Record kept with `partial`/`unparsed` |
| Detection | `RULE_INVALID` (startup), `RULE_RUNTIME_ERROR`, `REGEX_TIMEOUT` | Failing rule skipped and recorded in run `results.rule_errors`; run finishes as `succeeded_with_errors` |
| Job | `JOB_CRASHED`, `JOB_CANCELLED` | Worker heartbeat; stale `running` jobs marked failed at startup; idempotent retry |
| Report | `REPORT_RENDER_FAILED` | Error recorded; no partial file left in `exports/` |

### 14.2 API error envelope

```json
{
  "error": {
    "code": "FILE_TOO_LARGE",
    "message": "auth.log.gz exceeds the 2 GiB per-file limit.",
    "details": {"limit_bytes": 2147483648, "received_bytes": 3011456000},
    "request_id": "req_01JB..."
  }
}
```

### 14.3 Principles

- No silent failures. Every skipped record, member, rule, or file is counted
  and visible in the UI, the run record, and the report's limitations section.
- Unexpected exceptions are logged with the request or job ID. The API
  returns `INTERNAL_ERROR` without stack traces.
- Application logs are structured JSON, kept separate from evidence.
  Evidence content is never written to application logs.

---

## 15. Security of MIZAR itself

Uploaded logs are attacker-influenced input.

| Threat | Control |
|---|---|
| XSS via log content in UI | React text rendering only. No `dangerouslySetInnerHTML`. Strict CSP (`default-src 'self'`), no inline scripts |
| Markup injection in PDF | All text passes through an escaper before ReportLab `Paragraph`. No external resource loading |
| CSV formula injection | §13.2 |
| Zip-slip / path traversal | Member names normalized; absolute paths, `..`, symlinks, and device files rejected. Members are stored by hash, never by their names |
| Archive bombs | Limits on total uncompressed size (default 20 GiB per case), compression ratio (100:1 per member once it exceeds 10 MiB, configurable), member count (10,000), and nesting depth (3) |
| ReDoS | Rule regexes use `google-re2` (linear-time) where available, else a timeout. Parser regexes reviewed and anchored. Line length cap |
| Resource exhaustion | Per-file and per-case size limits, streaming everywhere, bounded batch sizes, disk-space pre-check |
| CSRF / drive-by from other websites | Binds `127.0.0.1` only. `Host` header allowlist (prevents DNS rebinding). Origin check plus a random per-launch API token injected into the SPA, required on state-changing requests |
| Malformed binary input (EVTX) | Parsing happens in the worker process, so a crash cannot take down the API. A per-file timeout is recorded as an error |
| Evidence tampering by the app | Evidence files are `0444` and only opened read-only. Hashes re-verified per run |
| Filename injection | Original names stored verbatim, displayed escaped, never used as filesystem paths |

---

## 16. API outline (v1)

```
POST   /api/cases                          create case
GET    /api/cases | /api/cases/{id}
POST   /api/cases/{id}/files?filename=…    raw body, one file per request; optional timezone_hint, year_hint, format_override
GET    /api/cases/{id}/files               source files + parse results
POST   /api/cases/{id}/files/{fid}/reparse format override / new hints → new ParseResult
POST   /api/cases/{id}/verify              re-hash all evidence (background job)
DELETE /api/cases/{id}                     body {"confirm_name": "<exact case name>"}
GET    /api/cases/{id}/jobs | POST /api/jobs/{jid}/cancel
GET    /api/formats                        format IDs for the override selector
GET    /api/cases/{id}/events              filter, paginate (cursor), search
GET    /api/events/{eid}                   normalized + raw record + links + groups
GET    /api/cases/{id}/timeline            buckets + page of events
GET    /api/cases/{id}/entities
POST   /api/cases/{id}/runs                start analysis run (optional param overrides)
GET    /api/cases/{id}/runs | /api/runs/{rid}
GET    /api/runs/{rid}/findings            sort/filter
GET    /api/findings/{fid}
PATCH  /api/findings/{fid}                 status, notes
POST   /api/runs/{rid}/exports             {format: pdf|json|csv, filters}
GET    /api/exports/{xid}                  download
GET    /api/jobs/{jid}                     progress
GET    /api/rules                          catalogue with versions and params
```

---

## 17. User interface sections

| Page | Content |
|---|---|
| Cases | List and create |
| Case overview | Evidence summary, ingestion status, latest run, findings by severity, time span, coverage gaps |
| Evidence | Upload (drag and drop, multiple, per-file timezone and year hints and format override), file table with hashes, detection scores, parse stats, warnings, verification status |
| Findings | Prioritized table with severity, confidence, and evidence strength shown separately; filters by status, rule, ATT&CK technique, entity |
| Finding detail | Every §11.1 field, evidence events with raw records, source file references with hashes, timeline mini-view, status and notes editor |
| Timeline | Unified timeline (§10.3) with histogram, filters, unplaced lane, session chains |
| Events | Full-text and field search over normalized events; event drawer shows normalized fields, raw record, locator, links, groups |
| Entities | Hosts, users, IPs, sessions with pivots |
| Runs | Run history, manifest viewer, diff between two runs |
| Export | PDF, JSON, CSV with filters |
| Rules | Read-only rule catalogue with parameters and descriptions |

Visual language: severity colors are always paired with a text label (never
color alone). Dark and light themes. All assets are bundled locally (no CDN).

---

## 18. Testing strategy

- **Synthetic fixture generator** (`fixtures/generator`): seeded and
  deterministic. Produces realistic background noise plus planted scenarios,
  for example:
  1. SSH brute force → success → sudo → useradd → usermod -aG sudo
  2. Windows password spray → 4624 type 10 → 4672 → 7045 service install →
     4698 scheduled task
  3. Web scan → SQLi → webshell POSTs answered with 200 → SSH logon from the
     same IP
  4. Port scan in firewall and Zeek logs
  5. Benign look-alikes (monitoring account with a stale password, authorized
     scanner) to measure false positives
  6. Hostile inputs: XSS payloads in user agents, zip-slip archive, oversize
     lines, invalid UTF-8, corrupt EVTX, DST-ambiguous local times, missing
     years

  Each scenario ships a `ground_truth.json` listing the expected findings.
- EVTX fixtures: native `.evtx` files cannot be generated easily on Linux.
  The generator writes EVTX-equivalent XML/JSON exports, and a small set of
  native `.evtx` test files is checked in (generated once on Windows, or taken
  from openly licensed samples). See open question Q4.
- **Unit tests:** each parser (golden files), each rule (positive and negative
  fixtures), timestamp policy edge cases.
- **Property tests** (Hypothesis): parsers never raise on random bytes and
  always preserve the raw record.
- **Integration tests:** upload → parse → run → export, determinism check
  (two runs give identical findings), integrity tamper test.
- **Performance test:** a 2 GB synthetic case. The original target of 50k
  events/s was an estimate and is not met by single-process Python parsing.
  Measured in Phase 2 (1M syslog lines, 97 MB, one worker): **~14k events/s**
  (≈ 12 min per 10M events), database ≈ 9.8× the log size, case-scoped field
  lookups ≈ 10 ms. Revised targets: ≥ 12k events/s for text formats, finding
  list < 500 ms, timeline page < 1 s (keyset pagination, Phase 4).
  Measured in Phase 3: a full analysis run (32 rules) over 1M events takes
  **~48 s** (≈ 8 min per 10M events); the finding list returns in < 10 ms.
  Measured in Phase 4 (1M events): case index build ≈ 12–15 s, timeline page
  ≈ 5–30 ms at any depth, histogram ≈ 0.6 s, entity list ≈ 35 ms.
- Tooling: pytest, ruff, mypy (strict on core packages), ESLint + TypeScript
  strict, Vitest, Playwright for a few end-to-end flows.

---

## 19. Delivery phases

Each phase ends runnable and tested, with a check-in before the next one.

| Phase | Deliverable |
|---|---|
| 0 | Repo skeleton, tooling, config, DB + migrations, error framework, Python 3.14 dependency check |
| 1 | Cases, upload, evidence store, hashing and verification, archive safety, format detection, jobs/worker, API |
| 2 | Event schema v1 (JSON Schema + docs), parsers (§7.2) + generic fallback, raw record storage, dedup groups, fixture generator |
| 3 | Rule engine, v1 rule catalogue, findings, analysis runs and manifest, determinism tests |
| 4 | Correlation: entities, links, sessions, timeline API |
| 5 | Frontend: all §17 pages |
| 6 | PDF / JSON / CSV export |
| 7 | Hardening pass (§15 verification), performance test, packaging (compose), user docs |

---

## 20. Review outcomes (2026-10-29)

| Q | Question | Outcome |
|---|---|---|
| Q1 | Log-cleared rule | Added as DEF-001 |
| Q2 | Size limits | Accepted (D11) |
| Q3 | Port | Accepted (D12) |
| Q4 | Native EVTX samples | Openly licensed samples first, Windows-generated later (D13) |
| Q5 | Branding | Corner watermark only (D14) |
| Q6 | Case deletion | Delete everything (D15) |
| Q7 | Licence | Apache-2.0 (D16) |
