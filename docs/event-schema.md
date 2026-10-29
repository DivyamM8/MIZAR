# Normalized event schema

Version **1.0.0**. Generated from `backend/mizar/schemas/event.v1.json` by `python -m mizar.events.schema_docs`; do not edit by hand.

Normalized record produced from one original log record. Version 1.0.0. Fields that a source does not provide are null; parsers never invent values. The original bytes stay in the immutable evidence file at original_record_reference; formats that cannot be read back by offset (EVTX, XML/JSON/CSV exports, UTF-16 text) also keep a stored copy. Storage holds schema_version, parser_version and ingestion_time once per parse result; the API presents them on every event.

| Field | Type | Description |
|---|---|---|
| `event_id` | string, uuid | Stable identifier: UUIDv5 of case, source file, content hash and record locator. Re-parsing the same source file yields the same IDs. |
| `schema_version` | constant `1.0.0` | Version of this schema the event conforms to. |
| `case_id` | string | Case the event belongs to. |
| `source_file_id` | string | Source file (evidence record) the original record came from. |
| `parse_result_id` | string | Parse run that produced this event (parser, version and hints used). |
| `source_type` | enum: `linux_auth`, `syslog`, `journald`, `auditd`, `windows_evtx`, `windows_evtx_export`, `web_access`, `zeek`, `firewall`, `cef`, `leef`, `proxy`, `generic` | Kind of source the record came from. |
| `parser_name` | string | Parser that produced the event, e.g. linux.sshd. |
| `parser_version` | string | SemVer of the parser. |
| `record_index` | integer | 0-based position of the record within its source file, in parse order. |
| `original_record_reference` | object | Locator of the original record within the source file: line numbers (1-based) and byte offsets for text, the record ID for EVTX, item or row indexes for structured exports. |
| `record_hash` | string | SHA-256 of the raw record bytes. Used to find the same record collected twice. |
| `timestamp_original` | string (nullable) | Timestamp exactly as written in the record. |
| `timestamp_utc` | string (nullable), date-time | UTC time, only when conversion is reliable (see timezone_assumption). Null otherwise; never guessed. |
| `timestamp_precision` | enum: `s`, `ms`, `us`, `ns` (nullable) | Precision of the original timestamp. |
| `timezone_assumption` | string | Basis for timestamp_utc: explicit offset in the record, UTC by format definition, analyst-supplied IANA zone, or none (timestamp_utc is null). |
| `hostname` | string (nullable) | Host that generated the record, as written. |
| `username` | string (nullable) | Primary subject or target account of the event, as written (case preserved). See extra for other accounts involved. |
| `user_domain` | string (nullable) | Windows domain or realm of username. |
| `source_ip` | string (nullable) | Validated IPv4/IPv6 address. Invalid values are null and kept in extra with an invalid_ip warning. |
| `destination_ip` | string (nullable) | Validated IPv4/IPv6 address. |
| `source_port` | integer (nullable) |  |
| `destination_port` | integer (nullable) |  |
| `protocol` | string (nullable) | Lowercase protocol, e.g. tcp, udp, ssh, http. |
| `event_category` | enum: `authentication`, `account_management`, `privilege`, `process`, `service`, `scheduled_task`, `file`, `network`, `web`, `system`, `other` (nullable) | Broad category. |
| `event_type` | string (nullable) | Normalized action, e.g. logon, logon_failed, user_created, http_request, connection_denied. |
| `event_outcome` | enum: `success`, `failure`, `unknown` (nullable) | Outcome as recorded by the source. Null when not applicable. |
| `event_code` | string (nullable) | Native code: Windows EventID, HTTP status, auditd record type, CEF signature ID. |
| `process_name` | string (nullable) | Process that logged or performed the action. |
| `process_id` | integer (nullable) |  |
| `session_id` | string (nullable) | Key that links events of one session: Windows logon ID, sshd process, Zeek uid, auditd session. |
| `message` | string (nullable) | Human-readable message as in the source, not rewritten. |
| `extra` | object | Source-specific fields not in the core schema. |
| `parsing_status` | enum: `parsed`, `partial`, `unparsed` | parsed: all applicable fields extracted; partial: some fields could not be extracted or validated; unparsed: kept as raw only. |
| `parse_warnings` | array | Machine-readable warning codes, e.g. timestamp_unparsed, invalid_ip, year_rollover_inferred. |
| `ingestion_time` | string, date-time | When MIZAR created the event (UTC). |

Every field is always present; fields a source does not provide are `null`.
