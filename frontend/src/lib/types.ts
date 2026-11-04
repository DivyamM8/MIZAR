// Mirrors backend/mizar/api/schemas.py. Times are ISO 8601 UTC strings.

export type Severity = "informational" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type FindingStatus = "open" | "investigating" | "confirmed" | "false_positive" | "resolved";

export interface Case {
  case_id: string;
  name: string;
  analyst_name: string;
  reference: string | null;
  description: string | null;
  default_timezone_hint: string | null;
  file_count: number;
  created_at: string;
  updated_at: string;
}

export interface ValidationMessage {
  level: string;
  code: string;
  message: string;
  details: Record<string, unknown>;
}

export interface ParseResult {
  parse_result_id: string;
  format_id: string;
  parser_name: string;
  parser_version: string;
  timezone_hint: string | null;
  year_hint: number | null;
  status: string;
  started_at: string;
  finished_at: string | null;
  records_total: number;
  records_parsed: number;
  records_partial: number;
  records_unparsed: number;
  warnings_by_code: Record<string, number>;
  file_problems: { counts?: Record<string, number>; samples?: { code: string; message: string }[] };
  first_timestamp_utc: string | null;
  last_timestamp_utc: string | null;
  error_code: string | null;
  error_message: string | null;
}

export interface SourceFile {
  source_file_id: string;
  case_id: string;
  sequence: number;
  parent_file_id: string | null;
  archive_member_path: string | null;
  archive_depth: number;
  sha256: string;
  original_filename: string;
  size_bytes: number;
  uploaded_by: string;
  ingestion_time: string;
  container_type: string | null;
  detected_format: string | null;
  detection_confidence: number | null;
  detection_candidates: { format_id: string; score: number; reason: string }[] | null;
  encoding: string | null;
  format_override: string | null;
  effective_format: string | null;
  timezone_hint: string | null;
  year_hint: number | null;
  status: string;
  integrity_status: string;
  last_verified_at: string | null;
  validation_messages: ValidationMessage[];
  parse: ParseResult | null;
}

export interface Job {
  job_id: string;
  case_id: string | null;
  job_type: string;
  status: string;
  progress: number;
  progress_message: string | null;
  result: Record<string, unknown> | null;
  error_code: string | null;
  error_message: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface FormatInfo {
  format_id: string;
  label: string;
  family: string;
}

export interface FindingMarker {
  finding_id: string;
  rule_id: string;
  severity: Severity;
  role: string;
}

export interface EventRow {
  event_id: string;
  timestamp_utc: string | null;
  timestamp_original: string | null;
  timezone_assumption: string;
  source_file_id: string;
  source_filename?: string | null;
  record_index: number;
  source_type?: string;
  hostname: string | null;
  username: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  event_category?: string | null;
  event_type: string | null;
  event_outcome: string | null;
  event_code: string | null;
  session_id?: string | null;
  parsing_status?: string;
  message: string | null;
  message_truncated?: boolean;
  findings?: FindingMarker[];
}

export interface EventFull extends EventRow {
  schema_version: string;
  case_id: string;
  parse_result_id: string;
  source_type: string;
  parser_name: string;
  parser_version: string;
  original_record_reference: Record<string, unknown>;
  record_hash: string;
  timestamp_precision: string | null;
  user_domain: string | null;
  source_port: number | null;
  protocol: string | null;
  process_name: string | null;
  process_id: number | null;
  extra: Record<string, unknown>;
  parsing_status: string;
  parse_warnings: string[];
  ingestion_time: string;
}

export interface EventDetail extends EventFull {
  raw_record: {
    source: string;
    encoding: string;
    size_bytes: number;
    text: string;
    lossless: boolean;
    verified: boolean | null;
    display_truncated: boolean;
  } | null;
  groups: { group_id: string; group_type: string; member_count: number; members: { event_id: string; source_file_id: string }[] }[];
  links: { outgoing: EventLink[]; incoming: EventLink[] };
}

export interface EventLink {
  link_type: string;
  basis: Record<string, unknown>;
  event_id: string;
}

export interface EventPage {
  items: EventFull[];
  total: number;
  limit: number;
  offset: number;
}

export interface TimelinePage {
  lane: "placed" | "unplaced";
  run_id: string | null;
  items: EventRow[];
  next_cursor: string | null;
  prev_cursor: string | null;
}

export interface Histogram {
  start_utc: string | null;
  end_utc: string | null;
  bucket_seconds: number | null;
  buckets: { start_utc: string; count: number; finding_events: number }[];
  placed: number;
  unplaced: number;
}

export interface Run {
  run_id: string;
  case_id: string;
  job_id: string | null;
  status: string;
  triggered_by: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  overrides: Record<string, Record<string, unknown>>;
  manifest_sha256: string | null;
  inputs_fingerprint: string | null;
  results: RunResults | null;
  error_code: string | null;
  error_message: string | null;
}

export interface RunResults {
  findings_total?: number;
  findings_by_severity?: Partial<Record<Severity, number>>;
  findings_by_rule?: Record<string, number>;
  events_evaluated?: number;
  rule_errors?: { rule_id: string; error: string; message: string }[];
  rule_notes?: Record<string, Record<string, unknown>>;
  coverage_gaps?: { source_file_id: string | null; filename: string | null; reason: string }[];
  evidence_verification?: Record<string, number>;
  duration_seconds?: number;
  error_details?: Record<string, unknown>;
}

export interface RunDetail extends Run {
  manifest: {
    inputs: Record<string, unknown>[];
    rules: { rule_id: string; rule_version: string; rule_file_sha256: string }[];
    params: Record<string, Record<string, unknown>>;
    config: Record<string, unknown>;
    mizar_version: string;
    event_schema_version: string;
    rule_format_version: string;
  } | null;
}

export interface FindingSummary {
  finding_id: string;
  run_id: string;
  case_id: string;
  fingerprint: string;
  rule_id: string;
  rule_version: string;
  title: string;
  description: string;
  severity: Severity;
  severity_rationale: string[];
  confidence: Confidence;
  confidence_rationale: string[];
  evidence_strength: string;
  attack_techniques: string[];
  first_observed_utc: string | null;
  last_observed_utc: string | null;
  entities: Record<string, unknown>;
  interpretation: string;
  source_files: { source_file_id: string; sha256: string | null; filename: string | null }[];
  related_finding_ids: string[];
  event_count: number;
  status: FindingStatus;
  analyst_notes: string | null;
  status_carried_from: string | null;
  updated_by: string | null;
  updated_at: string | null;
}

export interface FindingDetail extends FindingSummary {
  observed_evidence: Record<string, unknown>;
  alternative_explanations: string[];
  verification_steps: string[];
  evidence_events: (EventRow & { role: string; present: boolean })[];
  evidence_total: number;
  evidence_offset: number;
}

export interface Rule {
  rule_id: string;
  version: string;
  status: string;
  type: string;
  title: string;
  description: string;
  attack: string[];
  base_severity: Severity;
  base_confidence: Confidence;
  evidence_strength: string;
  params: Record<string, { type: string; default: unknown; description: string }>;
}

export interface Entity {
  entity_type: "host" | "user" | "ip";
  value: string;
  event_count: number;
  unplaced_count: number;
  first_seen_utc: string | null;
  last_seen_utc: string | null;
  as_source: number | null;
  as_destination: number | null;
  source_file_ids: string[];
  finding_count: number;
  findings_by_severity: Partial<Record<Severity, number>>;
  highest_severity: Severity | null;
}

export interface EntityPage {
  items: Entity[];
  total: number;
  run_id: string | null;
  index: { status: string; job_id: string | null; built_at: string | null };
}

export interface Session {
  session_group_id: string;
  case_id: string;
  hostname: string | null;
  session_id: string | null;
  event_count: number;
  first_utc: string | null;
  last_utc: string | null;
  usernames: string[];
  source_ips: string[];
  event_types: [string, number][];
  first_event_type: string | null;
  closed: boolean;
  events_without_utc: number;
  source_file_ids: string[];
}

export interface EntityDetail extends Entity {
  run_id: string | null;
  findings: { finding_id: string; rule_id: string; title: string; severity: Severity; confidence: Confidence }[];
  sessions: Session[];
}

export interface SessionDetail extends Session {
  events: EventRow[];
  offset: number;
}

export interface RelatedEvents {
  basis: Record<string, unknown>;
  note: string;
  items: EventRow[];
}

export type ExportFormat = "pdf" | "json" | "csv";

export interface ExportOptions {
  statuses: FindingStatus[];
  min_severity: Severity;
  marking: "draft" | "final";
  evidence_limit: number;
  all_events: boolean;
}

export interface Export {
  export_id: string;
  case_id: string;
  run_id: string;
  job_id: string | null;
  format: ExportFormat;
  status: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  options: ExportOptions;
  requested_by: string;
  created_at: string;
  finished_at: string | null;
  media_type: string | null;
  size_bytes: number | null;
  sha256: string | null;
  summary: {
    findings?: number;
    events?: number;
    all_events?: number;
    pages?: number;
    generated_at?: string;
    findings_excluded?: { by_status: number; by_severity: number };
  } | null;
  error_code: string | null;
  error_message: string | null;
}
