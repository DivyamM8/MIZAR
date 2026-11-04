import { type DragEvent, type FormEvent, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { Badge, ErrorBox, Empty, KeyValue, Loading, Mono, Section, StatusBadge } from "../components/ui";
import { api, ApiError, uploadFile } from "../lib/api";
import { bytes, count, utc } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { FormatInfo, Job, SourceFile } from "../lib/types";
import { TimezoneOptions } from "./CasesPage";

interface Queued {
  file: File;
  progress: number;
  state: "waiting" | "uploading" | "done" | "failed";
  error?: string;
}

const pending = (jobs: Job[]) => jobs.some((j) => j.status === "queued" || j.status === "running");

export function EvidencePage() {
  const { caseId = "" } = useParams();
  const base = `/api/cases/${encodeURIComponent(caseId)}`;
  const jobs = useApi<Job[]>(`${base}/jobs`, undefined, { pollMs: 1500, pollWhile: pending });
  const busy = jobs.data ? pending(jobs.data) : false;
  const files = useApi<SourceFile[]>(`${base}/files`, { _: busy ? `${jobs.data?.length}-busy` : `${jobs.data?.length}` });
  const formats = useApi<FormatInfo[]>("/api/formats");
  return (
    <div className="stack">
      <Upload caseId={caseId} formats={formats.data ?? []} onUploaded={jobs.reload} />
      <Section
        title="Evidence files"
        actions={
          <>
            {busy ? <Badge tone="info">processing…</Badge> : null}
            <button type="button" onClick={() => api(`${base}/verify`, { method: "POST" }).then(jobs.reload)}>
              Verify all hashes
            </button>
          </>
        }
      >
        <ErrorBox error={files.error} />
        {!files.data && !files.error ? <Loading /> : null}
        {files.data && !files.data.length ? <Empty>No evidence uploaded yet.</Empty> : null}
        {files.data?.length ? <FileTable files={files.data} formats={formats.data ?? []} onChanged={jobs.reload} /> : null}
      </Section>
    </div>
  );
}

function Upload({ caseId, formats, onUploaded }: { caseId: string; formats: FormatInfo[]; onUploaded: () => void }) {
  const [queue, setQueue] = useState<Queued[]>([]);
  const [hover, setHover] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const hints = useRef<HTMLFormElement>(null);

  async function run(selected: File[]) {
    const form = new FormData(hints.current ?? undefined);
    const params = {
      timezone_hint: String(form.get("timezone_hint") ?? "").trim() || undefined,
      year_hint: String(form.get("year_hint") ?? "").trim() || undefined,
      format_override: String(form.get("format_override") ?? "") || undefined,
    };
    const items: Queued[] = selected.map((file) => ({ file, progress: 0, state: "waiting" }));
    setQueue((current) => [...current.filter((q) => q.state !== "done"), ...items]);
    for (const item of items) {
      const update = (patch: Partial<Queued>) =>
        setQueue((current) => current.map((q) => (q.file === item.file ? { ...q, ...patch } : q)));
      update({ state: "uploading" });
      try {
        await uploadFile(caseId, item.file, params, (progress) => update({ progress }));
        update({ state: "done", progress: 1 });
        onUploaded();
      } catch (exc) {
        update({ state: "failed", error: exc instanceof ApiError ? `${exc.code}: ${exc.message}` : String(exc) });
      }
    }
  }

  function drop(event: DragEvent) {
    event.preventDefault();
    setHover(false);
    void run([...event.dataTransfer.files]);
  }

  return (
    <Section title="Upload evidence">
      <form ref={hints} className="form" onSubmit={(e: FormEvent) => e.preventDefault()}>
        <label>
          Timezone of logs without an offset
          <input name="timezone_hint" list="timezones" placeholder="case default" maxLength={64} />
        </label>
        <label>
          Year of the first record (classic syslog has no year)
          <input name="year_hint" type="number" min={1970} max={2100} placeholder="e.g. 2026" />
        </label>
        <label>
          Format
          <select name="format_override" defaultValue="">
            <option value="">Detect from content</option>
            {formats.map((f) => (
              <option key={f.format_id} value={f.format_id}>
                {f.label}
              </option>
            ))}
          </select>
        </label>
        <TimezoneOptions />
      </form>
      <div
        className={`dropzone${hover ? " hover" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setHover(true);
        }}
        onDragLeave={() => setHover(false)}
        onDrop={drop}
        onClick={() => input.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
      >
        Drop log files or archives here, or click to choose. Files are hashed and stored read-only; archives
        (zip, tar, gz, bz2, xz) are expanded into separate evidence records.
        <input
          ref={input}
          type="file"
          multiple
          hidden
          onChange={(e) => {
            void run([...(e.target.files ?? [])]);
            e.target.value = "";
          }}
        />
      </div>
      {queue.length ? (
        <ul className="plain uploads">
          {queue.map((item, n) => (
            <li key={n} className={`upload ${item.state}`}>
              <span>{item.file.name}</span> <span className="muted small">{bytes(item.file.size)}</span>{" "}
              {item.state === "uploading" ? <progress max={1} value={item.progress} /> : null}
              {item.state === "done" ? <Badge tone="ok">stored</Badge> : null}
              {item.state === "waiting" ? <Badge>waiting</Badge> : null}
              {item.state === "failed" ? <span className="error-inline">{item.error}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
    </Section>
  );
}

function FileTable({ files, formats, onChanged }: { files: SourceFile[]; formats: FormatInfo[]; onChanged: () => void }) {
  const [open, setOpen] = useState<string | null>(() => (window.location.hash ? window.location.hash.slice(1) : null));
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>File</th>
            <th>Size</th>
            <th>SHA-256</th>
            <th>Format</th>
            <th>Status</th>
            <th>Integrity</th>
            <th>Parse</th>
            <th>Records</th>
            <th>Messages</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file) => {
            const warnings = file.validation_messages.length + Object.keys(file.parse?.file_problems?.counts ?? {}).length;
            return (
              <FileRows
                key={file.source_file_id}
                file={file}
                warnings={warnings}
                expanded={open === file.source_file_id}
                onToggle={() => setOpen(open === file.source_file_id ? null : file.source_file_id)}
                formats={formats}
                onChanged={onChanged}
              />
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function FileRows({
  file,
  warnings,
  expanded,
  onToggle,
  formats,
  onChanged,
}: {
  file: SourceFile;
  warnings: number;
  expanded: boolean;
  onToggle: () => void;
  formats: FormatInfo[];
  onChanged: () => void;
}) {
  const parse = file.parse;
  const label = formats.find((f) => f.format_id === file.effective_format)?.label ?? file.effective_format;
  return (
    <>
      <tr id={file.source_file_id} className="clickable" onClick={onToggle}>
        <td>{file.sequence}</td>
        <td className="indent" data-depth={file.archive_depth}>
          {file.archive_depth ? "↳ " : ""}
          {file.archive_member_path ?? file.original_filename}
        </td>
        <td className="nowrap">{bytes(file.size_bytes)}</td>
        <td>
          <Mono title={file.sha256}>{file.sha256.slice(0, 16)}…</Mono>
        </td>
        <td>
          {file.container_type ? <Badge>{file.container_type} archive</Badge> : label ?? "—"}
          {file.format_override ? <Badge tone="info">override</Badge> : null}
        </td>
        <td>
          <StatusBadge status={file.status} />
        </td>
        <td>
          <StatusBadge status={file.integrity_status} />
        </td>
        <td>{parse ? <StatusBadge status={parse.status} /> : "—"}</td>
        <td className="nowrap">
          {parse ? (
            <>
              {count(parse.records_total)}
              {parse.records_partial || parse.records_unparsed ? (
                <span className="muted small"> ({parse.records_partial} partial, {parse.records_unparsed} unparsed)</span>
              ) : null}
            </>
          ) : (
            "—"
          )}
        </td>
        <td>{warnings ? <Badge tone="warn">{warnings}</Badge> : <span className="muted">—</span>}</td>
      </tr>
      {expanded ? (
        <tr className="detail-row">
          <td colSpan={10}>
            <FileDetail file={file} formats={formats} onChanged={onChanged} />
          </td>
        </tr>
      ) : null}
    </>
  );
}

function FileDetail({ file, formats, onChanged }: { file: SourceFile; formats: FormatInfo[]; onChanged: () => void }) {
  const [error, setError] = useState<Error>();
  const [queued, setQueued] = useState(false);
  const parse = file.parse;
  async function reparse(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const year = String(form.get("year_hint") ?? "").trim();
    try {
      await api(`/api/cases/${encodeURIComponent(file.case_id)}/files/${encodeURIComponent(file.source_file_id)}/reparse`, {
        method: "POST",
        body: {
          timezone_hint: String(form.get("timezone_hint") ?? "").trim() || null,
          year_hint: year ? Number(year) : null,
          format_override: String(form.get("format_override") ?? "") || null,
        },
      });
      setQueued(true);
      setError(undefined);
      onChanged();
    } catch (exc) {
      setError(exc as Error);
    }
  }
  return (
    <div className="grid-2">
      <div>
        <KeyValue
          rows={[
            ["Source file ID", <Mono key="i">{file.source_file_id}</Mono>],
            ["SHA-256", <Mono key="h">{file.sha256}</Mono>],
            ["Uploaded", `${utc(file.ingestion_time)} by ${file.uploaded_by}`],
            ["Last verified", utc(file.last_verified_at)],
            ["Encoding", file.encoding],
            ["Detected", file.detected_format ? `${file.detected_format} (${file.detection_confidence ?? "fallback"})` : null],
            ["Hints", `timezone ${file.timezone_hint ?? "none"}, year ${file.year_hint ?? "none"}`],
            ["Parser", parse ? `${parse.parser_name} ${parse.parser_version}` : null],
            ["Time span (UTC)", parse?.first_timestamp_utc ? `${utc(parse.first_timestamp_utc)} – ${utc(parse.last_timestamp_utc)}` : null],
            ["Parse error", parse?.error_code ? `${parse.error_code}: ${parse.error_message}` : null],
          ]}
        />
        {file.validation_messages.length ? (
          <>
            <h4>Validation messages</h4>
            <ul>
              {file.validation_messages.map((m, n) => (
                <li key={n}>
                  <Badge tone={m.level === "error" ? "bad" : "warn"}>{m.code}</Badge> {m.message}
                  {Object.keys(m.details).length ? <span className="muted small"> {JSON.stringify(m.details)}</span> : null}
                </li>
              ))}
            </ul>
          </>
        ) : null}
        {parse && Object.keys(parse.warnings_by_code).length ? (
          <>
            <h4>Record warnings</h4>
            <p>
              {Object.entries(parse.warnings_by_code).map(([code, n]) => (
                <span key={code}>
                  <Badge tone="warn">{code}</Badge> {n}{" "}
                </span>
              ))}
            </p>
          </>
        ) : null}
        {parse?.file_problems?.counts && Object.keys(parse.file_problems.counts).length ? (
          <>
            <h4>File problems</h4>
            <ul>
              {Object.entries(parse.file_problems.counts).map(([code, n]) => (
                <li key={code}>
                  <Badge tone="bad">{code}</Badge> ×{n}
                </li>
              ))}
            </ul>
          </>
        ) : null}
      </div>
      <div>
        {file.detection_candidates?.length ? (
          <>
            <h4>Detection candidates</h4>
            <table className="compact">
              <tbody>
                {file.detection_candidates.map((c) => (
                  <tr key={c.format_id}>
                    <td>{c.format_id}</td>
                    <td>{c.score}</td>
                    <td className="small">{c.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        ) : null}
        {file.status === "ready" ? (
          <>
            <h4>Parse again</h4>
            <form className="form" onSubmit={reparse}>
              <label>
                Timezone <input name="timezone_hint" list="timezones" defaultValue={file.timezone_hint ?? ""} />
              </label>
              <label>
                Year <input name="year_hint" type="number" min={1970} max={2100} defaultValue={file.year_hint ?? ""} />
              </label>
              <label>
                Format
                <select name="format_override" defaultValue={file.format_override ?? ""}>
                  <option value="">Detected ({file.detected_format})</option>
                  {formats.map((f) => (
                    <option key={f.format_id} value={f.format_id}>
                      {f.label}
                    </option>
                  ))}
                </select>
              </label>
              <ErrorBox error={error} />
              <div>
                <button type="submit">Re-parse</button>{" "}
                {queued ? <span className="muted">Queued. Re-run the analysis afterwards to refresh findings.</span> : null}
              </div>
            </form>
            <p>
              <Link to={`../events?source_file_id=${encodeURIComponent(file.source_file_id)}`} relative="path">
                Events from this file
              </Link>
            </p>
          </>
        ) : null}
      </div>
    </div>
  );
}
