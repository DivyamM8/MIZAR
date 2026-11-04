import { type FormEvent, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { Badge, Empty, ErrorBox, Loading, Mono, Section, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import { bytes, humanize, utc } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { Export, ExportFormat, FindingStatus, Run, Severity } from "../lib/types";
import { SEVERITIES, STATUSES } from "./FindingsPage";

const FINISHED = ["succeeded", "succeeded_with_errors"];
const FORMATS: [ExportFormat, string, string][] = [
  ["pdf", "PDF report", "Investigation report for reading and sharing: summary, scope, methodology, findings, timeline, limitations and run manifest."],
  ["json", "JSON", "Complete machine-readable record: case, run manifest, source files, findings and every referenced event with its original record."],
  ["csv", "CSV (ZIP)", "findings.csv, events.csv and source_files.csv for spreadsheets. Cells that a spreadsheet would run as formulas are prefixed with '."],
];
const pending = (rows: Export[]) => rows.some((e) => e.status === "queued" || e.status === "running");

export function ReportsPage() {
  const { caseId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const runs = useApi<Run[]>(`/api/cases/${encodeURIComponent(caseId)}/runs`);
  const finished = (runs.data ?? []).filter((r) => FINISHED.includes(r.status));
  const runId = params.get("run") ?? finished[0]?.run_id ?? null;

  if (runs.error) return <ErrorBox error={runs.error} />;
  if (!runs.data) return <Loading />;
  if (!finished.length) {
    return (
      <Section title="Reports and exports">
        <Empty>
          Reports are made from a finished analysis run. <Link to={`/cases/${encodeURIComponent(caseId)}/runs`}>Start a run</Link> first.
        </Empty>
      </Section>
    );
  }
  return (
    <div className="stack">
      <Section title="Reports and exports">
        <label className="row gap small">
          Analysis run
          <select value={runId ?? ""} onChange={(e) => setParams({ run: e.target.value })} aria-label="Analysis run">
            {finished.map((r) => (
              <option key={r.run_id} value={r.run_id}>
                {utc(r.created_at)} · {r.results?.findings_total ?? 0} findings · {r.run_id}
              </option>
            ))}
          </select>
        </label>
        <p className="muted small">
          Exports state the findings of the chosen run with their analyst status and notes at the moment the export is
          produced. Files are kept in the case&apos;s exports directory until deleted with the case.
        </p>
      </Section>
      {runId ? <RunExports key={runId} runId={runId} /> : null}
    </div>
  );
}

function RunExports({ runId }: { runId: string }) {
  const exports = useApi<Export[]>(`/api/runs/${encodeURIComponent(runId)}/exports`, undefined, { pollMs: 1000, pollWhile: pending });
  return (
    <>
      <NewExport runId={runId} onStarted={exports.reload} />
      <Section title="Exports of this run">
        <ErrorBox error={exports.error} />
        {!exports.data && !exports.error ? <Loading /> : null}
        {exports.data && !exports.data.length ? <Empty>No exports yet.</Empty> : null}
        {exports.data?.length ? <ExportTable rows={exports.data} onChange={exports.reload} /> : null}
      </Section>
    </>
  );
}

function NewExport({ runId, onStarted }: { runId: string; onStarted: () => void }) {
  const [format, setFormat] = useState<ExportFormat>("pdf");
  const [statuses, setStatuses] = useState<FindingStatus[]>([...STATUSES]);
  const [error, setError] = useState<Error>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const body: Record<string, unknown> = {
      format,
      statuses,
      min_severity: String(form.get("min_severity")) as Severity,
    };
    if (format === "pdf") {
      body.marking = String(form.get("marking"));
      body.evidence_limit = Number(form.get("evidence_limit"));
    } else {
      body.all_events = form.get("all_events") === "on";
    }
    setBusy(true);
    try {
      await api(`/api/runs/${encodeURIComponent(runId)}/exports`, { method: "POST", body });
      setError(undefined);
      onStarted();
    } catch (exc) {
      setError(exc as Error);
    } finally {
      setBusy(false);
    }
  }

  const toggle = (status: FindingStatus) =>
    setStatuses((current) => (current.includes(status) ? current.filter((s) => s !== status) : STATUSES.filter((s) => s === status || current.includes(s))));

  return (
    <Section title="New export">
      <form onSubmit={submit} className="stack">
        <fieldset className="choices" aria-label="Format">
          {FORMATS.map(([value, title, text]) => (
            <label key={value} className={`choice${format === value ? " selected" : ""}`}>
              <input type="radio" name="format" value={value} checked={format === value} onChange={() => setFormat(value)} />
              <strong>{title}</strong>
              <span className="muted small">{text}</span>
            </label>
          ))}
        </fieldset>
        <div className="form">
          <label>
            Minimum severity
            <select name="min_severity" defaultValue="informational">
              {[...SEVERITIES].reverse().map((s) => (
                <option key={s} value={s}>
                  {humanize(s)}
                  {s === "informational" ? " (all)" : " and above"}
                </option>
              ))}
            </select>
          </label>
          {format === "pdf" ? (
            <>
              <label>
                Marking
                <select name="marking" defaultValue="draft">
                  <option value="draft">Draft</option>
                  <option value="final">Final</option>
                </select>
              </label>
              <label>
                Supporting events shown per finding
                <input name="evidence_limit" type="number" min={1} max={500} defaultValue={10} />
              </label>
            </>
          ) : (
            <label className="inline-check">
              <span>
                <input type="checkbox" name="all_events" /> Include every event of the run&apos;s files, not only finding
                evidence
              </span>
            </label>
          )}
          <div className="wide">
            <div className="muted small">Include findings with status</div>
            <div className="row gap">
              {STATUSES.map((s) => (
                <label key={s} className="inline-check">
                  <span>
                    <input type="checkbox" checked={statuses.includes(s)} onChange={() => toggle(s)} /> {humanize(s)}
                  </span>
                </label>
              ))}
            </div>
          </div>
        </div>
        <div className="row gap">
          <button type="submit" className="primary" disabled={busy || !statuses.length}>
            Create export
          </button>
          {!statuses.length ? <span className="muted small">Choose at least one status.</span> : null}
        </div>
        <ErrorBox error={error} />
      </form>
    </Section>
  );
}

function describe(row: Export): string {
  const o = row.options;
  const parts: string[] = [];
  if (o.statuses.length < STATUSES.length) parts.push(o.statuses.map(humanize).join(", "));
  if (o.min_severity !== "informational") parts.push(`${humanize(o.min_severity)}+`);
  if (row.format === "pdf") parts.push(humanize(o.marking), `${o.evidence_limit} events/finding`);
  else if (o.all_events) parts.push("all events");
  return parts.join(" · ") || "all findings";
}

function contents(row: Export): string {
  const s = row.summary;
  if (!s) return "";
  const parts = [`${s.findings ?? 0} findings`];
  if (s.pages) parts.push(`${s.pages} pages`);
  if (s.all_events !== undefined) parts.push(`${s.all_events} events`);
  else if (s.events !== undefined && row.format !== "pdf") parts.push(`${s.events} events`);
  return parts.join(", ");
}

function ExportTable({ rows, onChange }: { rows: Export[]; onChange: () => void }) {
  const [error, setError] = useState<Error>();
  async function act(path: string, method: string) {
    try {
      await api(path, { method });
      setError(undefined);
      onChange();
    } catch (exc) {
      setError(exc as Error);
    }
  }
  return (
    <>
      <ErrorBox error={error} />
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Requested (UTC)</th>
              <th>Format</th>
              <th>Options</th>
              <th>Status</th>
              <th>Contents</th>
              <th>Size</th>
              <th>SHA-256</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.export_id}>
                <td className="nowrap" title={row.export_id}>
                  {utc(row.created_at)}
                </td>
                <td>
                  <Badge>{row.format.toUpperCase()}</Badge>
                </td>
                <td className="small">{describe(row)}</td>
                <td>
                  <StatusBadge status={row.status} />
                  {row.error_message ? <div className="small">{row.error_message}</div> : null}
                </td>
                <td className="small">{contents(row)}</td>
                <td className="nowrap">{row.size_bytes !== null ? bytes(row.size_bytes) : "—"}</td>
                <td>{row.sha256 ? <Mono title={row.sha256}>{row.sha256}</Mono> : "—"}</td>
                <td className="nowrap">
                  {row.status === "succeeded" ? (
                    <a className="button primary" href={`/api/exports/${encodeURIComponent(row.export_id)}/download`} download>
                      Download
                    </a>
                  ) : null}{" "}
                  {(row.status === "queued" || row.status === "running") && row.job_id ? (
                    <button type="button" onClick={() => act(`/api/jobs/${encodeURIComponent(row.job_id ?? "")}/cancel`, "POST")}>
                      Cancel
                    </button>
                  ) : (
                    <button type="button" onClick={() => act(`/api/exports/${encodeURIComponent(row.export_id)}`, "DELETE")}>
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">The SHA-256 identifies the exact file you downloaded; record it with the report.</p>
    </>
  );
}
