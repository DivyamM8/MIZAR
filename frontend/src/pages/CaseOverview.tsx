import { type FormEvent, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { ErrorBox, KeyValue, Loading, Section, SeverityBadge, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import { count, utc } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { Case, EventPage, Histogram, Job, Run, Severity, SourceFile } from "../lib/types";
import { TimezoneOptions } from "./CasesPage";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];

/** First and last placed event across files, from their parse results (not histogram bounds). */
function timeSpan(files: SourceFile[]): string {
  const firsts = files.map((f) => f.parse?.first_timestamp_utc).filter((t): t is string => Boolean(t)).sort();
  const lasts = files.map((f) => f.parse?.last_timestamp_utc).filter((t): t is string => Boolean(t)).sort();
  return firsts.length ? `${utc(firsts[0])} – ${utc(lasts[lasts.length - 1])}` : "—";
}
const pending = (jobs: Job[]) => jobs.some((j) => j.status === "queued" || j.status === "running");

export function CaseOverview() {
  const { caseId = "" } = useParams();
  const base = `/api/cases/${encodeURIComponent(caseId)}`;
  const theCase = useApi<Case>(base);
  const jobs = useApi<Job[]>(`${base}/jobs`, undefined, { pollMs: 1500, pollWhile: pending });
  const busy = jobs.data ? pending(jobs.data) : false;
  const files = useApi<SourceFile[]>(`${base}/files`, { _: busy ? 1 : 0 });
  const runs = useApi<Run[]>(`${base}/runs`, { _: busy ? 1 : 0 });
  const events = useApi<EventPage>(`${base}/events`, { limit: 1, _: busy ? 1 : 0 });
  const span = useApi<Histogram>(`${base}/timeline/histogram`, { buckets: 1, _: busy ? 1 : 0 });
  const [error, setError] = useState<Error>();

  async function start(path: string, body?: unknown) {
    setError(undefined);
    try {
      await api(path, { method: "POST", body });
      jobs.reload();
    } catch (exc) {
      setError(exc as Error);
    }
  }

  if (theCase.error) return <ErrorBox error={theCase.error} />;
  if (!theCase.data) return <Loading />;
  const latest = runs.data?.[0];
  const statuses = new Map<string, number>();
  for (const file of files.data ?? []) statuses.set(file.status, (statuses.get(file.status) ?? 0) + 1);
  const active = (jobs.data ?? []).filter((j) => j.status === "queued" || j.status === "running");
  return (
    <div className="grid-2">
      <Section
        title="Case"
        actions={
          <>
            <button type="button" className="primary" disabled={busy} onClick={() => start(`${base}/runs`, {})}>
              Run analysis
            </button>
            <button type="button" disabled={busy} onClick={() => start(`${base}/verify`)}>
              Verify evidence hashes
            </button>
          </>
        }
      >
        <ErrorBox error={error} />
        <KeyValue
          rows={[
            ["Name", theCase.data.name],
            ["Reference", theCase.data.reference],
            ["Analyst", theCase.data.analyst_name],
            ["Default timezone hint", theCase.data.default_timezone_hint],
            ["Created", utc(theCase.data.created_at)],
            ["Description", theCase.data.description],
          ]}
        />
        {active.length ? (
          <div className="jobs">
            {active.map((job) => (
              <div key={job.job_id} className="job">
                <StatusBadge status={job.status} /> {job.job_type.replace(/_/g, " ")}{" "}
                <progress max={1} value={job.progress} /> <span className="muted small">{job.progress_message}</span>
              </div>
            ))}
          </div>
        ) : null}
      </Section>
      <Section title="Evidence" actions={<Link to="evidence">Manage evidence</Link>}>
        <KeyValue
          rows={[
            ["Files", count(files.data?.length)],
            ["By status", [...statuses].map(([status, n]) => <span key={status}><StatusBadge status={status} /> {n} </span>)],
            ["Events", count(events.data?.total)],
            ["Time span (UTC)", timeSpan(files.data ?? [])],
            ["Events without reliable time", count(span.data?.unplaced)],
            ["Integrity", (files.data ?? []).some((f) => f.integrity_status !== "verified") ? <StatusBadge status="integrity_failed" /> : files.data?.length ? <StatusBadge status="verified" /> : "—"],
          ]}
        />
      </Section>
      <Section title="Latest analysis" actions={latest ? <Link to={`runs/${latest.run_id}`}>Run details</Link> : null}>
        {!latest ? <p className="muted">No analysis has been run yet.</p> : null}
        {latest ? (
          <>
            <KeyValue
              rows={[
                ["Status", <StatusBadge key="s" status={latest.status} />],
                ["Started", utc(latest.created_at)],
                ["Findings", count(latest.results?.findings_total)],
                ["Error", latest.error_message],
              ]}
            />
            <div className="severity-bar">
              {SEVERITY_ORDER.map((level) => (
                <Link key={level} to={`findings?run=${latest.run_id}&severity=${level}`} className="severity-count">
                  <SeverityBadge severity={level} /> {latest.results?.findings_by_severity?.[level] ?? 0}
                </Link>
              ))}
            </div>
          </>
        ) : null}
      </Section>
      <Section title="Coverage gaps">
        {latest?.results?.coverage_gaps?.length ? (
          <ul>
            {latest.results.coverage_gaps.map((gap, n) => (
              <li key={n}>
                {gap.filename ? <strong>{gap.filename}: </strong> : null}
                {gap.reason}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">{latest ? "None recorded in the latest run." : "Shown after an analysis run."}</p>
        )}
      </Section>
      <EditCase value={theCase.data} onSaved={theCase.reload} />
      <DeleteCase value={theCase.data} />
    </div>
  );
}

function EditCase({ value, onSaved }: { value: Case; onSaved: () => void }) {
  const [error, setError] = useState<Error>();
  const [saved, setSaved] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const text = (name: string) => (String(form.get(name) ?? "").trim() || null);
    try {
      await api(`/api/cases/${encodeURIComponent(value.case_id)}`, {
        method: "PATCH",
        body: {
          name: text("name") ?? value.name,
          analyst_name: text("analyst_name") ?? value.analyst_name,
          reference: text("reference"),
          description: text("description"),
          default_timezone_hint: text("default_timezone_hint"),
        },
      });
      setError(undefined);
      setSaved(true);
      onSaved();
    } catch (exc) {
      setError(exc as Error);
    }
  }
  return (
    <Section title="Edit case">
      <form className="form" onSubmit={submit} onChange={() => setSaved(false)}>
        <label>Name <input name="name" defaultValue={value.name} required /></label>
        <label>Analyst <input name="analyst_name" defaultValue={value.analyst_name} required /></label>
        <label>Reference <input name="reference" defaultValue={value.reference ?? ""} /></label>
        <label>
          Default timezone hint <input name="default_timezone_hint" list="timezones" defaultValue={value.default_timezone_hint ?? ""} />
        </label>
        <label className="wide">Description <textarea name="description" rows={3} defaultValue={value.description ?? ""} /></label>
        <TimezoneOptions />
        <ErrorBox error={error} />
        <div>
          <button type="submit">Save</button> {saved ? <span className="muted">Saved.</span> : null}
        </div>
      </form>
    </Section>
  );
}

function DeleteCase({ value }: { value: Case }) {
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<Error>();
  async function remove() {
    try {
      await api(`/api/cases/${encodeURIComponent(value.case_id)}`, { method: "DELETE", body: { confirm_name: confirm } });
      navigate("/");
    } catch (exc) {
      setError(exc as Error);
    }
  }
  return (
    <Section title="Delete case">
      <p>
        Deletes the case, its findings, exports and evidence files. Evidence also held by another case is kept.
        This cannot be undone. Type <strong>{value.name}</strong> to confirm.
      </p>
      <div className="row gap">
        <input value={confirm} onChange={(e) => setConfirm(e.target.value)} aria-label="Case name to confirm" />
        <button type="button" className="danger" disabled={confirm !== value.name} onClick={remove}>
          Delete permanently
        </button>
      </div>
      <ErrorBox error={error} />
    </Section>
  );
}
