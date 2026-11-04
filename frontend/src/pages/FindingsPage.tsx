import { Link, useParams, useSearchParams } from "react-router-dom";

import { Badge, ErrorBox, Empty, Loading, Section, SeverityBadge, StatusBadge } from "../components/ui";
import { humanize, utc } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { FindingSummary, Run } from "../lib/types";

export const SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export const STATUSES = ["open", "investigating", "confirmed", "false_positive", "resolved"] as const;

export function useRuns(caseId: string) {
  return useApi<Run[]>(`/api/cases/${encodeURIComponent(caseId)}/runs`);
}

export function defaultRun(runs: Run[] | undefined): Run | undefined {
  return runs?.find((r) => r.status === "succeeded" || r.status === "succeeded_with_errors");
}

export function FindingsPage() {
  const { caseId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const runs = useRuns(caseId);
  const runId = params.get("run") ?? defaultRun(runs.data)?.run_id ?? null;
  const severity = params.get("severity") ?? "";
  const status = params.get("status") ?? "";
  const findings = useApi<FindingSummary[]>(runId ? `/api/runs/${encodeURIComponent(runId)}/findings` : null, {
    severity,
    status,
  });
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next);
  };
  if (runs.data && !runs.data.length) {
    return (
      <Section title="Findings">
        <Empty>
          No analysis yet. Start one from the <Link to={`/cases/${encodeURIComponent(caseId)}`}>overview</Link>.
        </Empty>
      </Section>
    );
  }
  return (
    <Section
      title="Findings"
      actions={
        <div className="row gap">
          <label>
            Run{" "}
            <select value={runId ?? ""} onChange={(e) => set("run", e.target.value)}>
              {(runs.data ?? []).map((run) => (
                <option key={run.run_id} value={run.run_id}>
                  {utc(run.created_at)} · {humanize(run.status)} · {run.results?.findings_total ?? 0} findings
                </option>
              ))}
            </select>
          </label>
          <label>
            Severity{" "}
            <select value={severity} onChange={(e) => set("severity", e.target.value)}>
              <option value="">all</option>
              {SEVERITIES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <label>
            Status{" "}
            <select value={status} onChange={(e) => set("status", e.target.value)}>
              <option value="">all</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {humanize(s)}
                </option>
              ))}
            </select>
          </label>
        </div>
      }
    >
      <p className="muted small">
        Sorted by severity, then confidence, then evidence strength, then first observed time. Severity, confidence and
        evidence strength are separate judgments and are never combined into one score.
      </p>
      <ErrorBox error={runs.error ?? findings.error} />
      {!findings.data && !findings.error ? <Loading /> : null}
      {findings.data && !findings.data.length ? <Empty>No findings match.</Empty> : null}
      {findings.data?.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Evidence</th>
                <th>Rule</th>
                <th>Finding</th>
                <th>First observed (UTC)</th>
                <th>Last observed</th>
                <th>Events</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.data.map((f) => (
                <tr key={f.finding_id}>
                  <td>
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td>{f.confidence}</td>
                  <td>{f.evidence_strength}</td>
                  <td className="nowrap">
                    <Link to={`/rules#${f.rule_id}`}>{f.rule_id}</Link>
                  </td>
                  <td>
                    <Link to={f.finding_id}>{f.title}</Link>
                    {f.attack_techniques.length ? <div className="muted small">{f.attack_techniques.join(", ")}</div> : null}
                  </td>
                  <td className="nowrap">{utc(f.first_observed_utc)}</td>
                  <td className="nowrap">{utc(f.last_observed_utc)}</td>
                  <td>{f.event_count}</td>
                  <td>
                    <StatusBadge status={f.status} />
                    {f.status_carried_from ? <Badge tone="neutral" title={`Carried from ${f.status_carried_from}`}>carried</Badge> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </Section>
  );
}
