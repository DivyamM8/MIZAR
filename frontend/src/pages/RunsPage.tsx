import { type FormEvent, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { Badge, ErrorBox, Empty, JsonView, KeyValue, Loading, Mono, Section, SeverityBadge, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import { count, shortHash, utc } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { FindingSummary, Rule, Run, RunDetail as Detail } from "../lib/types";
import { SEVERITIES } from "./FindingsPage";

const active = (runs: Run[]) => runs.some((r) => r.status === "queued" || r.status === "running");

export function RunsPage() {
  const { caseId = "" } = useParams();
  const runs = useApi<Run[]>(`/api/cases/${encodeURIComponent(caseId)}/runs`, undefined, { pollMs: 1500, pollWhile: active });
  const [params, setParams] = useSearchParams();
  const left = params.get("a");
  const right = params.get("b");
  return (
    <div className="stack">
      <StartRun caseId={caseId} onStarted={runs.reload} />
      <Section title="Analysis runs">
        <ErrorBox error={runs.error} />
        {!runs.data && !runs.error ? <Loading /> : null}
        {runs.data && !runs.data.length ? <Empty>No runs yet.</Empty> : null}
        {runs.data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Compare</th>
                  <th>Started (UTC)</th>
                  <th>Status</th>
                  <th>Findings</th>
                  {SEVERITIES.map((s) => (
                    <th key={s}>
                      <SeverityBadge severity={s} />
                    </th>
                  ))}
                  <th>Overrides</th>
                  <th>Inputs fingerprint</th>
                </tr>
              </thead>
              <tbody>
                {runs.data.map((run) => (
                  <tr key={run.run_id}>
                    <td className="nowrap">
                      <input type="radio" name="a" aria-label="Compare from" checked={left === run.run_id} onChange={() => setParams({ a: run.run_id, ...(right ? { b: right } : {}) })} />
                      <input type="radio" name="b" aria-label="Compare to" checked={right === run.run_id} onChange={() => setParams({ ...(left ? { a: left } : {}), b: run.run_id })} />
                    </td>
                    <td className="nowrap">
                      <Link to={run.run_id}>{utc(run.created_at)}</Link>
                    </td>
                    <td>
                      <StatusBadge status={run.status} />
                      {run.error_code ? <div className="small">{run.error_code}</div> : null}
                    </td>
                    <td>{count(run.results?.findings_total)}</td>
                    {SEVERITIES.map((s) => (
                      <td key={s}>{run.results?.findings_by_severity?.[s] ?? "—"}</td>
                    ))}
                    <td className="small">{Object.keys(run.overrides).length ? Object.keys(run.overrides).join(", ") : "defaults"}</td>
                    <td>
                      <Mono title={run.inputs_fingerprint ?? ""}>{shortHash(run.inputs_fingerprint)}</Mono>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Section>
      {left && right && left !== right ? <Compare caseId={caseId} left={left} right={right} /> : null}
    </div>
  );
}

function StartRun({ caseId, onStarted }: { caseId: string; onStarted: () => void }) {
  const rules = useApi<Rule[]>("/api/rules");
  const [overrides, setOverrides] = useState<Record<string, Record<string, number | string>>>({});
  const [error, setError] = useState<Error>();
  const tunable = (rules.data ?? []).filter((r) => Object.keys(r.params).length);
  function add(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const [ruleId, param] = String(form.get("param") ?? "").split("/");
    const raw = String(form.get("value") ?? "").trim();
    if (!ruleId || !param || !raw) return;
    const rule = rules.data?.find((r) => r.rule_id === ruleId);
    const value = rule?.params[param]?.type === "integer" ? Number(raw) : raw;
    setOverrides((current) => ({ ...current, [ruleId]: { ...(current[ruleId] ?? {}), [param]: value } }));
  }
  async function start() {
    try {
      await api(`/api/cases/${encodeURIComponent(caseId)}/runs`, { method: "POST", body: { overrides } });
      setError(undefined);
      onStarted();
    } catch (exc) {
      setError(exc as Error);
    }
  }
  return (
    <Section title="Start an analysis run" actions={<button type="button" className="primary" onClick={start}>Run analysis</button>}>
      <p className="muted small">
        Runs all {rules.data?.length ?? ""} rules over the case after re-verifying evidence hashes. Parameter overrides
        are recorded in the run manifest.
      </p>
      <form className="row gap" onSubmit={add}>
        <select name="param" aria-label="Parameter">
          {tunable.flatMap((rule) =>
            Object.entries(rule.params).map(([name, p]) => (
              <option key={`${rule.rule_id}/${name}`} value={`${rule.rule_id}/${name}`}>
                {rule.rule_id} {name} (default {String(p.default)})
              </option>
            )),
          )}
        </select>
        <input name="value" placeholder="value, e.g. 10 or 15m" aria-label="Value" />
        <button type="submit">Add override</button>
        {Object.keys(overrides).length ? (
          <button type="button" onClick={() => setOverrides({})}>
            Clear overrides
          </button>
        ) : null}
      </form>
      {Object.keys(overrides).length ? <JsonView value={overrides} /> : null}
      <ErrorBox error={error ?? rules.error} />
    </Section>
  );
}

function Compare({ caseId, left, right }: { caseId: string; left: string; right: string }) {
  const a = useApi<FindingSummary[]>(`/api/runs/${encodeURIComponent(left)}/findings`);
  const b = useApi<FindingSummary[]>(`/api/runs/${encodeURIComponent(right)}/findings`);
  if (!a.data || !b.data) return <Loading what="Comparing" />;
  const before = new Map(a.data.map((f) => [f.fingerprint, f]));
  const after = new Map(b.data.map((f) => [f.fingerprint, f]));
  const added = b.data.filter((f) => !before.has(f.fingerprint));
  const gone = a.data.filter((f) => !after.has(f.fingerprint));
  const changed = b.data.filter((f) => {
    const old = before.get(f.fingerprint);
    return old && (old.severity !== f.severity || old.confidence !== f.confidence || old.event_count !== f.event_count);
  });
  const list = (items: FindingSummary[], note?: (f: FindingSummary) => string) =>
    items.length ? (
      <ul className="plain">
        {items.map((f) => (
          <li key={f.finding_id}>
            <SeverityBadge severity={f.severity} /> <Link to={`/cases/${encodeURIComponent(caseId)}/findings/${f.finding_id}`}>{f.title}</Link>{" "}
            {note ? <span className="muted small">{note(f)}</span> : null}
          </li>
        ))}
      </ul>
    ) : (
      <p className="muted">None.</p>
    );
  return (
    <Section title="Run comparison (by finding fingerprint)">
      <div className="grid-3">
        <div>
          <h4>New in the later run ({added.length})</h4>
          {list(added)}
        </div>
        <div>
          <h4>Not reproduced ({gone.length})</h4>
          {list(gone)}
        </div>
        <div>
          <h4>Changed ({changed.length})</h4>
          {list(changed, (f) => {
            const old = before.get(f.fingerprint);
            return old ? `was ${old.severity}/${old.confidence}, ${old.event_count} events` : "";
          })}
        </div>
      </div>
    </Section>
  );
}

export function RunDetailPage() {
  const { caseId = "", runId = "" } = useParams();
  const run = useApi<Detail>(`/api/runs/${encodeURIComponent(runId)}`, undefined, {
    pollMs: 1500,
    pollWhile: (r) => r.status === "queued" || r.status === "running",
  });
  if (run.error) return <ErrorBox error={run.error} />;
  if (!run.data) return <Loading />;
  const r = run.data;
  const results = r.results ?? {};
  return (
    <div className="stack">
      <Section title={`Run ${r.run_id}`} actions={
          <span className="row gap">
            <Link to={`/cases/${encodeURIComponent(caseId)}/findings?run=${r.run_id}`}>Findings of this run</Link>
            <Link to={`/cases/${encodeURIComponent(caseId)}/reports?run=${r.run_id}`}>Reports</Link>
          </span>
        }
      >
        <KeyValue
          rows={[
            ["Status", <StatusBadge key="s" status={r.status} />],
            ["Started by", r.triggered_by],
            ["Created / finished (UTC)", `${utc(r.created_at)} / ${utc(r.finished_at)}`],
            ["Duration", results.duration_seconds !== undefined ? `${results.duration_seconds}s` : null],
            ["Events evaluated", count(results.events_evaluated)],
            ["Findings", count(results.findings_total)],
            ["Evidence verification", results.evidence_verification ? JSON.stringify(results.evidence_verification) : null],
            ["Error", r.error_code ? `${r.error_code}: ${r.error_message}` : null],
            ["Manifest SHA-256", <Mono key="m">{r.manifest_sha256 ?? "—"}</Mono>],
            ["Inputs fingerprint", <Mono key="f">{r.inputs_fingerprint ?? "—"}</Mono>],
          ]}
        />
        <p className="muted small">
          Runs with the same inputs fingerprint used identical evidence, parsers, rules and parameters, and produce the
          same findings.
        </p>
        {results.error_details ? <JsonView value={results.error_details} /> : null}
      </Section>
      {results.rule_errors?.length ? (
        <Section title="Rule errors">
          <ul>
            {results.rule_errors.map((e) => (
              <li key={e.rule_id}>
                <Badge tone="bad">{e.rule_id}</Badge> {e.error}: {e.message}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
      {results.coverage_gaps?.length || (results.rule_notes && Object.keys(results.rule_notes).length) ? (
        <Section title="Coverage gaps and rule notes">
          <ul>
            {(results.coverage_gaps ?? []).map((g, n) => (
              <li key={n}>
                {g.filename ? <strong>{g.filename}: </strong> : null}
                {g.reason}
              </li>
            ))}
            {Object.entries(results.rule_notes ?? {}).map(([rule, notes]) =>
              Object.entries(notes).map(([key, value]) => (
                <li key={`${rule}-${key}`}>
                  <Badge>{rule}</Badge> {key.replace(/_/g, " ")}: {String(value)}
                </li>
              )),
            )}
          </ul>
        </Section>
      ) : null}
      {r.manifest ? (
        <>
          <Section title={`Inputs (${r.manifest.inputs.length})`}>
            <div className="table-wrap">
              <table className="compact">
                <thead>
                  <tr>
                    <th>File</th>
                    <th>SHA-256</th>
                    <th>Format</th>
                    <th>Parser</th>
                    <th>Parse</th>
                    <th>Records</th>
                    <th>Hints</th>
                  </tr>
                </thead>
                <tbody>
                  {r.manifest.inputs.map((input) => (
                    <tr key={String(input.source_file_id)}>
                      <td>{String(input.filename)}</td>
                      <td>
                        <Mono>{String(input.sha256)}</Mono>
                      </td>
                      <td>{String(input.format ?? input.container_type ?? "—")}</td>
                      <td>{input.parser_name ? `${String(input.parser_name)} ${String(input.parser_version)}` : "—"}</td>
                      <td>{input.parse_status ? <StatusBadge status={String(input.parse_status)} /> : "—"}</td>
                      <td>{input.records_total === null ? "—" : String(input.records_total)}</td>
                      <td className="small">
                        {input.timezone_hint ? `tz ${String(input.timezone_hint)}` : ""} {input.year_hint ? `year ${String(input.year_hint)}` : ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
          <Section title="Versions, rules and parameters">
            <KeyValue
              rows={[
                ["MIZAR", r.manifest.mizar_version],
                ["Event schema", r.manifest.event_schema_version],
                ["Rule format", r.manifest.rule_format_version],
                ["Rules", r.manifest.rules.length],
              ]}
            />
            <h4>Effective parameters and configuration</h4>
            <JsonView value={{ params: r.manifest.params, config: r.manifest.config }} />
            <h4>Rule files</h4>
            <JsonView value={r.manifest.rules} />
          </Section>
        </>
      ) : null}
    </div>
  );
}
