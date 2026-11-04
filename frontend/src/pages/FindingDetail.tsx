import { type FormEvent, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { EventTable } from "../components/EventTable";
import { Badge, ErrorBox, JsonView, KeyValue, Loading, Mono, Section, SeverityBadge, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import { humanize, utc } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { FindingDetail as Finding } from "../lib/types";
import { STATUSES } from "./FindingsPage";

const PAGE = 200;
const EXPLAINED = new Set(["event_count", "weighted_count", "evidence_events_linked", "evidence_truncated", "distinct", "top_values", "sample_event_ids", "params"]);

export function FindingDetail() {
  const { caseId = "", findingId = "" } = useParams();
  const [offset, setOffset] = useState(0);
  const finding = useApi<Finding>(`/api/findings/${encodeURIComponent(findingId)}`, { offset });
  if (finding.error) return <ErrorBox error={finding.error} />;
  if (!finding.data) return <Loading />;
  const f = finding.data;
  const observed = f.observed_evidence;
  const caseBase = `/cases/${encodeURIComponent(caseId)}`;
  return (
    <div className="stack">
      <Section
        title={
          <span>
            <SeverityBadge severity={f.severity} /> {f.title}
          </span>
        }
        actions={<Link to={`${caseBase}/timeline?finding_id=${encodeURIComponent(f.finding_id)}`}>Show on timeline</Link>}
      >
        <p>{f.description}</p>
        <div className="grid-3">
          <div className="rating">
            <h4>
              Severity: <SeverityBadge severity={f.severity} />
            </h4>
            <p className="muted small">How serious this would be if the interpretation is correct.</p>
            <ol>{f.severity_rationale.map((r, n) => <li key={n}>{r}</li>)}</ol>
          </div>
          <div className="rating">
            <h4>Confidence: {f.confidence}</h4>
            <p className="muted small">How likely the interpretation is, given the data.</p>
            <ol>{f.confidence_rationale.map((r, n) => <li key={n}>{r}</li>)}</ol>
          </div>
          <div className="rating">
            <h4>Evidence: {f.evidence_strength}</h4>
            <p className="muted small">
              {{
                direct: "The records themselves show the behavior.",
                corroborated: "Several independent sources agree.",
                circumstantial: "Shared attributes or timing only.",
                inferred: "Derived from rarity or absence.",
              }[f.evidence_strength] ?? ""}
            </p>
          </div>
        </div>
      </Section>
      <div className="grid-2">
        <Section title="Interpretation (hypothesis)">
          <p>{f.interpretation}</p>
          <h4>Alternative explanations</h4>
          <ul>{f.alternative_explanations.map((a, n) => <li key={n}>{a}</li>)}</ul>
          <h4>Verification steps</h4>
          <ol>{f.verification_steps.map((v, n) => <li key={n}>{v}</li>)}</ol>
        </Section>
        <AnalystPanel finding={f} onSaved={finding.reload} />
      </div>
      <div className="grid-2">
        <Section title="Observed">
          <KeyValue
            rows={[
              ["First observed (UTC)", utc(f.first_observed_utc)],
              ["Last observed (UTC)", utc(f.last_observed_utc)],
              ["Events", `${observed.event_count}${observed.weighted_count !== observed.event_count ? ` records standing for ${observed.weighted_count} occurrences` : ""}`],
              ["Rule", <Link key="r" to={`/rules#${f.rule_id}`}>{f.rule_id} {f.rule_version}</Link>],
              ["ATT&CK", f.attack_techniques.join(", ")],
              ["Finding ID", <Mono key="i">{f.finding_id}</Mono>],
              ["Fingerprint", <Mono key="p" title={f.fingerprint}>{f.fingerprint.slice(0, 16)}…</Mono>],
              ["Parameters", <Mono key="m">{JSON.stringify(observed.params)}</Mono>],
            ]}
          />
          <h4>Entities</h4>
          <KeyValue rows={Object.entries(f.entities).map(([k, v]) => [humanize(k), Array.isArray(v) ? v.join(", ") : String(v)])} />
          {observed.top_values && Object.keys(observed.top_values as object).length ? (
            <>
              <h4>Most frequent values</h4>
              <KeyValue
                rows={Object.entries(observed.top_values as Record<string, [string, number][]>).map(([k, values]) => [
                  humanize(k),
                  values.map(([v, n]) => `${v} (${n})`).join(", "),
                ])}
              />
            </>
          ) : null}
          {Object.keys(observed).some((k) => !EXPLAINED.has(k)) ? (
            <>
              <h4>Rule-specific facts</h4>
              <JsonView value={Object.fromEntries(Object.entries(observed).filter(([k]) => !EXPLAINED.has(k)))} />
            </>
          ) : null}
        </Section>
        <Section title="Sources">
          <table className="compact">
            <thead>
              <tr>
                <th>File</th>
                <th>SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {f.source_files.map((s) => (
                <tr key={s.source_file_id}>
                  <td>
                    <Link to={`${caseBase}/evidence#${s.source_file_id}`}>{s.filename ?? s.source_file_id}</Link>
                  </td>
                  <td>
                    <Mono>{s.sha256 ?? "—"}</Mono>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {f.related_finding_ids.length ? (
            <>
              <h4>Chained findings</h4>
              <ul className="plain">
                {f.related_finding_ids.map((id) => (
                  <li key={id}>
                    <Link to={`../${encodeURIComponent(id)}`} relative="path">
                      {id}
                    </Link>
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </Section>
      </div>
      <Section
        title={`Evidence events (${f.evidence_total}${observed.evidence_truncated ? ` linked of ${observed.event_count}` : ""})`}
        actions={
          <div className="row gap">
            <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(offset - PAGE, 0))}>
              Previous
            </button>
            <span className="muted small">
              {offset + 1}–{Math.min(offset + PAGE, f.evidence_total)}
            </span>
            <button type="button" disabled={offset + PAGE >= f.evidence_total} onClick={() => setOffset(offset + PAGE)}>
              Next
            </button>
          </div>
        }
      >
        {f.evidence_events.some((e) => !e.present) ? (
          <p className="warn-box">Some linked records no longer exist in the current parse of their file.</p>
        ) : null}
        <EventTable
          showFindings={false}
          events={f.evidence_events.map((e) => ({
            ...e,
            source_filename: f.source_files.find((s) => s.source_file_id === e.source_file_id)?.filename ?? null,
          }))}
          extra={{
            header: "Role",
            cell: (e) => {
              const row = e as (typeof f.evidence_events)[number];
              return row.present ? <Badge>{humanize(row.role)}</Badge> : <Badge tone="warn">missing</Badge>;
            },
          }}
        />
      </Section>
    </div>
  );
}

function AnalystPanel({ finding, onSaved }: { finding: Finding; onSaved: () => void }) {
  const [error, setError] = useState<Error>();
  const [saved, setSaved] = useState(false);
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api(`/api/findings/${encodeURIComponent(finding.finding_id)}`, {
        method: "PATCH",
        body: { status: String(form.get("status")), analyst_notes: String(form.get("analyst_notes") ?? "") || null },
      });
      setSaved(true);
      setError(undefined);
      onSaved();
    } catch (exc) {
      setError(exc as Error);
    }
  }
  return (
    <Section title="Analyst review">
      <form className="form" onSubmit={save} onChange={() => setSaved(false)}>
        <label>
          Status
          <select name="status" defaultValue={finding.status}>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {humanize(s)}
              </option>
            ))}
          </select>
        </label>
        <label className="wide">
          Notes <textarea name="analyst_notes" rows={6} defaultValue={finding.analyst_notes ?? ""} maxLength={20000} />
        </label>
        <ErrorBox error={error} />
        <div>
          <button type="submit" className="primary">
            Save review
          </button>{" "}
          {saved ? <span className="muted">Saved.</span> : null}
        </div>
      </form>
      <p className="muted small">
        Current: <StatusBadge status={finding.status} />
        {finding.updated_by ? ` by ${finding.updated_by} at ${utc(finding.updated_at)}` : ""}
        {finding.status_carried_from ? ` (carried from ${finding.status_carried_from})` : ""}. "Confirmed" records the
        analyst's judgment; MIZAR never confirms a finding by itself. Review status carries to later runs of the same
        finding.
      </p>
    </Section>
  );
}
