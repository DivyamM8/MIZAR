import { Link, useParams, useSearchParams } from "react-router-dom";

import { EventTable } from "../components/EventTable";
import { FilterBar } from "../components/FilterBar";
import { Badge, ErrorBox, Empty, KeyValue, Loading, Section, SeverityBadge, StatusBadge } from "../components/ui";
import { count, humanize, utc } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { EntityDetail as Detail, EntityPage, Session, SessionDetail as SessionFull } from "../lib/types";

const TYPES: [string, string][] = [["host", "Hosts"], ["user", "Users"], ["ip", "IP addresses"]];

function entityLink(caseId: string, type: string, value: string): string {
  return `/cases/${encodeURIComponent(caseId)}/entities/detail?type=${type}&value=${encodeURIComponent(value)}`;
}

export function EntitiesPage() {
  const { caseId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const type = params.get("type") ?? "";
  const page = useApi<EntityPage>(`/api/cases/${encodeURIComponent(caseId)}/entities`, {
    type,
    q: params.get("q") ?? "",
    limit: 200,
  });
  return (
    <Section
      title="Entities"
      actions={
        <div className="row gap">
          {[["", "All"], ...TYPES].map(([value, label]) => (
            <button
              key={value}
              type="button"
              className={type === value ? "active" : ""}
              onClick={() => {
                const next = new URLSearchParams(params);
                if (value) next.set("type", value);
                else next.delete("type");
                setParams(next);
              }}
            >
              {label}
            </button>
          ))}
        </div>
      }
    >
      <FilterBar fields={[{ name: "q", label: "Value contains" }]} />
      {page.data && page.data.index.status !== "current" ? (
        <p className="warn-box">Case index is {humanize(page.data.index.status)}; entities may be incomplete.</p>
      ) : null}
      <ErrorBox error={page.error} />
      {!page.data && !page.error ? <Loading /> : null}
      {page.data && !page.data.items.length ? <Empty>No entities.</Empty> : null}
      {page.data?.items.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Events</th>
                <th>First seen (UTC)</th>
                <th>Last seen</th>
                <th>As source / destination</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody>
              {page.data.items.map((e) => (
                <tr key={`${e.entity_type}:${e.value}`}>
                  <td>{e.entity_type}</td>
                  <td>
                    <Link to={entityLink(caseId, e.entity_type, e.value)}>{e.value}</Link>
                  </td>
                  <td>
                    {count(e.event_count)}
                    {e.unplaced_count ? <span className="muted small"> ({e.unplaced_count} untimed)</span> : null}
                  </td>
                  <td className="nowrap">{utc(e.first_seen_utc)}</td>
                  <td className="nowrap">{utc(e.last_seen_utc)}</td>
                  <td>{e.entity_type === "ip" ? `${e.as_source ?? 0} / ${e.as_destination ?? 0}` : "—"}</td>
                  <td>
                    {e.finding_count ? (
                      <>
                        <SeverityBadge severity={e.highest_severity} /> {e.finding_count}
                      </>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {page.data.total > page.data.items.length ? (
            <p className="muted small">Showing the {page.data.items.length} most active of {page.data.total}. Use the filter to narrow.</p>
          ) : null}
        </div>
      ) : null}
    </Section>
  );
}

export function EntityDetailPage() {
  const { caseId = "" } = useParams();
  const [params] = useSearchParams();
  const type = params.get("type") ?? "";
  const value = params.get("value") ?? "";
  const entity = useApi<Detail>(`/api/cases/${encodeURIComponent(caseId)}/entity`, { type, value });
  if (entity.error) return <ErrorBox error={entity.error} />;
  if (!entity.data) return <Loading />;
  const e = entity.data;
  const filter = type === "host" ? "hostname" : type === "user" ? "username" : "ip";
  return (
    <div className="stack">
      <Section
        title={`${humanize(type)}: ${e.value}`}
        actions={<Link to={`/cases/${encodeURIComponent(caseId)}/timeline?${filter}=${encodeURIComponent(e.value)}`}>Timeline for this {type}</Link>}
      >
        <KeyValue
          rows={[
            ["Events", count(e.event_count)],
            ["Without reliable time", count(e.unplaced_count)],
            ["First seen (UTC)", utc(e.first_seen_utc)],
            ["Last seen (UTC)", utc(e.last_seen_utc)],
            ...(type === "ip" ? ([["As source / destination", `${e.as_source ?? 0} / ${e.as_destination ?? 0}`]] as [string, string][]) : []),
            ["Source files", e.source_file_ids.length],
          ]}
        />
      </Section>
      <Section title={`Findings naming this ${type} (${e.findings.length})`}>
        {e.findings.length ? (
          <ul className="plain">
            {e.findings.map((f) => (
              <li key={f.finding_id}>
                <SeverityBadge severity={f.severity} /> <Link to={`/cases/${encodeURIComponent(caseId)}/findings/${f.finding_id}`}>{f.title}</Link>{" "}
                <span className="muted small">{f.rule_id}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">None in the selected run.</p>
        )}
      </Section>
      <Section title={`Sessions (${e.sessions.length})`}>
        <SessionTable caseId={caseId} sessions={e.sessions} />
      </Section>
    </div>
  );
}

export function SessionTable({ caseId, sessions }: { caseId: string; sessions: Session[] }) {
  if (!sessions.length) return <p className="muted">No sessions.</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>Session</th>
            <th>Start (UTC)</th>
            <th>End</th>
            <th>Accounts</th>
            <th>Addresses</th>
            <th>Events</th>
            <th>Activity</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <tr key={s.session_group_id}>
              <td>{s.hostname ?? "—"}</td>
              <td>
                <Link to={`/cases/${encodeURIComponent(caseId)}/sessions/${s.session_group_id}`}>{s.session_id}</Link>
              </td>
              <td className="nowrap">{utc(s.first_utc)}</td>
              <td className="nowrap">
                {utc(s.last_utc)} {s.closed ? <Badge>closed</Badge> : <Badge tone="warn" title="No logoff or session-closed event was recorded">no close</Badge>}
              </td>
              <td>{s.usernames.join(", ") || "—"}</td>
              <td>{s.source_ips.join(", ") || "—"}</td>
              <td>{s.event_count}</td>
              <td className="small">{s.event_types.map(([t, n]) => `${humanize(t)}${n > 1 ? ` ×${n}` : ""}`).join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function SessionsPage() {
  const { caseId = "" } = useParams();
  const [params] = useSearchParams();
  const sessions = useApi<{ items: Session[]; total: number }>(`/api/cases/${encodeURIComponent(caseId)}/sessions`, {
    hostname: params.get("hostname") ?? "",
    username: params.get("username") ?? "",
    ip: params.get("ip") ?? "",
    limit: 200,
  });
  return (
    <Section title={`Sessions (${count(sessions.data?.total)})`}>
      <p className="muted small">
        Events sharing a logon or session ID on one host (Windows logon ID, sshd process, auditd session, Zeek
        connection), split after 8 hours without activity. Shared system logon IDs are not treated as sessions.
      </p>
      <FilterBar fields={[{ name: "hostname", label: "Host" }, { name: "username", label: "Account" }, { name: "ip", label: "Address" }]} />
      <ErrorBox error={sessions.error} />
      {!sessions.data && !sessions.error ? <Loading /> : <SessionTable caseId={caseId} sessions={sessions.data?.items ?? []} />}
    </Section>
  );
}

export function SessionDetailPage() {
  const { groupId = "" } = useParams();
  const session = useApi<SessionFull>(`/api/sessions/${encodeURIComponent(groupId)}`, { limit: 500 });
  if (session.error) return <ErrorBox error={session.error} />;
  if (!session.data) return <Loading />;
  const s = session.data;
  return (
    <div className="stack">
      <Section title={`Session ${s.session_id} on ${s.hostname ?? "unknown host"}`}>
        <KeyValue
          rows={[
            ["Start (UTC)", utc(s.first_utc)],
            ["End (UTC)", utc(s.last_utc)],
            ["Closed", s.closed ? <StatusBadge key="c" status="resolved" /> : "no close event recorded"],
            ["Accounts", s.usernames.join(", ")],
            ["Addresses", s.source_ips.join(", ")],
            ["Events", s.event_count],
            ["Events without reliable time", s.events_without_utc],
          ]}
        />
      </Section>
      <Section title="Session events (in order)">
        <EventTable events={s.events} />
        {s.event_count > s.events.length ? <p className="muted small">First {s.events.length} of {s.event_count} shown.</p> : null}
      </Section>
    </div>
  );
}
