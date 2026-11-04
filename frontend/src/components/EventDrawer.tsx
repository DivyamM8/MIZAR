import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { humanize, utc } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { EventDetail, RelatedEvents } from "../lib/types";
import { EventTable } from "./EventTable";
import { Badge, ErrorBox, JsonView, KeyValue, Loading, Mono, StatusBadge, TimeBasis } from "./ui";

const RELATED_FIELDS = ["source_ip", "destination_ip", "username", "hostname"] as const;

export function useOpenEvent(): (eventId: string) => void {
  const [params, setParams] = useSearchParams();
  return (eventId: string) => {
    const next = new URLSearchParams(params);
    next.set("event", eventId);
    setParams(next);
  };
}

export function EventDrawer() {
  const [params, setParams] = useSearchParams();
  const eventId = params.get("event");
  const { data, error } = useApi<EventDetail>(eventId ? `/api/events/${encodeURIComponent(eventId)}` : null);
  const close = () => {
    const next = new URLSearchParams(params);
    next.delete("event");
    setParams(next);
  };
  if (!eventId) return null;
  return (
    <aside className="drawer" aria-label="Event detail">
      <header className="drawer-head">
        <h2>Event</h2>
        <button type="button" onClick={close} aria-label="Close">
          Close
        </button>
      </header>
      <ErrorBox error={error} />
      {!data && !error ? <Loading /> : null}
      {data && data.event_id === eventId ? <EventBody event={data} /> : null}
    </aside>
  );
}

function RawRecord({ event }: { event: EventDetail }) {
  const raw = event.raw_record;
  if (!raw) return <div className="muted">No raw record available.</div>;
  return (
    <div>
      <div className="row gap">
        <Badge tone="neutral">{raw.source === "evidence_file" ? "read from evidence file" : "stored copy"}</Badge>
        {raw.verified === true ? <Badge tone="ok">matches record hash</Badge> : null}
        {raw.verified === false ? (
          <Badge tone="bad" title="The evidence file no longer matches the hash recorded at parse time">
            does NOT match record hash
          </Badge>
        ) : null}
        {!raw.lossless ? <Badge tone="warn">undecodable bytes shown as �</Badge> : null}
        {raw.display_truncated ? <Badge tone="warn">truncated for display</Badge> : null}
        <span className="muted small">
          {raw.encoding}, {raw.size_bytes} bytes
        </span>
      </div>
      <pre className="raw">{raw.text}</pre>
    </div>
  );
}

function EventBody({ event }: { event: EventDetail }) {
  const caseId = event.case_id;
  return (
    <div className="drawer-body">
      <h3>{humanize(event.event_type) || "event"}</h3>
      <KeyValue
        rows={[
          ["UTC time", utc(event.timestamp_utc)],
          ["Original time", <Mono key="t">{event.timestamp_original ?? "—"}</Mono>],
          ["Time basis", <TimeBasis key="b" assumption={event.timezone_assumption} />],
          ["Host", event.hostname],
          ["User", event.user_domain ? `${event.user_domain}\\${event.username ?? ""}` : event.username],
          ["Source", event.source_ip ? `${event.source_ip}${event.source_port !== null ? `:${event.source_port}` : ""}` : null],
          ["Destination", event.destination_ip ? `${event.destination_ip}${event.destination_port !== null ? `:${event.destination_port}` : ""}` : null],
          ["Protocol", event.protocol],
          ["Category / outcome", `${humanize(event.event_category)} / ${humanize(event.event_outcome)}`],
          ["Code", event.event_code],
          ["Process", event.process_name ? `${event.process_name}${event.process_id !== null ? ` (${event.process_id})` : ""}` : null],
          ["Session", event.session_id],
          ["Parsing", <span key="p"><StatusBadge status={event.parsing_status} /> {event.parse_warnings.join(", ")}</span>],
          ["Source type / parser", `${event.source_type} / ${event.parser_name} ${event.parser_version}`],
          ["Source file", <Link key="f" to={`/cases/${encodeURIComponent(caseId)}/evidence#${event.source_file_id}`}>{event.source_file_id}</Link>],
          ["Locator", <Mono key="l">{JSON.stringify(event.original_record_reference)}</Mono>],
          ["Record SHA-256", <Mono key="h">{event.record_hash}</Mono>],
          ["Event ID", <Mono key="i">{event.event_id}</Mono>],
        ]}
      />
      <h4>Message</h4>
      <pre className="raw">{event.message ?? "—"}</pre>
      <h4>Original record</h4>
      <RawRecord event={event} />
      {event.groups.length ? (
        <>
          <h4>Groups</h4>
          <ul className="plain">
            {event.groups.map((group) => (
              <li key={group.group_id}>
                {group.group_type === "session" ? (
                  <Link to={`/cases/${encodeURIComponent(caseId)}/sessions/${group.group_id}`}>Session of {group.member_count} events</Link>
                ) : (
                  <span>Same record in {group.member_count} files (duplicate group)</span>
                )}
              </li>
            ))}
          </ul>
        </>
      ) : null}
      <Links event={event} />
      <Related event={event} />
      <h4>Source-specific fields</h4>
      <JsonView value={event.extra} />
    </div>
  );
}

function Links({ event }: { event: EventDetail }) {
  const open = useOpenEvent();
  const all = [
    ...event.links.incoming.map((l) => ({ ...l, direction: "in" as const })),
    ...event.links.outgoing.map((l) => ({ ...l, direction: "out" as const })),
  ];
  if (!all.length) return null;
  const label = (kind: string, direction: "in" | "out") =>
    kind === "parent_process_of"
      ? direction === "in" ? "Parent process" : "Child process"
      : direction === "in" ? "Performed by process" : "Activity of this process";
  return (
    <>
      <h4>Documented links</h4>
      <p className="muted small">From fields the source itself records (Sysmon ProcessGuid).</p>
      <ul className="plain">
        {all.map((link, n) => (
          <li key={n}>
            <button type="button" className="link" onClick={() => open(link.event_id)}>
              {label(link.link_type, link.direction)}
            </button>{" "}
            <span className="muted small">{String(link.basis.value ?? "")}</span>
          </li>
        ))}
      </ul>
    </>
  );
}

function Related({ event }: { event: EventDetail }) {
  const [field, setField] = useState<string>(event.source_ip ? "source_ip" : event.username ? "username" : "hostname");
  const [window, setWindow] = useState("30m");
  const { data, error } = useApi<RelatedEvents>(`/api/events/${encodeURIComponent(event.event_id)}/related`, {
    field,
    window,
    limit: 50,
  });
  return (
    <>
      <h4>Related events</h4>
      <div className="row gap">
        <label>
          Same{" "}
          <select value={field} onChange={(e) => setField(e.target.value)}>
            {RELATED_FIELDS.map((f) => (
              <option key={f} value={f}>
                {humanize(f)}
              </option>
            ))}
          </select>
        </label>
        <label>
          within ±{" "}
          <select value={window} onChange={(e) => setWindow(e.target.value)}>
            {["5m", "30m", "2h", "24h"].map((w) => (
              <option key={w}>{w}</option>
            ))}
          </select>
        </label>
      </div>
      <ErrorBox error={error} />
      {data ? (
        <>
          <p className="muted small">{data.note}</p>
          {data.items.length ? <EventTable events={data.items} compact /> : null}
        </>
      ) : null}
    </>
  );
}
