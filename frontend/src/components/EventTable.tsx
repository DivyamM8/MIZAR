import type { ReactNode } from "react";

import { humanize, utc } from "../lib/format";
import type { EventRow } from "../lib/types";
import { useOpenEvent } from "./EventDrawer";
import { SeverityBadge, TimeBasis } from "./ui";

export function EventTable({
  events,
  compact = false,
  showFindings = true,
  extra,
}: {
  events: EventRow[];
  compact?: boolean;
  showFindings?: boolean;
  extra?: { header: string; cell: (event: EventRow) => ReactNode };
}) {
  const open = useOpenEvent();
  return (
    <div className="table-wrap">
      <table className="events">
        <thead>
          <tr>
            {extra ? <th>{extra.header}</th> : null}
            <th>UTC time</th>
            {!compact ? <th>Original time</th> : null}
            <th>Host</th>
            <th>User</th>
            <th>Source → destination</th>
            <th>Event</th>
            {!compact ? <th>File</th> : null}
            <th>Message</th>
            {!compact && showFindings ? <th>Findings</th> : null}
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.event_id} className="clickable" onClick={() => open(event.event_id)}>
              {extra ? <td>{extra.cell(event)}</td> : null}
              <td className="nowrap">
                {event.timestamp_utc ? utc(event.timestamp_utc) : <TimeBasis assumption={event.timezone_assumption} />}
              </td>
              {!compact ? (
                <td className="nowrap mono small" title={event.timezone_assumption}>
                  {event.timestamp_original ?? "—"}
                </td>
              ) : null}
              <td>{event.hostname ?? "—"}</td>
              <td>{event.username ?? "—"}</td>
              <td className="nowrap">
                {event.source_ip ?? ""}
                {event.destination_ip ? ` → ${event.destination_ip}${event.destination_port ? `:${event.destination_port}` : ""}` : ""}
              </td>
              <td className="event">
                {humanize(event.event_type)}
                {event.event_outcome ? <span className={`outcome ${event.event_outcome}`}> {event.event_outcome}</span> : null}
              </td>
              {!compact ? (
                <td className="file small" title={event.source_filename ?? event.source_file_id}>
                  {event.source_filename ?? event.source_file_id}
                </td>
              ) : null}
              <td className="message">{event.message ?? ""}</td>
              {!compact && showFindings ? (
                <td className="markers">
                  {(event.findings ?? []).map((marker) => (
                    <span key={marker.finding_id} className="marker" title={`${marker.finding_id} (${marker.role})`}>
                      <SeverityBadge severity={marker.severity} /> {marker.rule_id}
                    </span>
                  ))}
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
