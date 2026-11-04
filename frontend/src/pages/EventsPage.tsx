import { useParams, useSearchParams } from "react-router-dom";

import { EventTable } from "../components/EventTable";
import { EVENT_FILTERS, FilterBar, paramsFor } from "../components/FilterBar";
import { ErrorBox, Empty, Loading, Section } from "../components/ui";
import { count } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { EventPage } from "../lib/types";

const PAGE = 100;
const FIELDS = [
  ...EVENT_FILTERS,
  { name: "event_category", label: "Category", options: ["authentication", "account_management", "privilege", "process", "service", "scheduled_task", "file", "network", "web", "system", "other"].map((c): [string, string] => [c, c.replace(/_/g, " ")]) },
  { name: "parsing_status", label: "Parsing", options: [["parsed", "parsed"], ["partial", "partial"], ["unparsed", "unparsed"]] as [string, string][] },
  { name: "source_file_id", label: "Source file ID" },
];

export function EventsPage() {
  const { caseId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const offset = Number(params.get("offset") ?? 0);
  const filters = paramsFor(params, FIELDS.map((f) => f.name));
  const events = useApi<EventPage>(`/api/cases/${encodeURIComponent(caseId)}/events`, { ...filters, limit: PAGE, offset });
  const move = (to: number) => {
    const next = new URLSearchParams(params);
    next.set("offset", String(Math.max(to, 0)));
    setParams(next);
  };
  const total = events.data?.total ?? 0;
  return (
    <Section
      title={`Event search (${count(events.data?.total)})`}
      actions={
        <div className="row gap">
          <button type="button" disabled={offset === 0} onClick={() => move(offset - PAGE)}>
            Previous
          </button>
          <span className="muted small">
            {total ? `${offset + 1}–${Math.min(offset + PAGE, total)}` : "0"}
          </span>
          <button type="button" disabled={offset + PAGE >= total} onClick={() => move(offset + PAGE)}>
            Next
          </button>
        </div>
      }
    >
      <FilterBar fields={FIELDS} reset={["offset"]} />
      <p className="muted small">Events with a reliable UTC time first, in time order; then the rest in file order.</p>
      <ErrorBox error={events.error} />
      {!events.data && !events.error ? <Loading /> : null}
      {events.data && !events.data.items.length ? <Empty>No events match.</Empty> : null}
      {events.data?.items.length ? <EventTable events={events.data.items} /> : null}
    </Section>
  );
}
