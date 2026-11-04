import { useParams, useSearchParams } from "react-router-dom";

import { EventTable } from "../components/EventTable";
import { EVENT_FILTERS, FilterBar, paramsFor } from "../components/FilterBar";
import { Histogram } from "../components/Histogram";
import { Badge, ErrorBox, Empty, Loading, Section } from "../components/ui";
import { useApi } from "../lib/hooks";
import type { Histogram as HistogramData, SourceFile, TimelinePage as Page } from "../lib/types";
import { SEVERITIES } from "./FindingsPage";

const FILTER_NAMES = [...EVENT_FILTERS.map((f) => f.name), "source_file_id", "min_severity", "finding_id", "run_id"];

export function TimelinePage() {
  const { caseId = "" } = useParams();
  const base = `/api/cases/${encodeURIComponent(caseId)}`;
  const [params, setParams] = useSearchParams();
  const files = useApi<SourceFile[]>(`${base}/files`);
  const lane = params.get("lane") === "unplaced" ? "unplaced" : "placed";
  const filters = paramsFor(params, FILTER_NAMES);
  const cursor = paramsFor(params, ["after", "before"]);
  const page = useApi<Page>(`${base}/timeline`, { lane, limit: 100, ...filters, ...cursor });
  const histogram = useApi<HistogramData>(`${base}/timeline/histogram`, { buckets: 120, ...filters });

  const go = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(patch)) {
      if (value === null) next.delete(key);
      else next.set(key, value);
    }
    setParams(next);
  };
  const fields = [
    ...EVENT_FILTERS,
    {
      name: "source_file_id",
      label: "File",
      options: (files.data ?? [])
        .filter((f) => !f.container_type)
        .map((f): [string, string] => [f.source_file_id, f.archive_member_path ?? f.original_filename]),
    },
    { name: "min_severity", label: "Evidence of findings ≥", options: SEVERITIES.map((s): [string, string] => [s, s]) },
  ];
  return (
    <div className="stack">
      <Section title="Timeline (UTC)">
        <FilterBar fields={fields} reset={["after", "before"]} />
        {params.get("finding_id") ? (
          <p>
            <Badge tone="info">Showing evidence of {params.get("finding_id")}</Badge>{" "}
            <button type="button" className="link" onClick={() => go({ finding_id: null, after: null, before: null })}>
              show all events
            </button>
          </p>
        ) : null}
        <ErrorBox error={histogram.error} />
        {histogram.data ? (
          <Histogram
            data={histogram.data}
            onSelect={(start, end) => go({ start, end, after: null, before: null, lane: null })}
          />
        ) : null}
        <div className="row gap lane-toggle">
          <button type="button" className={lane === "placed" ? "active" : ""} onClick={() => go({ lane: null, after: null, before: null })}>
            Placed in time ({histogram.data?.placed.toLocaleString() ?? "…"})
          </button>
          <button
            type="button"
            className={lane === "unplaced" ? "active" : ""}
            onClick={() => go({ lane: "unplaced", after: null, before: null })}
            title="Events without a reliable UTC time, in file order. Supply timezone/year hints and re-parse to place them."
          >
            Without reliable time ({histogram.data?.unplaced.toLocaleString() ?? "…"})
          </button>
        </div>
      </Section>
      <Section
        title={lane === "placed" ? "Events" : "Events without reliable time (file order)"}
        actions={
          <div className="row gap">
            <button type="button" disabled={!page.data?.prev_cursor} onClick={() => go({ before: page.data?.prev_cursor ?? null, after: null })}>
              ← Earlier
            </button>
            <button type="button" disabled={!page.data?.next_cursor} onClick={() => go({ after: page.data?.next_cursor ?? null, before: null })}>
              Later →
            </button>
          </div>
        }
      >
        <ErrorBox error={page.error} />
        {!page.data && !page.error ? <Loading /> : null}
        {page.data && !page.data.items.length ? <Empty>No events match.</Empty> : null}
        {page.data?.items.length ? (
          <>
            {page.data.run_id ? <p className="muted small">Finding markers from run {page.data.run_id}.</p> : null}
            <EventTable events={page.data.items} />
          </>
        ) : null}
      </Section>
    </div>
  );
}
