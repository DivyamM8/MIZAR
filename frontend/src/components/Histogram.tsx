import { duration, utc } from "../lib/format";
import type { Histogram as HistogramData } from "../lib/types";

// Plain SVG bars; the darker overlay is the share of events that are finding evidence.
export function Histogram({
  data,
  onSelect,
}: {
  data: HistogramData;
  onSelect?: (start: string, end: string) => void;
}) {
  if (!data.buckets.length || !data.bucket_seconds) return null;
  const size = data.bucket_seconds;
  const max = Math.max(...data.buckets.map((b) => b.count), 1);
  const width = 1000;
  const height = 90;
  const barWidth = width / data.buckets.length;
  const end = (start: string) => new Date(new Date(start).getTime() + size * 1000).toISOString();
  return (
    <figure className="histogram">
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="Events over time">
        {data.buckets.map((bucket, n) => {
          const h = (bucket.count / max) * (height - 4);
          const f = (bucket.finding_events / max) * (height - 4);
          return (
            <g key={bucket.start_utc} className={onSelect ? "clickable" : undefined} onClick={() => onSelect?.(bucket.start_utc, end(bucket.start_utc))}>
              <title>
                {`${utc(bucket.start_utc)} (+${duration(size)}): ${bucket.count} events, ${bucket.finding_events} finding evidence`}
              </title>
              <rect x={n * barWidth} y={0} width={barWidth} height={height} className="bar-hit" />
              <rect x={n * barWidth + 0.5} y={height - h} width={Math.max(barWidth - 1, 0.5)} height={h} className="bar" />
              {f > 0 ? <rect x={n * barWidth + 0.5} y={height - f} width={Math.max(barWidth - 1, 0.5)} height={f} className="bar-finding" /> : null}
            </g>
          );
        })}
      </svg>
      <figcaption className="row spread small muted">
        <span>{utc(data.start_utc)}</span>
        <span>
          {data.placed.toLocaleString()} placed events, {duration(size)} per bar
          {data.unplaced ? `, ${data.unplaced.toLocaleString()} without reliable time` : ""} · darker = finding evidence
        </span>
        <span>{utc(data.end_utc)}</span>
      </figcaption>
    </figure>
  );
}
