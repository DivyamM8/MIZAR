// Display helpers. All times are shown in UTC with an explicit "Z", never converted to the
// browser's local zone: investigators compare times across sources and reports.

export function utc(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const iso = date.toISOString();
  const fraction = value.match(/\.(\d+)/)?.[1];
  const subsecond = fraction && !/^0+$/.test(fraction) ? `.${fraction.slice(0, 6).replace(/0+$/, "")}` : "";
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)}${subsecond}Z`;
}

export function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size < 10 ? 1 : 0)} ${units[unit]}`;
}

export function count(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : value.toLocaleString("en-US");
}

export function duration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 360) / 10}h`;
  return `${Math.round(seconds / 8640) / 10}d`;
}

export function shortHash(hash: string | null | undefined): string {
  return hash ? `${hash.slice(0, 12)}…` : "—";
}

/** How the UTC time of an event was established (DESIGN.md §4). */
export function timeBasis(assumption: string): { label: string; tone: "ok" | "hint" | "none" } {
  if (assumption === "explicit") return { label: "offset in record", tone: "ok" };
  if (assumption === "format_defined_utc") return { label: "UTC by format", tone: "ok" };
  if (assumption.startsWith("analyst_hint:")) return { label: `hint ${assumption.slice(13)}`, tone: "hint" };
  return { label: "no reliable time", tone: "none" };
}

export function humanize(value: string | null | undefined): string {
  return value ? value.replace(/_/g, " ") : "—";
}
