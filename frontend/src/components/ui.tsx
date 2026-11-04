import type { ReactNode } from "react";

import { ApiError } from "../lib/api";
import { humanize, timeBasis } from "../lib/format";
import type { Severity } from "../lib/types";

// Severity is always shown as text plus color, never color alone.
export function SeverityBadge({ severity }: { severity: Severity | null | undefined }) {
  if (!severity) return <span className="muted">—</span>;
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

export function Badge({ children, tone = "neutral", title }: { children: ReactNode; tone?: string; title?: string }) {
  return (
    <span className={`badge tone-${tone}`} title={title}>
      {children}
    </span>
  );
}

const STATUS_TONES: Record<string, string> = {
  succeeded: "ok",
  succeeded_with_warnings: "warn",
  succeeded_with_errors: "warn",
  ready: "ok",
  verified: "ok",
  expanded: "ok",
  current: "ok",
  running: "info",
  queued: "info",
  stored: "info",
  expanding: "info",
  failed: "bad",
  integrity_failed: "bad",
  missing: "bad",
  unsupported: "warn",
  cancelled: "neutral",
  open: "info",
  investigating: "warn",
  confirmed: "bad",
  false_positive: "neutral",
  resolved: "ok",
};

export function StatusBadge({ status }: { status: string | null | undefined }) {
  if (!status) return <span className="muted">—</span>;
  return <Badge tone={STATUS_TONES[status] ?? "neutral"}>{humanize(status)}</Badge>;
}

export function TimeBasis({ assumption }: { assumption: string }) {
  const basis = timeBasis(assumption);
  return (
    <Badge tone={basis.tone === "ok" ? "neutral" : basis.tone === "hint" ? "info" : "warn"} title={assumption}>
      {basis.label}
    </Badge>
  );
}

export function ErrorBox({ error }: { error: Error | undefined }) {
  if (!error) return null;
  const api = error instanceof ApiError ? error : null;
  return (
    <div className="error-box" role="alert">
      <strong>{api?.code ?? "Error"}</strong> {error.message}
      {api?.details && "errors" in api.details ? (
        <ul>
          {(api.details.errors as { loc: unknown[]; msg: string }[]).map((item, n) => (
            <li key={n}>
              {item.loc.slice(1).join(".")}: {item.msg}
            </li>
          ))}
        </ul>
      ) : null}
      {api?.requestId ? <div className="muted small">Request {api.requestId}</div> : null}
    </div>
  );
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <div className="muted loading">{what}…</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Section({ title, actions, children }: { title: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      <header className="panel-head">
        <h2>{title}</h2>
        {actions ? <div className="actions">{actions}</div> : null}
      </header>
      {children}
    </section>
  );
}

export function KeyValue({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([key, value], n) => (
        <div key={n} className="kv-row">
          <dt>{key}</dt>
          <dd>{value ?? <span className="muted">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Any JSON value, rendered as text (never as markup). */
export function JsonView({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}

export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <code className="mono" title={title}>
      {children}
    </code>
  );
}
