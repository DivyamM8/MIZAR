import { type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";

export interface FilterField {
  name: string;
  label: string;
  placeholder?: string;
  options?: [string, string][];
}

export const EVENT_FILTERS: FilterField[] = [
  { name: "hostname", label: "Host" },
  { name: "username", label: "User" },
  { name: "ip", label: "IP (source or destination)" },
  { name: "event_type", label: "Event type", placeholder: "e.g. logon_failed" },
  { name: "q", label: "Message contains" },
  { name: "start", label: "From (UTC)", placeholder: "2026-10-29T12:00:00Z" },
  { name: "end", label: "To (UTC)", placeholder: "2026-10-29T13:00:00Z" },
];

/** Filters live in the URL so a view can be shared and survives reloads. */
export function FilterBar({ fields, reset = [] }: { fields: FilterField[]; reset?: string[] }) {
  const [params, setParams] = useSearchParams();
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const next = new URLSearchParams(params);
    for (const field of fields) {
      const value = String(form.get(field.name) ?? "").trim();
      if (value) next.set(field.name, value);
      else next.delete(field.name);
    }
    for (const key of reset) next.delete(key);
    setParams(next);
  }
  function clear() {
    const next = new URLSearchParams(params);
    for (const field of fields) next.delete(field.name);
    for (const key of reset) next.delete(key);
    setParams(next);
  }
  return (
    <form className="filters" onSubmit={submit} key={params.toString()}>
      {fields.map((field) => (
        <label key={field.name}>
          {field.label}
          {field.options ? (
            <select name={field.name} defaultValue={params.get(field.name) ?? ""}>
              <option value="">any</option>
              {field.options.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          ) : (
            <input name={field.name} defaultValue={params.get(field.name) ?? ""} placeholder={field.placeholder} />
          )}
        </label>
      ))}
      <div className="row gap">
        <button type="submit" className="primary">
          Apply
        </button>
        <button type="button" onClick={clear}>
          Clear
        </button>
      </div>
    </form>
  );
}

export function paramsFor(params: URLSearchParams, names: string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (const name of names) {
    const value = params.get(name);
    if (value) result[name] = value;
  }
  return result;
}
