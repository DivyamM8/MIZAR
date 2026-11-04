import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { ErrorBox, Empty, Loading, Section } from "../components/ui";
import { api } from "../lib/api";
import { utc } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { Case } from "../lib/types";

export const TIMEZONES: string[] = (() => {
  try {
    return Intl.supportedValuesOf("timeZone");
  } catch {
    return ["UTC"];
  }
})();

export function TimezoneOptions() {
  return (
    <datalist id="timezones">
      <option value="UTC" />
      {TIMEZONES.map((zone) => (
        <option key={zone} value={zone} />
      ))}
    </datalist>
  );
}

export function CasesPage() {
  const cases = useApi<Case[]>("/api/cases");
  return (
    <div className="stack">
      <Section title="Cases">
        <ErrorBox error={cases.error} />
        {!cases.data && !cases.error ? <Loading /> : null}
        {cases.data && !cases.data.length ? <Empty>No cases yet. Create one to start uploading evidence.</Empty> : null}
        {cases.data?.length ? (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Reference</th>
                <th>Analyst</th>
                <th>Files</th>
                <th>Created (UTC)</th>
              </tr>
            </thead>
            <tbody>
              {cases.data.map((item) => (
                <tr key={item.case_id}>
                  <td>
                    <Link to={`/cases/${encodeURIComponent(item.case_id)}`}>{item.name}</Link>
                  </td>
                  <td>{item.reference ?? "—"}</td>
                  <td>{item.analyst_name}</td>
                  <td>{item.file_count}</td>
                  <td>{utc(item.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </Section>
      <NewCase />
    </div>
  );
}

function NewCase() {
  const navigate = useNavigate();
  const [error, setError] = useState<Error>();
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const value = (name: string) => (String(form.get(name) ?? "").trim() || null);
    setBusy(true);
    try {
      const created = await api<Case>("/api/cases", {
        method: "POST",
        body: {
          name: value("name"),
          analyst_name: value("analyst_name"),
          reference: value("reference"),
          description: value("description"),
          default_timezone_hint: value("default_timezone_hint"),
        },
      });
      navigate(`/cases/${encodeURIComponent(created.case_id)}/evidence`);
    } catch (exc) {
      setError(exc as Error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Section title="New case">
      <form className="form" onSubmit={submit}>
        <label>
          Case name <input name="name" required maxLength={200} />
        </label>
        <label>
          Analyst <input name="analyst_name" required maxLength={200} />
        </label>
        <label>
          Reference (ticket) <input name="reference" maxLength={200} />
        </label>
        <label>
          Default timezone for logs without one{" "}
          <input name="default_timezone_hint" list="timezones" placeholder="e.g. Europe/Berlin" maxLength={64} />
        </label>
        <label className="wide">
          Description <textarea name="description" rows={3} maxLength={10000} />
        </label>
        <TimezoneOptions />
        <ErrorBox error={error} />
        <div>
          <button type="submit" className="primary" disabled={busy}>
            Create case
          </button>
        </div>
      </form>
    </Section>
  );
}
