import { useEffect, useState } from "react";
import { NavLink, Outlet, useParams } from "react-router-dom";

import { useApi } from "../lib/hooks";
import type { Case } from "../lib/types";
import { EventDrawer } from "./EventDrawer";

const CASE_TABS: [string, string][] = [
  ["", "Overview"],
  ["evidence", "Evidence"],
  ["findings", "Findings"],
  ["timeline", "Timeline"],
  ["events", "Events"],
  ["entities", "Entities"],
  ["sessions", "Sessions"],
  ["runs", "Runs"],
];

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => localStorage.getItem("mizar-theme") ?? "auto");
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("mizar-theme", theme);
  }, [theme]);
  const next = () => setTheme((t) => (t === "auto" ? "dark" : t === "dark" ? "light" : "auto"));
  return [theme, next];
}

export function Layout() {
  const { caseId } = useParams();
  const { data: current } = useApi<Case>(caseId ? `/api/cases/${encodeURIComponent(caseId)}` : null);
  const [theme, nextTheme] = useTheme();
  return (
    <div className="app">
      <header className="topbar">
        <NavLink to="/" className="brand">
          MIZAR
        </NavLink>
        {caseId ? (
          <div className="case-title" title={caseId}>
            {current?.name ?? caseId}
            {current?.reference ? <span className="muted"> · {current.reference}</span> : null}
          </div>
        ) : null}
        <nav className="topnav">
          <NavLink to="/" end>
            Cases
          </NavLink>
          <NavLink to="/rules">Rules</NavLink>
          <button type="button" className="link" onClick={nextTheme} title="Color theme">
            Theme: {theme}
          </button>
        </nav>
      </header>
      {caseId ? (
        <nav className="tabs" aria-label="Case sections">
          {CASE_TABS.map(([path, label]) => (
            <NavLink key={path} to={`/cases/${encodeURIComponent(caseId)}${path ? `/${path}` : ""}`} end={path === ""}>
              {label}
            </NavLink>
          ))}
        </nav>
      ) : null}
      <main className="content">
        <Outlet />
      </main>
      <EventDrawer />
    </div>
  );
}
