import { createBrowserRouter, Link, RouterProvider } from "react-router-dom";

import { Layout } from "./components/Layout";
import { CaseOverview } from "./pages/CaseOverview";
import { CasesPage } from "./pages/CasesPage";
import { EntitiesPage, EntityDetailPage, SessionDetailPage, SessionsPage } from "./pages/EntitiesPage";
import { EventsPage } from "./pages/EventsPage";
import { EvidencePage } from "./pages/EvidencePage";
import { FindingDetail } from "./pages/FindingDetail";
import { FindingsPage } from "./pages/FindingsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { RulesPage } from "./pages/RulesPage";
import { RunDetailPage, RunsPage } from "./pages/RunsPage";
import { TimelinePage } from "./pages/TimelinePage";

function NotFound() {
  return (
    <div className="panel">
      <h2>Page not found</h2>
      <Link to="/">Back to cases</Link>
    </div>
  );
}

export const routes = [
  {
    element: <Layout />,
    children: [
      { path: "/", element: <CasesPage /> },
      { path: "/rules", element: <RulesPage /> },
      {
        path: "/cases/:caseId",
        children: [
          { index: true, element: <CaseOverview /> },
          { path: "evidence", element: <EvidencePage /> },
          { path: "findings", element: <FindingsPage /> },
          { path: "findings/:findingId", element: <FindingDetail /> },
          { path: "timeline", element: <TimelinePage /> },
          { path: "events", element: <EventsPage /> },
          { path: "entities", element: <EntitiesPage /> },
          { path: "entities/detail", element: <EntityDetailPage /> },
          { path: "sessions", element: <SessionsPage /> },
          { path: "sessions/:groupId", element: <SessionDetailPage /> },
          { path: "runs", element: <RunsPage /> },
          { path: "runs/:runId", element: <RunDetailPage /> },
          { path: "reports", element: <ReportsPage /> },
        ],
      },
      { path: "*", element: <NotFound /> },
    ],
  },
];

export function App() {
  return <RouterProvider router={createBrowserRouter(routes)} />;
}
