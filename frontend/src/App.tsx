import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { FolderKanban, History, Plus, Settings, ShieldCheck } from "lucide-react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { apiClient } from "./api/client";
import { LegacyRunRedirect } from "./pages/LegacyRunRedirect";
import { ProjectDetailPage } from "./pages/ProjectDetailPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { RunDetailPage } from "./pages/RunDetailPage";
import { RunListPage } from "./pages/RunListPage";
import { ScanWizardPage } from "./pages/ScanWizardPage";
import { SettingsPage } from "./pages/SettingsPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 1000
    }
  }
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppFrame />
    </QueryClientProvider>
  );
}

function AppFrame() {
  const healthQuery = useQuery({
    queryKey: ["health"],
    queryFn: apiClient.getHealth,
    retry: false
  });

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck aria-hidden="true" />
          <div>
            <strong>Deep Strange Fake</strong>
            <span>{healthQuery.data?.status === "ok" ? "Evidence engine online" : "API pending"}</span>
          </div>
        </div>
        <nav aria-label="Primary navigation">
          <NavLink to="/projects">
            <FolderKanban size={18} aria-hidden="true" />
            Projects
          </NavLink>
          <NavLink to="/scans/new">
            <Plus size={18} aria-hidden="true" />
            New scan
          </NavLink>
          <NavLink to="/runs">
            <History size={18} aria-hidden="true" />
            All runs
          </NavLink>
          <NavLink to="/settings">
            <Settings size={18} aria-hidden="true" />
            Settings
          </NavLink>
        </nav>
        <div className="sidebar-caption">Agent-led security investigation</div>
      </aside>
      <main>
        <Routes>
          <Route path="/" element={<Navigate to="/projects" replace />} />
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
          <Route path="/projects/:projectId/scans/new" element={<ScanWizardPage />} />
          <Route path="/projects/:projectId/runs" element={<ProjectDetailPage runsOnly />} />
          <Route path="/projects/:projectId/runs/:jobId" element={<RunDetailPage />} />
          <Route path="/scans/new" element={<ScanWizardPage />} />
          <Route path="/create" element={<Navigate to="/scans/new" replace />} />
          <Route path="/runs" element={<RunListPage />} />
          <Route path="/runs/:jobId" element={<LegacyRunRedirect />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/projects" replace />} />
        </Routes>
      </main>
    </div>
  );
}
