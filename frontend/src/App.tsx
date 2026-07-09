import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { Activity, History, ShieldCheck } from "lucide-react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { apiClient } from "./api/client";
import { CreateScanPage } from "./pages/CreateScanPage";
import { RunDetailPage } from "./pages/RunDetailPage";
import { RunListPage } from "./pages/RunListPage";

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
            <strong>Audit Console</strong>
            <span>{healthQuery.data?.status === "ok" ? "API online" : "API pending"}</span>
          </div>
        </div>
        <nav>
          <NavLink to="/create">
            <Activity size={18} aria-hidden="true" />
            New scan
          </NavLink>
          <NavLink to="/runs">
            <History size={18} aria-hidden="true" />
            Runs
          </NavLink>
        </nav>
      </aside>
      <main>
        <Routes>
          <Route path="/" element={<Navigate to="/create" replace />} />
          <Route path="/create" element={<CreateScanPage />} />
          <Route path="/runs" element={<RunListPage />} />
          <Route path="/runs/:jobId" element={<RunDetailPage />} />
        </Routes>
      </main>
    </div>
  );
}
