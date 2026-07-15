import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ArrowUpRight, Plus } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { apiClient } from "../api/client";
import { ErrorState, LoadingState } from "../components/DataState";
import { EmptyState } from "../components/EmptyState";
import { ProjectSecurityDashboard } from "../components/ProjectSecurityDashboard";
import { StatusBadge } from "../components/StatusBadge";

export function ProjectDetailPage({ runsOnly = false }: { runsOnly?: boolean }) {
  const { projectId = "" } = useParams();
  const projectQuery = useQuery({
    queryKey: ["project", projectId],
    queryFn: () => apiClient.getProject(projectId),
    enabled: Boolean(projectId)
  });
  const runsQuery = useQuery({
    queryKey: ["project-runs", projectId],
    queryFn: () => apiClient.listProjectRuns(projectId),
    enabled: Boolean(projectId),
    refetchInterval: 5000
  });
  const dashboardQuery = useQuery({
    queryKey: ["project-dashboard", projectId],
    queryFn: () => apiClient.getProjectDashboard(projectId),
    enabled: Boolean(projectId) && !runsOnly,
    refetchInterval: 5000
  });

  if (projectQuery.isLoading || runsQuery.isLoading || (!runsOnly && dashboardQuery.isLoading)) return <LoadingState title="Loading project" />;
  if (projectQuery.isError || !projectQuery.data) return <ErrorState title={String(projectQuery.error ?? "Project is unavailable")} />;
  if (runsQuery.isError) return <ErrorState title={String(runsQuery.error)} />;
  if (!runsOnly && (dashboardQuery.isError || !dashboardQuery.data)) {
    return <ErrorState title={`Security dashboard unavailable: ${String(dashboardQuery.error ?? "no response")}`} />;
  }

  const project = projectQuery.data;
  const runs = [...(runsQuery.data?.jobs ?? [])].reverse();

  return (
    <section className="page-panel project-detail">
      <Link className="back-link" to="/projects">
        <ArrowLeft size={16} aria-hidden="true" /> Projects
      </Link>
      <header className="kinetic-hero project-hero">
        <div>
          <span className="eyebrow">{project.source_kind} / {project.status}</span>
          <h1>{runsOnly ? "Run history" : project.display_name}</h1>
          <p className="technical-value">{project.source_display}</p>
        </div>
        <span className="hero-count" aria-label={`${runs.length} runs`}>{String(runs.length).padStart(2, "0")}</span>
      </header>

      {!runsOnly && dashboardQuery.data && <ProjectSecurityDashboard dashboard={dashboardQuery.data} />}

      <div className="section-heading-row">
        <div>
          <span className="eyebrow">Immutable audit history</span>
          <h2>{runsOnly ? "All runs" : "Recent runs"}</h2>
        </div>
        <div className="page-actions">
          {!runsOnly && <Link className="outline-action" to={`/projects/${projectId}/runs`}>Full history</Link>}
          <Link className="primary-action" to={`/projects/${projectId}/scans/new`}>
            <Plus size={18} aria-hidden="true" /> New scan
          </Link>
        </div>
      </div>

      {runs.length === 0 ? (
        <EmptyState title="This project has no scan history" />
      ) : (
        <div className="table-wrap stable-surface">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Phase</th>
                <th>Revision</th>
                <th>Validated</th>
                <th>Created</th>
                <th>Audit</th>
              </tr>
            </thead>
            <tbody>
              {(runsOnly ? runs : runs.slice(0, 8)).map((run) => (
                <tr key={run.job_id}>
                  <td><StatusBadge status={run.status} /></td>
                  <td>{run.phase ?? "queued"}</td>
                  <td className="technical-value">{run.resolved_commit ?? run.requested_revision ?? "working tree"}</td>
                  <td>{String(run.summary.validated_count ?? 0)}</td>
                  <td>{formatTime(run.created_at)}</td>
                  <td>
                    <Link className="inline-link" to={`/projects/${projectId}/runs/${run.job_id}`}>
                      Inspect <ArrowUpRight size={15} aria-hidden="true" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function formatTime(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}
