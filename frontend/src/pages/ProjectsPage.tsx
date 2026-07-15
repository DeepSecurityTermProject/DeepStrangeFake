import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Archive, ArrowUpRight, Plus, RefreshCw, RotateCcw, Save, Search } from "lucide-react";
import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { apiClient } from "../api/client";
import type { Project, ProjectFilters } from "../api/types";
import { ErrorState, LoadingState } from "../components/DataState";
import { EmptyState } from "../components/EmptyState";
import { KineticMarquee } from "../components/KineticMarquee";
import { StatusBadge } from "../components/StatusBadge";

export function ProjectsPage() {
  const queryClient = useQueryClient();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<ProjectFilters["status"]>("active");
  const [securityStatus, setSecurityStatus] = useState("");
  const [order, setOrder] = useState<ProjectFilters["order"]>("recent");
  const [editingId, setEditingId] = useState("");
  const [editingName, setEditingName] = useState("");

  const filters = { query, status, security_status: securityStatus, order };
  const projectsQuery = useQuery({
    queryKey: ["projects", filters],
    queryFn: () => apiClient.listProjects(filters),
    placeholderData: (previous) => previous,
    refetchInterval: 5000
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["projects"] });
  const lifecycleMutation = useMutation({
    mutationFn: ({ project, action }: { project: Project; action: "archive" | "restore" }) =>
      action === "archive" ? apiClient.archiveProject(project.project_id) : apiClient.restoreProject(project.project_id),
    onSuccess: refresh
  });
  const renameMutation = useMutation({
    mutationFn: ({ projectId, name }: { projectId: string; name: string }) =>
      apiClient.updateProject(projectId, name),
    onSuccess: () => {
      setEditingId("");
      refresh();
    }
  });

  if (projectsQuery.isLoading) return <LoadingState title="Loading projects" />;
  if (projectsQuery.isError) return <ErrorState title={String(projectsQuery.error)} />;

  const projects = projectsQuery.data?.projects ?? [];
  const running = projects.filter((project) => ["queued", "running"].includes(project.latest_run?.status ?? "")).length;
  const degraded = projects.filter((project) => ["degraded", "failed"].includes(project.latest_run?.status ?? "")).length;

  function saveName(event: FormEvent, projectId: string) {
    event.preventDefault();
    if (editingName.trim()) renameMutation.mutate({ projectId, name: editingName.trim() });
  }

  return (
    <section className="page-panel project-catalog">
      <header className="kinetic-hero compact-hero">
        <div>
          <span className="eyebrow">Project intelligence / 01</span>
          <h1>Projects</h1>
          <p>One repository. Every audit. One evidence-backed history.</p>
        </div>
        <div className="hero-count" aria-label={`${projectsQuery.data?.total ?? 0} projects`}>
          {String(projectsQuery.data?.total ?? 0).padStart(2, "0")}
        </div>
      </header>

      <KineticMarquee
        label="Project status summary"
        items={[`${projects.length} visible projects`, `${running} active scans`, `${degraded} needs attention`, "Evidence before conclusions"]}
      />

      <div className="catalog-toolbar" aria-label="Project filters">
        <label className="search-control">
          <Search size={18} aria-hidden="true" />
          <span className="sr-only">Search projects</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search project or source" />
        </label>
        <label className="compact-field">
          <span>Status</span>
          <select value={status} onChange={(event) => setStatus(event.target.value as ProjectFilters["status"])}>
            <option value="active">Active</option>
            <option value="archived">Archived</option>
            <option value="all">All</option>
          </select>
        </label>
        <label className="compact-field">
          <span>Latest run</span>
          <select value={securityStatus} onChange={(event) => setSecurityStatus(event.target.value)}>
            <option value="">Any state</option>
            <option value="running">Running</option>
            <option value="succeeded">Succeeded</option>
            <option value="degraded">Degraded</option>
            <option value="failed">Failed</option>
          </select>
        </label>
        <label className="compact-field">
          <span>Order</span>
          <select value={order} onChange={(event) => setOrder(event.target.value as ProjectFilters["order"])}>
            <option value="recent">Recently updated</option>
            <option value="name">Project name</option>
          </select>
        </label>
        <button className="icon-action" type="button" onClick={() => projectsQuery.refetch()} aria-label="Refresh projects">
          <RefreshCw size={18} aria-hidden="true" />
        </button>
        <Link className="primary-action" to="/scans/new">
          <Plus size={18} aria-hidden="true" /> New scan
        </Link>
      </div>

      {(lifecycleMutation.error || renameMutation.error) && (
        <div className="form-error" role="alert">
          {String(lifecycleMutation.error ?? renameMutation.error)}
        </div>
      )}

      {projects.length === 0 ? (
        <EmptyState title={status === "archived" ? "No archived projects" : "No projects match these filters"} />
      ) : (
        <div className="project-grid">
          {projects.map((project, index) => (
            <article className="project-card" key={project.project_id}>
              <span className="decorative-index" aria-hidden="true">
                {String(index + 1).padStart(2, "0")}
              </span>
              <div className="project-card-topline">
                <span className="source-kind">{project.source_kind}</span>
                {project.latest_run ? <StatusBadge status={project.latest_run.status} /> : <span className="status-badge status-empty">Not scanned</span>}
              </div>
              {editingId === project.project_id ? (
                <form className="rename-form" onSubmit={(event) => saveName(event, project.project_id)}>
                  <label>
                    <span className="sr-only">Project name</span>
                    <input autoFocus value={editingName} onChange={(event) => setEditingName(event.target.value)} />
                  </label>
                  <button className="icon-action" type="submit" aria-label={`Save ${project.display_name} name`}>
                    <Save size={18} aria-hidden="true" />
                  </button>
                </form>
              ) : (
                <button
                  className="project-title-button"
                  type="button"
                  onClick={() => {
                    setEditingId(project.project_id);
                    setEditingName(project.display_name);
                  }}
                  aria-label={`Rename ${project.display_name}`}
                >
                  {project.display_name}
                </button>
              )}
              <p className="project-source">{project.source_display}</p>
              <dl className="project-facts">
                <div>
                  <dt>Language</dt>
                  <dd>{project.languages[0]?.name ?? "Pending analysis"}</dd>
                </div>
                <div>
                  <dt>Last activity</dt>
                  <dd>{formatTime(project.latest_run?.created_at ?? project.updated_at)}</dd>
                </div>
                <div>
                  <dt>Phase</dt>
                  <dd>{project.latest_run?.phase ?? "No runs"}</dd>
                </div>
              </dl>
              <div className="project-card-actions">
                <Link className="card-link" to={`/projects/${project.project_id}`}>
                  Open project <ArrowUpRight size={17} aria-hidden="true" />
                </Link>
                <Link className="card-link" to={`/projects/${project.project_id}/scans/new`}>
                  New scan <Plus size={17} aria-hidden="true" />
                </Link>
                <button
                  className="ghost-action"
                  type="button"
                  onClick={() => lifecycleMutation.mutate({ project, action: project.status === "archived" ? "restore" : "archive" })}
                  disabled={lifecycleMutation.isPending || ["queued", "running"].includes(project.latest_run?.status ?? "")}
                >
                  {project.status === "archived" ? <RotateCcw size={17} aria-hidden="true" /> : <Archive size={17} aria-hidden="true" />}
                  {project.status === "archived" ? "Restore" : "Archive"}
                </button>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function formatTime(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}
