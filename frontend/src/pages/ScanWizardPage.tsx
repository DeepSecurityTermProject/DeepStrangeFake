import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, Check, GitBranch, Play, ShieldCheck } from "lucide-react";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { apiClient } from "../api/client";
import type {
  ApiOptions,
  GraphMode,
  McpMode,
  MemoryMode,
  Project,
  RevisionType,
  SourcePreflightResponse,
  SourceSpec,
  ValidationLevel
} from "../api/types";
import { ErrorState, LoadingState } from "../components/DataState";

const FALLBACK_OPTIONS: ApiOptions = {
  provider_modes: ["mock", "openai-compatible"],
  graph_modes: ["agent-led", "legacy", "deterministic-graph", "adaptive-graph"],
  default_graph_mode: "agent-led",
  memory_modes: ["lexical", "embedding", "off"],
  mcp_modes: ["on", "degraded", "off"],
  validation_levels: ["static-only", "poc-generate", "sandbox", "manual"],
  llm_decision_roles: ["orchestrator", "recon", "analysis", "verification"],
  sandbox_runners: ["local", "docker"],
  default_docker_image: "python:3.12-slim",
  default_docker_context: "",
  default_docker_host: "",
  default_exclude_patterns: ["tests/**", "fixtures/**", "external/**"],
  remote_acquisition: { enabled: false, network_enabled: false, allowed_hosts: [], supports_head: false, limits: {} }
};

export function ScanWizardPage() {
  const navigate = useNavigate();
  const { projectId: routeProjectId = "" } = useParams();
  const [searchParams] = useSearchParams();
  const rerunId = searchParams.get("rerun") || "";
  const rerunApplied = useRef("");
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [mode, setMode] = useState<"existing" | "new">(routeProjectId ? "existing" : "new");
  const [selectedProjectId, setSelectedProjectId] = useState(routeProjectId);
  const [sourceKind, setSourceKind] = useState<SourceSpec["kind"]>("local");
  const [localPath, setLocalPath] = useState("");
  const [remoteUrl, setRemoteUrl] = useState("");
  const [revisionType, setRevisionType] = useState<RevisionType>("default");
  const [revision, setRevision] = useState("");
  const [preview, setPreview] = useState<SourcePreflightResponse | null>(null);
  const [graphMode, setGraphMode] = useState<GraphMode>("agent-led");
  const [runtime, setRuntime] = useState(true);
  const [provider, setProvider] = useState("mock");
  const [model, setModel] = useState("");
  const [memoryMode, setMemoryMode] = useState<MemoryMode>("lexical");
  const [mcpMode, setMcpMode] = useState<McpMode>("off");
  const [validationLevel, setValidationLevel] = useState<ValidationLevel>("static-only");
  const [includePatterns, setIncludePatterns] = useState("");
  const [excludePatterns, setExcludePatterns] = useState("");

  const optionsQuery = useQuery({ queryKey: ["options"], queryFn: apiClient.getOptions });
  const projectsQuery = useQuery({
    queryKey: ["projects", "wizard"],
    queryFn: () => apiClient.listProjects({ status: "active", order: "recent" })
  });
  const routeProjectQuery = useQuery({
    queryKey: ["project", routeProjectId],
    queryFn: () => apiClient.getProject(routeProjectId),
    enabled: Boolean(routeProjectId)
  });
  const rerunQuery = useQuery({
    queryKey: ["rerun-config", rerunId],
    queryFn: () => apiClient.getRerunConfiguration(rerunId),
    enabled: Boolean(rerunId)
  });
  const options = optionsQuery.data ?? FALLBACK_OPTIONS;
  const selectedProject = useMemo<Project | undefined>(() => {
    if (routeProjectQuery.data) return routeProjectQuery.data;
    return projectsQuery.data?.projects.find((project) => project.project_id === selectedProjectId);
  }, [projectsQuery.data, routeProjectQuery.data, selectedProjectId]);

  useEffect(() => {
    const prior = rerunQuery.data?.configuration;
    if (!prior || rerunApplied.current === rerunId) return;
    rerunApplied.current = rerunId;
    setMode("existing");
    setSelectedProjectId(routeProjectId || rerunQuery.data?.project_id || "");
    if (prior.graph_mode) setGraphMode(prior.graph_mode);
    if (typeof prior.runtime === "boolean") setRuntime(prior.runtime);
    if (prior.llm_provider) setProvider(prior.llm_provider);
    if (prior.model) setModel(prior.model);
    if (prior.memory_mode) setMemoryMode(prior.memory_mode);
    if (prior.mcp_mode) setMcpMode(prior.mcp_mode);
    if (prior.validation_level) setValidationLevel(prior.validation_level);
    setIncludePatterns((prior.include_patterns ?? []).join("\n"));
    setExcludePatterns((prior.exclude_patterns ?? []).join("\n"));
  }, [rerunId, rerunQuery.data, routeProjectId]);

  const preflightMutation = useMutation({
    mutationFn: apiClient.preflightSource,
    onSuccess: (result) => {
      setPreview(result);
      setStep(2);
    }
  });
  const createMutation = useMutation({
    mutationFn: async () => {
      if (!preview) throw new Error("preflight-required");
      const targetProjectId = routeProjectId || selectedProjectId || preview.existing_project_id || "";
      const payload = {
        source: preview.source,
        preflight_token: preview.preflight_token,
        runtime,
        graph_mode: graphMode,
        llm_provider: provider,
        model: provider === "mock" ? undefined : model.trim() || undefined,
        llm_decisions: runtime,
        llm_decision_roles: runtime ? ["orchestrator", "recon", "analysis", "verification"] : undefined,
        memory_mode: memoryMode,
        mcp_mode: mcpMode,
        validation_level: validationLevel,
        include_patterns: parsePatterns(includePatterns),
        exclude_patterns: parsePatterns(excludePatterns || options.default_exclude_patterns.join("\n"))
      };
      return targetProjectId
        ? apiClient.createProjectRun(targetProjectId, payload)
        : apiClient.createRun(payload);
    },
    onSuccess: (result) => navigate(result.run_url || `/projects/${result.project_id}/runs/${result.job_id}`)
  });

  if (optionsQuery.isLoading || projectsQuery.isLoading || (routeProjectId && routeProjectQuery.isLoading) || (rerunId && rerunQuery.isLoading)) {
    return <LoadingState title="Preparing scan workflow" />;
  }
  if (optionsQuery.isError || projectsQuery.isError || routeProjectQuery.isError || rerunQuery.isError) {
    return <ErrorState title={String(optionsQuery.error ?? projectsQuery.error ?? routeProjectQuery.error ?? rerunQuery.error)} />;
  }

  function sourceForPreflight(): SourceSpec | null {
    if (mode === "existing") return selectedProject?.source ?? null;
    if (sourceKind === "local") {
      const path = localPath.trim();
      return path ? { kind: "local", path } : null;
    }
    const url = remoteUrl.trim();
    return url ? { kind: sourceKind, url } : null;
  }

  function runPreflight(event: FormEvent) {
    event.preventDefault();
    const source = sourceForPreflight();
    if (!source) return;
    preflightMutation.mutate({
      source,
      ...(source.kind === "local" ? {} : { revision_type: revisionType, ...(revisionType === "default" ? {} : { revision: revision.trim() }) })
    });
  }

  return (
    <section className="page-panel scan-wizard-page">
      <Link className="back-link" to={routeProjectId ? `/projects/${routeProjectId}` : "/projects"}>
        <ArrowLeft size={16} aria-hidden="true" /> {routeProjectId ? "Project" : "Projects"}
      </Link>
      <header className="kinetic-hero wizard-hero">
        <div>
          <span className="eyebrow">Source / preflight / launch</span>
          <h1>{rerunId ? "Rerun review" : "New scan"}</h1>
          <p>{rerunId ? "Review copied settings and resolve the source again before launching a new independent run." : "Resolve the exact source before the Agent begins its investigation."}</p>
        </div>
        <span className="hero-count" aria-label={`Step ${step} of 3`}>0{step}</span>
      </header>

      <ol className="wizard-progress" aria-label="Scan creation progress">
        {["Code source", "Repository preflight", "Review and launch"].map((label, index) => {
          const number = index + 1;
          return (
            <li className={step === number ? "active" : step > number ? "complete" : ""} key={label} aria-current={step === number ? "step" : undefined}>
              <span>{step > number ? <Check size={18} aria-hidden="true" /> : `0${number}`}</span>
              {label}
            </li>
          );
        })}
      </ol>

      {rerunId && <div className="notice-strip">Configuration copied from {rerunId}. No scan starts until source preflight and final review are confirmed.</div>}

      {step === 1 && (
        <form className="wizard-panel" onSubmit={runPreflight}>
          {!routeProjectId && (
            <fieldset className="segmented-field">
              <legend>Project relationship</legend>
              <div className="segmented wide-segmented">
                <button type="button" className={mode === "new" ? "active" : ""} onClick={() => setMode("new")}>New source</button>
                <button type="button" className={mode === "existing" ? "active" : ""} onClick={() => setMode("existing")}>Existing project</button>
              </div>
            </fieldset>
          )}

          {mode === "existing" ? (
            <label className="field dramatic-field">
              <span>Project</span>
              <select value={selectedProjectId} onChange={(event) => setSelectedProjectId(event.target.value)} required>
                <option value="">Select a project</option>
                {projectsQuery.data?.projects.map((project) => (
                  <option key={project.project_id} value={project.project_id}>{project.display_name} — {project.source_display}</option>
                ))}
              </select>
            </label>
          ) : (
            <>
              <fieldset className="segmented-field">
                <legend>Repository source</legend>
                <div className="segmented source-segmented">
                  {(["local", "github", "gitlab"] as SourceSpec["kind"][]).map((kind) => (
                    <button
                      type="button"
                      key={kind}
                      className={sourceKind === kind ? "active" : ""}
                      disabled={kind !== "local" && !options.remote_acquisition?.enabled}
                      onClick={() => setSourceKind(kind)}
                    >
                      {kind}
                    </button>
                  ))}
                </div>
              </fieldset>
              {sourceKind === "local" ? (
                <label className="field dramatic-field">
                  <span>Server-local absolute path</span>
                  <input value={localPath} onChange={(event) => setLocalPath(event.target.value)} required placeholder="D:\\path\\to\\repository" aria-describedby="local-path-help" />
                  <small id="local-path-help">The backend must be allowed to read this directory.</small>
                </label>
              ) : (
                <label className="field dramatic-field">
                  <span>Public {sourceKind} HTTPS URL</span>
                  <input value={remoteUrl} onChange={(event) => setRemoteUrl(event.target.value)} placeholder={`https://${sourceKind}.com/owner/repository`} required />
                </label>
              )}
            </>
          )}

          {(mode === "existing" ? selectedProject?.source.kind !== "local" : sourceKind !== "local") && (
            <div className="form-grid revision-grid">
              <label className="field">
                <span>Revision type</span>
                <select value={revisionType} onChange={(event) => setRevisionType(event.target.value as RevisionType)}>
                  <option value="default">Default branch</option>
                  <option value="branch">Branch</option>
                  <option value="tag">Tag</option>
                  <option value="commit">Commit SHA</option>
                </select>
              </label>
              {revisionType !== "default" && (
                <label className="field">
                  <span>{revisionType}</span>
                  <input value={revision} onChange={(event) => setRevision(event.target.value)} required />
                </label>
              )}
            </div>
          )}

          {preflightMutation.error && <div className="form-error" role="alert">{String(preflightMutation.error)}</div>}
          <button className="primary-action large-action" type="submit" disabled={preflightMutation.isPending || !sourceForPreflight()}>
            <ShieldCheck size={20} aria-hidden="true" /> {preflightMutation.isPending ? "Checking source" : "Run preflight"}
            <ArrowRight size={20} aria-hidden="true" />
          </button>
        </form>
      )}

      {step === 2 && preview && (
        <div className="wizard-panel preflight-result">
          <div className="preflight-title">
            <ShieldCheck size={36} aria-hidden="true" />
            <div><span className="eyebrow">Policy verified</span><h2>{preview.suggested_name}</h2></div>
          </div>
          {preview.existing_project_id && (
            <div className="notice-strip">This source already belongs to a project. The new run will be attached to its existing history.</div>
          )}
          <dl className="preflight-grid">
            <div><dt>Source</dt><dd className="technical-value">{preview.source_display}</dd></div>
            <div><dt>Resolved commit</dt><dd className="technical-value">{preview.resolved_commit ?? "Working tree"}</dd></div>
            <div><dt>Files</dt><dd>{String(preview.metadata.file_count ?? "After acquisition")}</dd></div>
            <div><dt>Total bytes</dt><dd>{formatBytes(preview.metadata.total_bytes)}</dd></div>
            <div><dt>Languages</dt><dd>{preview.languages.map((item) => item.name).join(", ") || "After acquisition"}</dd></div>
            <div><dt>Token expires</dt><dd>{formatTime(preview.expires_at)}</dd></div>
          </dl>
          <div className="wizard-actions">
            <button className="outline-action" type="button" onClick={() => setStep(1)}><ArrowLeft size={18} aria-hidden="true" /> Edit source</button>
            <button className="primary-action" type="button" onClick={() => setStep(3)}>Configure scan <ArrowRight size={18} aria-hidden="true" /></button>
          </div>
        </div>
      )}

      {step === 3 && preview && (
        <form className="wizard-panel" onSubmit={(event) => { event.preventDefault(); createMutation.mutate(); }}>
          <div className="section-heading-row">
            <div><span className="eyebrow">Trusted source locked</span><h2>Review execution</h2></div>
            <GitBranch size={36} aria-hidden="true" />
          </div>
          <div className="form-grid">
            <label className="field"><span>Graph mode</span><select value={graphMode} onChange={(event) => setGraphMode(event.target.value as GraphMode)}>{options.graph_modes.map((value) => <option key={value}>{value}</option>)}</select></label>
            <label className="field"><span>Provider</span><select value={provider} onChange={(event) => setProvider(event.target.value)}>{options.provider_modes.map((value) => <option key={value}>{value}</option>)}</select></label>
            {provider !== "mock" && <label className="field"><span>Model</span><input value={model} onChange={(event) => setModel(event.target.value)} /></label>}
            <label className="field"><span>Memory</span><select value={memoryMode} onChange={(event) => setMemoryMode(event.target.value as MemoryMode)}>{options.memory_modes.map((value) => <option key={value}>{value}</option>)}</select></label>
            <label className="field"><span>MCP</span><select value={mcpMode} onChange={(event) => setMcpMode(event.target.value as McpMode)}>{options.mcp_modes.map((value) => <option key={value}>{value}</option>)}</select></label>
            <label className="field"><span>Validation</span><select value={validationLevel} onChange={(event) => setValidationLevel(event.target.value as ValidationLevel)}>{options.validation_levels.map((value) => <option key={value}>{value}</option>)}</select></label>
            <label className="check-row"><input type="checkbox" checked={runtime} onChange={(event) => setRuntime(event.target.checked)} /><span>Enable Agent runtime</span></label>
          </div>
          <div className="form-grid scope-grid">
            <label className="field"><span>Include patterns</span><textarea value={includePatterns} onChange={(event) => setIncludePatterns(event.target.value)} /></label>
            <label className="field"><span>Exclude patterns</span><textarea value={excludePatterns} onChange={(event) => setExcludePatterns(event.target.value)} placeholder={options.default_exclude_patterns.join("\n")} /></label>
          </div>
          <div className="launch-summary">
            <span>Source</span><strong className="technical-value">{preview.source_display}</strong>
            <span>Revision</span><strong className="technical-value">{preview.resolved_commit ?? "Working tree"}</strong>
            <span>Execution</span><strong>{graphMode} / {provider} / {validationLevel}</strong>
          </div>
          {createMutation.error && <div className="form-error" role="alert">{String(createMutation.error)}</div>}
          <div className="wizard-actions">
            <button className="outline-action" type="button" onClick={() => setStep(2)}><ArrowLeft size={18} aria-hidden="true" /> Preflight</button>
            <button className="primary-action large-action" type="submit" disabled={createMutation.isPending}>
              <Play size={20} aria-hidden="true" /> {createMutation.isPending ? "Starting audit" : "Launch audit"}
            </button>
          </div>
        </form>
      )}
    </section>
  );
}

function parsePatterns(value: string): string[] {
  return value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
}

function formatBytes(value: unknown): string {
  if (typeof value !== "number") return "After acquisition";
  if (value < 1024) return `${value} B`;
  return `${(value / 1024).toFixed(1)} KiB`;
}

function formatTime(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}
