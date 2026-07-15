export type JobStatus = "queued" | "running" | "succeeded" | "degraded" | "cancelled" | "failed";
export type MemoryMode = "lexical" | "embedding" | "off";
export type McpMode = "on" | "degraded" | "off";
export type ValidationLevel = "static-only" | "poc-generate" | "sandbox" | "manual";
export type SandboxRunner = "local" | "docker";
export type GraphMode = "agent-led" | "legacy" | "deterministic-graph" | "adaptive-graph";
export type RevisionType = "default" | "branch" | "tag" | "commit";
export type SourceSpec =
  | { kind: "local"; path: string }
  | { kind: "github"; url: string; commit?: string }
  | { kind: "gitlab"; url: string; commit?: string };

export interface ScanRunRequest {
  target?: string;
  source?: SourceSpec;
  runtime?: boolean;
  graph_mode?: GraphMode;
  llm_provider?: string;
  model?: string;
  llm_decisions?: boolean;
  llm_decision_roles?: string[];
  memory_mode?: MemoryMode;
  mcp_mode?: McpMode;
  validation_level?: ValidationLevel;
  sandbox_enabled?: boolean;
  sandbox_runner?: SandboxRunner;
  sandbox_docker_image?: string;
  sandbox_docker_context?: string;
  sandbox_docker_host?: string;
  llm_poc_repair?: boolean;
  max_repair_attempts?: number;
  include_patterns?: string[];
  exclude_patterns?: string[];
  output?: string;
  resume_run_id?: string;
  project_id?: string;
  preflight_token?: string;
}

export interface CreateRunResponse {
  job_id: string;
  status: JobStatus | string;
  status_url: string;
  project_id?: string | null;
  run_url?: string | null;
}

export interface JobStatusResponse {
  job_id: string;
  project_id?: string | null;
  target: string;
  status: JobStatus | string;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  output_dir: string;
  run_dir?: string | null;
  summary: Record<string, unknown>;
  error: string;
  source?: SourceSpec | null;
  phase?: string;
  requested_revision?: string | null;
  resolved_commit?: string | null;
  acquisition_summary?: Record<string, unknown>;
  acquisition_ref?: string | null;
  cleanup_status?: string | null;
}

export interface JobListResponse {
  jobs: JobStatusResponse[];
  total?: number | null;
  limit?: number | null;
  offset?: number | null;
  has_more?: boolean | null;
}

export type AuditEventCategory =
  | "system"
  | "rationale"
  | "hypothesis"
  | "action"
  | "tool"
  | "evidence"
  | "validation"
  | "budget"
  | "state"
  | "error";

export type AuditEventSeverity = "debug" | "info" | "notice" | "warning" | "error" | "critical";

export interface AuditEvent {
  schema_version: "audit-event.v1" | string;
  run_id: string;
  event_id: number;
  timestamp: string;
  category: AuditEventCategory;
  phase: string;
  actor: string;
  title: string;
  summary: Record<string, unknown>;
  severity: AuditEventSeverity;
  status: string;
  correlation_id?: string | null;
  causation_id?: string | null;
  artifact_refs: string[];
}

export interface AuditEventSnapshot {
  schema_version: "audit-event.v1" | string;
  run_id: string;
  events: AuditEvent[];
  last_event_id: number;
  terminal?: AuditEvent | null;
  history_status: "live" | "complete" | "unavailable" | "reconstructed" | string;
  history_reason?: string;
  journal_event_count?: number;
  replay_limit?: number;
  replay_from_event_id?: number;
  history_truncated?: boolean;
}

export interface RerunConfiguration {
  source_run_id: string;
  project_id: string;
  configuration: ScanRunRequest;
}

export interface SourcePreflightRequest {
  source: SourceSpec;
  revision_type?: RevisionType;
  revision?: string;
}

export interface SourcePreflightResponse {
  preflight_token: string;
  expires_at: string;
  source: SourceSpec;
  source_identity: string;
  source_display: string;
  suggested_name: string;
  revision_type: RevisionType | "local" | string;
  requested_revision?: string | null;
  resolved_commit?: string | null;
  policy_version: string;
  languages: Array<{ name: string; files: number; [key: string]: unknown }>;
  metadata: Record<string, unknown>;
  existing_project_id?: string | null;
}

export interface Project {
  project_id: string;
  display_name: string;
  source_kind: SourceSpec["kind"] | string;
  source: SourceSpec;
  source_identity: string;
  source_display: string;
  status: "active" | "archived" | string;
  languages: Array<{ name: string; files?: number; [key: string]: unknown }>;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  archived_at?: string | null;
  latest_run?: JobStatusResponse | null;
}

export interface ProjectListResponse {
  projects: Project[];
  total: number;
  limit?: number | null;
  offset?: number | null;
  has_more?: boolean | null;
}

export interface PostureFinding {
  finding_id: string;
  title: string;
  vulnerability_class: string;
  severity: string;
  confidence?: number | null;
  location: { path: string; start_line?: number | null; end_line?: number | null; symbol?: string | null };
  verification_status: string;
  evidence_state: string;
  evidence_refs: string[];
  artifact_refs: Array<{ path: string; url: string }>;
  run_id: string;
  fingerprint: string;
  fingerprint_version: string;
  trend_status?: string;
  run_url?: string;
}

export interface PostureCompleteness {
  schema_version: string;
  complete: boolean;
  status: string;
  checks: Record<string, boolean>;
  reasons: string[];
}

export interface DashboardRunSummary {
  job_id: string;
  project_id: string;
  status: JobStatus | string;
  phase?: string | null;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  requested_revision?: string | null;
  resolved_commit?: string | null;
  cleanup_status?: string | null;
}

export interface DashboardProject extends Omit<Project, "latest_run"> {
  latest_run?: DashboardRunSummary | null;
}

export interface PostureSnapshot {
  schema_version: string;
  run_id: string;
  project_id: string;
  created_at: string;
  versions: {
    completeness: string;
    risk_formula: string;
    fingerprint: string;
    trend: string;
  };
  availability: { status: "available" | "partial" | "unavailable" | string; reasons: string[] };
  run: DashboardRunSummary;
  repository: {
    resolved_commit?: string | null;
    languages: Record<string, number>;
    dependency_count: number;
  };
  coverage: {
    available: boolean;
    scanned_files?: number | null;
    scanned_bytes?: number | null;
    language?: string | null;
    scope?: Record<string, unknown> | null;
  };
  findings: {
    contract_available: boolean;
    validated: PostureFinding[];
    states: Record<"candidate" | "pending" | "manual" | "rejected" | "inconclusive", PostureFinding[]>;
    validation_counts: Record<"validated" | "candidate" | "pending" | "manual" | "rejected" | "inconclusive", number>;
    evidence_gate_failures: number;
  };
  severity_counts: Record<string, number>;
  risk: {
    available: boolean;
    authoritative: boolean;
    score?: number | null;
    uncapped_total: number;
    cap: number;
    formula: string;
    formula_version: string;
    severity_weights: Record<string, number>;
    confidence_fallback_rule: string;
    fallback_count: number;
    clamped_count: number;
    components: Array<Record<string, unknown>>;
  };
  completeness: PostureCompleteness;
  quality: {
    requested_mode?: string | null;
    effective_mode?: string | null;
    fallback_reason?: string | null;
    degraded_reasons: string[];
    budget: Record<string, unknown>;
    accounting_status?: string | null;
    accounting_gaps: Array<Record<string, unknown>>;
    evidence_complete: boolean;
    validation_complete: boolean;
  };
  trend: {
    comparison_status: string;
    comparable: boolean;
    basis_run_id?: string | null;
    counts: Record<"new" | "persistent" | "resolved" | "reintroduced" | "unconfirmed", number>;
    limitations: string[];
  };
}

export interface ProjectSecurityDashboard {
  schema_version: string;
  state: "no-runs" | "running-only" | "complete" | "stale-historical-posture" | "no-complete-posture" | string;
  project: DashboardProject;
  latest_run?: DashboardRunSummary | null;
  latest_run_posture?: PostureSnapshot | null;
  latest_complete_posture?: PostureSnapshot | null;
  posture?: PostureSnapshot | null;
  posture_is_historical: boolean;
  active_runs: DashboardRunSummary[];
  recent_runs: Array<{
    run: DashboardRunSummary;
    posture_status: string;
    completeness: PostureCompleteness | Record<string, unknown>;
    risk_score?: number | null;
    confirmed_count?: number | null;
    trend_counts?: Record<string, number> | null;
  }>;
  trend_series: Array<{
    run_id: string;
    created_at: string;
    complete: boolean;
    risk_score?: number | null;
    confirmed_count: number;
    severity_counts: Record<string, number>;
    trend_counts: Record<string, number>;
    comparison_status: string;
  }>;
  high_risk_findings: PostureFinding[];
  limitations: string[];
}

export interface ProjectFilters {
  query?: string;
  status?: "active" | "archived" | "all";
  security_status?: string;
  order?: "recent" | "name";
}

export interface ApiOptions {
  provider_modes: string[];
  graph_modes: GraphMode[];
  default_graph_mode: GraphMode;
  memory_modes: MemoryMode[];
  mcp_modes: McpMode[];
  validation_levels: ValidationLevel[];
  llm_decision_roles: string[];
  sandbox_runners: SandboxRunner[];
  default_docker_image: string;
  default_docker_context: string;
  default_docker_host: string;
  llm_poc_repair_default?: boolean;
  max_repair_attempts_default?: number;
  max_repair_attempts_range?: [number, number] | number[];
  poc_repair_effective_source?: string;
  poc_repair_requires_docker?: boolean;
  default_exclude_patterns: string[];
  remote_acquisition?: {
    enabled: boolean;
    network_enabled: boolean;
    allowed_hosts: string[];
    supports_head: boolean;
    limits: Record<string, number>;
  };
}

export interface RuntimeTask {
  id?: string;
  role: string;
  kind: string;
  status: string;
  fallback_reason?: string;
  artifact_refs?: string[];
  message_refs?: string[];
  graph_node_id?: string | null;
  graph_revision?: number | null;
  attempt?: number;
  lineage?: Record<string, unknown>;
}

export interface RuntimeState {
  status?: string;
  graph_mode?: GraphMode | string;
  initial_graph_ref?: string | null;
  final_graph_ref?: string | null;
  checkpoint_counts?: Record<string, number>;
  execution_path?: string[];
  graph_fallback_reason?: string;
  tasks?: RuntimeTask[];
  [key: string]: unknown;
}

export interface ReplaySummary {
  message_count?: number;
  decision_lifecycle?: Record<string, unknown>;
  runtime_lifecycle?: Record<string, unknown>;
  repair_lifecycle?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface ReportFinding {
  id?: string;
  title?: string;
  vulnerability_class?: string;
  severity?: string;
  confidence?: number;
  location?: { path?: string; start_line?: number; end_line?: number };
  evidence?: string[];
  remediation?: string;
  verification_status?: string;
  verification_reason?: string;
  validation?: Record<string, unknown>;
  repair_summary?: {
    attempt_count?: number;
    classifications?: Array<Record<string, unknown>>;
    semantic_integrity_status?: string;
    safety_status?: string;
    provisional_status?: string;
    final_status?: string;
    integrity?: Record<string, unknown>;
    final_stop_reason?: string;
  };
  [key: string]: unknown;
}

export interface AuditReport {
  executive_summary?: Record<string, unknown>;
  findings?: ReportFinding[];
  verification_candidates?: ReportFinding[];
  runtime?: {
    graph?: GraphSummary;
    investigation?: InvestigationSummary;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface InvestigationSummary {
  requested_mode?: string;
  effective_mode?: string;
  fallback_reason?: string;
  degraded_reasons?: string[];
  hypothesis_counts?: Record<string, number>;
  evidence_gate_counts?: Record<string, number>;
  verification_plan_refs?: string[];
  investigation_budget?: Record<string, unknown>;
  checkpoint_summary?: Record<string, unknown>;
}

export interface GraphSummary {
  mode?: GraphMode | string;
  schema_version?: string;
  template_id?: string;
  template_version?: string;
  revision?: number;
  mutation_counts?: { committed?: number; denied?: number };
  checkpoint_counts?: Record<string, number>;
  checkpoint_total?: number;
  replan_count?: number;
  execution_path?: string[];
  execution_path_summary?: Record<string, number>;
  fallback_reason?: string;
  artifact_refs?: Record<string, unknown>;
}
