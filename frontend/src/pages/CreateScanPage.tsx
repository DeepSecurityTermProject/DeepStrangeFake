import { useMutation, useQuery } from "@tanstack/react-query";
import { Play, ShieldCheck } from "lucide-react";
import { FormEvent, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { apiClient } from "../api/client";
import type { ApiOptions, McpMode, MemoryMode, SandboxRunner, ValidationLevel } from "../api/types";

const DEFAULT_OPTIONS: ApiOptions = {
  provider_modes: ["mock", "openai-compatible"],
  memory_modes: ["lexical", "embedding", "off"],
  mcp_modes: ["on", "degraded", "off"],
  validation_levels: ["static-only", "poc-generate", "sandbox", "manual"],
  llm_decision_roles: ["orchestrator", "recon", "analysis", "verification"],
  sandbox_runners: ["local", "docker"],
  default_docker_image: "python:3.12-slim",
  default_docker_context: "",
  default_docker_host: "",
  llm_poc_repair_default: false,
  max_repair_attempts_default: 1,
  max_repair_attempts_range: [0, 2],
  poc_repair_effective_source: "default",
  poc_repair_requires_docker: true,
  default_exclude_patterns: ["tests/**", "test/**", "fixtures/**", "external/**", "openspec/**", ".codex/**"]
};

function parsePatterns(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function CreateScanPage() {
  const navigate = useNavigate();
  const [target, setTarget] = useState("fixtures/integration_smoke");
  const [runtime, setRuntime] = useState(false);
  const [provider, setProvider] = useState("mock");
  const [model, setModel] = useState("");
  const [llmDecisions, setLlmDecisions] = useState(false);
  const [roles, setRoles] = useState<string[]>(["analysis", "verification"]);
  const [memoryMode, setMemoryMode] = useState<MemoryMode>("lexical");
  const [mcpMode, setMcpMode] = useState<McpMode>("off");
  const [validationLevel, setValidationLevel] = useState<ValidationLevel>("static-only");
  const [sandboxEnabled, setSandboxEnabled] = useState(false);
  const [sandboxRunner, setSandboxRunner] = useState<SandboxRunner>("local");
  const [dockerImage, setDockerImage] = useState(DEFAULT_OPTIONS.default_docker_image);
  const [dockerContext, setDockerContext] = useState(DEFAULT_OPTIONS.default_docker_context);
  const [dockerHost, setDockerHost] = useState(DEFAULT_OPTIONS.default_docker_host);
  const [llmPoCRepair, setLlmPoCRepair] = useState(false);
  const [maxRepairAttempts, setMaxRepairAttempts] = useState(1);
  const [includePatterns, setIncludePatterns] = useState("");
  const [excludePatterns, setExcludePatterns] = useState(DEFAULT_OPTIONS.default_exclude_patterns.join("\n"));
  const [targetError, setTargetError] = useState("");

  const optionsQuery = useQuery({
    queryKey: ["options"],
    queryFn: apiClient.getOptions
  });
  const options = optionsQuery.data ?? DEFAULT_OPTIONS;
  const selectedDockerImage = dockerImage.trim() || options.default_docker_image;
  const selectedDockerContext = dockerContext.trim();
  const selectedDockerHost = dockerHost.trim();
  const providerMode = provider === "mock" ? "mock" : "openai-compatible";
  const selectedRoles = useMemo(() => roles.filter(Boolean), [roles]);

  const createRun = useMutation({
    mutationFn: apiClient.createRun,
    onSuccess: (result) => navigate(`/runs/${result.job_id}`)
  });

  function toggleRole(role: string) {
    setRoles((current) => (current.includes(role) ? current.filter((item) => item !== role) : [...current, role]));
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    const cleanTarget = target.trim();
    if (!cleanTarget) {
      setTargetError("Target is required");
      return;
    }
    setTargetError("");
    const requestedModel = providerMode === "mock" ? "" : model.trim();
    createRun.mutate({
      target: cleanTarget,
      runtime,
      llm_provider: providerMode,
      llm_decisions: llmDecisions,
      llm_decision_roles: llmDecisions ? selectedRoles : undefined,
      memory_mode: memoryMode,
      mcp_mode: mcpMode,
      validation_level: validationLevel,
      sandbox_enabled: sandboxEnabled,
      sandbox_runner: sandboxRunner,
      llm_poc_repair: llmPoCRepair,
      max_repair_attempts: maxRepairAttempts,
      ...(sandboxRunner === "docker"
        ? {
            sandbox_docker_image: selectedDockerImage,
            ...(selectedDockerContext ? { sandbox_docker_context: selectedDockerContext } : {}),
            ...(selectedDockerHost ? { sandbox_docker_host: selectedDockerHost } : {})
          }
        : {}),
      include_patterns: parsePatterns(includePatterns),
      exclude_patterns: parsePatterns(excludePatterns),
      ...(requestedModel ? { model: requestedModel } : {})
    });
  }

  return (
    <section className="page-panel">
      <div className="page-heading">
        <div>
          <h1>Scan Console</h1>
          <p>Local audit workflow</p>
        </div>
        <ShieldCheck aria-hidden="true" />
      </div>
      <form className="scan-form" onSubmit={submit}>
        <label className="field">
          <span>Target</span>
          <input
            id="target"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            aria-invalid={Boolean(targetError)}
          />
        </label>
        {targetError && <div className="form-error">{targetError}</div>}

        <div className="form-grid">
          <label className="check-row">
            <input id="runtime" type="checkbox" checked={runtime} onChange={(event) => setRuntime(event.target.checked)} />
            <span>Runtime</span>
          </label>
          <label className="check-row">
            <input
              id="llm-decisions"
              type="checkbox"
              checked={llmDecisions}
              onChange={(event) => setLlmDecisions(event.target.checked)}
            />
            <span>LLM decisions</span>
          </label>
          <label className="check-row">
            <input
              id="sandbox-enabled"
              type="checkbox"
              checked={sandboxEnabled}
              onChange={(event) => setSandboxEnabled(event.target.checked)}
            />
            <span>Sandbox execution</span>
          </label>
          <label className="check-row">
            <input
              id="llm-poc-repair"
              type="checkbox"
              checked={llmPoCRepair}
              onChange={(event) => {
                const enabled = event.target.checked;
                setLlmPoCRepair(enabled);
                if (enabled) {
                  setRuntime(true);
                  setValidationLevel("sandbox");
                  setSandboxEnabled(true);
                  setSandboxRunner("docker");
                }
              }}
            />
            <span>LLM PoC repair</span>
          </label>
        </div>

        <fieldset className="segmented-field">
          <legend>Provider</legend>
          <div className="segmented">
            {options.provider_modes.map((mode) => (
              <button
                type="button"
                className={providerMode === mode ? "active" : ""}
                key={mode}
                onClick={() => setProvider(mode)}
              >
                {mode === "mock" ? "Mock" : "Real"}
              </button>
            ))}
          </div>
        </fieldset>

        {providerMode !== "mock" && (
          <label className="field">
            <span>Model</span>
            <input value={model} onChange={(event) => setModel(event.target.value)} />
          </label>
        )}

        <div className="form-grid">
          <label className="field">
            <span>Memory</span>
            <select value={memoryMode} onChange={(event) => setMemoryMode(event.target.value as MemoryMode)}>
              {options.memory_modes.map((mode) => (
                <option key={mode} value={mode}>
                  {mode}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>MCP</span>
            <select value={mcpMode} onChange={(event) => setMcpMode(event.target.value as McpMode)}>
              {options.mcp_modes.map((mode) => (
                <option key={mode} value={mode}>
                  {mode}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Validation</span>
            <select
              value={validationLevel}
              onChange={(event) => {
                const next = event.target.value as ValidationLevel;
                setValidationLevel(next);
                if (next === "sandbox") {
                  setSandboxEnabled(true);
                } else {
                  setLlmPoCRepair(false);
                }
              }}
            >
              {options.validation_levels.map((level) => (
                <option key={level} value={level}>
                  {level}
                </option>
              ))}
            </select>
          </label>
          {sandboxEnabled && (
            <label className="field">
              <span>Sandbox runner</span>
              <select
                value={sandboxRunner}
                onChange={(event) => {
                  const next = event.target.value as SandboxRunner;
                  setSandboxRunner(next);
                  if (next !== "docker") {
                    setLlmPoCRepair(false);
                  }
                }}
              >
                {options.sandbox_runners.map((runner) => (
                  <option key={runner} value={runner}>
                    {runner}
                  </option>
                ))}
              </select>
            </label>
          )}
          {sandboxEnabled && sandboxRunner === "docker" && (
            <label className="field">
              <span>Docker image</span>
              <input value={dockerImage} onChange={(event) => setDockerImage(event.target.value)} />
            </label>
          )}
          {llmPoCRepair && validationLevel === "sandbox" && sandboxRunner === "docker" && (
            <label className="field">
              <span>Maximum repair attempts</span>
              <select
                value={maxRepairAttempts}
                onChange={(event) => setMaxRepairAttempts(Number(event.target.value))}
              >
                {[0, 1, 2].map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
          )}
          {sandboxEnabled && sandboxRunner === "docker" && (
            <label className="field">
              <span>Docker context</span>
              <input value={dockerContext} onChange={(event) => setDockerContext(event.target.value)} />
            </label>
          )}
          {sandboxEnabled && sandboxRunner === "docker" && (
            <label className="field">
              <span>Docker host</span>
              <input value={dockerHost} onChange={(event) => setDockerHost(event.target.value)} />
            </label>
          )}
        </div>

        {llmDecisions && (
          <fieldset className="role-grid">
            <legend>Decision roles</legend>
            {options.llm_decision_roles.map((role) => (
              <label className="check-row" key={role}>
                <input type="checkbox" checked={roles.includes(role)} onChange={() => toggleRole(role)} />
                <span>{role}</span>
              </label>
            ))}
          </fieldset>
        )}

        <div className="form-grid scope-grid">
          <label className="field">
            <span>Include patterns</span>
            <textarea value={includePatterns} onChange={(event) => setIncludePatterns(event.target.value)} rows={4} />
          </label>
          <label className="field">
            <span>Exclude patterns</span>
            <textarea value={excludePatterns} onChange={(event) => setExcludePatterns(event.target.value)} rows={4} />
          </label>
        </div>

        {createRun.error && <div className="form-error">{String(createRun.error)}</div>}
        <button className="primary-action" type="submit" disabled={createRun.isPending}>
          <Play size={18} aria-hidden="true" />
          Create scan
        </button>
      </form>
    </section>
  );
}
