import { useState } from "react";
import { EmptyState } from "../components/EmptyState";
import { StatusBadge } from "../components/StatusBadge";
import type { AuditReport, JobStatusResponse, ReplaySummary, ReportFinding, RuntimeState } from "../api/types";

type TabId = "summary" | "findings" | "runtime" | "replay" | "markdown";

const TABS: Array<{ id: TabId; label: string }> = [
  { id: "summary", label: "Summary" },
  { id: "findings", label: "Findings" },
  { id: "runtime", label: "Runtime Tasks" },
  { id: "replay", label: "Replay" },
  { id: "markdown", label: "Markdown Report" }
];

interface RunDetailTabsProps {
  job: JobStatusResponse;
  runtimeState?: RuntimeState;
  replaySummary?: ReplaySummary;
  reportJson?: AuditReport;
  markdownReport?: string;
}

export function RunDetailTabs({ job, runtimeState, replaySummary, reportJson, markdownReport }: RunDetailTabsProps) {
  const [activeTab, setActiveTab] = useState<TabId>("summary");

  return (
    <div className="detail-tabs">
      <div className="tab-list" role="tablist" aria-label="Run detail sections">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            type="button"
            aria-selected={activeTab === tab.id}
            className={activeTab === tab.id ? "active" : ""}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="tab-panel">
        {activeTab === "summary" && <SummaryTab job={job} reportJson={reportJson} />}
        {activeTab === "findings" && <FindingsTab reportJson={reportJson} />}
        {activeTab === "runtime" && <RuntimeTasksTab runtimeState={runtimeState} />}
        {activeTab === "replay" && <ReplayTab replaySummary={replaySummary} />}
        {activeTab === "markdown" && <MarkdownReportTab markdownReport={markdownReport} />}
      </div>
    </div>
  );
}

function SummaryTab({ job, reportJson }: { job: JobStatusResponse; reportJson?: AuditReport }) {
  const summary = job.summary ?? {};
  const reportSummary = reportJson?.executive_summary ?? {};
  const graph = reportJson?.runtime?.graph;
  return (
    <div className="summary-grid">
      <Metric label="Status" value={<StatusBadge status={job.status} />} />
      <Metric label="Target" value={job.target} />
      <Metric label="Run directory" value={job.run_dir || job.output_dir} />
      <Metric label="Candidates" value={stringValue(summary.candidate_count)} />
      <Metric label="Rejected" value={stringValue(summary.rejected_count)} />
      <Metric label="Validated" value={stringValue(summary.validated_count)} />
      <Metric label="Confirmed" value={stringValue(valueFrom(summary, reportSummary, "confirmed_count"))} />
      <Metric label="Likely" value={stringValue(valueFrom(summary, reportSummary, "likely_count"))} />
      <Metric label="Manual required" value={stringValue(valueFrom(summary, reportSummary, "manual_required_count"))} />
      <Metric label="Runtime state" value={stringValue(summary.runtime_state_ref)} />
      {graph && <Metric label="Graph mode" value={stringValue(graph.mode)} />}
      {graph && <Metric label="Graph revision" value={stringValue(graph.revision)} />}
      {graph && <Metric label="Graph mutations" value={`${graph.mutation_counts?.committed ?? 0} committed / ${graph.mutation_counts?.denied ?? 0} denied`} />}
      {graph && <Metric label="Graph checkpoints" value={stringValue(graph.checkpoint_total)} />}
      {graph && <Metric label="Graph fallback" value={graph.fallback_reason || "none"} />}
      {job.error && <Metric label="Error" value={job.error} />}
    </div>
  );
}

function FindingsTab({ reportJson }: { reportJson?: AuditReport }) {
  const findings = reportJson?.verification_candidates ?? reportJson?.findings ?? [];
  if (!reportJson) {
    return <EmptyState title="Report JSON is not available" />;
  }
  if (findings.length === 0) {
    return <EmptyState title="No findings in report" />;
  }
  return (
    <div className="finding-list">
      {findings.map((finding, index) => (
        <article className="finding-item" key={finding.id ?? `${finding.title}-${index}`}>
          <div className="finding-heading">
            <div>
              <h3>{finding.title ?? "Untitled finding"}</h3>
              <p>{finding.vulnerability_class ?? "unknown class"}</p>
            </div>
            <div className="finding-badges">
              {finding.verification_status && <span className={`verification-status verification-${finding.verification_status}`}>{statusLabel(finding.verification_status)}</span>}
              <span className={`severity severity-${finding.severity ?? "unknown"}`}>{finding.severity ?? "unknown"}</span>
            </div>
          </div>
          <dl className="compact-list">
            <dt>Location</dt>
            <dd>{formatLocation(finding.location)}</dd>
            <dt>Status</dt>
            <dd>{statusLabel(finding.verification_status) || "n/a"}</dd>
            <dt>Reason</dt>
            <dd>{finding.verification_reason ?? "n/a"}</dd>
            <dt>Confidence</dt>
            <dd>{finding.confidence === undefined ? "n/a" : `${Math.round(finding.confidence * 100)}%`}</dd>
            <dt>Exit code</dt>
            <dd>{stringValue(validationValue(finding, "exit_code"))}</dd>
            <dt>Runner</dt>
            <dd>{stringValue(validationEnvironmentValue(finding, "runner"))}</dd>
            <dt>Docker image</dt>
            <dd>{stringValue(validationEnvironmentValue(finding, "docker_image"))}</dd>
            <dt>Judge</dt>
            <dd>{stringValue(validationValue(finding, "judge_reason"))}</dd>
            <dt>Repair attempts</dt>
            <dd>{stringValue(repairSummaryValue(finding, "attempt_count") ?? validationValue(finding, "repair_attempt_count"))}</dd>
            <dt>Repair classifications</dt>
            <dd>{formatRepairClassifications(repairSummaryValue(finding, "classifications"))}</dd>
            <dt>Semantic integrity</dt>
            <dd>{stringValue(repairSummaryValue(finding, "semantic_integrity_status"))}</dd>
            <dt>Safety gate</dt>
            <dd>{stringValue(repairSummaryValue(finding, "safety_status"))}</dd>
            <dt>Repair stop</dt>
            <dd>{stringValue(repairSummaryValue(finding, "final_stop_reason"))}</dd>
            <dt>Target integrity</dt>
            <dd>{formatIntegrity(repairSummaryValue(finding, "integrity"))}</dd>
            <dt>stdout</dt>
            <dd>{stringValue(validationValue(finding, "stdout_preview"))}</dd>
            <dt>stderr</dt>
            <dd>{stringValue(validationValue(finding, "stderr_preview"))}</dd>
            <dt>PoC refs</dt>
            <dd>{formatRefs(validationValue(finding, "poc_refs"))}</dd>
            <dt>Sandbox refs</dt>
            <dd>{formatRefs(validationValue(finding, "sandbox_result_refs"))}</dd>
            <dt>Evidence</dt>
            <dd>{finding.evidence?.join(" | ") || "n/a"}</dd>
            <dt>Remediation</dt>
            <dd>{finding.remediation ?? "n/a"}</dd>
          </dl>
        </article>
      ))}
    </div>
  );
}

function RuntimeTasksTab({ runtimeState }: { runtimeState?: RuntimeState }) {
  if (!runtimeState) {
    return <EmptyState title="Runtime state is not available" />;
  }
  const tasks = runtimeState.tasks ?? [];
  if (tasks.length === 0) {
    return <EmptyState title="No runtime tasks recorded" />;
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Graph node</th>
            <th>Revision</th>
            <th>Attempt</th>
            <th>Role</th>
            <th>Kind</th>
            <th>Status</th>
            <th>Artifacts</th>
            <th>Messages</th>
            <th>Fallback</th>
          </tr>
        </thead>
        <tbody>
          {tasks.map((task, index) => (
            <tr key={task.id ?? `${task.role}-${index}`}>
              <td>{task.id ?? index + 1}</td>
              <td>{task.graph_node_id ?? "n/a"}</td>
              <td>{task.graph_revision ?? "n/a"}</td>
              <td>{task.attempt ?? 0}</td>
              <td>{task.role}</td>
              <td>{task.kind}</td>
              <td>{task.status}</td>
              <td>{task.artifact_refs?.length ?? 0}</td>
              <td>{task.message_refs?.length ?? 0}</td>
              <td>{task.fallback_reason ?? ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ReplayTab({ replaySummary }: { replaySummary?: ReplaySummary }) {
  if (!replaySummary) {
    return <EmptyState title="Replay summary is not available" />;
  }
  return (
    <div className="json-grid">
      <Metric label="Message count" value={String(replaySummary.message_count ?? 0)} />
      <JsonBlock title="Decision lifecycle" value={replaySummary.decision_lifecycle ?? {}} />
      <JsonBlock title="Runtime lifecycle" value={replaySummary.runtime_lifecycle ?? {}} />
      <JsonBlock title="PoC repair lifecycle" value={replaySummary.repair_lifecycle ?? {}} />
    </div>
  );
}

function MarkdownReportTab({ markdownReport }: { markdownReport?: string }) {
  if (!markdownReport) {
    return <EmptyState title="Markdown report is not available" />;
  }
  return <pre className="markdown-report">{markdownReport}</pre>;
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value || "n/a"}</strong>
    </div>
  );
}

function JsonBlock({ title, value }: { title: string; value: unknown }) {
  return (
    <section className="json-block">
      <h3>{title}</h3>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </section>
  );
}

function stringValue(value: unknown): string {
  if (value === undefined || value === null || value === "") {
    return "n/a";
  }
  return String(value);
}

function valueFrom(primary: Record<string, unknown>, secondary: Record<string, unknown>, key: string): unknown {
  return primary[key] ?? secondary[key];
}

function validationValue(finding: { validation?: Record<string, unknown> }, key: string): unknown {
  return finding.validation?.[key];
}

function validationEnvironmentValue(finding: { validation?: Record<string, unknown> }, key: string): unknown {
  const environment = finding.validation?.environment;
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    return undefined;
  }
  return (environment as Record<string, unknown>)[key];
}

function repairSummaryValue(
  finding: ReportFinding,
  key: string
): unknown {
  return (finding.repair_summary as Record<string, unknown> | undefined)?.[key];
}

function formatRepairClassifications(value: unknown): string {
  if (!Array.isArray(value) || value.length === 0) {
    return "n/a";
  }
  return value
    .map((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        return String(entry);
      }
      const record = entry as Record<string, unknown>;
      return `${stringValue(record.failure_class)}@${stringValue(record.attempt_index)}`;
    })
    .join(" | ");
}

function formatIntegrity(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return "n/a";
  }
  const integrity = value as Record<string, unknown>;
  if (integrity.unchanged === true) {
    return "unchanged";
  }
  if (integrity.unchanged === false) {
    return `changed (${stringValue(integrity.changed_count)} changed, ${stringValue(integrity.added_count)} added, ${stringValue(integrity.removed_count)} removed)`;
  }
  return "n/a";
}

function formatRefs(value: unknown): string {
  if (Array.isArray(value)) {
    return value.length ? value.join(" | ") : "n/a";
  }
  return stringValue(value);
}

function statusLabel(status?: string): string {
  if (!status) {
    return "";
  }
  return status
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatLocation(location?: { path?: string; start_line?: number; end_line?: number }): string {
  if (!location?.path) {
    return "n/a";
  }
  const line = location.start_line ? `:${location.start_line}` : "";
  return `${location.path}${line}`;
}
