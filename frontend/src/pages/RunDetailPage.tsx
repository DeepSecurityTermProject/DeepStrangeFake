import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, RefreshCw, RotateCcw, XCircle } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { apiClient } from "../api/client";
import { isTerminalStatus } from "../api/polling";
import type { AuditEvent, AuditEventSnapshot, JobStatusResponse, RuntimeState } from "../api/types";
import { ErrorState, LoadingState } from "../components/DataState";
import { StatusBadge } from "../components/StatusBadge";
import { useAuditEventStream } from "../events/useAuditEventStream";
import { RunDetailTabs } from "./RunDetailTabs";

export function RunDetailPage() {
  const { jobId = "", projectId = "" } = useParams();
  const [searchParams] = useSearchParams();
  const focusedFindingId = searchParams.get("finding") ?? undefined;
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState({ actor: "all", category: "all", phase: "all", severity: "all" });
  const runQuery = useQuery({ queryKey: ["run", jobId], queryFn: () => apiClient.getRun(jobId), enabled: Boolean(jobId) });
  const reconcileEvent = useCallback((event: AuditEvent) => {
    if (event.category !== "state") return;
    queryClient.setQueryData<JobStatusResponse>(["run", jobId], (current) => {
      if (!current) return current;
      const eventStatus = textValue(event.summary.job_status) || event.status;
      return { ...current, phase: textValue(event.summary.phase) || event.phase || current.phase, status: eventStatus === "running" && isTerminalStatus(current.status) ? current.status : eventStatus };
    });
  }, [jobId, queryClient]);
  const reconcileSnapshot = useCallback((snapshot: AuditEventSnapshot) => {
    const latestState = [...snapshot.events].reverse().find((event) => event.category === "state");
    if (latestState) reconcileEvent(latestState);
  }, [reconcileEvent]);
  const stream = useAuditEventStream({
    projectId: projectId || runQuery.data?.project_id || "",
    jobId,
    enabled: Boolean(jobId && (projectId || runQuery.data?.project_id)),
    onEvent: reconcileEvent,
    onSnapshot: reconcileSnapshot
  });
  const job = runQuery.data;
  const terminal = isTerminalStatus(job?.status) || stream.connection === "terminal";
  const [clockNow, setClockNow] = useState(() => Date.now());
  useEffect(() => {
    if (terminal) return;
    setClockNow(Date.now());
    const timer = window.setInterval(() => setClockNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [terminal]);
  useEffect(() => {
    if (!jobId || terminal) return;
    const delay = stream.connection === "polling-fallback" ? 2_000 : 15_000;
    const timer = window.setInterval(() => void runQuery.refetch(), delay);
    return () => window.clearInterval(timer);
  }, [jobId, runQuery.refetch, stream.connection, terminal]);
  const cancelMutation = useMutation({ mutationFn: () => apiClient.cancelRun(jobId), onSuccess: (cancelled) => queryClient.setQueryData(["run", jobId], cancelled) });
  const runtimeQuery = useQuery({ queryKey: ["runtime-state", jobId], queryFn: () => apiClient.getRuntimeState(jobId), enabled: terminal });
  const replayQuery = useQuery({ queryKey: ["replay-summary", jobId], queryFn: () => apiClient.getReplaySummary(jobId), enabled: terminal });
  const reportJsonQuery = useQuery({ queryKey: ["report-json", jobId], queryFn: () => apiClient.getReportJson(jobId), enabled: terminal });
  const markdownQuery = useQuery({ queryKey: ["markdown-report", jobId], queryFn: () => apiClient.getMarkdownReport(jobId), enabled: terminal });

  if (runQuery.isLoading) return <LoadingState title="Loading run workspace" />;
  if (runQuery.isError || !job) return <ErrorState title={String(runQuery.error ?? "Run is not available")} />;

  const effectiveProjectId = projectId || job.project_id || "";
  const mode = textValue(reportJsonQuery.data?.runtime?.investigation?.effective_mode) || textValue(job.summary.effective_mode) || textValue(job.summary.requested_mode) || "unavailable";
  const fallbackReason = textValue(reportJsonQuery.data?.runtime?.investigation?.fallback_reason) || textValue(job.summary.fallback_reason);
  const filteredEvents = filterEvents(stream.events, filters);
  const actors = unique(stream.events.map((event) => event.actor).filter(Boolean));
  const categories = unique(stream.events.map((event) => event.category));
  const phases = unique(stream.events.map((event) => event.phase).filter(Boolean));
  const severities = unique(stream.events.map((event) => event.severity));
  const latestBudget = [...stream.events].reverse().find((event) => event.category === "budget")?.summary.remaining;

  function confirmCancellation() {
    if (window.confirm("Cancel this active audit? Persisted evidence will be retained.")) cancelMutation.mutate();
  }

  return (
    <section className="page-panel run-workspace">
      <header className="run-workspace-header">
        <div>
          <Link className="back-link" to={effectiveProjectId ? `/projects/${effectiveProjectId}/runs` : "/runs"}><ArrowLeft size={16} aria-hidden="true" />{effectiveProjectId ? "Project runs" : "All runs"}</Link>
          <p className="eyebrow">Live investigation workspace</p><h1>{job.job_id}</h1><p className="technical-value">{job.target}</p>
        </div>
        <div className="page-actions">
          {!terminal && <button className="outline-action" type="button" onClick={confirmCancellation} disabled={cancelMutation.isPending}><XCircle size={18} aria-hidden="true" /> Cancel audit</button>}
          {terminal && effectiveProjectId && <Link className="outline-action" to={`/projects/${effectiveProjectId}/scans/new?rerun=${encodeURIComponent(job.job_id)}`}><RotateCcw size={18} aria-hidden="true" /> Review and rerun</Link>}
          <button className="icon-action" type="button" onClick={() => void runQuery.refetch()} aria-label="Refresh run snapshot"><RefreshCw size={18} aria-hidden="true" /></button>
        </div>
      </header>
      <div className="run-status-grid" aria-label="Run status summary">
        <RunMetric label="Status" value={<StatusBadge status={job.status} />} /><RunMetric label="Phase" value={job.phase || "unavailable"} /><RunMetric label="Progress" value={`${phaseProgress(job.phase)}%`} /><RunMetric label="Effective mode" value={mode} />
        <RunMetric label="Elapsed" value={elapsed(job, clockNow)} /><RunMetric label="Budget" value={latestBudget ? compactJson(latestBudget) : "unavailable"} /><RunMetric label="Event stream" value={connectionLabel(stream.connection)} /><RunMetric label="Events" value={String(stream.events.length)} />
      </div>
      {fallbackReason && <div className="run-alert warning-alert"><strong>Execution fallback:</strong> {fallbackReason}</div>}
      {job.status === "degraded" && <div className="run-alert warning-alert"><strong>Degraded result.</strong> Risk evidence may be incomplete; inspect the report quality indicators.</div>}
      {job.status === "failed" && <div className="run-alert error-alert"><strong>Audit failed:</strong> {job.error || "No public diagnostic is available."}</div>}
      {job.status === "cancelled" && <div className="run-alert neutral-alert"><strong>Audit cancelled.</strong> Events and artifacts persisted before cancellation remain available.</div>}
      {stream.connection === "polling-fallback" && <div className="run-alert warning-alert"><strong>Live stream unavailable.</strong> Job status is polling every two seconds while background event recovery continues.</div>}
      {stream.historyStatus === "unavailable" && <div className="run-alert neutral-alert"><strong>Event history unavailable.</strong> {stream.historyReason || "This imported or legacy run has no public event journal."}</div>}
      {stream.historyStatus === "reconstructed" && <div className="run-alert neutral-alert"><strong>Reconstructed history.</strong> Events were derived from legacy artifacts and are not a live journal.</div>}
      {cancelMutation.isError && <p className="form-error">{String(cancelMutation.error)}</p>}
      <div className="run-workspace-grid">
        <section className="timeline-panel" aria-labelledby="timeline-title">
          <div className="section-heading-row"><div><p className="eyebrow">Persisted public evidence</p><h2 id="timeline-title">Investigation timeline</h2></div><span className={`connection-pill connection-${stream.connection}`}>{connectionLabel(stream.connection)}</span></div>
          <div className="timeline-filters" aria-label="Timeline filters">
            <FilterSelect label="Agent" value={filters.actor} options={actors} onChange={(actor) => setFilters((current) => ({ ...current, actor }))} />
            <FilterSelect label="Category" value={filters.category} options={categories} onChange={(category) => setFilters((current) => ({ ...current, category }))} />
            <FilterSelect label="Phase" value={filters.phase} options={phases} onChange={(phase) => setFilters((current) => ({ ...current, phase }))} />
            <FilterSelect label="Severity" value={filters.severity} options={severities} onChange={(severity) => setFilters((current) => ({ ...current, severity }))} />
          </div>
          <EventTimeline events={filteredEvents} historyStatus={stream.historyStatus} />
        </section>
        <InvestigationSidePanel events={stream.events} runtimeState={runtimeQuery.data} stream={stream} />
      </div>
      {terminal && <section className="terminal-artifacts" aria-labelledby="artifact-title"><div className="section-heading-row"><div><p className="eyebrow">Terminal evidence</p><h2 id="artifact-title">Report and replay</h2></div></div><RunDetailTabs job={job} runtimeState={runtimeQuery.data} replaySummary={replayQuery.data} reportJson={reportJsonQuery.data} markdownReport={markdownQuery.data} focusFindingId={focusedFindingId} /></section>}
    </section>
  );
}

function EventTimeline({ events, historyStatus }: { events: AuditEvent[]; historyStatus: string }) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const lastEventId = events.at(-1)?.event_id ?? 0;
  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    if (typeof viewport.scrollTo === "function") {
      viewport.scrollTo({ top: viewport.scrollHeight, behavior: "smooth" });
    } else {
      viewport.scrollTop = viewport.scrollHeight;
    }
  }, [lastEventId]);
  if (!events.length) return <div className="timeline-viewport" ref={viewportRef} role="log" aria-live="polite" data-testid="investigation-timeline"><div className="timeline-empty">{historyStatus === "unavailable" ? "No public event journal exists for this run." : "Waiting for the first persisted investigation event."}</div></div>;
  let previousDay = "";
  return <div className="timeline-viewport" ref={viewportRef} role="log" aria-live="polite" aria-relevant="additions" data-testid="investigation-timeline"><ol className="event-timeline">{events.flatMap((event) => {
    const day = formatDay(event.timestamp);
    const divider = day !== previousDay ? <li className="timeline-day" key={`day-${day}`}><span>{day}</span></li> : null;
    previousDay = day;
    const card = <li className={`event-card event-${event.severity}`} key={event.event_id}><div className="event-rail" aria-hidden="true"><span>{String(event.event_id).padStart(2, "0")}</span></div><article><div className="event-meta"><time dateTime={event.timestamp}>{formatTimestamp(event.timestamp)}</time><span>{event.actor || "system"}</span><span>{event.category}</span><span>{event.phase || "unphased"}</span></div><div className="event-title-row"><h3>{event.title}</h3><span className={`event-status severity-${event.severity}`}>{event.severity} · {event.status}</span></div>{event.correlation_id && <p className="event-correlation">Correlation: {event.correlation_id}</p>}<EventSummary summary={event.summary} /><details className="event-details"><summary>Inspect bounded event details</summary><pre>{JSON.stringify(event.summary, null, 2)}</pre>{event.artifact_refs.length > 0 && <ul className="artifact-links">{event.artifact_refs.map((ref) => <li key={ref}><a href={ref}>Open authorized artifact</a></li>)}</ul>}</details></article></li>;
    return divider ? [divider, card] : [card];
  })}</ol></div>;
}

function EventSummary({ summary }: { summary: Record<string, unknown> }) {
  const entries = Object.entries(summary).slice(0, 6);
  if (!entries.length) return <p className="event-summary">No additional public detail.</p>;
  return <dl className="event-summary-grid">{entries.map(([key, value]) => <div key={key}><dt>{humanize(key)}</dt><dd>{compactJson(value)}</dd></div>)}</dl>;
}

function InvestigationSidePanel({ events, runtimeState, stream }: { events: AuditEvent[]; runtimeState?: RuntimeState; stream: ReturnType<typeof useAuditEventStream> }) {
  const agents = unique(events.filter((event) => ["rationale", "hypothesis", "action", "tool"].includes(event.category)).map((event) => event.actor).filter(Boolean));
  const hypotheses = unique(events.map((event) => textValue(event.summary.hypothesis_id)).filter(Boolean));
  const evidence = events.filter((event) => event.category === "evidence").length;
  const tasks = runtimeState?.tasks ?? [];
  return <aside className="investigation-side" aria-label="Investigation status"><p className="eyebrow">Public investigation state</p><h2>What is active</h2><dl className="side-metrics"><div><dt>Agents observed</dt><dd>{agents.length}</dd></div><div><dt>Hypotheses</dt><dd>{hypotheses.length}</dd></div><div><dt>Evidence events</dt><dd>{evidence}</dd></div><div><dt>Last event ID</dt><dd>{stream.lastEventId || "—"}</dd></div></dl><section><h3>Agents</h3>{agents.length ? <ul className="plain-list">{agents.map((agent) => <li key={agent}>{agent}</li>)}</ul> : <p className="side-empty">No Agent activity recorded yet.</p>}</section><section><h3>Runtime tasks</h3>{tasks.length ? <ul className="plain-list">{tasks.slice(-8).map((task, index) => <li key={task.id || `${task.role}-${index}`}><span>{task.role}</span><strong>{task.status}</strong></li>)}</ul> : <p className="side-empty">Task details become available from terminal runtime artifacts.</p>}</section><section className="connection-diagnostics"><h3>Connection</h3><p>{connectionLabel(stream.connection)}</p><small>Failures: {stream.failures} · Last heartbeat: {stream.heartbeatAt ? formatTimestamp(stream.heartbeatAt) : "not observed"}</small></section></aside>;
}

function FilterSelect({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) { return <label className="compact-field"><span>{label}</span><select aria-label={`${label} filter`} value={value} onChange={(event) => onChange(event.target.value)}><option value="all">All</option>{options.map((option) => <option value={option} key={option}>{option}</option>)}</select></label>; }
function RunMetric({ label, value }: { label: string; value: React.ReactNode }) { return <div className="run-metric"><span>{label}</span><strong>{value}</strong></div>; }
function filterEvents(events: AuditEvent[], filters: Record<string, string>) { return events.filter((event) => (filters.actor === "all" || event.actor === filters.actor) && (filters.category === "all" || event.category === filters.category) && (filters.phase === "all" || event.phase === filters.phase) && (filters.severity === "all" || event.severity === filters.severity)); }
function unique(values: string[]) { return [...new Set(values)].sort((left, right) => left.localeCompare(right)); }
function textValue(value: unknown): string { return typeof value === "string" ? value : ""; }
function compactJson(value: unknown): string { if (value === null || value === undefined || value === "") return "unavailable"; if (["string", "number", "boolean"].includes(typeof value)) return String(value); const text = JSON.stringify(value); return text.length > 180 ? `${text.slice(0, 177)}…` : text; }
function humanize(value: string) { return value.replaceAll("_", " "); }
function formatTimestamp(value: string) { const parsed = new Date(value); return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleString(); }
function formatDay(value: string) { const parsed = new Date(value); return Number.isNaN(parsed.valueOf()) ? "Undated" : parsed.toLocaleDateString(); }
function elapsed(job: JobStatusResponse, now: number) { const start = new Date(job.started_at || job.created_at).valueOf(); const end = job.finished_at ? new Date(job.finished_at).valueOf() : now; if (!Number.isFinite(start) || !Number.isFinite(end)) return "unavailable"; const seconds = Math.max(0, Math.floor((end - start) / 1_000)); if (seconds < 60) return `${seconds}s`; if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`; return `${Math.floor(seconds / 3_600)}h ${Math.floor((seconds % 3_600) / 60)}m`; }
function phaseProgress(phase?: string) { const phases = ["queued", "validating-source", "acquiring", "resolving-commit", "exporting", "analyzing", "scanning", "verifying", "reporting", "cleaning-up", "complete"]; const index = phases.indexOf(phase || "queued"); if (phase === "failed" || phase === "cancelled") return 100; return Math.round((Math.max(0, index) / (phases.length - 1)) * 100); }
function connectionLabel(connection: string) { return ({ idle: "Initializing", connecting: "Connecting", live: "Live", reconnecting: "Reconnecting", "polling-fallback": "Polling fallback", terminal: "Replay complete", unavailable: "History unavailable" } as Record<string, string>)[connection] || connection; }
