import { ArrowUpRight, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import type { PostureSnapshot, ProjectSecurityDashboard as Dashboard } from "../api/types";
import { KineticMarquee } from "./KineticMarquee";
import { StatusBadge } from "./StatusBadge";

const severities = ["critical", "high", "medium", "low", "informational"] as const;
const validationStates = ["candidate", "pending", "manual", "rejected", "inconclusive"] as const;
const trendStates = ["new", "persistent", "resolved", "reintroduced", "unconfirmed"] as const;

export function ProjectSecurityDashboard({ dashboard }: { dashboard: Dashboard }) {
  const posture = dashboard.posture ?? null;
  const latestPosture = dashboard.latest_run_posture ?? null;
  const validationSource = latestPosture?.findings.contract_available ? latestPosture : posture;
  const qualitySource = latestPosture ?? posture;
  const latestRun = dashboard.latest_run;
  const latestCoverage = latestPosture ?? (
    posture?.run.job_id === latestRun?.job_id ? posture : null
  );
  const confirmed = posture?.findings.validated.length ?? null;
  const score = posture?.risk.score ?? null;
  const postureRun = dashboard.latest_complete_posture?.run;
  const stateMessage = dashboardStateMessage(dashboard);

  return (
    <div className="posture-dashboard">
      <KineticMarquee
        speed="slow"
        label="Project security posture summary"
        items={[
          `Project ${dashboard.project.display_name}`,
          `Latest ${latestRun?.status ?? "no run"}`,
          `Confirmed ${confirmed ?? "unavailable"}`,
          `Risk ${score ?? "unavailable"}`,
          `Posture ${postureRun?.job_id ?? "not established"}`
        ]}
      />

      {stateMessage && (
        <div className={`posture-notice posture-state-${dashboard.state}`} role="status">
          <ShieldAlert size={22} aria-hidden="true" />
          <div>
            <strong>{stateMessage.title}</strong>
            <span>{stateMessage.detail}</span>
          </div>
        </div>
      )}

      <section aria-labelledby="latest-audit-heading">
        <div className="section-heading-row">
          <div>
            <span className="eyebrow">Latest-run truth</span>
            <h2 id="latest-audit-heading">Audit status</h2>
          </div>
          {latestRun && <StatusBadge status={latestRun.status} />}
        </div>
        <div className="posture-fact-grid">
          <Fact label="Latest run" value={latestRun?.job_id ?? "No audit submitted"} technical />
          <Fact label="Started" value={formatTime(latestRun?.started_at)} />
          <Fact label="Finished" value={formatTime(latestRun?.finished_at)} />
          <Fact label="Active runs" value={String(dashboard.active_runs.length)} />
          <Fact
            label="Scanned files"
            value={formatMaybeNumber(latestCoverage?.coverage.scanned_files)}
          />
          <Fact
            label="Coverage"
            value={latestCoverage?.coverage.available ? "Evidence complete" : "Unavailable / incomplete"}
          />
          <Fact
            label="Latest complete posture"
            value={postureRun?.job_id ?? "Not established"}
            technical
          />
          <Fact
            label="Posture attribution"
            value={dashboard.posture_is_historical ? "Historical — not latest run" : posture ? "Latest run" : "Unavailable"}
          />
        </div>
      </section>

      <section aria-labelledby="risk-heading">
        <div className="section-heading-row">
          <div>
            <span className="eyebrow">Validated findings only</span>
            <h2 id="risk-heading">Security posture</h2>
          </div>
        </div>
        <div className="risk-layout">
          <article className={`risk-card ${score === null ? "risk-unavailable" : ""}`}>
            <span>Deterministic risk / 100</span>
            <strong aria-label={score === null ? "Risk score unavailable" : `Risk score ${score} out of 100`}>
              {score === null ? "N/A" : String(score).padStart(2, "0")}
            </strong>
            <p>
              {posture?.risk.authoritative
                ? "Trusted code calculated this score from evidence-gated findings."
                : "No complete posture is available; the console does not publish a misleading zero score."}
            </p>
            {posture && (
              <details>
                <summary>Formula and components</summary>
                <p className="technical-value">{posture.risk.formula}</p>
                <p>Version: <code>{posture.risk.formula_version}</code></p>
                <p>
                  Weights: critical {posture.risk.severity_weights.critical}, high {posture.risk.severity_weights.high},
                  medium {posture.risk.severity_weights.medium}, low {posture.risk.severity_weights.low}, informational {posture.risk.severity_weights.informational}.
                </p>
                <p>{posture.risk.confidence_fallback_rule}</p>
                <p>{posture.risk.components.length} validated component(s); {posture.risk.fallback_count} confidence fallback(s).</p>
              </details>
            )}
          </article>

          <article className="confirmed-card">
            <span>Confirmed findings</span>
            <strong>{confirmed === null ? "N/A" : String(confirmed).padStart(2, "0")}</strong>
            <div className="severity-distribution" aria-label="Confirmed finding severity distribution">
              {severities.map((severity) => {
                const count = posture?.severity_counts[severity] ?? 0;
                const max = Math.max(1, ...(posture ? Object.values(posture.severity_counts) : [1]));
                return (
                  <div key={severity} className="severity-row">
                    <span>{severity}</span>
                    <div className="severity-bar" aria-hidden="true">
                      <i className={`severity-fill severity-fill-${severity}`} style={{ width: `${(count / max) * 100}%` }} />
                    </div>
                    <strong>{count}</strong>
                  </div>
                );
              })}
            </div>
          </article>
        </div>

        <div className="validation-state-grid" aria-label="Separate validation state counts">
          {validationStates.map((state) => (
            <Fact
              key={state}
              label={state === "candidate" ? "Static / likely candidates" : state}
              value={
                validationSource?.findings.contract_available
                  ? String(validationSource.findings.validation_counts[state] ?? 0)
                  : "Unavailable"
              }
            />
          ))}
        </div>
        <p className="posture-caption">
          Candidate, pending, manual, rejected, and inconclusive records are deliberately excluded from confirmed totals and core risk.
        </p>
      </section>

      <TrendSection dashboard={dashboard} />
      <QualitySection snapshot={qualitySource} />
      <HighRiskSection dashboard={dashboard} />
    </div>
  );
}

function TrendSection({ dashboard }: { dashboard: Dashboard }) {
  return (
    <section aria-labelledby="trend-heading">
      <div className="section-heading-row">
        <div>
          <span className="eyebrow">Comparable complete runs</span>
          <h2 id="trend-heading">Recent trend</h2>
        </div>
      </div>
      {dashboard.trend_series.length === 0 ? (
        <p className="posture-empty">No terminal posture snapshots are available yet.</p>
      ) : (
        <>
          <div className="trend-bars" aria-hidden="true">
            {dashboard.trend_series.map((point) => (
              <div className={`trend-bar ${point.complete ? "" : "trend-bar-incomplete"}`} key={point.run_id}>
                <i style={{ height: `${Math.max(4, point.risk_score ?? 0)}%` }} />
                <span>{point.risk_score ?? "N/A"}</span>
              </div>
            ))}
          </div>
          <div className="table-wrap trend-table">
            <table>
              <caption className="sr-only">Numeric security posture trend by run</caption>
              <thead>
                <tr>
                  <th>Run</th><th>Complete</th><th>Risk</th><th>Confirmed</th>
                  {trendStates.map((state) => <th key={state}>{state}</th>)}
                </tr>
              </thead>
              <tbody>
                {dashboard.trend_series.map((point) => (
                  <tr key={point.run_id}>
                    <td className="technical-value">{point.run_id}</td>
                    <td>{point.complete ? "Yes" : `No — ${point.comparison_status}`}</td>
                    <td>{point.risk_score ?? "Unavailable"}</td>
                    <td>{point.confirmed_count}</td>
                    {trendStates.map((state) => <td key={state}>{point.trend_counts[state] ?? 0}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

function QualitySection({ snapshot }: { snapshot: PostureSnapshot | null }) {
  const budget = snapshot?.quality.budget;
  const budgetText = isUnavailable(budget)
    ? "Unavailable"
    : budget
      ? summarizeBudget(budget)
      : "Unavailable";
  return (
    <section aria-labelledby="quality-heading">
      <div className="section-heading-row">
        <div>
          <span className="eyebrow">Distinct from vulnerability severity</span>
          <h2 id="quality-heading">Investigation quality</h2>
        </div>
      </div>
      <div className="quality-grid">
        <QualityCard label="Evidence completeness" value={snapshot ? yesNo(snapshot.quality.evidence_complete) : "Unavailable"} />
        <QualityCard label="Validation completion" value={snapshot ? yesNo(snapshot.quality.validation_complete) : "Unavailable"} />
        <QualityCard label="Effective mode" value={snapshot?.quality.effective_mode ?? "Unavailable"} />
        <QualityCard label="Accounting" value={snapshot?.quality.accounting_status ?? "Unavailable"} />
        <QualityCard label="Budget usage" value={budgetText} technical />
        <QualityCard
          label="Fallback / degradation"
          value={snapshot?.quality.fallback_reason || snapshot?.quality.degraded_reasons.join(", ") || "None reported"}
          warning={Boolean(snapshot?.quality.fallback_reason || snapshot?.quality.degraded_reasons.length)}
        />
      </div>
    </section>
  );
}

function HighRiskSection({ dashboard }: { dashboard: Dashboard }) {
  return (
    <section aria-labelledby="high-risk-heading">
      <div className="section-heading-row">
        <div>
          <span className="eyebrow">Evidence-linked findings</span>
          <h2 id="high-risk-heading">High-risk drill-down</h2>
        </div>
      </div>
      {dashboard.high_risk_findings.length === 0 ? (
        <p className="posture-empty">
          {dashboard.posture ? "The complete posture contains no confirmed findings." : "No complete posture exists yet."}
        </p>
      ) : (
        <div className="high-risk-list">
          {dashboard.high_risk_findings.map((finding) => (
            <article key={finding.fingerprint} className="high-risk-item">
              <div>
                <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
                <span className="trend-label">{finding.trend_status ?? "unconfirmed"}</span>
              </div>
              <h3>{finding.title}</h3>
              <p className="technical-value">
                {finding.location.path}:{finding.location.start_line ?? "?"} · {finding.vulnerability_class}
              </p>
              <p>{finding.evidence_refs.length} evidence reference(s) · {finding.evidence_state}</p>
              <Link className="outline-action" to={finding.run_url ?? `/projects/${dashboard.project.project_id}/runs/${finding.run_id}`}>
                Open run and finding <ArrowUpRight size={16} aria-hidden="true" />
              </Link>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function Fact({ label, value, technical = false }: { label: string; value: string; technical?: boolean }) {
  return (
    <div className="posture-fact">
      <span>{label}</span>
      <strong className={technical ? "technical-value" : undefined}>{value}</strong>
    </div>
  );
}

function QualityCard({ label, value, technical = false, warning = false }: { label: string; value: string; technical?: boolean; warning?: boolean }) {
  return (
    <article className={`quality-card ${warning ? "quality-warning" : ""}`}>
      <span>{label}</span>
      <strong className={technical ? "technical-value" : undefined}>{value}</strong>
    </article>
  );
}

function dashboardStateMessage(dashboard: Dashboard) {
  if (dashboard.state === "no-runs") return { title: "No audit history", detail: "Start a scan to establish this project's first security posture." };
  if (dashboard.state === "running-only") return { title: "Audit in progress", detail: "No complete posture exists yet. Active runs are shown without a zero-risk claim." };
  if (dashboard.state === "stale-historical-posture") return {
    title: "Latest run is incomplete",
    detail: `The newest run is ${dashboard.latest_run?.status ?? "incomplete"}; the displayed posture is historical and comes from ${dashboard.latest_complete_posture?.run_id ?? "an earlier run"}.`
  };
  if (dashboard.state === "no-complete-posture") return {
    title: "No complete posture",
    detail: `Required evidence is unavailable: ${dashboard.limitations.join(", ") || "unknown limitation"}.`
  };
  if (dashboard.latest_run_posture?.trend.comparison_status === "incompatible-fingerprint-version") return {
    title: "Trend comparison unavailable",
    detail: "Finding fingerprint versions are incompatible; continuity is not inferred."
  };
  return null;
}

function formatMaybeNumber(value: number | null | undefined) {
  return typeof value === "number" ? value.toLocaleString() : "Unavailable";
}

function formatTime(value: string | null | undefined) {
  if (!value) return "Unavailable";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function yesNo(value: boolean) {
  return value ? "Complete" : "Incomplete";
}

function isUnavailable(value: unknown): boolean {
  return Boolean(value && typeof value === "object" && "status" in value && (value as { status?: string }).status === "unavailable");
}

function summarizeBudget(value: Record<string, unknown>) {
  const used = value.used && typeof value.used === "object" ? value.used as Record<string, unknown> : value;
  const requests = used.requests ?? used.llm_requests;
  const tokens = used.tokens ?? used.llm_tokens;
  const parts = [requests !== undefined ? `${String(requests)} requests` : "", tokens !== undefined ? `${String(tokens)} tokens` : ""].filter(Boolean);
  return parts.join(" / ") || "Available in run details";
}
