import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, RefreshCw } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { apiClient } from "../api/client";
import { isTerminalStatus, runStatusRefetchInterval } from "../api/polling";
import type { JobStatusResponse } from "../api/types";
import { ErrorState, LoadingState } from "../components/DataState";
import { RunDetailTabs } from "./RunDetailTabs";

export function RunDetailPage() {
  const { jobId = "" } = useParams();
  const runQuery = useQuery({
    queryKey: ["run", jobId],
    queryFn: () => apiClient.getRun(jobId),
    enabled: Boolean(jobId),
    refetchInterval: (query) => runStatusRefetchInterval(query.state.data as JobStatusResponse | undefined)
  });

  const job = runQuery.data;
  const terminal = isTerminalStatus(job?.status);

  const runtimeQuery = useQuery({
    queryKey: ["runtime-state", jobId],
    queryFn: () => apiClient.getRuntimeState(jobId),
    enabled: terminal
  });
  const replayQuery = useQuery({
    queryKey: ["replay-summary", jobId],
    queryFn: () => apiClient.getReplaySummary(jobId),
    enabled: terminal
  });
  const reportJsonQuery = useQuery({
    queryKey: ["report-json", jobId],
    queryFn: () => apiClient.getReportJson(jobId),
    enabled: terminal
  });
  const markdownQuery = useQuery({
    queryKey: ["markdown-report", jobId],
    queryFn: () => apiClient.getMarkdownReport(jobId),
    enabled: terminal
  });

  if (runQuery.isLoading) {
    return <LoadingState title="Loading run" />;
  }
  if (runQuery.isError || !job) {
    return <ErrorState title={String(runQuery.error ?? "Run is not available")} />;
  }

  return (
    <section className="page-panel">
      <div className="page-heading">
        <div>
          <Link className="back-link" to="/runs">
            <ArrowLeft size={16} aria-hidden="true" />
            Runs
          </Link>
          <h1>{job.job_id}</h1>
          <p>{terminal ? "Artifacts loaded after terminal status" : "Polling until completion"}</p>
        </div>
        <button className="icon-action" type="button" onClick={() => runQuery.refetch()} aria-label="Refresh run">
          <RefreshCw size={18} aria-hidden="true" />
        </button>
      </div>
      <RunDetailTabs
        job={job}
        runtimeState={runtimeQuery.data}
        replaySummary={replayQuery.data}
        reportJson={reportJsonQuery.data}
        markdownReport={markdownQuery.data}
      />
    </section>
  );
}
