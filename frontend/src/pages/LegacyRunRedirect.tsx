import { useQuery } from "@tanstack/react-query";
import { Navigate, useParams } from "react-router-dom";
import { apiClient } from "../api/client";
import { ErrorState, LoadingState } from "../components/DataState";

export function LegacyRunRedirect() {
  const { jobId = "" } = useParams();
  const runQuery = useQuery({
    queryKey: ["run", jobId],
    queryFn: () => apiClient.getRun(jobId),
    enabled: Boolean(jobId)
  });

  if (runQuery.isLoading) return <LoadingState title="Resolving run workspace" />;
  if (runQuery.isError || !runQuery.data) {
    return <ErrorState title={String(runQuery.error ?? "Run is unavailable")} />;
  }
  if (!runQuery.data.project_id) {
    return <ErrorState title="This legacy run has not been attached to a project" />;
  }
  return <Navigate to={`/projects/${runQuery.data.project_id}/runs/${jobId}`} replace />;
}
