import { useEffect, useReducer, useRef } from "react";
import { apiClient } from "../api/client";
import type { AuditEvent, AuditEventSnapshot } from "../api/types";
import { auditEventReducer, initialAuditEventState } from "./auditEventState";

const RECONNECT_DELAYS_MS = [500, 1_000, 2_000];
const FALLBACK_RECOVERY_MS = 15_000;
const RECONCILE_MS = 15_000;

interface AuditEventStreamOptions {
  projectId: string;
  jobId: string;
  enabled?: boolean;
  onEvent?: (event: AuditEvent) => void;
  onSnapshot?: (snapshot: AuditEventSnapshot) => void;
}

export function useAuditEventStream({
  projectId,
  jobId,
  enabled = true,
  onEvent,
  onSnapshot
}: AuditEventStreamOptions) {
  const [state, dispatch] = useReducer(auditEventReducer, initialAuditEventState(jobId));
  const callbacks = useRef({ onEvent, onSnapshot });
  callbacks.current = { onEvent, onSnapshot };

  useEffect(() => {
    dispatch({ type: "reset", runId: jobId });
    if (!enabled || !projectId || !jobId) return;
    let disposed = false;
    let source: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let reconcileTimer: ReturnType<typeof setInterval> | undefined;
    let failures = 0;
    let cursor = 0;

    const closeSource = () => {
      source?.close();
      source = null;
    };

    const loadSnapshot = async () => {
      const snapshot = await apiClient.getRunEventSnapshot(projectId, jobId);
      if (disposed) return snapshot;
      cursor = Math.max(cursor, snapshot.last_event_id);
      dispatch({ type: "snapshot", snapshot });
      callbacks.current.onSnapshot?.(snapshot);
      return snapshot;
    };

    const scheduleConnect = (fallback: boolean) => {
      if (disposed) return;
      const delay = fallback
        ? FALLBACK_RECOVERY_MS
        : RECONNECT_DELAYS_MS[Math.min(Math.max(failures - 1, 0), RECONNECT_DELAYS_MS.length - 1)];
      retryTimer = setTimeout(() => connect(true), delay);
    };

    const connect = (reconnecting = false) => {
      if (disposed || typeof EventSource === "undefined") {
        dispatch({ type: "stream-error", failures: RECONNECT_DELAYS_MS.length, fallback: true });
        return;
      }
      closeSource();
      dispatch({ type: "connecting", reconnecting });
      const url = `/api/projects/${encodeURIComponent(projectId)}/runs/${encodeURIComponent(jobId)}/events?cursor=${cursor}`;
      source = new EventSource(url);
      source.onopen = () => {
        if (disposed) return;
        failures = 0;
        dispatch({ type: "connected" });
      };
      source.addEventListener("audit-event", (raw) => {
        if (disposed) return;
        const event = JSON.parse((raw as MessageEvent<string>).data) as AuditEvent;
        cursor = Math.max(cursor, event.event_id);
        dispatch({ type: "event", event });
        callbacks.current.onEvent?.(event);
      });
      source.addEventListener("heartbeat", () => {
        if (!disposed) dispatch({ type: "heartbeat", timestamp: new Date().toISOString() });
      });
      source.addEventListener("terminal-snapshot", (raw) => {
        if (disposed) return;
        const terminal = JSON.parse((raw as MessageEvent<string>).data) as {
          status?: string;
          last_event_id?: number;
        };
        cursor = Math.max(cursor, terminal.last_event_id ?? 0);
        dispatch({ type: "terminal", status: terminal.status, lastEventId: terminal.last_event_id });
        closeSource();
      });
      source.onerror = () => {
        if (disposed) return;
        closeSource();
        failures += 1;
        const fallback = failures >= RECONNECT_DELAYS_MS.length;
        dispatch({ type: "stream-error", failures, fallback });
        scheduleConnect(fallback);
      };
    };

    void loadSnapshot()
      .then((snapshot) => {
        if (!snapshot?.terminal && !disposed) connect(false);
      })
      .catch(() => {
        failures = RECONNECT_DELAYS_MS.length;
        dispatch({ type: "stream-error", failures, fallback: true });
        scheduleConnect(true);
      });
    reconcileTimer = setInterval(() => {
      void loadSnapshot().catch(() => undefined);
    }, RECONCILE_MS);

    return () => {
      disposed = true;
      closeSource();
      if (retryTimer) clearTimeout(retryTimer);
      if (reconcileTimer) clearInterval(reconcileTimer);
    };
  }, [enabled, jobId, projectId]);

  return state;
}
