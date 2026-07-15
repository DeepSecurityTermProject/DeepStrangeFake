import type { AuditEvent, AuditEventSnapshot } from "../api/types";

export type EventConnectionState =
  | "idle"
  | "connecting"
  | "live"
  | "reconnecting"
  | "polling-fallback"
  | "terminal"
  | "unavailable";

export interface AuditEventState {
  runId: string;
  events: AuditEvent[];
  lastEventId: number;
  connection: EventConnectionState;
  failures: number;
  heartbeatAt?: string;
  historyStatus: string;
  historyReason: string;
  terminalStatus?: string;
}

export type AuditEventAction =
  | { type: "reset"; runId: string }
  | { type: "snapshot"; snapshot: AuditEventSnapshot }
  | { type: "event"; event: AuditEvent }
  | { type: "connecting"; reconnecting?: boolean }
  | { type: "connected" }
  | { type: "heartbeat"; timestamp: string }
  | { type: "stream-error"; failures: number; fallback: boolean }
  | { type: "terminal"; status?: string; lastEventId?: number };

export function initialAuditEventState(runId = ""): AuditEventState {
  return {
    runId,
    events: [],
    lastEventId: 0,
    connection: "idle",
    failures: 0,
    historyStatus: "live",
    historyReason: ""
  };
}

export function auditEventReducer(state: AuditEventState, action: AuditEventAction): AuditEventState {
  if (action.type === "reset") return initialAuditEventState(action.runId);
  if (action.type === "snapshot") {
    if (state.runId && action.snapshot.run_id !== state.runId) return state;
    const events = mergeEvents(state.events, action.snapshot.events);
    const terminal = action.snapshot.terminal;
    return {
      ...state,
      runId: action.snapshot.run_id,
      events,
      lastEventId: Math.max(action.snapshot.last_event_id, lastEventId(events)),
      historyStatus: action.snapshot.history_status,
      historyReason: action.snapshot.history_reason ?? "",
      connection: terminal
        ? "terminal"
        : action.snapshot.history_status === "unavailable"
          ? "unavailable"
          : state.connection,
      terminalStatus: terminal?.status ?? state.terminalStatus
    };
  }
  if (action.type === "event") {
    if (state.runId && action.event.run_id !== state.runId) return state;
    const events = mergeEvents(state.events, [action.event]);
    const terminal = action.event.category === "state" && ["succeeded", "degraded", "failed", "cancelled"].includes(action.event.status);
    return {
      ...state,
      runId: action.event.run_id,
      events,
      lastEventId: Math.max(state.lastEventId, action.event.event_id),
      connection: terminal ? "terminal" : state.connection,
      terminalStatus: terminal ? action.event.status : state.terminalStatus
    };
  }
  if (action.type === "connecting") {
    return { ...state, connection: action.reconnecting ? "reconnecting" : "connecting" };
  }
  if (action.type === "connected") {
    return { ...state, connection: "live", failures: 0 };
  }
  if (action.type === "heartbeat") {
    return { ...state, heartbeatAt: action.timestamp };
  }
  if (action.type === "stream-error") {
    return {
      ...state,
      failures: action.failures,
      connection: action.fallback ? "polling-fallback" : "reconnecting"
    };
  }
  if (action.type === "terminal") {
    return {
      ...state,
      connection: "terminal",
      terminalStatus: action.status ?? state.terminalStatus,
      lastEventId: Math.max(state.lastEventId, action.lastEventId ?? 0)
    };
  }
  return state;
}

function mergeEvents(current: AuditEvent[], incoming: AuditEvent[]): AuditEvent[] {
  const byId = new Map<number, AuditEvent>();
  for (const event of [...current, ...incoming]) {
    if (Number.isInteger(event.event_id) && event.event_id > 0) byId.set(event.event_id, event);
  }
  return [...byId.values()].sort((left, right) => left.event_id - right.event_id);
}

function lastEventId(events: AuditEvent[]): number {
  return events.length ? events[events.length - 1].event_id : 0;
}
