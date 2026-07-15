import { describe, expect, it } from "vitest";
import type { AuditEvent, AuditEventSnapshot } from "../api/types";
import { auditEventReducer, initialAuditEventState } from "./auditEventState";

function event(eventId: number, overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    schema_version: "audit-event.v1",
    run_id: "JOB-1",
    event_id: eventId,
    timestamp: `2026-07-15T00:00:0${eventId}Z`,
    category: "action",
    phase: "analyzing",
    actor: "analysis",
    title: `Event ${eventId}`,
    summary: {},
    severity: "info",
    status: "recorded",
    artifact_refs: [],
    ...overrides
  };
}

describe("auditEventReducer", () => {
  it("orders events, suppresses duplicate IDs, and merges refresh snapshots idempotently", () => {
    const snapshot: AuditEventSnapshot = {
      schema_version: "audit-event.v1",
      run_id: "JOB-1",
      events: [event(2), event(1), event(2, { title: "Event 2 refreshed" })],
      last_event_id: 2,
      history_status: "live"
    };
    let state = auditEventReducer(initialAuditEventState("JOB-1"), { type: "snapshot", snapshot });
    state = auditEventReducer(state, { type: "event", event: event(3) });
    state = auditEventReducer(state, { type: "event", event: event(3, { title: "Event 3 replay" }) });
    state = auditEventReducer(state, { type: "snapshot", snapshot: { ...snapshot, events: [event(1), event(2), event(3)] , last_event_id: 3 } });
    expect(state.events.map((item) => item.event_id)).toEqual([1, 2, 3]);
    expect(state.lastEventId).toBe(3);
  });

  it("tracks fallback, heartbeat, unavailable history, and terminal recovery", () => {
    let state = auditEventReducer(initialAuditEventState("JOB-1"), { type: "stream-error", failures: 3, fallback: true });
    expect(state.connection).toBe("polling-fallback");
    state = auditEventReducer(state, { type: "heartbeat", timestamp: "2026-07-15T01:00:00Z" });
    expect(state.heartbeatAt).toBe("2026-07-15T01:00:00Z");
    state = auditEventReducer(state, {
      type: "snapshot",
      snapshot: { schema_version: "audit-event.v1", run_id: "JOB-1", events: [], last_event_id: 0, history_status: "unavailable", history_reason: "legacy-run-without-public-journal" }
    });
    expect(state.connection).toBe("unavailable");
    state = auditEventReducer(state, { type: "terminal", status: "degraded", lastEventId: 9 });
    expect(state).toMatchObject({ connection: "terminal", terminalStatus: "degraded", lastEventId: 9 });
  });
});
