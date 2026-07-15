import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "../api/client";
import type { AuditEvent } from "../api/types";
import { useAuditEventStream } from "./useAuditEventStream";

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  readonly url: string;
  onopen: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  closed = false;
  listeners = new Map<string, Array<(event: MessageEvent<string>) => void>>();

  constructor(url: string | URL) {
    this.url = String(url);
    FakeEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: EventListenerOrEventListenerObject) {
    const callback = typeof listener === "function" ? listener : listener.handleEvent.bind(listener);
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), callback as (event: MessageEvent<string>) => void]);
  }

  close() { this.closed = true; }
  emit(type: string, payload: unknown) {
    const event = new MessageEvent(type, { data: JSON.stringify(payload) });
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
  fail() { this.onerror?.(new Event("error")); }
}

function event(eventId: number): AuditEvent {
  return {
    schema_version: "audit-event.v1", run_id: "JOB-1", event_id: eventId,
    timestamp: "2026-07-15T00:00:00Z", category: "action", phase: "analyzing",
    actor: "analysis", title: `Event ${eventId}`, summary: {}, severity: "info",
    status: "recorded", artifact_refs: []
  };
}

describe("useAuditEventStream", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeEventSource.instances = [];
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.spyOn(apiClient, "getRunEventSnapshot").mockResolvedValue({
      schema_version: "audit-event.v1", run_id: "JOB-1", events: [event(1)],
      last_event_id: 1, history_status: "live"
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("loads a snapshot, resumes from the saved ID, suppresses duplicates, and recovers from polling fallback", async () => {
    const { result, unmount } = renderHook(() => useAuditEventStream({ projectId: "PRJ-1", jobId: "JOB-1" }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(FakeEventSource.instances).toHaveLength(1);
    expect(FakeEventSource.instances[0].url).toContain("cursor=1");
    act(() => {
      FakeEventSource.instances[0].onopen?.(new Event("open"));
      FakeEventSource.instances[0].emit("audit-event", event(2));
      FakeEventSource.instances[0].emit("audit-event", event(2));
    });
    expect(result.current.events.map((item) => item.event_id)).toEqual([1, 2]);
    expect(result.current.connection).toBe("live");

    act(() => FakeEventSource.instances[0].fail());
    act(() => vi.advanceTimersByTime(500));
    expect(FakeEventSource.instances[1].url).toContain("cursor=2");
    act(() => FakeEventSource.instances[1].fail());
    act(() => vi.advanceTimersByTime(1_000));
    act(() => FakeEventSource.instances[2].fail());
    expect(result.current.connection).toBe("polling-fallback");
    expect(result.current.failures).toBe(3);
    act(() => vi.advanceTimersByTime(15_000));
    expect(FakeEventSource.instances).toHaveLength(4);
    expect(FakeEventSource.instances[3].url).toContain("cursor=2");
    act(() => FakeEventSource.instances[3].onopen?.(new Event("open")));
    expect(result.current.connection).toBe("live");
    unmount();
    expect(FakeEventSource.instances.at(-1)?.closed).toBe(true);
  });

  it("refreshes from the latest persisted snapshot without issuing a cancel command", async () => {
    const cancelSpy = vi.spyOn(apiClient, "cancelRun");
    const first = renderHook(() => useAuditEventStream({ projectId: "PRJ-1", jobId: "JOB-1" }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(FakeEventSource.instances[0].url).toContain("cursor=1");
    first.unmount();
    expect(FakeEventSource.instances[0].closed).toBe(true);

    vi.mocked(apiClient.getRunEventSnapshot).mockResolvedValue({
      schema_version: "audit-event.v1", run_id: "JOB-1", events: [event(1), event(2)],
      last_event_id: 2, history_status: "live"
    });
    const refreshed = renderHook(() => useAuditEventStream({ projectId: "PRJ-1", jobId: "JOB-1" }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(FakeEventSource.instances[1].url).toContain("cursor=2");
    expect(refreshed.result.current.events.map((item) => item.event_id)).toEqual([1, 2]);
    expect(cancelSpy).not.toHaveBeenCalled();
    refreshed.unmount();
  });
});
