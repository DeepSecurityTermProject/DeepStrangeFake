import { describe, expect, it } from "vitest";
import { runStatusRefetchInterval } from "./polling";

describe("runStatusRefetchInterval", () => {
  it("polls queued and running jobs", () => {
    expect(runStatusRefetchInterval({ status: "queued" })).toBe(2000);
    expect(runStatusRefetchInterval({ status: "running" })).toBe(2000);
  });

  it("stops polling terminal jobs", () => {
    expect(runStatusRefetchInterval({ status: "succeeded" })).toBe(false);
    expect(runStatusRefetchInterval({ status: "failed" })).toBe(false);
  });
});
