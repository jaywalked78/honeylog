import { describe, it, expect } from "vitest";
import { compute } from "../detector/metrics/MetricsWithinWindow.js";
import { uaReputation } from "./uaReputation.js";
import { makeRequest } from "../test-support/factories.js";
import type { HoneyRequest } from "../detector/types.js";
import type { RequestObservationFromStrategy } from "./Strategy.js";

function observations(reqs: HoneyRequest[]): RequestObservationFromStrategy[] {
  return reqs.map((r) => ({
    stream: "ua-reputation",
    key: r.ip,
    value: r,
    request_id: r.id,
  }));
}

const markerSnapshotIgnoredByThisStrategy = undefined as never;

describe("uaReputation", () => {
  const exploitToolRequest = makeRequest({
    ip: "5.5.5.5",
    route: "/",
    user_agent: "libredtail-http",
    threat_level: "low",
  });
  const benignBrowserRequest = makeRequest({
    ip: "5.5.5.5",
    route: "/",
    user_agent: "Mozilla/5.0",
    threat_level: "low",
  });
  const metrics = compute([exploitToolRequest, benignBrowserRequest]);

  it("observes only exploit-tool user agents", () => {
    expect(uaReputation.observe(exploitToolRequest, metrics)).not.toBeNull();
    expect(uaReputation.observe(benignBrowserRequest, metrics)).toBeNull();
  });

  it("does not observe a null user agent", () => {
    expect(
      uaReputation.observe(makeRequest({ user_agent: null }), metrics),
    ).toBeNull();
  });

  it("scores a fixed weak-standalone confidence with the matched UAs as evidence", () => {
    const result = uaReputation.score(
      observations([exploitToolRequest]),
      metrics,
      markerSnapshotIgnoredByThisStrategy,
    );
    expect(result).not.toBeNull();
    expect(result!.confidence).toBe(0.5);
    expect(result!.evidence.matchedUas).toEqual(["libredtail-http"]);
    expect(result!.evidence.requestCount).toBe(1);
  });

  it("emits an ip identifier", () => {
    const result = uaReputation.score(
      observations([exploitToolRequest]),
      metrics,
      markerSnapshotIgnoredByThisStrategy,
    );
    expect(uaReputation.identifier_from("5.5.5.5", result!)).toBe(
      "ua-reputation|ip=5.5.5.5",
    );
  });
});
