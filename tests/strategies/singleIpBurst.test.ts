import { describe, it, expect } from "vitest";
import { compute } from "../../src/detector/metrics/MetricsWithinWindow.js";
import { singleIpBurst } from "../../src/strategies/singleIpBurst.js";
import { makeRequest } from "../../src/test-support/factories.js";
import { InMemoryMarkerStore } from "../../src/detector/MarkerSnapshot.js";
import type { HoneyRequest } from "../../src/detector/types.js";
import type { RequestObservationFromStrategy } from "../../src/strategies/Strategy.js";

const WINDOW_START_MS = new Date("2026-06-12T00:00:00.000Z").getTime();

function observations(reqs: HoneyRequest[]): RequestObservationFromStrategy[] {
  return reqs.map((r) => ({
    stream: "single-ip-burst",
    key: r.ip,
    value: r,
    request_id: r.id,
  }));
}

function singleIpProbingDistinctPathsAcrossSpan(
  pathCount: number,
  spanMs: number,
): HoneyRequest[] {
  return Array.from({ length: pathCount }, (_, pathIndex) =>
    makeRequest({
      ip: "80.94.95.211",
      route: `/.env.${pathIndex}`,
      created_at: new Date(WINDOW_START_MS + (pathIndex * spanMs) / pathCount),
    }),
  );
}

const emptyMarkerSnapshot = new InMemoryMarkerStore().snapshotMarkers(
  new Date(WINDOW_START_MS),
);

describe("singleIpBurst.score time axis", () => {
  it("recovers a low-and-slow scanner that the burst decay zeroes out", () => {
    const thirteenDaysMs = 13 * 24 * 3600 * 1000;
    const reqs = singleIpProbingDistinctPathsAcrossSpan(120, thirteenDaysMs);
    const result = singleIpBurst.score(observations(reqs), compute(reqs), emptyMarkerSnapshot);
    expect(result).not.toBeNull();
    expect(result!.evidence.burstScore).toBe(0);
    expect(result!.evidence.persistenceScore as number).toBeGreaterThan(0.8);
    expect(result!.evidence.timeScore as number).toBeGreaterThan(0.8);
  });

  it("keeps a sub-60s burst at full timeScore", () => {
    const thirtySecondsMs = 30 * 1000;
    const reqs = singleIpProbingDistinctPathsAcrossSpan(120, thirtySecondsMs);
    const result = singleIpBurst.score(observations(reqs), compute(reqs), emptyMarkerSnapshot);
    expect(result).not.toBeNull();
    expect(result!.evidence.burstScore).toBe(1);
    expect(result!.evidence.timeScore).toBe(1);
  });

  it("gives no persistence credit to a single-request IP", () => {
    const reqs = [makeRequest({ ip: "80.94.95.211", route: "/.env" })];
    const result = singleIpBurst.score(observations(reqs), compute(reqs), emptyMarkerSnapshot);
    expect(result).not.toBeNull();
    expect(result!.evidence.spanDays).toBe(0);
    expect(result!.evidence.persistenceScore as number).toBeLessThan(0.1);
  });
});
