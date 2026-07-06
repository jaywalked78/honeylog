import { describe, it, expect } from "vitest";
import { compute } from "../../src/detector/metrics/MetricsWithinWindow.js";
import { asnPathFingerprintCluster } from "../../src/strategies/asnPathFingerprintCluster.js";
import { makeRequest } from "../../src/test-support/factories.js";
import type { HoneyRequest } from "../../src/detector/types.js";
import type { RequestObservationFromStrategy } from "../../src/strategies/Strategy.js";

// makeRequest defaults ip_location.asn to this and threat_level to "high"
const AS = 396982;

function observations(reqs: HoneyRequest[]): RequestObservationFromStrategy[] {
  return reqs.map((r) => ({
    stream: "asn-path-fingerprint-cluster",
    key: AS,
    value: r,
    request_id: r.id,
  }));
}

function scatteredIpsReplayingIdenticalRouteSetWithPerRequestUaRotation(
  ips: string[],
): HoneyRequest[] {
  const reqs: HoneyRequest[] = [];
  let uaSeq = 0;
  for (const ip of ips) {
    for (const route of ["/actuator/env", "/actuator/heapdump", "/api/credentials.json"]) {
      reqs.push(makeRequest({ ip, route, user_agent: `ua-${uaSeq++}` }));
    }
  }
  return reqs;
}

const markerSnapshotIgnoredByThisStrategy = undefined as never;

describe("asnPathFingerprintCluster.score", () => {
  const ips = ["34.150.99.95", "34.6.141.86", "8.235.68.101"];

  it("scores a minimal gate-passing cluster near the medium boundary", () => {
    const reqs = scatteredIpsReplayingIdenticalRouteSetWithPerRequestUaRotation(ips);
    const result = asnPathFingerprintCluster.score(
      observations(reqs),
      compute(reqs),
      markerSnapshotIgnoredByThisStrategy,
    );
    expect(result).not.toBeNull();
    // ~0.55: rotationScore maxes (~0.88) but 3 IPs / 3 paths keep the size and breadth corroborators
    // low; high confidence needs real-campaign scale (asserted in the Task 8 JSON replay).
    expect(result!.confidence).toBeGreaterThan(0.5);
    expect(result!.confidence).toBeLessThan(0.65);
    expect(result!.evidence.ipCount).toBe(3);
    expect(result!.evidence.pathUnionSize).toBe(3);
  });

  it("emits an asn|fp identifier", () => {
    const reqs = scatteredIpsReplayingIdenticalRouteSetWithPerRequestUaRotation(ips);
    const result = asnPathFingerprintCluster.score(
      observations(reqs),
      compute(reqs),
      markerSnapshotIgnoredByThisStrategy,
    );
    expect(asnPathFingerprintCluster.identifier_from(AS, result!)).toMatch(
      /^asn-path-fingerprint-cluster\|asn=396982\|fp=/,
    );
  });

  it("observes only members of the dominant cluster, keeping candidate fields cluster-scoped", () => {
    const clusterMembers = scatteredIpsReplayingIdenticalRouteSetWithPerRequestUaRotation(ips);
    const sameAsnOutsider = makeRequest({
      ip: "34.99.99.99",
      route: "/wp-config.php",
      user_agent: "outsider-ua",
    });
    const outsiderSecondRoute = makeRequest({
      ip: "34.99.99.99",
      route: "/backup.sql",
      user_agent: "outsider-ua",
    });
    const metrics = compute([...clusterMembers, sameAsnOutsider, outsiderSecondRoute]);

    expect(asnPathFingerprintCluster.observe(clusterMembers[0], metrics)).not.toBeNull();
    expect(asnPathFingerprintCluster.observe(sameAsnOutsider, metrics)).toBeNull();
  });

  it("does not fire on a 2-IP cluster", () => {
    const reqs = scatteredIpsReplayingIdenticalRouteSetWithPerRequestUaRotation(ips.slice(0, 2));
    expect(
      asnPathFingerprintCluster.score(
        observations(reqs),
        compute(reqs),
        markerSnapshotIgnoredByThisStrategy,
      ),
    ).toBeNull();
  });
});
