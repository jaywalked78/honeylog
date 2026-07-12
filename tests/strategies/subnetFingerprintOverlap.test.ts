import { describe, it, expect } from "vitest";
import { compute } from "../../src/detector/metrics/MetricsWithinWindow.js";
import { subnetFingerprintOverlap } from "../../src/strategies/subnetFingerprintOverlap.js";
import { classifyConfidence } from "../../src/utils/strategyHelpers.js";
import { makeRequest, ATTACK_POOL } from "../../src/test-support/factories.js";
import type { HoneyRequest } from "../../src/detector/types.js";
import type { RequestObservationFromStrategy } from "../../src/strategies/Strategy.js";

function observations(
  reqs: HoneyRequest[],
  subnet: string,
): RequestObservationFromStrategy[] {
  return reqs.map((r) => ({
    stream: "subnet-fingerprint-overlap",
    key: subnet,
    value: r,
    request_id: r.id,
  }));
}

// The strategy's score() ignores the marker snapshot (only single-ip-burst reads it).
const noSnapshot = undefined as never;

function score(reqs: HoneyRequest[], subnet: string) {
  return subnetFingerprintOverlap.score(
    observations(reqs, subnet),
    compute(reqs),
    noSnapshot,
  );
}

describe("subnetFingerprintOverlap.score", () => {
  it("does not score a single-path ONVIF census (pathUnion < 2)", () => {
    const reqs = ["10", "11", "12", "13"].map((octet) =>
      makeRequest({ ip: `69.5.169.${octet}`, route: "/onvif/device_service" }),
    );
    expect(score(reqs, "69.5.169.0/24")).toBeNull();
  });

  it("rescues a breadth-led spray (cohesion ~= 0, many attack paths) at MED+", () => {
    // 6 IPs, wordlist-DIVIDED into disjoint 4-path slices: no route overlap, ~24 attack paths total.
    // The old cohesion-dominant blend scored this none; maxOR must rescue it via the breadth arm.
    const spray: HoneyRequest[] = [];
    for (let ipIdx = 0; ipIdx < 6; ipIdx++) {
      for (const route of ATTACK_POOL.slice(ipIdx * 4, ipIdx * 4 + 4)) {
        spray.push(makeRequest({ ip: `45.135.193.${10 + ipIdx}`, route }));
      }
    }
    const result = score(spray, "45.135.193.0/24");
    expect(result).not.toBeNull();
    expect(["medium", "high"]).toContain(classifyConfidence(result!.confidence));
  });

  it("scores a convergent credential cluster (cohesion ~= 1) via the cohesion arm", () => {
    // 4 IPs share the SAME 5-path credential set.
    const conv: HoneyRequest[] = [];
    for (let ipIdx = 0; ipIdx < 4; ipIdx++) {
      for (const route of ATTACK_POOL.slice(0, 5)) {
        conv.push(makeRequest({ ip: `78.153.140.${20 + ipIdx}`, route }));
      }
    }
    expect(score(conv, "78.153.140.0/24")).not.toBeNull();
  });

  it("excludes Tor requests in observe (handed to tor-distributed-scan)", () => {
    const torReq = makeRequest({ ip: "192.42.116.5", route: "/.env", is_tor: true });
    expect(subnetFingerprintOverlap.observe(torReq, compute([]))).toBeNull();
  });
});
