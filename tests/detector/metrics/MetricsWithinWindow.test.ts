import { describe, it, expect } from "vitest";
import { compute } from "../../../src/detector/metrics/MetricsWithinWindow.js";
import { makeRequest } from "../../../src/test-support/factories.js";
import type { HoneyRequest } from "../../../src/detector/types.js";

describe("per_ip_useragent_diversity", () => {
  it("is 1.0 when every request from an IP uses a distinct UA", () => {
    const reqs = ["a", "b", "c", "d"].map((ua) =>
      makeRequest({ ip: "1.1.1.1", user_agent: `ua-${ua}` }),
    );
    expect(compute(reqs).per_ip_useragent_diversity.get("1.1.1.1")).toBe(1);
  });

  it("is low when a single UA repeats across requests", () => {
    const reqs = [0, 1, 2, 3].map(() =>
      makeRequest({ ip: "2.2.2.2", user_agent: "ua-x" }),
    );
    expect(compute(reqs).per_ip_useragent_diversity.get("2.2.2.2")).toBe(0.25);
  });
});

describe("per_asn_fingerprint_clusters", () => {
  it("surfaces the dominant same-fingerprint cluster in an ASN", () => {
    // Three IPs share the identical 2-path set {/a,/b}; a fourth probes a different set {/c}.
    const reqs: HoneyRequest[] = [];
    for (const ip of ["3.3.3.1", "3.3.3.2", "3.3.3.3"]) {
      reqs.push(makeRequest({ ip, route: "/a" }), makeRequest({ ip, route: "/b" }));
    }
    reqs.push(makeRequest({ ip: "3.3.3.9", route: "/c" }));

    const cluster = compute(reqs).per_asn_fingerprint_clusters.get(396982);
    expect(cluster).toBeDefined();
    expect(cluster!.ipCount).toBe(3);
    expect(cluster!.pathUnionSize).toBe(2);
    expect([...cluster!.ips].sort()).toEqual(["3.3.3.1", "3.3.3.2", "3.3.3.3"]);
  });

  it("does not let a larger single-path census cluster shadow a multi-path cluster", () => {
    // Five IPs probing exactly one shared endpoint (census) vs three IPs sharing a 2-path wordlist.
    const reqs: HoneyRequest[] = [];
    for (const ip of ["4.4.4.1", "4.4.4.2", "4.4.4.3", "4.4.4.4", "4.4.4.5"]) {
      reqs.push(makeRequest({ ip, route: "/pdown" }));
    }
    for (const ip of ["3.3.3.1", "3.3.3.2", "3.3.3.3"]) {
      reqs.push(makeRequest({ ip, route: "/a" }), makeRequest({ ip, route: "/b" }));
    }

    const cluster = compute(reqs).per_asn_fingerprint_clusters.get(396982);
    expect(cluster).toBeDefined();
    expect(cluster!.ipCount).toBe(3);
    expect(cluster!.pathUnionSize).toBe(2);
  });

  it("exposes no cluster when an ASN has only single-path fingerprints", () => {
    const reqs = ["5.5.5.1", "5.5.5.2", "5.5.5.3"].map((ip) =>
      makeRequest({ ip, route: "/pdown" }),
    );
    expect(compute(reqs).per_asn_fingerprint_clusters.get(396982)).toBeUndefined();
  });
});
