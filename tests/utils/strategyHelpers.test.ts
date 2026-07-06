import { describe, it, expect } from "vitest";
import {
  classifyConfidence,
  isAttackPath,
  jaccard,
  mean,
  routeSetFingerprint,
} from "../../src/utils/strategyHelpers.js";
import { ATTACK_POOL } from "../../src/test-support/factories.js";

describe("classifyConfidence", () => {
  it("maps confidence to threat bands", () => {
    expect(classifyConfidence(0.8)).toBe("high");
    expect(classifyConfidence(0.6)).toBe("medium");
    expect(classifyConfidence(0.45)).toBe("low");
    expect(classifyConfidence(0.3)).toBe("none");
  });

  it("uses inclusive lower bounds at each band edge", () => {
    expect(classifyConfidence(0.75)).toBe("high");
    expect(classifyConfidence(0.55)).toBe("medium");
    expect(classifyConfidence(0.4)).toBe("low");
    expect(classifyConfidence(0.399)).toBe("none");
  });
});

describe("isAttackPath", () => {
  it("matches every known attack path in the fixture pool", () => {
    for (const route of ATTACK_POOL) {
      expect(isAttackPath(route), route).toBe(true);
    }
  });

  it("does not match benign paths", () => {
    expect(isAttackPath("/")).toBe(false);
    expect(isAttackPath("/favicon.ico")).toBe(false);
  });
});

describe("jaccard", () => {
  it("is 1 for identical non-empty sets", () => {
    expect(jaccard(new Set(["a", "b"]), new Set(["a", "b"]))).toBe(1);
  });

  it("is 0 for disjoint sets", () => {
    expect(jaccard(new Set(["a"]), new Set(["b"]))).toBe(0);
  });

  it("treats two empty sets as 0 (no behavior is not identical behavior)", () => {
    expect(jaccard(new Set(), new Set())).toBe(0);
  });
});

describe("routeSetFingerprint", () => {
  it("is order-independent", () => {
    expect(routeSetFingerprint(new Set(["/a", "/b"]))).toBe(
      routeSetFingerprint(new Set(["/b", "/a"])),
    );
  });

  it("differs for different route sets", () => {
    expect(routeSetFingerprint(new Set(["/a"]))).not.toBe(
      routeSetFingerprint(new Set(["/b"])),
    );
  });
});

describe("mean", () => {
  it("returns 0 for empty input", () => {
    expect(mean([])).toBe(0);
  });

  it("averages the values", () => {
    expect(mean([1, 2, 3])).toBe(2);
  });
});
