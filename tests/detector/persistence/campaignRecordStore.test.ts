import { describe, it, expect } from "vitest";
import {
  serializeEvidenceForStorage,
  normalizeEvidenceForStorage,
  evidenceEqualsIgnoringKeyOrder,
  buildEvidenceHistoryEntry,
} from "../../../src/detector/persistence/campaignRecordStore.js";
import { makeCandidate } from "../../../src/test-support/factories.js";

describe("serializeEvidenceForStorage", () => {
  it("replaces non-finite numbers so JSONB round-trips match render output", () => {
    const serialized = serializeEvidenceForStorage({
      ratio: Infinity,
      gap: NaN,
      score: 0.5,
    });
    expect(JSON.parse(serialized)).toEqual({
      ratio: "Infinity",
      gap: "NaN",
      score: 0.5,
    });
  });
});

describe("evidenceEqualsIgnoringKeyOrder", () => {
  it("is key-order insensitive, matching Postgres jsonb equality", () => {
    expect(
      evidenceEqualsIgnoringKeyOrder(
        { a: 1, b: { c: 2, d: 3 } },
        { b: { d: 3, c: 2 }, a: 1 },
      ),
    ).toBe(true);
  });

  it("detects value differences at any depth", () => {
    expect(evidenceEqualsIgnoringKeyOrder({ a: 1, b: { c: 2 } }, { a: 1, b: { c: 3 } })).toBe(
      false,
    );
  });
});

describe("buildEvidenceHistoryEntry", () => {
  it("stamps observed_at from time_range.last and normalizes evidence", () => {
    const candidate = makeCandidate({
      confidence: 0.81,
      evidence: { burstScore: Infinity },
    });
    expect(buildEvidenceHistoryEntry(candidate)).toEqual({
      observed_at: candidate.time_range.last.toISOString(),
      confidence: 0.81,
      evidence: { burstScore: "Infinity" },
    });
  });
});

describe("normalizeEvidenceForStorage", () => {
  it("returns the parsed form of the serialized evidence", () => {
    expect(normalizeEvidenceForStorage({ gap: NaN, n: 2 })).toEqual({
      gap: "NaN",
      n: 2,
    });
  });
});
