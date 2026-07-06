import { describe, it, expect, beforeEach } from "vitest";
import type { CampaignRecordStore } from "../detector/persistence/campaignRecordStore.js";
import { makeCandidate } from "./factories.js";

// makeStore must return a FRESH, empty store per test; callers own any
// scratch-schema / pool setup and teardown.
export function describeCampaignRecordStoreContract(
  implementationName: string,
  makeStore: () => Promise<CampaignRecordStore>,
): void {
  describe(`CampaignRecordStore contract: ${implementationName}`, () => {
    let store: CampaignRecordStore;

    beforeEach(async () => {
      store = await makeStore();
    });

    it("inserts a new campaign on first fire, seeding history with entry #1", async () => {
      const candidate = makeCandidate();
      const result = await store.upsertCandidate(candidate, "backtest");

      expect(result.outcome).toBe("inserted");
      expect(result.campaign.times_fired).toBe(1);
      expect(result.campaign.status).toBe("active");
      expect(result.campaign.source).toBe("backtest");
      expect(result.campaign.identifier).toBe(candidate.identifier);
      expect(result.campaign.confidence).toBe(candidate.confidence);
      expect(result.campaign.peak_confidence).toBe(candidate.confidence);
      expect(result.campaign.first_seen).toEqual(candidate.time_range.first);
      expect(result.campaign.last_seen).toEqual(candidate.time_range.last);
      expect(result.campaign.request_ids).toEqual([]);
      expect(result.campaign.evidence_history).toEqual([
        {
          observed_at: candidate.time_range.last.toISOString(),
          confidence: candidate.confidence,
          evidence: candidate.evidence,
        },
      ]);
    });

    it("updates lifecycle without appending history when evidence is identical", async () => {
      await store.upsertCandidate(makeCandidate(), "backtest");
      const laterFire = makeCandidate({
        time_range: {
          first: new Date("2026-06-12T06:00:00.000Z"),
          last: new Date("2026-06-12T06:45:00.000Z"),
        },
      });

      const result = await store.upsertCandidate(laterFire, "backtest");

      expect(result.outcome).toBe("updated");
      expect(result.campaign.times_fired).toBe(2);
      expect(result.campaign.last_seen).toEqual(laterFire.time_range.last);
      expect(result.campaign.evidence_history).toHaveLength(1);
    });

    it("appends a history entry and replaces evidence when evidence differs", async () => {
      await store.upsertCandidate(makeCandidate(), "backtest");
      const changedFire = makeCandidate({
        confidence: 0.81,
        evidence: { requestCount: 90, burstScore: 0.95 },
        time_range: {
          first: new Date("2026-06-12T06:00:00.000Z"),
          last: new Date("2026-06-12T06:45:00.000Z"),
        },
      });

      const result = await store.upsertCandidate(changedFire, "backtest");

      expect(result.campaign.evidence).toEqual({
        requestCount: 90,
        burstScore: 0.95,
      });
      expect(result.campaign.evidence_history).toHaveLength(2);
      expect(result.campaign.evidence_history[1]).toEqual({
        observed_at: changedFire.time_range.last.toISOString(),
        confidence: 0.81,
        evidence: { requestCount: 90, burstScore: 0.95 },
      });
    });

    it("tracks peak_confidence as a high-water mark while confidence stays latest", async () => {
      await store.upsertCandidate(
        makeCandidate({ confidence: 0.9, evidence: { requestCount: 100 } }),
        "backtest",
      );
      const quieterFire = makeCandidate({
        confidence: 0.5,
        evidence: { requestCount: 10 },
        time_range: {
          first: new Date("2026-06-12T06:00:00.000Z"),
          last: new Date("2026-06-12T06:45:00.000Z"),
        },
      });

      const result = await store.upsertCandidate(quieterFire, "backtest");

      expect(result.campaign.confidence).toBe(0.5);
      expect(result.campaign.peak_confidence).toBe(0.9);
    });

    it("takes the LEAST first_seen and keeps last_seen on out-of-order windows", async () => {
      const june12 = makeCandidate();
      await store.upsertCandidate(june12, "backtest");
      const earlierWindow = makeCandidate({
        time_range: {
          first: new Date("2026-06-11T00:00:00.000Z"),
          last: new Date("2026-06-11T00:45:00.000Z"),
        },
      });

      const result = await store.upsertCandidate(earlierWindow, "backtest");

      expect(result.campaign.first_seen).toEqual(
        earlierWindow.time_range.first,
      );
      expect(result.campaign.last_seen).toEqual(june12.time_range.last);
    });

    it("findOpenByIdentifier returns the open row, null when absent", async () => {
      const candidate = makeCandidate();
      await store.upsertCandidate(candidate, "backtest");

      const found = await store.findOpenByIdentifier(candidate.identifier);
      expect(found?.identifier).toBe(candidate.identifier);

      const missing = await store.findOpenByIdentifier("no|such=row");
      expect(missing).toBeNull();
    });

    it("listByStatus returns active rows sorted by peak_confidence descending", async () => {
      await store.upsertCandidate(
        makeCandidate({
          identifier: "single-ip-burst|ip=203.0.113.7",
          confidence: 0.6,
        }),
        "backtest",
      );
      await store.upsertCandidate(
        makeCandidate({
          identifier: "ua-reputation|ip=198.51.100.9",
          confidence: 0.9,
        }),
        "backtest",
      );

      const active = await store.listByStatus("active");

      expect(active.map((row) => row.identifier)).toEqual([
        "ua-reputation|ip=198.51.100.9",
        "single-ip-burst|ip=203.0.113.7",
      ]);
      expect(await store.listByStatus("closed")).toEqual([]);
    });

    it("returns detached rows that do not mutate stored state", async () => {
      const candidate = makeCandidate();
      const result = await store.upsertCandidate(candidate, "backtest");
      result.campaign.confidence = 999;
      result.campaign.contributing_ips.push("192.0.2.1");

      const found = await store.findOpenByIdentifier(candidate.identifier);
      expect(found?.confidence).toBe(candidate.confidence);
      expect(found?.contributing_ips).toEqual(candidate.contributing_ips);
    });
  });
}
