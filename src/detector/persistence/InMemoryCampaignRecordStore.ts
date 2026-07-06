import { randomUUID } from "node:crypto";
import type { CampaignCandidateFromStrategy } from "../types.js";
import type {
  CampaignRecordStore,
  CampaignRow,
  CampaignSource,
  CampaignStatus,
  CampaignUpsertResult,
} from "./campaignRecordStore.js";
import {
  buildEvidenceHistoryEntry,
  evidenceEqualsIgnoringKeyOrder,
} from "./campaignRecordStore.js";

// Returns structuredClone'd rows so callers cannot mutate stored state, matching how
// Postgres hands back freshly deserialized rows.
export class InMemoryCampaignRecordStore implements CampaignRecordStore {
  private openRowsByIdentifier = new Map<string, CampaignRow>();

  async upsertCandidate(
    candidate: CampaignCandidateFromStrategy,
    source: CampaignSource,
  ): Promise<CampaignUpsertResult> {
    const historyEntry = buildEvidenceHistoryEntry(candidate);
    const existing = this.openRowsByIdentifier.get(candidate.identifier);

    if (existing === undefined) {
      const now = new Date();
      const row: CampaignRow = {
        id: randomUUID(),
        identifier: candidate.identifier,
        strategy_id: candidate.strategy_id,
        campaign_type: candidate.default_campaign_type,
        status: "active",
        source,
        confidence: candidate.confidence,
        peak_confidence: candidate.confidence,
        campaign_threat_level: candidate.campaign_threat_level,
        first_seen: candidate.time_range.first,
        last_seen: candidate.time_range.last,
        times_fired: 1,
        contributing_ips: [...candidate.contributing_ips],
        sample_paths_probed: [...candidate.sample_paths_probed],
        sample_user_agents: [...candidate.sample_user_agents],
        related_strategy_tags: [...candidate.related_strategy_tags],
        request_ids: [],
        evidence: historyEntry.evidence,
        evidence_history: [historyEntry],
        extracted_entities: [],
        extracted_relationships: [],
        created_at: now,
        updated_at: now,
      };
      this.openRowsByIdentifier.set(candidate.identifier, row);
      return { outcome: "inserted", campaign: structuredClone(row) };
    }

    if (candidate.time_range.first < existing.first_seen) {
      existing.first_seen = candidate.time_range.first;
    }
    if (candidate.time_range.last > existing.last_seen) {
      existing.last_seen = candidate.time_range.last;
    }
    existing.times_fired += 1;
    existing.confidence = candidate.confidence;
    existing.peak_confidence = Math.max(
      existing.peak_confidence,
      candidate.confidence,
    );
    existing.campaign_threat_level = candidate.campaign_threat_level;
    existing.contributing_ips = [...candidate.contributing_ips];
    existing.sample_paths_probed = [...candidate.sample_paths_probed];
    existing.sample_user_agents = [...candidate.sample_user_agents];
    existing.related_strategy_tags = [...candidate.related_strategy_tags];
    if (!evidenceEqualsIgnoringKeyOrder(existing.evidence, historyEntry.evidence)) {
      existing.evidence_history = [...existing.evidence_history, historyEntry];
    }
    existing.evidence = historyEntry.evidence;
    existing.updated_at = new Date();
    return { outcome: "updated", campaign: structuredClone(existing) };
  }

  async findOpenByIdentifier(identifier: string): Promise<CampaignRow | null> {
    const row = this.openRowsByIdentifier.get(identifier);
    return row === undefined ? null : structuredClone(row);
  }

  async listByStatus(status: CampaignStatus): Promise<CampaignRow[]> {
    return [...this.openRowsByIdentifier.values()]
      .filter((row) => row.status === status)
      .sort((a, b) => b.peak_confidence - a.peak_confidence)
      .map((row) => structuredClone(row));
  }
}
