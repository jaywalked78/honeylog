import type { CampaignCandidateFromStrategy, ThreatLevel } from "../types.js";

// === TYPES ===

export type CampaignSource = "backtest" | "live";
export type CampaignStatus = "active" | "dormant" | "closed";

export interface EvidenceHistoryEntry {
  observed_at: string; // ISO 8601
  confidence: number;
  evidence: Record<string, unknown>;
}

// DB-shaped type: snake_case mirrors the campaigns table, like HoneyRequest.
export interface CampaignRow {
  id: string;
  identifier: string;
  strategy_id: string;
  campaign_type: string;
  status: CampaignStatus;
  source: CampaignSource;
  confidence: number;
  peak_confidence: number;
  campaign_threat_level: ThreatLevel;
  first_seen: Date;
  last_seen: Date;
  times_fired: number;
  contributing_ips: string[];
  sample_paths_probed: string[];
  sample_user_agents: string[];
  related_strategy_tags: string[];
  request_ids: string[];
  evidence: Record<string, unknown>;
  evidence_history: EvidenceHistoryEntry[];
  extracted_entities: unknown[];
  extracted_relationships: unknown[];
  created_at: Date;
  updated_at: Date;
}

export interface CampaignUpsertResult {
  outcome: "inserted" | "updated";
  campaign: CampaignRow;
}

// === STORE CONTRACT ===

export interface CampaignRecordStore {
  upsertCandidate(
    candidate: CampaignCandidateFromStrategy,
    source: CampaignSource,
  ): Promise<CampaignUpsertResult>;
  findOpenByIdentifier(identifier: string): Promise<CampaignRow | null>;
  listByStatus(status: CampaignStatus): Promise<CampaignRow[]>;
}

// === EVIDENCE HELPERS ===

// JSON has no NaN/Infinity; stringify them so evidence survives JSONB storage.
export function jsonReplacerForNonFinite(_key: string, value: unknown): unknown {
  if (typeof value === "number" && !Number.isFinite(value)) {
    if (Number.isNaN(value)) return "NaN";
    return value > 0 ? "Infinity" : "-Infinity";
  }
  return value;
}

export function serializeEvidenceForStorage(
  evidence: Record<string, unknown>,
): string {
  return JSON.stringify(evidence, jsonReplacerForNonFinite);
}

export function normalizeEvidenceForStorage(
  evidence: Record<string, unknown>,
): Record<string, unknown> {
  return JSON.parse(serializeEvidenceForStorage(evidence));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, nested]) => [key, sortKeysDeep(nested)]),
    );
  }
  return value;
}

// Must agree with the SQL history CASE in PostgresCampaignRecordStore, where jsonb "=" is deep.
export function evidenceEqualsIgnoringKeyOrder(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
): boolean {
  return (
    JSON.stringify(sortKeysDeep(left), jsonReplacerForNonFinite) ===
    JSON.stringify(sortKeysDeep(right), jsonReplacerForNonFinite)
  );
}

// Built in TS, not SQL, so both stores emit an identical observed_at (PG timestamptz text != toISOString()).
export function buildEvidenceHistoryEntry(
  candidate: CampaignCandidateFromStrategy,
): EvidenceHistoryEntry {
  return {
    observed_at: candidate.time_range.last.toISOString(),
    confidence: candidate.confidence,
    evidence: normalizeEvidenceForStorage(candidate.evidence),
  };
}
