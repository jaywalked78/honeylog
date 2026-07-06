import type pg from "pg";
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
  serializeEvidenceForStorage,
} from "./campaignRecordStore.js";

const VALID_TABLE_NAME = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

export interface PostgresCampaignRecordStoreOptions {
  tableName?: string;
}

// Table name is unqualified: schema resolution rides on the pool's search_path, like the middleware INSERT.
export class PostgresCampaignRecordStore implements CampaignRecordStore {
  private readonly pool: pg.Pool;
  private readonly tableName: string;

  constructor(
    pool: pg.Pool,
    options: PostgresCampaignRecordStoreOptions = {},
  ) {
    const tableName = options.tableName ?? "campaigns";
    if (!VALID_TABLE_NAME.test(tableName)) {
      throw new Error(
        `Invalid tableName: "${tableName}". Must match ${VALID_TABLE_NAME}`,
      );
    }
    this.pool = pool;
    this.tableName = tableName;
  }

  async upsertCandidate(
    candidate: CampaignCandidateFromStrategy,
    source: CampaignSource,
  ): Promise<CampaignUpsertResult> {
    const historyEntry = buildEvidenceHistoryEntry(candidate);

    // jsonb "=" in the history CASE is deep equality; the partial unique index
    // campaigns_open_identifier is the ON CONFLICT arbiter, so closed rows never conflict.
    const result = await this.pool.query<CampaignRow & { inserted: boolean }>(
      `
      INSERT INTO ${this.tableName} (
        identifier, strategy_id, campaign_type, source,
        confidence, peak_confidence, campaign_threat_level,
        first_seen, last_seen,
        contributing_ips, sample_paths_probed, sample_user_agents,
        related_strategy_tags, evidence, evidence_history
      ) VALUES (
        $1, $2, $3, $4,
        $5, $5, $6,
        $7, $8,
        $9::jsonb, $10::jsonb, $11::jsonb,
        $12::jsonb, $13::jsonb, jsonb_build_array($14::jsonb)
      )
      ON CONFLICT (identifier) WHERE status != 'closed'
      DO UPDATE SET
        first_seen            = LEAST(${this.tableName}.first_seen, EXCLUDED.first_seen),
        last_seen             = GREATEST(${this.tableName}.last_seen, EXCLUDED.last_seen),
        times_fired           = ${this.tableName}.times_fired + 1,
        confidence            = EXCLUDED.confidence,
        peak_confidence       = GREATEST(${this.tableName}.peak_confidence, EXCLUDED.confidence),
        campaign_threat_level = EXCLUDED.campaign_threat_level,
        contributing_ips      = EXCLUDED.contributing_ips,
        sample_paths_probed   = EXCLUDED.sample_paths_probed,
        sample_user_agents    = EXCLUDED.sample_user_agents,
        related_strategy_tags = EXCLUDED.related_strategy_tags,
        evidence_history      = CASE
          WHEN ${this.tableName}.evidence = EXCLUDED.evidence
            THEN ${this.tableName}.evidence_history
          ELSE ${this.tableName}.evidence_history || jsonb_build_array($14::jsonb)
        END,
        evidence              = EXCLUDED.evidence,
        updated_at            = NOW()
      RETURNING *, (xmax = 0) AS inserted -- xmax = 0 means the row came from INSERT, not UPDATE
      `,
      [
        candidate.identifier,
        candidate.strategy_id,
        candidate.default_campaign_type,
        source,
        candidate.confidence,
        candidate.campaign_threat_level,
        candidate.time_range.first,
        candidate.time_range.last,
        JSON.stringify(candidate.contributing_ips),
        JSON.stringify(candidate.sample_paths_probed),
        JSON.stringify(candidate.sample_user_agents),
        JSON.stringify(candidate.related_strategy_tags),
        serializeEvidenceForStorage(candidate.evidence),
        JSON.stringify(historyEntry),
      ],
    );

    const { inserted, ...campaign } = result.rows[0];
    return { outcome: inserted ? "inserted" : "updated", campaign };
  }

  async findOpenByIdentifier(identifier: string): Promise<CampaignRow | null> {
    const result = await this.pool.query<CampaignRow>(
      `SELECT * FROM ${this.tableName} WHERE identifier = $1 AND status != 'closed'`,
      [identifier],
    );
    return result.rows[0] ?? null;
  }

  async listByStatus(status: CampaignStatus): Promise<CampaignRow[]> {
    const result = await this.pool.query<CampaignRow>(
      `SELECT * FROM ${this.tableName} WHERE status = $1 ORDER BY peak_confidence DESC`,
      [status],
    );
    return result.rows;
  }
}
