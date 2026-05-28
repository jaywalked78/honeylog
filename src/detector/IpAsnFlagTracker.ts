import { dbc } from "../helpers/database_connector.js";
import { FlagSnapshot, type FlagScope } from "./FlagSnapshot.js";

export interface FlagFilter {
  ips?: string[];
  asns?: number[];
  subnets?: string[];
}

export class IpAsnFlagTracker {
  async snapshotFlags(
    filter: FlagFilter,
    asOf: Date = new Date(),
  ): Promise<FlagSnapshot> {
    const getFlagsSql = `
    SELECT scope_type, scope_value, flag_name, expires_at
    FROM logs_flag_tracker
    WHERE expires_at > $1
    AND (
      (scope_type = 'ip' AND scope_value = ANY($2))
      OR (scope_type = 'asn' AND scope_value = ANY($3))
      OR (scope_type = 'asn_subnet' AND scope_value = ANY($4))
    )
    `;
    const rows = await dbc.query<{
      scope_type: FlagScope;
      scope_value: string;
      flag_name: string;
      expires_at: Date;
    }>(getFlagsSql, [
      asOf,
      filter.ips ?? [],
      (filter.asns ?? []).map(String),
      filter.subnets ?? [],
    ]);

    const flags = new Map<string, number>();
    for (const row of rows) {
      const key = `${row.scope_type}:${row.scope_value}:${row.flag_name}`;
      flags.set(key, row.expires_at.getTime());
    }
    return new FlagSnapshot(flags, asOf.getTime());
  }
}
