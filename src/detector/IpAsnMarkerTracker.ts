import { dbc } from "../helpers/database_connector.js";
import { MarkerSnapshot, type MarkerScope } from "./MarkerSnapshot.js";

export interface SnapshotScope {
  ips?: string[];
  asns?: number[];
  subnets?: string[];
}

export class IpAsnMarkerTracker {
  async snapshotMarkers(
    filter: SnapshotScope,
    asOf: Date = new Date(),
  ): Promise<MarkerSnapshot> {
    // DB column is named flag_name (historical); aliased to marker_name so
    // the rest of the code reads one vocabulary.
    const getMarkersSql = `
    SELECT scope_type, scope_value, flag_name AS marker_name, expires_at
    FROM logs_flag_tracker
    WHERE expires_at > $1
    AND (
      (scope_type = 'ip' AND scope_value = ANY($2))
      OR (scope_type = 'asn' AND scope_value = ANY($3))
      OR (scope_type = 'asn_subnet' AND scope_value = ANY($4))
    )
    `;
    const rows = await dbc.query<{
      scope_type: MarkerScope;
      scope_value: string;
      marker_name: string;
      expires_at: Date;
    }>(getMarkersSql, [
      asOf,
      filter.ips ?? [],
      (filter.asns ?? []).map(String),
      filter.subnets ?? [],
    ]);

    const markers = new Map<string, number>();
    for (const row of rows) {
      const key = `${row.scope_type}:${row.scope_value}:${row.marker_name}`;
      markers.set(key, row.expires_at.getTime());
    }
    return new MarkerSnapshot(markers, asOf.getTime());
  }
}
