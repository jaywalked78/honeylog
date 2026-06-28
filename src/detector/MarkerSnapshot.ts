export type MarkerScope = "ip" | "asn" | "asn_subnet";

export class MarkerSnapshot {
  constructor(
    private markers: Map<string, number>,
    private asOfMs: number,
  ) {}

  hasMarker(
    scope_type: MarkerScope,
    scope_value: string | number,
    marker_name: string,
  ): boolean {
    const key = `${scope_type}:${scope_value}:${marker_name}`;
    const expiresAt = this.markers.get(key);
    if (expiresAt === undefined) return false;
    return expiresAt > this.asOfMs;
  }

  markerTtl(
    scope_type: MarkerScope,
    scope_value: string | number,
    marker_name: string,
  ): number {
    const key = `${scope_type}:${scope_value}:${marker_name}`;
    const expiresAt = this.markers.get(key);
    if (expiresAt === undefined) return 0;
    const remaining = expiresAt - this.asOfMs;
    return remaining > 0 ? remaining : 0;
  }
}

// In-memory marker store for alpha; the PG IpAsnMarkerTracker stays dormant until the persistence issue.
export class InMemoryMarkerStore {
  private markers = new Map<string, number>();

  recordMarker(
    scope_type: MarkerScope,
    scope_value: string | number,
    marker_name: string,
    expiresAtMs: number,
  ): void {
    const key = `${scope_type}:${scope_value}:${marker_name}`;
    this.markers.set(key, expiresAtMs);
  }

  // Copy so a handed-out snapshot doesn't shift under later writes this epoch.
  snapshotMarkers(asOf: Date): MarkerSnapshot {
    return new MarkerSnapshot(new Map(this.markers), asOf.getTime());
  }
}
