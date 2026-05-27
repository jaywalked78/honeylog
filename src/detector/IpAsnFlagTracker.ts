export type FlagScope = "ip" | "asn" | "asn_subnet";

export class IpAsnFlagTracker {
  private flags = new Map<string, number>();
  private now: () => number;

  constructor(now: () => number = Date.now) {
    this.now = now;
  }

  setFlag(
    scope_type: FlagScope,
    scope_value: string | number,
    flag_name: string,
    expire_ms: number,
  ): void {
    const key = this.buildKey(scope_type, scope_value, flag_name);
    const expiresAt = this.now() + expire_ms;
    this.flags.set(key, expiresAt);
  }

  hasFlag(
    scope_type: FlagScope,
    scope_value: string | number,
    flag_name: string,
  ): boolean {
    const key = this.buildKey(scope_type, scope_value, flag_name);
    const expiresAt = this.flags.get(key);
    if (expiresAt === undefined) return false;
    if (this.now() >= expiresAt) {
      // opportunistic cleanup keeps the Map from growing unboundedly between sweeps
      this.flags.delete(key);
      return false;
    }
    return true;
  }

  flagTtl(
    scope_type: FlagScope,
    scope_value: string | number,
    flag_name: string,
  ): number {
    const key = this.buildKey(scope_type, scope_value, flag_name);
    const expiresAt = this.flags.get(key);
    if (expiresAt === undefined) return 0;
    const remaining = expiresAt - this.now();
    return remaining > 0 ? remaining : 0;
  }

  clearFlag(
    scope_type: FlagScope,
    scope_value: string | number,
    flag_name: string,
  ): void {
    const key = this.buildKey(scope_type, scope_value, flag_name);
    this.flags.delete(key);
  }

  sweepExpiredFlags(): void {
    const cutoff = this.now();
    for (const [key, expiresAt] of this.flags) {
      if (cutoff >= expiresAt) {
        this.flags.delete(key);
      }
    }
  }

  private buildKey(
    scope_type: FlagScope,
    scope_value: string | number,
    flag_name: string,
  ): string {
    return `${scope_type}:${scope_value}:${flag_name}`;
  }
}
