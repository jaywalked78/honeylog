export type FlagScope = "ip" | "asn" | "asn_subnet";

export class FlagSnapshot {
  constructor(
    private flags: Map<string, number>,
    private asOfMs: number,
  ) {
    this.flags = flags;
    this.asOfMs = asOfMs;
  }

  hasFlag(
    scope_type: FlagScope,
    scope_value: string | number,
    flag_name: string,
  ): boolean {
    const key = `${scope_type}:${scope_value}:${flag_name}`;
    const expiresAt = this.flags.get(key);
    if (expiresAt === undefined) return false;
    return expiresAt > this.asOfMs;
  }

  flagTtl(
    scope_type: FlagScope,
    scope_value: string | number,
    flag_name: string,
  ): number {
    const key = `${scope_type}:${scope_value}:${flag_name}`;
    const expiresAt = this.flags.get(key);
    if (expiresAt === undefined) return 0;
    const remaining = expiresAt - this.asOfMs;
    return remaining > 0 ? remaining : 0;
  }
}
