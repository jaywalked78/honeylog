import { createHash } from "node:crypto";
import { PATH_THREATS } from "../middleware/threatDefinitions.js";
import type { ThreatLevel } from "../detector/types.js";

export function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

export function subnet24(ip: string): string {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    throw new Error("Invalid IP address");
  }
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

// Jaccard similarity: the shared middle of a Venn diagram divided by both circles combined
// (items in both sets / distinct items across both). Two empty sets return 0: "no behavior" is not "identical behavior".
export function jaccard(firstSet: Set<string>, secondSet: Set<string>): number {
  if (firstSet.size === 0 && secondSet.size === 0) return 0;
  let intersection = 0;
  for (const item of firstSet) {
    if (secondSet.has(item)) intersection++;
  }
  const union = firstSet.size + secondSet.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

// Stable fingerprint of an IP's route set: identical wordlist tiers collide exactly (observed jaccard 1.0).
// Sorted so element order does not change the hash. sha1 is non-cryptographic use here (collision id only).
export function routeSetFingerprint(routes: Set<string>): string {
  return createHash("sha1").update([...routes].sort().join("\n")).digest("hex");
}

export function mean(values: number[]): number {
  if (values.length === 0) return 0;
  let total = 0;
  for (const value of values) total += value;
  return total / values.length;
}

// An attack path is any route matching a current PATH_THREATS pattern. Reuses the production
// classifier (adaptable, no hardcoded denylist) instead of hand-assigned severity labels.
export function isAttackPath(route: string): boolean {
  return PATH_THREATS.some((threat) => threat.pattern.test(route));
}

// Map a strategy confidence (0..1) to a threat band. Pure function of confidence, identical for every
// strategy, so it lives here and is applied once at candidate-build time - not inside each score().
export function classifyConfidence(confidence: number): ThreatLevel {
  if (confidence >= 0.75) return "high";
  if (confidence >= 0.55) return "medium";
  if (confidence >= 0.4) return "low";
  return "none";
}
