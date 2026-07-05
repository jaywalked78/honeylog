import type { Strategy, StrategyScoreResult } from "./Strategy.js";
import type { HoneyRequest } from "../detector/types.js";
import { EXPLOIT_TOOL_UA } from "../middleware/threatDefinitions.js";

const REFIRE_SUPPRESSION_WINDOW_MS = 8 * 60 * 60 * 1000;

// Weak standalone: one self-identified tool UA is a reputation hit, not a campaign by itself. Its
// real weight is the related_strategy_tags co-occurrence boost in the routing policy when it stacks
// with another strategy on the same IP.
const WEAK_STANDALONE_CONFIDENCE = 0.5;

function isExploitToolUa(userAgent: string | null): boolean {
  if (userAgent == null) return false;
  return EXPLOIT_TOOL_UA.some((pattern) => pattern.test(userAgent));
}

export const uaReputation: Strategy = {
  id: "ua-reputation",
  related_strategy_tags: ["known_tooling", "rce_probe"],
  default_campaign_type: "known-exploit-tooling",
  default_suppress_for_ms: REFIRE_SUPPRESSION_WINDOW_MS,
  metrics_required: [],
  markers_observed: [],
  markers_consumed: [],

  observe(req) {
    if (!isExploitToolUa(req.user_agent)) return null;
    return {
      stream: "ua-reputation",
      key: req.ip,
      value: req,
      request_id: req.id,
    };
  },

  score(requestObservations): StrategyScoreResult | null {
    const requests = requestObservations.map((obs) => obs.value as HoneyRequest);
    const matchedUas = [
      ...new Set(
        requests
          .map((req) => req.user_agent)
          .filter((ua): ua is string => isExploitToolUa(ua)),
      ),
    ];
    if (matchedUas.length === 0) return null;
    return {
      confidence: WEAK_STANDALONE_CONFIDENCE,
      evidence: { matchedUas, requestCount: requests.length },
    };
  },

  identifier_from(key): string {
    return `ua-reputation|ip=${key}`;
  },
};
