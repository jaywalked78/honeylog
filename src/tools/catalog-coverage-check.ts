import assert from "node:assert";
import { KNOWN_CAMPAIGNS } from "../middleware/detectedCampaigns.js";
import { asnPathFingerprintCluster } from "../strategies/asnPathFingerprintCluster.js";
import { uaReputation } from "../strategies/uaReputation.js";
import { singleIpBurst } from "../strategies/singleIpBurst.js";
import { subnetFingerprintOverlap } from "../strategies/subnetFingerprintOverlap.js";

const catalogIds = new Set(KNOWN_CAMPAIGNS.map((campaign) => campaign.id));

for (const strategy of [
  asnPathFingerprintCluster,
  uaReputation,
  singleIpBurst,
  subnetFingerprintOverlap,
]) {
  assert.ok(
    catalogIds.has(strategy.default_campaign_type),
    `catalog missing entry for ${strategy.id} -> ${strategy.default_campaign_type}`,
  );
}

assert.ok(
  catalogIds.has("rotating-ua-env-sweep"),
  "rotating-ua-env-sweep sibling not catalogued",
);
console.log("OK");
