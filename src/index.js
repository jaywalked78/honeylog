// Main middleware factory.
export { honey } from "./middleware/honey.js";

// Threat pattern library - exported so consumers can extend, filter, or
// inspect what honey is matching against.
export {
  BOT_PATTERNS,
  PATH_THREATS,
  METHOD_THREATS,
  BODY_THREATS,
} from "./middleware/threatDefinitions.js";

// Geo enrichment - call initGeo() at startup with paths to your MaxMind
// GeoLite2 .mmdb files. Without this, geo enrichment is silently disabled
// and the `ip_location` column will be null on every row.
export { initGeo, geoLookup } from "./helpers/geoLookup.js";

// Tor classification - call fetchTorExitNodes() at startup (and optionally
// startTorRefreshInterval() to refresh every 12h). Without this,
// `is_tor` will be false on every row.
export {
  fetchTorExitNodes,
  startTorRefreshInterval,
  isTorExitNode,
  classifyIp,
} from "./helpers/ipClassifier.js";
