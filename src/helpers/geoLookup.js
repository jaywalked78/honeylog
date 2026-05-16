import maxmind from "maxmind";

let cityDb = null;
let asnDb = null;

/**
 * Initialize MaxMind GeoLite2 databases. Call once at app startup, before
 * mounting `honey`. If either path fails to load, geo enrichment for that
 * dimension is silently disabled and the middleware keeps working.
 *
 * @param {Object} options
 * @param {string} [options.cityPath]  Absolute path to GeoLite2-City.mmdb.
 * @param {string} [options.asnPath]   Absolute path to GeoLite2-ASN.mmdb.
 * @param {{ info?: Function, error?: Function }} [options.logger]
 *                                     Logger (defaults to console).
 * @returns {Promise<boolean>} true if at least one database loaded.
 */
export async function initGeo({ cityPath, asnPath, logger = console } = {}) {
  let loaded = 0;

  if (cityPath) {
    try {
      cityDb = await maxmind.open(cityPath);
      loaded++;
    } catch (error) {
      (logger.error || console.error).call(
        logger,
        "[honeylog] GeoLite2-City failed to load:",
        error.message,
      );
    }
  }

  if (asnPath) {
    try {
      asnDb = await maxmind.open(asnPath);
      loaded++;
    } catch (error) {
      (logger.error || console.error).call(
        logger,
        "[honeylog] GeoLite2-ASN failed to load:",
        error.message,
      );
    }
  }

  if (loaded > 0) {
    (logger.info || console.log).call(
      logger,
      `[honeylog] GeoIP databases loaded (${loaded}/2)`,
    );
  }

  return loaded > 0;
}

export function geoLookup(ip) {
  if (
    !cityDb ||
    !asnDb ||
    !ip ||
    ip === "0.0.0.0" ||
    ip === "::1" ||
    ip === "127.0.0.1" ||
    ip.startsWith("::ffff:127.")
  ) {
    return null;
  }

  try {
    const city = cityDb.get(ip);
    const asn = asnDb.get(ip);

    return {
      country: city?.country?.iso_code || null,
      city: city?.city?.names?.en || null,
      latitude: city?.location?.latitude || null,
      longitude: city?.location?.longitude || null,
      asn: asn?.autonomous_system_number || null,
      org: asn?.autonomous_system_organization || null,
    };
  } catch {
    return null;
  }
}
