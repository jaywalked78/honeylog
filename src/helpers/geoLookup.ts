import maxmind, {
  type Reader,
  type CityResponse,
  type AsnResponse,
} from "maxmind";

// === SHARED TYPES ===

export interface GeoLookupLogger {
  info?: (...args: unknown[]) => void;
  error?: (...args: unknown[]) => void;
}

export interface GeoLookupOptions {
  cityPath?: string; // Absolute path to GeoLite2-City.mmdb.
  asnPath?: string; // Absolute path to GeoLite2-ASN.mmdb.
  logger?: GeoLookupLogger; // Logger (defaults to console).
}

export interface GeoLocation {
  country: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: number | null;
  org: string | null;
}

let cityDb: Reader<CityResponse> | null = null;
let asnDb: Reader<AsnResponse> | null = null;

// Initialize MaxMind GeoLite2 databases. Call once at app startup, before
// mounting `honey`. If either path fails to load, geo enrichment for that
// layer is silently disabled and the middleware keeps working. MaxMind's free
// databases don't always have city/coordinate coverage, and some IPs land in

// Returns true if at least one database loaded.

export async function initGeo({
  cityPath,
  asnPath,
  logger = console,
}: GeoLookupOptions = {}): Promise<boolean> {
  let loaded = 0;

  const safeOpen = async <R extends CityResponse | AsnResponse>(
    label: string,
    dbPath: string | undefined,
    opener: (path: string) => Promise<Reader<R>>,
  ): Promise<Reader<R> | null> => {
    if (!dbPath) return null;
    try {
      return await opener(dbPath);
    } catch (error) {
      const err = error as Error;
      (logger.error || console.error).call(
        logger,
        `[honeylog] ${label} failed to load: ${err.message}`,
      );
      return null;
    }
  };

  const [city, asn] = await Promise.all([
    safeOpen<CityResponse>("GeoLite2-City", cityPath, (p) =>
      maxmind.open<CityResponse>(p),
    ),
    safeOpen<AsnResponse>("GeoLite2-ASN", asnPath, (p) =>
      maxmind.open<AsnResponse>(p),
    ),
  ]);
  cityDb = city;
  asnDb = asn;
  loaded = (cityDb ? 1 : 0) + (asnDb ? 1 : 0);

  if (loaded > 0) {
    (logger.info || console.log).call(
      logger,
      `[honeylog] GeoIP databases loaded (${loaded}/2)`,
    );
  }

  return loaded > 0;
}

export function geoLookup(ip: string): GeoLocation | null {
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
      latitude: city?.location?.latitude ?? null,
      longitude: city?.location?.longitude ?? null,
      asn: asn?.autonomous_system_number ?? null,
      org: asn?.autonomous_system_organization || null,
    };
  } catch {
    return null;
  }
}
