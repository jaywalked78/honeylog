# GeoLite2 Databases

This folder is the **suggested default location** for the MaxMind GeoLite2
`.mmdb` files that honeylog uses for geo and ASN enrichment. The files
themselves are gitignored - you supply them yourself under your own
MaxMind license.

> honeylog doesn't require this specific path - it accepts absolute paths
> to `.mmdb` files wherever they live on disk. This folder is just a
> convention so the scaffolding is obvious.

## What goes here

- `GeoLite2-City.mmdb` - country, city, coordinates
- `GeoLite2-ASN.mmdb` - autonomous system number and organization

If either file is missing, that dimension is silently disabled and the
middleware keeps working - you just get `null` for those fields in
`ip_location`.

## How to get them

1. Create a free MaxMind account at <https://www.maxmind.com/en/geolite2/signup>
2. Generate a license key from your account portal
3. Either:
   - **Manual** - Download the `.mmdb` files from the MaxMind portal and
     drop them in this folder, OR
   - **Automated (recommended for production)** - install
     [`geoipupdate`](https://github.com/maxmind/geoipupdate) and run it on
     a cron. It handles the weekly refresh that MaxMind publishes and
     keeps your files current without manual intervention.

## How to wire them up

In your app's startup, before mounting `honey()`:

```js
import path from "path";
import { fileURLToPath } from "url";
import { initGeo } from "honeylog";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

await initGeo({
  cityPath: path.resolve(__dirname, "data/GeoLite2-City.mmdb"),
  asnPath: path.resolve(__dirname, "data/GeoLite2-ASN.mmdb"),
});

// then mount honey() normally
```

Paths must be absolute. Use `path.resolve()` or `path.join()` to build
them from a known anchor (`__dirname`, `process.cwd()`, an env var, etc.)
rather than hard-coding strings.

## Why gitignored

MaxMind's GeoLite2 license explicitly prohibits redistribution of the
`.mmdb` files. Each operator must download their own copy under their own
license key. Even on a private repo this is a habit worth keeping - if
the repo ever becomes public, you don't want `.mmdb` files in the history.
