import { parseNginxLog } from "./backfill-from-nginx.js";

const sample = `172.16.0.1 - - [27/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"`;

const parsed = parseNginxLog(sample);

console.log(parsed);
