/**
 * Detected Campaigns - known attacker campaigns observed in production traffic.
 *
 * Grounding data for the future campaignDetector module (honeylog v0.2).
 * Each campaign documents:
 *   - id, aliases, description, severity, first/last observed
 *   - detection: criteria the detector can use to recognize this campaign
 *     archetype in incoming traffic (type, indicators, time windows)
 *   - known_sources: specific IP/ASN/org tuples observed running this campaign
 *   - signature_paths: representative paths that strongly indicate this campaign
 *
 * Source data: logs_requests across multiple weekly analysis windows
 * (2026-04 through 2026-05-23), totaling ~13k+ classified requests.
 *
 * Maintenance: add new sources to existing campaigns as continuity instances
 * appear; add new campaign entries when a novel archetype is identified across
 * 2+ independent observations.
 */

// === DETECTION TYPES ===
//
//   single_ip_high_volume    - one IP runs an exhaustive wordlist sweep
//   asn_subnet_spray         - multiple IPs from same /24 or ASN, low per-IP
//   distributed_tor_scan     - many Tor exit IPs, each low-volume, same fingerprint
//   path_traversal_bypass    - path-normalization or URL-encoding evasion
//   webshell_hunt            - probes for pre-installed backdoors (not installing)
//   method_anomaly           - non-standard HTTP method recurring (PROPFIND, etc.)
//   credential_subdirectory  - same target file across dozens of route prefixes
//   distributed_rce_probe    - same RCE exploit fired across prefixes from many unrelated ASNs (cross-ASN single-shot botnet)
//
// Note: asn_subnet_spray should require min_unique_paths > 1 per subnet before
// promotion, so benign single-"/" edge/uptime clusters do not false-positive.

// A single IP/subnet/ASN tuple observed running a campaign. `ip` holds either a
// literal address or a CIDR/masked form (e.g. "78.153.140.0/24", "192.42.116.x").
export interface CampaignSource {
  ip: string;
  asn: number;
  org: string;
  date: string;
  path_count?: number;
  notes?: string;
}

export interface KnownCampaign {
  id: string;
  aliases: string[];
  description: string;
  first_observed: string;
  last_observed: string;
  severity: "low" | "medium" | "high";
  detection: {
    type: string;
    // Per-campaign statistical thresholds; keys vary by detection type.
    indicators: Record<string, unknown>;
  };
  known_sources: CampaignSource[];
  signature_paths: string[];
}

export const KNOWN_CAMPAIGNS: KnownCampaign[] = [
  {
    id: "comprehensive-credential-harvester",
    aliases: ["DO-credential-sweep", "full-wordlist-scanner"],
    description:
      "Single IP runs an exhaustive credential file wordlist (~270 to 1730+ paths) in one sweep. Targets cloud CLI configs, SSH/SSL keys, framework configs, backup archives, Spring Boot Actuator endpoints, Git/SVN exposure. Often uses fake Googlebot UA. Speed varies from measured (4-6 paths/sec) to extreme (100 paths/sec).",
    first_observed: "2026-04-30",
    last_observed: "2026-07-03",
    severity: "high",
    detection: {
      type: "single_ip_high_volume",
      indicators: {
        min_unique_paths: 150,
        path_categories: [
          "env_files",
          "cloud_cli_creds",
          "ssh_ssl_keys",
          "framework_configs",
          "backup_archives",
          "spring_actuator",
          "git_svn_exposure",
          "vpn_tunnel_configs",
        ],
        time_window_minutes: 60,
        ua_signals: ["fake_googlebot", "minimal_mozilla", "single_browser_ua"],
      },
    },
    known_sources: [
      {
        ip: "137.184.53.78",
        asn: 14061,
        org: "DigitalOcean, LLC",
        date: "2026-04-30",
        path_count: 270,
        notes: "Original observed instance, measured pace",
      },
      {
        ip: "142.93.228.138",
        asn: 14061,
        org: "DigitalOcean, LLC",
        date: "2026-05-09",
        path_count: 314,
        notes: "Same scanner family from DigitalOcean, slightly broader wordlist",
      },
      {
        ip: "151.243.150.23",
        asn: 207043,
        org: "Dedik Services Limited",
        date: "2026-05-20",
        path_count: 1730,
        notes: "Extreme variant: 1730 paths in 17 seconds (~100 req/sec) with fake Googlebot UA",
      },
      {
        ip: "159.203.100.69",
        asn: 14061,
        org: "DigitalOcean, LLC",
        date: "2026-05-23",
        path_count: 331,
        notes: "331 unique paths in ~3 seconds (~110 req/sec). Notable specialization: VPN/mesh tunnel credentials (cloudflared, headscale, ipsec, nebula, netbird, openvpn, twingate, wireguard) and APISIX gateway admin (/apisix/admin/routes, services, prometheus/metrics)",
      },
      {
        ip: "151.243.150.23",
        asn: 209413,
        org: "Dedik Services Limited",
        date: "2026-05-29",
        path_count: 1130,
        notes: "Same Dedik fake-Googlebot actor as the 2026-05-20 instance, ASN drift 207043 -> 209413 (same org, city now Frankfurt am Main DE). 1130 unique paths (2155 total requests) in ~17 seconds (~125 req/sec). Wordlist grew vs prior 1730-path sweep",
      },
      {
        ip: "64.89.161.29",
        asn: 205759,
        org: "Ghosty Networks LLC",
        date: "2026-05-30",
        path_count: 359,
        notes: "New ASN. Classic dotfile credential wordlist (/.aws/*, /.azure/*, /.config/gcloud/*, /.dbeaver/*, FileZilla, _ignition/execute-solution) at measured pace (359 unique paths in ~90 seconds, ~4 req/sec)",
      },
      {
        ip: "142.93.150.252",
        asn: 14061,
        org: "DigitalOcean, LLC",
        date: "2026-05-26",
        path_count: 330,
        notes: "DigitalOcean continuity (Toronto CA), single Linux-Chrome UA. 330 unique paths in ~3 seconds (~110 req/sec). Specializes in cloud service-account JSON, PEM keys, and SQL backups (serviceAccountKey.json, firebase-admin.json, *.sql)",
      },
      {
        ip: "151.243.150.222",
        asn: 209413,
        org: "Dedik Services Limited",
        date: "2026-07-03",
        path_count: 1042,
        notes: "Same Dedik fake-Googlebot actor, new IP on same org/ASN (prior instances 151.243.150.23). 1042 unique paths (1112 requests) in ~14 seconds (~80 req/sec): /.aws/credentials, /.git/HEAD, /wp-config.php.*, /composer.lock, /.env.*",
      },
      {
        ip: "130.12.180.0/24",
        asn: 202412,
        org: "Omegatech LTD",
        date: "2026-06-29..2026-07-02",
        path_count: 92,
        notes: "DISTRIBUTED VARIANT: classic dotfile-cred wordlist (/.aws/*, /.azure/*, /.boto, /.cargo/*, /.config/gcloud/*, /.dbeaver/*, FileZilla) but spread across 3 IPs in one /24 (.77/.196/.48, 89-92 paths each) instead of single-IP. Candidate to reclassify as an asn_subnet_spray sibling if delivery mode recurs",
      },
    ],
    signature_paths: [
      "/accessKeys.csv",
      "/actuator/heapdump",
      "/actuator/env",
      "/.aws/credentials.bak",
      "/.config/gcloud/credentials.db",
      "/serviceAccountKey.json",
      "/.kube/config",
      "/secret_token.rb",
      "/credentials.yml.enc",
      "/.ssh/id_rsa",
      "/wp-config.php.bak",
      "/.git/config",
      "/etc/wireguard/wg0.conf",
      "/etc/openvpn/server.key",
      "/etc/headscale/private.key",
      "/apisix/admin/routes",
    ],
  },

  {
    id: "env-subdirectory-spray",
    aliases: ["env-route-enumeration", "laravel-env-hunt"],
    description:
      "Same target file (.env) hit across dozens of route prefixes - /admin/.env, /api/v1/.env, /staging/.env, /brevo/.env, /cron/.env, etc. Looking for misconfigured framework deployments that leave .env exposed under sub-routes. Recurring weekly for 8+ weeks from same IR-based host.",
    first_observed: "2026-03-15",
    last_observed: "2026-06-08",
    severity: "high",
    detection: {
      type: "credential_subdirectory",
      indicators: {
        target_filename: ".env",
        min_subdirectory_variants: 20,
        time_window_minutes: 30,
      },
    },
    known_sources: [
      {
        ip: "192.253.248.169",
        asn: 213790,
        org: "Limited Network LTD",
        date: "2026-05-26",
        path_count: 121,
        notes: "Original source, still running weekly (11+ weeks of persistence). 121 unique paths this window (.env across /api, /backend, /admin, /laravel, /core, /app, /dev, /staging plus phpinfo probes). Dual-purpose actor - also the static-lfi-path-bypass source",
      },
      {
        ip: "172.94.9.241",
        asn: 213790,
        org: "Limited Network LTD",
        date: "2026-05-23",
        notes: "Same-ASN second source - first time the actor appears from a second IP on this ASN, suggesting infrastructure expansion",
      },
      {
        ip: "165.22.63.87",
        asn: 14061,
        org: "DigitalOcean, LLC",
        date: "2026-05-08",
        notes: "DO-based variant, hit 175+ unique .env subdirectory paths in single sweep",
      },
      {
        ip: "192.253.248.169",
        asn: 213790,
        org: "Limited Network LTD",
        date: "2026-06-08",
        path_count: 59,
        notes: "Original source still running - now ~14 weeks of persistence. 59 unique paths this window (.env across /api, /twilio plus .php-suffixed env variants /.env.php, /.env.sample.php, /.env.local.php, /config.dev.php). Dual-purpose actor (also static-lfi-path-bypass)",
      },
      {
        ip: "179.43.168.58",
        asn: 51852,
        org: "Private Layer INC",
        date: "2026-06-08",
        path_count: 126,
        notes: "CH bulletproof (Private Layer), NEW ASN for this campaign. Clean 126-path single-IP .env wordlist (/.env, /.env.local, /.env.production, /.env.prod, /.env.staging, /.env.dev) in a ~19s burst",
      },
    ],
    signature_paths: [
      "/admin/.env",
      "/api/.env",
      "/api/v1/.env",
      "/staging/.env",
      "/laravel/.env",
      "/server/.env",
      "/portal/.env",
      "/cron/.env",
      "/brevo/.env",
      "/dashboard/.env",
    ],
  },

  {
    id: "distributed-tor-config-scan",
    aliases: ["church-of-cyberology-scan", "tor-distributed-recon"],
    description:
      "Distributed config-file enumeration across dozens of Tor exit IPs. Each IP hits only 1-6 paths total, but the ASN coordinates a coherent sweep covering dompdf, FileZilla credentials, postman collections, asyncapi specs, Oracle sqlnet, cPanel configs. Per-IP rate limiting cannot catch this; only ASN-level clustering across a 30-min window surfaces it.",
    first_observed: "2026-05-08",
    last_observed: "2026-05-15",
    severity: "high",
    detection: {
      type: "distributed_tor_scan",
      indicators: {
        single_asn: 4224,
        min_distinct_ips: 6,
        max_paths_per_ip: 6,
        time_window_minutes: 30,
        is_tor_exit: true,
      },
    },
    known_sources: [
      {
        ip: "192.42.116.x",
        asn: 4224,
        org: "Church of Cyberology",
        date: "2026-05-09",
        notes: "Dozens of IPs across the /24, each low-volume (1-6 paths), all Tor exit nodes",
      },
    ],
    signature_paths: [
      "/dompdf/dompdf/www/setup.php",
      "/files/FileZilla.xml",
      "/recentservers.xml",
      "/postman_collection.json",
      "/asyncapi.yaml",
      "/html/bin/sqlnet.log",
      "/.cpbackup-exclude.conf",
      "/PEAR/.registry/pear.reg",
    ],
  },

  {
    id: "asn-subnet-env-spray",
    aliases: ["pfcloud-spray", "multi-ip-subnet-campaign"],
    description:
      "Multi-IP .env spray from same /24 subnet. Adjacent IPs each hit ~30-100 requests targeting .env files and credential paths. Per-IP rate limiting catches each individually but cannot correlate across the subnet. Classic Datacamp/FNS/Pfcloud bulletproof-host pattern.",
    first_observed: "2026-05-09",
    last_observed: "2026-07-03",
    severity: "high",
    detection: {
      type: "asn_subnet_spray",
      indicators: {
        same_asn_and_subnet: true,
        subnet_mask: 24,
        min_distinct_ips_in_subnet: 2,
        time_window_minutes: 30,
        shared_fingerprint: true,
      },
    },
    known_sources: [
      {
        ip: "45.135.193.156",
        asn: 51396,
        org: "Pfcloud UG (haftungsbeschrankt)",
        date: "2026-05-15",
      },
      {
        ip: "45.135.193.157",
        asn: 51396,
        org: "Pfcloud UG (haftungsbeschrankt)",
        date: "2026-05-15",
      },
      {
        ip: "192.109.200.217",
        asn: 51396,
        org: "Pfcloud UG (haftungsbeschrankt)",
        date: "2026-05-15",
      },
      {
        ip: "176.65.149.253",
        asn: 51396,
        org: "Pfcloud UG (haftungsbeschrankt)",
        date: "2026-05-23",
        notes: "Continuation of ASN-level coordination on a different /24 (176.65.149.0/24), confirming campaign infrastructure spans multiple subnets within the same hosting provider",
      },
      {
        ip: "80.94.95.0/24",
        asn: 204428,
        org: "SS-Net",
        date: "2026-06-28..2026-07-03",
        path_count: 32,
        notes: "NEW PROVIDER. 3 IPs (.211/.187/.34), 148 reqs, .env + .env.php variants incl. /twilio/.env.php, /sendgrid/.env.php",
      },
      {
        ip: "77.83.39.0/24",
        asn: 214940,
        org: "Kprohost LLC",
        date: "2026-06-28..2026-07-03",
        path_count: 3,
        notes: "NEW PROVIDER. 4 IPs, 9x /.env + 7x /.git/config, 17 UAs across 17 reqs (per-request rotation)",
      },
    ],
    signature_paths: [
      "/.env",
      "/.env.save",
      "/.env.example",
      "/laravel/.env",
      "/api/.env",
      "/admin/.env",
      "/backend/.env",
      "/staging/.env",
      "/phpinfo.php",
    ],
  },

  {
    id: "androxgh0st",
    aliases: ["androxghost", "hostglobal-androx"],
    description:
      "Recurring Androxgh0st-family scanner: GET probes for .env followed by POST attempts with credential-validation payloads from same IP. Targets cloud SMTP credentials (SendGrid, Twilio, AWS SES). Running 4+ consecutive weeks from rotating Hostglobal.plus IPs.",
    first_observed: "2026-04-15",
    last_observed: "2026-07-05",
    severity: "high",
    detection: {
      type: "single_ip_high_volume",
      indicators: {
        path_categories: ["env_files", "smtp_creds", "cloud_api_creds"],
        body_signals: ["aws_credential_validation", "smtp_test_payload", "androxgh0st_signed_body"],
        body_signature: '{"0x[]": "androxgh0st"}',
        get_followed_by_post: true,
      },
    },
    known_sources: [
      {
        ip: "78.153.140.156",
        asn: 202306,
        org: "Hostglobal.plus Ltd",
        date: "2026-04-15",
      },
      {
        ip: "78.153.140.252",
        asn: 202306,
        org: "Hostglobal.plus Ltd",
        date: "2026-04-22",
      },
      {
        ip: "78.153.140.50",
        asn: 202306,
        org: "Hostglobal.plus Ltd",
        date: "2026-05-15",
      },
      {
        ip: "78.153.140.43",
        asn: 202306,
        org: "Hostglobal.plus Ltd",
        date: "2026-05-23",
        notes: "6th consecutive week, 4th IP from same /24 (78.153.140.0/24). Classic GET /.env then POST / pattern persists unchanged",
      },
      {
        ip: "78.153.140.39",
        asn: 202306,
        org: "Hostglobal.plus Ltd",
        date: "2026-05-23",
        notes: "Same /24 (78.153.140.0/24, GB). GET /.env + POST / with literally-signed body {\"0x[]\": \"androxgh0st\"}. 7 distinct IPs from this subnet active this window (.39, .43, .148, .156, .250, .251, .252), GET/POST pairing jaccard ~1.0",
      },
      {
        ip: "78.153.140.148",
        asn: 202306,
        org: "Hostglobal.plus Ltd",
        date: "2026-05-24",
        notes: "Same /24, highest per-IP volume this window. GET /.env + POST / signed body {\"0x[]\": \"androxgh0st\"}",
      },
      {
        ip: "78.153.140.250",
        asn: 202306,
        org: "Hostglobal.plus Ltd",
        date: "2026-05-28",
        notes: "Same /24, signed POST body {\"0x[]\": \"androxgh0st\"}",
      },
      {
        ip: "78.153.140.251",
        asn: 202306,
        org: "Hostglobal.plus Ltd",
        date: "2026-05-30",
        notes: "Same /24, signed POST body {\"0x[]\": \"androxgh0st\"}",
      },
      {
        ip: "78.153.140.0/24",
        asn: 202306,
        org: "Hostglobal.plus Ltd",
        date: "2026-06-28..2026-07-05",
        notes: "Continued activity, no new IPs: .156/.252/.50/.250 (all already catalogued) running the exact 36x GET /.env + 36x POST / pairing through 2026-07-05",
      },
    ],
    signature_paths: [
      "/.env",
      "/aws.json",
      "/sendgrid.env",
      "/twilio.json",
      "/mailgun.env",
    ],
  },

  {
    id: "php-webshell-hunt",
    aliases: ["azure-webshell-scan", "backdoor-survey"],
    description:
      "Scanner enumerating common PHP webshell filenames - not attempting to install backdoors, just checking which ones already exist on the host (i.e., looking for boxes someone else already owns). Sourced from Microsoft Azure ranges.",
    first_observed: "2026-05-09",
    last_observed: "2026-07-04",
    severity: "medium",
    detection: {
      type: "webshell_hunt",
      indicators: {
        path_categories: ["known_webshell_filenames"],
        min_distinct_webshell_paths: 5,
        time_window_minutes: 10,
      },
    },
    known_sources: [
      {
        ip: "20.9.31.235",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-05-09",
      },
      {
        ip: "20.197.195.237",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-05-09",
      },
      {
        ip: "20.226.2.52",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-05-27",
        path_count: 232,
        notes: "232 unique .php backdoor filenames in one sweep (Brazil edge). Volume far exceeds the 5-path detection threshold",
      },
      {
        ip: "20.12.209.255",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-05-28",
        path_count: 204,
        notes: "204 unique .php backdoor filenames (US). Report stated 215; log confirms 204 distinct .php paths",
      },
      {
        ip: "4.228.83.111",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-05-24",
        path_count: 124,
        notes: "124 unique .php backdoor filenames (Brazil edge)",
      },
      {
        ip: "172.212.190.121",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-05-23",
        path_count: 121,
        notes: "121 unique .php backdoor filenames (US)",
      },
      {
        ip: "20.206.111.238",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-05-26",
        path_count: 96,
        notes: "96 unique .php backdoor filenames (Brazil edge)",
      },
      {
        ip: "74.249.212.250",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-05-25",
        path_count: 80,
        notes: "80 unique .php backdoor filenames (US). Random-string filenames (/tdd.php, /0x.php, /adminfuns.php, /wpxml.php, /cA3bHIkVhgP.php)",
      },
      {
        ip: "4.193.112.29",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-06-08",
        path_count: 292,
        notes: "SG. 292 unique .php backdoor filenames. Leads /wp-content/plugins/hellopress/wp_filemanager.php, /this_is_a_new_hello_world.php, /nf_tracking.php, /wp-Blogs.php. Single Linux/Chrome UA",
      },
      {
        ip: "52.154.129.156",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-06-08",
        path_count: 172,
        notes: "US. 154 .php webshell filenames (/dx.php, /x.php, /wss.php, hellopress wp_filemanager.php)",
      },
      {
        ip: "52.138.34.68",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-06-08",
        path_count: 144,
        notes: "CA. 144 .php webshell filenames (/ff.php, /x.php, hellopress wp_filemanager.php)",
      },
      {
        ip: "4.204.235.48",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-06-08",
        path_count: 103,
        notes: "CA. 103 .php webshell filenames (/adminfuns.php, /sx_pms.php, /wp-info.php, hellopress wp_filemanager.php)",
      },
      {
        ip: "20.63.210.3",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-06-08",
        path_count: 34,
        notes: "JP. 31 .php webshell filenames (/file5.php, /goods.php, hellopress wp_filemanager.php). Lower-volume edge node, same fingerprint",
      },
      {
        ip: "179.43.163.26",
        asn: 51852,
        org: "Private Layer INC",
        date: "2026-06-08",
        path_count: 213,
        notes: "CH bulletproof (Private Layer). MULTI-VECTOR: php-webshell primary (38 sig), plus phpunit-rce 5 (eval-stdin.php - cross-ref distributed-multivector-rce-botnet), env 7, extension-enum 6, recon (/status, /openapi.json, /v1/agent/self). New ASN for this campaign",
      },
      {
        ip: "172.161.73.175",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-06-29",
        path_count: 168,
        notes: "No UA. Leads /wp-content/plugins/hellopress/wp_filemanager.php + /this_is_a_new_hello_world.php + random .php filenames",
      },
      {
        ip: "20.219.164.250",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-07-04",
        path_count: 132,
        notes: "No UA, same hellopress/wp_filemanager.php lead",
      },
      {
        ip: "20.63.218.136",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-06-30",
        path_count: 130,
        notes: "No UA, same hellopress/wp_filemanager.php lead",
      },
      {
        ip: "4.232.93.183",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-07-01",
        path_count: 115,
        notes: "No UA, same hellopress/wp_filemanager.php lead",
      },
      {
        ip: "72.146.44.117",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-06-28",
        path_count: 113,
        notes: "No UA, same hellopress/wp_filemanager.php lead",
      },
      {
        ip: "74.248.36.50",
        asn: 8075,
        org: "Microsoft Corporation",
        date: "2026-06-29",
        path_count: 56,
        notes: "No UA, same hellopress/wp_filemanager.php lead. Six Azure IPs active this window (2026-06-28..07-04)",
      },
    ],
    signature_paths: [
      "/xenon1337.php",
      "/wp-temp.php",
      "/dx.php",
      "/zoko.php",
      "/x0.php",
      "/wpxml.php",
    ],
  },

  {
    id: "static-lfi-path-bypass",
    aliases: ["static-prefix-traversal", "path-normalization-bypass"],
    description:
      "LFI attempts that prefix paths with /static/ followed by traversal or URL-encoded segments to bypass dotfile/etc rules. Targets /etc/passwd, /proc/self/environ, Kubernetes service tokens, ~/.aws/credentials. Caught by current rules but tracked here to recognize repeat actors.",
    first_observed: "2026-05-01",
    last_observed: "2026-05-08",
    severity: "high",
    detection: {
      type: "path_traversal_bypass",
      indicators: {
        prefix_pattern: "/static/",
        traversal_indicators: ["%2f", "%2e", "....//", "/../"],
        target_categories: ["etc_files", "proc_self", "k8s_tokens", "aws_creds"],
      },
    },
    known_sources: [
      {
        ip: "192.253.248.169",
        asn: 213790,
        org: "Limited Network LTD",
        date: "2026-05-01",
        notes: "Same actor as env-subdirectory-spray; dual-purpose campaign",
      },
      {
        ip: "45.86.202.163",
        asn: 0,
        org: "unknown",
        date: "2026-05-08",
        notes: "URL-encoded variants: %2F, %2f, ....// obfuscation",
      },
    ],
    signature_paths: [
      "/static//etc/passwd",
      "/static//proc/self/environ",
      "/static//run/secrets/kubernetes.io/serviceaccount/token",
      "/static//root/.kube/config",
      "/static/%2fetc%2fpasswd",
      "/static/....//etc/passwd",
    ],
  },

  {
    id: "propfind-recurring",
    aliases: ["webdav-probe", "method-anomaly-propfind"],
    description:
      "Persistent PROPFIND probes from a single source over many weeks. WebDAV method abuse to enumerate filesystem structure or test for WebDAV-enabled IIS / Apache deployments. Low volume per request but high persistence.",
    first_observed: "2026-04-08",
    last_observed: "2026-07-05",
    severity: "medium",
    detection: {
      type: "method_anomaly",
      indicators: {
        http_method: "PROPFIND",
        min_persistence_days: 14,
        same_source: true,
      },
    },
    known_sources: [
      {
        ip: "46.151.178.13",
        asn: 211443,
        org: "Sino Worldwide Trading Limited",
        date: "2026-05-29",
        path_count: 94,
        notes: "Same IP for 8+ weeks (NL). 94 PROPFIND probes to / this window (up from 25), spanning ~6 days. Never blocked, never changes pattern",
      },
      {
        ip: "46.151.178.13",
        asn: 211443,
        org: "Sino Worldwide Trading Limited",
        date: "2026-06-08",
        path_count: 1,
        notes: "NL. Same IP continuing 9+ weeks. 28 PROPFIND probes to / over a ~6-day span (down from 94 last window, pattern unchanged, never blocked)",
      },
      {
        ip: "46.151.178.13",
        asn: 211443,
        org: "Sino Worldwide Trading Limited",
        date: "2026-07-05",
        path_count: 1,
        notes: "NL. Same IP, 13+ weeks. 27 PROPFIND probes to / spanning 2026-06-28..2026-07-05, pattern unchanged",
      },
    ],
    signature_paths: ["/"],
  },

  {
    id: "url-encoded-dotfile-bypass",
    aliases: ["pfcloud-encoded-sweep", "%2e-bypass-spray"],
    description:
      "Single IP runs a massive credential wordlist where every dot in path segments is URL-encoded as %2e (e.g., /%2eenv%2ebackup, /backup%2esql, /etc/exim4/exim4%2econf). Tests for honeypots/WAFs that only match literal dotfile patterns. Rotates browser UAs across requests within the same sweep, then issues both encoded and plain variants back-to-back to detect rule asymmetries. Distinct from asn-subnet-env-spray in that it's a single high-volume IP rather than distributed across a /24.",
    first_observed: "2026-05-23",
    last_observed: "2026-05-23",
    severity: "high",
    detection: {
      type: "single_ip_high_volume",
      indicators: {
        min_unique_paths: 200,
        time_window_minutes: 15,
        encoded_dot_ratio_min: 0.3,
        path_categories: [
          "encoded_dotfiles",
          "encoded_backups",
          "encoded_mail_configs",
          "git_directory",
          "framework_app_configs",
        ],
        ua_signals: ["rotating_browser_uas_same_ip"],
      },
    },
    known_sources: [
      {
        ip: "45.153.34.165",
        asn: 51396,
        org: "Pfcloud UG (haftungsbeschrankt)",
        date: "2026-05-23",
        path_count: 348,
        notes: "348 unique paths in ~6 minutes, rotates 5+ browser UAs (Chrome 121/122 Mac, Edge, Firefox, Safari) from same source IP. Hits both encoded and plain variants of /etc/exim4/exim4.conf, /etc/mail/sendmail.cf, /etc/postfix/main.cf etc.",
      },
    ],
    signature_paths: [
      "/%2eenv",
      "/%2eenv%2ebackup",
      "/%2egit/config",
      "/backup%2esql",
      "/etc/exim4/exim4%2econf",
      "/etc/mail/sendmail%2ecf",
      "/etc/postfix/main%2ecf",
      "/%2eAWS/credentials",
      "/config%2ephp",
      "/database%2eyml",
    ],
  },

  {
    id: "multi-extension-discovery-scan",
    aliases: ["filename-fingerprint-scan", "akamai-discovery-burst"],
    description:
      "Single IP fingerprints framework by enumerating canonical paths across every plausible file extension - /admin.{asp,aspx,cfm,cgi,jhtml,jsa,jsp,php,pl,shtml}, /index.X, /default.X, /home.X, /base.X. Combined with product version disclosure probes (vRNI, hoverfly, centreon, decisioncenter, geoserver, Atlassian Confluence). Goal is server fingerprint discovery, not exploitation - feeds downstream targeted scanners. Mobile (iPhone) UA spoof from Akamai/Linode hosting is unusual signature.",
    first_observed: "2026-05-23",
    last_observed: "2026-05-23",
    severity: "medium",
    detection: {
      type: "single_ip_high_volume",
      indicators: {
        min_unique_paths: 200,
        time_window_seconds: 60,
        path_categories: [
          "extension_enumeration",
          "api_version_disclosure",
          "product_fingerprinting",
        ],
        signal_patterns: [
          "same_basename_many_extensions",
          "iphone_ua_from_datacenter_ip",
        ],
      },
    },
    known_sources: [
      {
        ip: "198.58.117.211",
        asn: 63949,
        org: "Akamai Connected Cloud",
        date: "2026-05-23",
        path_count: 267,
        notes: "267 unique paths in sub-second burst (timestamps within single second), iPhone UA from Akamai-hosted IP - likely Linode legacy infrastructure under new Akamai branding",
      },
    ],
    signature_paths: [
      "/admin.asp",
      "/admin.aspx",
      "/admin.cfm",
      "/admin.cgi",
      "/admin.jhtml",
      "/admin.jsp",
      "/api/version",
      "/api/v1/info",
      "/api/v2/about",
      "/api/v2/hoverfly/version",
      "/api/vip/i18n/api/v2/translation/products/vRNIUI/versions/1",
      "/CFIDE/componentutils/",
      "/centreon/api/latest/platform/versions",
    ],
  },

  {
    id: "distributed-multivector-rce-botnet",
    aliases: ["phpunit-shellshock-spray", "cve-2017-9841-cve-2021-41773-cluster"],
    description:
      "Loosely-coordinated botnet of single-shot hosts across many unrelated ASNs, each firing the same canonical RCE probe set across dozens of route prefixes. Two fused vectors from an overlapping IP set: (1) CVE-2017-9841 PHPUnit eval-stdin.php under /, /api, /admin, /laravel, /cms, /crm, /blog, /V2, etc, and (2) CVE-2021-41773 Apache path traversal (/cgi-bin/.%2e/.../bin/sh). Same exploit target across many prefixes, distributed across ASNs - defeats both per-IP rate limiting and single-ASN clustering. PHPUnit IP set (13) overlaps the CVE-2021-41773 set (20) by 12 of 13, confirming a single botnet.",
    first_observed: "2026-05-23",
    last_observed: "2026-05-27",
    severity: "high",
    detection: {
      type: "distributed_rce_probe",
      indicators: {
        target_signatures: ["eval-stdin.php", "cgi-bin/.%2e/...bin/sh"],
        min_prefix_variants_per_ip: 38,
        min_distinct_ips: 13,
        min_distinct_asns: 10,
        cross_vector_ip_overlap: "12_of_13",
        time_window_days: 4,
        per_ip_volume_max: 47,
      },
    },
    known_sources: [
      {
        ip: "95.215.108.177",
        asn: 207713,
        org: "Global Internet Solutions LLC",
        date: "2026-05-27",
        path_count: 46,
        notes: "RU. 46 prefix variants of eval-stdin.php plus cgi-bin traversal",
      },
      {
        ip: "38.210.202.125",
        asn: 273250,
        org: "SOLUCIONES DE TECNOLOGIA JAH SA DE CV",
        date: "2026-05-27",
        path_count: 46,
        notes: "MX. Member of the 12-of-13 cross-vector overlap set",
      },
      {
        ip: "152.32.132.28",
        asn: 135377,
        org: "UCLOUD INFORMATION TECHNOLOGY HK LIMITED",
        date: "2026-05-27",
        path_count: 46,
        notes: "HK UCloud",
      },
      {
        ip: "152.32.226.205",
        asn: 135377,
        org: "UCLOUD INFORMATION TECHNOLOGY HK LIMITED",
        date: "2026-05-23",
        path_count: 46,
        notes: "HK UCloud, second IP from same ASN",
      },
      {
        ip: "34.100.174.162",
        asn: 396982,
        org: "Google LLC",
        date: "2026-05-27",
        path_count: 46,
        notes: "Google Cloud, IN",
      },
      {
        ip: "110.35.80.116",
        asn: 17727,
        org: "PT. NAP Info Lintas Nusa",
        date: "2026-05-27",
        path_count: 1,
        notes: "ID. CVE-2021-41773 cgi-bin traversal single-shot member",
      },
    ],
    signature_paths: [
      "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
      "/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
      "/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
      "/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
      "/cms/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
      "/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
      "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh",
    ],
  },

  {
    id: "rotating-ua-actuator-sweep",
    aliases: ["spring-actuator-ua-rotation", "gcp-actuator-twins"],
    description:
      "Spring Boot Actuator endpoint enumeration where a single IP rotates a unique User-Agent on nearly every request (~340 distinct UAs across 383 requests - mobile, desktop, legacy browsers, feature phones) to defeat UA-based rate limiting and fingerprinting. The identical 381-path wordlist appears from multiple Google Cloud IPs on different days (path jaccard = 1.0 between 8.228.10.221 and 34.179.152.37), confirming a shared tool / distributed operation. The per-IP UA diversity ratio is the discriminator versus comprehensive-credential-harvester, which uses a single UA or fake Googlebot.",
    first_observed: "2026-05-29",
    last_observed: "2026-06-30",
    severity: "high",
    detection: {
      type: "single_ip_high_volume",
      indicators: {
        min_unique_paths: 381,
        time_window_seconds: 4,
        per_ip_ua_diversity_ratio: 0.88,
        cross_ip_path_jaccard: 1.0,
        path_categories: ["spring_actuator"],
        ua_signals: ["per_request_ua_rotation"],
      },
    },
    known_sources: [
      {
        ip: "8.228.10.221",
        asn: 396982,
        org: "Google LLC",
        date: "2026-05-29",
        path_count: 381,
        notes: "US. 383 requests / 339 distinct UAs (ratio 0.88), 381 unique paths in ~3 seconds (~130 req/sec)",
      },
      {
        ip: "34.179.152.37",
        asn: 396982,
        org: "Google LLC",
        date: "2026-05-30",
        path_count: 381,
        notes: "DE. 383 requests / 345 distinct UAs (ratio 0.90), identical 381-path wordlist as 8.228.10.221 (jaccard 1.0)",
      },
      {
        ip: "35.230.167.244",
        asn: 396982,
        org: "Google LLC",
        date: "2026-05-29",
        path_count: 151,
        notes: "US. 151 paths / 143 distinct UAs - partial sweep, same UA-rotation signature",
      },
      {
        ip: "8.228.28.75",
        asn: 396982,
        org: "Google LLC",
        date: "2026-06-08",
        path_count: 381,
        notes: "US. 383 requests / 341 distinct UAs (ratio 0.89), 381 unique paths in ~2s. New IP, identical 381-path actuator+credentials.json wordlist as the 8.228.10.221/34.179.152.37 twins (cross-IP jaccard ~1.0). Leads /api/credentials.json, /private/credentials.json, /actuator/heapdump, /actuator/configprops",
      },
      {
        ip: "34.64.230.57",
        asn: 396982,
        org: "Google LLC",
        date: "2026-06-08",
        path_count: 381,
        notes: "KR. 383 requests / 345 distinct UAs (ratio 0.90), identical wordlist to 8.228.28.75 (jaccard ~1.0). EVOLUTION: now also sets a fake Googlebot UA on top of per-request rotation - first fake-Googlebot + UA-rotation blend in this campaign",
      },
      {
        ip: "34.125.229.250",
        asn: 396982,
        org: "Google LLC",
        date: "2026-06-08",
        path_count: 151,
        notes: "US. 151 paths in ~1s, 146 distinct UAs (ratio 0.97), fake Googlebot. CONTENT DRIFT: rotates UAs over a .env wordlist (/.env.local, /.env.production, /.env.bak) not actuator paths - same UA-rotation tradecraft as 35.230.167.244, env target set. If this env-rotation variant recurs, consider splitting a rotating-ua-env-sweep sibling",
      },
      {
        ip: "35.197.80.60",
        asn: 396982,
        org: "Google LLC",
        date: "2026-06-08",
        path_count: 151,
        notes: "US. 151 paths in ~3s, 147 distinct UAs (ratio 0.97). Same .env UA-rotation wordlist as 34.125.229.250 (sibling burst)",
      },
      {
        ip: "34.165.145.139",
        asn: 396982,
        org: "Google LLC",
        date: "2026-06-30",
        path_count: 542,
        notes: "563 requests / 474 distinct UAs (ratio 0.84), 542 paths in ~4s. WORDLIST GREW 381 -> 542: adds docker-compose/terraform/helm/secrets tier on top of actuator+credentials.json core",
      },
    ],
    signature_paths: [
      "/actuator/heapdump",
      "/actuator/env",
      "/actuator/configprops",
      "/actuator/threaddump",
      "/actuator/httptrace",
      "/api/actuator/heapdump",
      "/heapdump",
      "/threaddump",
    ],
  },

  {
    id: "js-asset-sourcemap-recon",
    aliases: ["frontend-bundle-enumeration", "bucklog-js-hunt"],
    description:
      "Single IP enumerates front-end build artifacts and bundler paths to fingerprint the JS framework and harvest source maps / leaked secrets in bundles - /main.js, /app.js, /bundle.js, /runtime.js, /vendor.js, /_next/static/chunks/*, /_nuxt/entry.js, /static/js/*. Distinct from credential-harvesters: targets the client build pipeline, not server config files. Includes a GravitySMTP WP plugin probe (/wp-json/gravitysmtp/v1/tests/mock-data).",
    first_observed: "2026-05-25",
    last_observed: "2026-05-25",
    severity: "medium",
    detection: {
      type: "single_ip_high_volume",
      indicators: {
        min_unique_paths: 400,
        time_window_seconds: 90,
        path_categories: ["js_bundles", "sourcemaps", "framework_build_artifacts"],
        signal_patterns: ["basename_ext_dominated_by_js_and_map", "curl_ua"],
      },
    },
    known_sources: [
      {
        ip: "185.177.72.49",
        asn: 211590,
        org: "Bucklog SARL",
        date: "2026-05-25",
        path_count: 464,
        notes: "FR. 464 unique paths in ~79 seconds, curl/8.7.1 with occasional Chrome UA. The lone PHPUnit-only IP not part of the distributed-multivector-rce-botnet overlap set",
      },
    ],
    signature_paths: [
      "/main.js",
      "/app.js",
      "/bundle.js",
      "/runtime.js",
      "/vendor.js",
      "/_next/static/chunks/main.js",
      "/_nuxt/app.js",
      "/static/js/main.js",
      "/assets/index.js",
      "/wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings",
    ],
  },

  {
    id: "cryptominer-stratum-probe",
    aliases: ["xmrig-stratum-injection", "mining-subscribe-probe"],
    description:
      "Host sends Stratum / cryptomining JSON-RPC payloads as the HTTP request line - {\"method\":\"mining.subscribe\",...} and {\"method\":\"login\",\"params\":{\"login\":\"49eYcP7o...\",\"agent\":\"XMRig/6.15.3\"}} (Monero wallet + XMRig agent), interleaved with malware-stager path probes (/SiteLoader, /stager64, /mPlayer, /download/file.ext) and a TLS ClientHello. Likely a worm checking whether the host is an exposed mining proxy or pre-owned box to enlist.",
    first_observed: "2026-05-24",
    last_observed: "2026-05-24",
    severity: "medium",
    detection: {
      type: "method_anomaly",
      indicators: {
        malformed_method_prefix: "{\"id\":",
        body_signals: ["mining.subscribe", "jsonrpc", "XMRig", "monero_wallet_string"],
        paired_with: ["stager_filename_probes"],
      },
    },
    known_sources: [
      {
        ip: "185.213.175.176",
        asn: 41608,
        org: "NextGenWebs, S.L.",
        date: "2026-05-24",
        path_count: 15,
        notes: "ES. 15 requests including 5 malformed (Stratum JSON-RPC method lines + TLS ClientHello). Monero wallet 49eYcP7o..., agent XMRig/6.15.3",
      },
    ],
    signature_paths: [
      "/SiteLoader",
      "/stager64",
      "/mPlayer",
      "/download/file.ext",
    ],
  },

  {
    id: "botnet-c2-checkin-probe",
    aliases: ["mirai-style-c2-beacon", "hacked-host-checkin"],
    description:
      "Malformed method containing a botnet C2 check-in string: 145.ll|'|'|SGFjS2VkX0Q0OTkwNjI3|'|'|WIN-JNAPIER0859|'|'|JNapier|'|'|19-02-01|'|'||'|'|Win - the base64 segment SGFjS2VkX0Q0OTkwNjI3 decodes to HacKed_D4990627, the hostname/username delimiter format of a known Windows RAT/botnet beacon (classic NjRAT-family |'|'|-delimited check-in). The bot is blindly beaconing its infected-host inventory to our IP as if we were its C2 - high intel value, identifies an infected host.",
    first_observed: "2026-05-24",
    last_observed: "2026-05-26",
    severity: "low",
    detection: {
      type: "method_anomaly",
      indicators: {
        method_signature: "|'|'|",
        body_signals: ["base64_HacKed_prefix", "windows_hostname_token", "version_date_token"],
        same_source: true,
      },
    },
    known_sources: [
      {
        ip: "66.240.205.34",
        asn: 10439,
        org: "CariNet, Inc.",
        date: "2026-05-24",
        path_count: 2,
        notes: "US. Appeared twice with the |'|'|-delimited check-in. Likely itself a compromised/abused host",
      },
    ],
    signature_paths: ["/"],
  },

  {
    id: "gcp-serviceaccount-key-spray",
    aliases: ["advin-gcp-key-hunt"],
    description:
      "Multiple IPs in 208.84.100.0/24 (ASN 22295 Advin Services LLC) run the identical ~62-path Google Cloud service-account JSON key wordlist (service-account-key.json, firebase-adminsdk.json, gcp-credentials.json, keyfile.json, client_secret.json, ...) days apart. Structurally the asn-subnet-env-spray archetype (multi-IP same-/24 coordinated credential sweep) but specialized to GCP/Firebase key files rather than .env, and from a different provider than catalog's Pfcloud. This is the live structural replacement for the absent asn-subnet-env-spray (Pfcloud AS51396) this window - that ASN did not recur.",
    first_observed: "2026-05-24",
    last_observed: "2026-06-08",
    severity: "high",
    detection: {
      type: "asn_subnet_spray",
      indicators: {
        same_asn_and_subnet: true,
        asn: 22295,
        subnet_mask: 24,
        min_distinct_ips_in_subnet: 2,
        min_unique_paths: 2,
        shared_fingerprint: true,
        cross_ip_path_jaccard: 0.95,
      },
    },
    known_sources: [
      {
        ip: "208.84.100.11",
        asn: 22295,
        org: "Advin Services LLC",
        date: "2026-05-27",
        path_count: 62,
        notes: "US, ip_type unknown. 62 unique GCP-key paths, 65 requests in ~8 seconds",
      },
      {
        ip: "208.84.100.96",
        asn: 22295,
        org: "Advin Services LLC",
        date: "2026-05-31",
        path_count: 65,
        notes: "US, ip_type unknown. Identical GCP-key wordlist as .11 (jaccard 0.95)",
      },
      {
        ip: "208.84.100.117",
        asn: 22295,
        org: "Advin Services LLC",
        date: "2026-05-24",
        path_count: 1,
        notes: "US. Low-volume member of the subnet sweep",
      },
      {
        ip: "208.84.100.233",
        asn: 22295,
        org: "Advin Services LLC",
        date: "2026-05-26",
        path_count: 1,
        notes: "US. Low-volume member of the subnet sweep",
      },
      {
        ip: "208.84.100.145",
        asn: 22295,
        org: "Advin Services LLC",
        date: "2026-06-08",
        path_count: 83,
        notes: "US, ip_type unknown. Same 208.84.100.0/24 subnet. GCP/Firebase key wordlist + .env: /config/service-account.json, /google-service-account.json, /client_secrets.json, /sa-private-key.json, /application_default_credentials.json. Slow span (~3 days), identical wordlist",
      },
      {
        ip: "208.84.100.162",
        asn: 22295,
        org: "Advin Services LLC",
        date: "2026-06-08",
        path_count: 76,
        notes: "US, ip_type unknown. Same /24, 76 paths in a 1s burst: /serviceAccountKey.json, /firebase.json, /config/credentials.json, /gcp-credentials.json, /app/.env",
      },
    ],
    signature_paths: [
      "/service-account-key.json",
      "/firebase-adminsdk.json",
      "/gcp-credentials.json",
      "/google-service-account.json",
      "/keyfile.json",
      "/sa-private-key.json",
      "/client_secret.json",
      "/.env",
    ],
  },

  {
    id: "vpn-appliance-recon",
    aliases: ["pulse-secure-probe", "sra-sstp-vpn-scan"],
    description:
      "Probes for SSL-VPN / Pulse Secure / SonicWall appliance endpoints, using the WebDAV-adjacent SSTP_DUPLEX_POST method against /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ (SonicWall SRA marker GUID) plus /dana-na/..., /remote/login, /vpnsvc/connect.cgi, /dana-cached/hc/HostCheckerInstaller.osx (Pulse Connect Secure). Seen from Akamai/Linode and DigitalOcean hosts, sometimes interleaved with other non-standard methods (GQWW, PROPFIND, SMB negotiate).",
    first_observed: "2026-05-24",
    last_observed: "2026-05-27",
    severity: "medium",
    detection: {
      type: "method_anomaly",
      indicators: {
        http_method: "SSTP_DUPLEX_POST",
        path_signatures: ["dana-na", "sra_{GUID}", "vpnsvc", "remote/login"],
      },
    },
    known_sources: [
      {
        ip: "104.248.77.54",
        asn: 14061,
        org: "DigitalOcean, LLC",
        date: "2026-05-27",
        path_count: 1,
        notes: "US. Single SSTP_DUPLEX_POST against the SonicWall SRA marker path",
      },
      {
        ip: "170.187.157.175",
        asn: 63949,
        org: "Akamai Connected Cloud",
        date: "2026-05-24",
        path_count: 19,
        notes: "US Akamai/Linode. Mixed-method probe (GET, GQWW, HEAD, OPTIONS, POST, PROPFIND, SSTP_DUPLEX_POST)",
      },
      {
        ip: "69.164.217.74",
        asn: 63949,
        org: "Akamai Connected Cloud",
        date: "2026-05-24",
        notes: "US Akamai/Linode. Also fired an SMB negotiate (\\x00\\x00\\x00'\\xFFSMBr...) as the method",
      },
    ],
    signature_paths: [
      "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/",
      "/dana-na/nc/nc_gina_ver.txt",
      "/dana-na/auth/url_default/welcome.cgi",
      "/remote/login",
      "/vpnsvc/connect.cgi",
      "/dana-cached/hc/HostCheckerInstaller.osx",
    ],
  },

  {
    id: "open-proxy-abuse-probe",
    aliases: ["connect-proxy-test", "forward-proxy-scan"],
    description:
      "CONNECT requests to external hosts (www.google.com:443, www.baidu.com:443) testing whether the server is a misconfigured open forward proxy that will relay traffic. Low volume, high persistence per IP.",
    first_observed: "2026-05-24",
    last_observed: "2026-05-26",
    severity: "low",
    detection: {
      type: "method_anomaly",
      indicators: {
        http_method: "CONNECT",
        route_is_external_host: true,
        repeated: true,
      },
    },
    known_sources: [
      {
        ip: "185.91.127.85",
        asn: 49581,
        org: "Tube-Hosting",
        date: "2026-05-24",
        path_count: 20,
        notes: "DE. 20 CONNECT to www.google.com:443 over 2 days",
      },
      {
        ip: "43.248.187.60",
        asn: 4837,
        org: "CHINA UNICOM China169 Backbone",
        date: "2026-05-26",
        path_count: 2,
        notes: "CN. 2 CONNECT to www.baidu.com:443. Report listed no ASN; log resolves AS4837 China Unicom",
      },
    ],
    signature_paths: [
      "CONNECT www.google.com:443",
      "CONNECT www.baidu.com:443",
    ],
  },

  {
    id: "onvif-device-service-distributed-sweep",
    aliases: ["hydra-onvif-census", "iot-camera-inventory-scan"],
    description:
      "Massive single-target IoT-camera census: hundreds of IPs across many /24s in one ASN (Hydra Communications AS25369) each hit /onvif/device_service (ONVIF SOAP device-discovery endpoint) plus / and /favicon.ico. Per-IP volume is ~1-2 paths so per-IP rate limiting and pairwise-cohesion subnet detection both miss it; only ASN-level fan-out on a single canonical target surfaces it. The /onvif/device_service hits use a Go-http-client/1.1 UA (Infrawatch/1.0 appears on the subnet's / probes), so possibly a benign infra-scanner, but catalogued so the subnet-spray strategy does not false-positive and so a genuine ONVIF-exploitation follow-up can be correlated.",
    first_observed: "2026-05-31",
    last_observed: "2026-07-05",
    severity: "low",
    detection: {
      type: "asn_subnet_spray",
      indicators: {
        single_asn: 25369,
        target_path: "/onvif/device_service",
        min_distinct_ips_across_asn: 60,
        max_paths_per_ip: 2,
        ua_signals: ["go_http_client_ua", "infrawatch_ua"],
        subnet_fan_out: true,
      },
    },
    known_sources: [
      {
        ip: "69.5.169.0/24",
        asn: 25369,
        org: "Hydra Communications Ltd",
        date: "2026-06-08",
        path_count: 1,
        notes: "DE. 61 distinct IPs in this /24, 84 reqs, each hitting /onvif/device_service (+/, /favicon.ico). Go-http-client/1.1 UA",
      },
      {
        ip: "31.14.254.0/24",
        asn: 25369,
        org: "Hydra Communications Ltd",
        date: "2026-06-08",
        path_count: 1,
        notes: "GB. 7 IPs, same /onvif/device_service target",
      },
      {
        ip: "193.124.20.0/24",
        asn: 25369,
        org: "Hydra Communications Ltd",
        date: "2026-06-08",
        path_count: 1,
        notes: "DE. 6 IPs, same target",
      },
      {
        ip: "185.223.235.0/24",
        asn: 25369,
        org: "Hydra Communications Ltd",
        date: "2026-06-08",
        path_count: 1,
        notes: "NL. 4 IPs, same target. Additional sibling /24s this window: 81.19.219.0/24 (GB), 5.226.140.0/24 (GB), 188.240.59.0/24 (GB), 89.21.67.0/24 (NL)",
      },
      {
        ip: "81.19.216.0/24",
        asn: 25369,
        org: "Hydra Communications Ltd",
        date: "2026-07-04",
        path_count: 3,
        notes: "EVOLUTION: sweep now also fans out /mcp and /sse (MCP / AI-agent-server discovery) alongside /onvif/device_service. 49 Hydra IPs active across the ASN this window (2026-06-28..07-05), incl. 69.5.169.0/24 (22 IPs), 193.124.20.0/24, 89.21.67.0/24",
      },
    ],
    signature_paths: [
      "/onvif/device_service",
      "/mcp",
      "/sse",
    ],
  },

  {
    id: "phishing-kit-asset-spray",
    aliases: ["tahuwin-kit-probe", "phishing-asset-existence-check"],
    description:
      "Multi-IP /24 sweep checking for the static image assets of a deployed phishing kit - /img/login.png, /img/logo-tahuwin.webp, /img/livechat.webp, /img/Whatsapp.webp, /img/Telegram.webp, /img/daftar.png ('tahuwin'/'daftar' are Indonesian gambling-site phishing-kit markers). The attacker is fingerprinting whether a stolen kit is already live on the host (asset-existence check, not exploitation), distributed across a /24 to dodge per-IP rate limiting. Each IP fires ~16 of the same asset paths in a 1-5s burst.",
    first_observed: "2026-05-31",
    last_observed: "2026-06-08",
    severity: "medium",
    detection: {
      type: "asn_subnet_spray",
      indicators: {
        same_asn_and_subnet: true,
        asn: 3356,
        subnet_mask: 24,
        min_distinct_ips_in_subnet: 3,
        min_unique_paths: 5,
        shared_fingerprint: true,
        path_categories: ["phishing_kit_assets"],
      },
    },
    known_sources: [
      {
        ip: "205.169.39.28",
        asn: 3356,
        org: "Level 3 Parent, LLC",
        date: "2026-06-08",
        path_count: 16,
        notes: "US. 16 /img/*.webp + /img/*.png phishing-kit assets in a 4s burst",
      },
      {
        ip: "205.169.39.111",
        asn: 3356,
        org: "Level 3 Parent, LLC",
        date: "2026-06-08",
        path_count: 16,
        notes: "US. Same asset list, 5s burst",
      },
      {
        ip: "205.169.39.16",
        asn: 3356,
        org: "Level 3 Parent, LLC",
        date: "2026-06-08",
        path_count: 16,
        notes: "US. Same asset list. 7 distinct IPs from 205.169.39.0/24 active this window (71 reqs total), shared /img/* fingerprint",
      },
      {
        ip: "205.169.39.115",
        asn: 3356,
        org: "Level 3 Parent, LLC",
        date: "2026-06-08",
        path_count: 16,
        notes: "US. Same asset list, 1s burst (/img/toa.png additionally)",
      },
    ],
    signature_paths: [
      "/img/login.png",
      "/img/daftar.png",
      "/img/logo-tahuwin.webp",
      "/img/tahuwin.webp",
      "/img/livechat.webp",
      "/img/Whatsapp.webp",
      "/img/Telegram.webp",
    ],
  },
  {
    id: "asn-path-fingerprint-cluster",
    aliases: ["cross-egress-fingerprint-scan", "rotating-egress-scan"],
    description:
      "One operator replays an identical path wordlist from many IPs scattered across an ASN's address space (rotating cloud egress), never 3 in one /24, often with per-request User-Agent rotation. Detected by grouping the ASN's threat IPs by exact route-set fingerprint and firing on any >= 3-IP cluster regardless of subnet. Content-agnostic: the same mechanism covers actuator, .env, and .git wordlist tiers; the routing/LLM layer refines to the specific content archetype. Distinct from subnet-fingerprint-overlap (keys on /24) and distributed-multivector-rce-botnet (keys on exploit signature across ASNs).",
    first_observed: "2026-06-12",
    last_observed: "2026-06-30",
    severity: "high",
    detection: {
      type: "asn_fingerprint_cluster",
      indicators: {
        min_distinct_ips_in_cluster: 3,
        cross_ip_path_jaccard: 1.0,
        min_path_union: 2,
        per_ip_ua_diversity_ratio: 0.8,
        ua_signals: ["per_request_ua_rotation"],
        crosses_subnet_boundary: true,
      },
    },
    known_sources: [
      {
        ip: "34.150.99.95",
        asn: 396982,
        org: "Google LLC",
        date: "2026-06-14",
        path_count: 425,
        notes: "One of 7 GCP IPs (HK/NL/US/KR/CA) each firing 427 requests / 425 identical paths / ~380 rotating UAs in a 3-5s burst. cross-IP path jaccard 1.0",
      },
      {
        ip: "34.47.164.216",
        asn: 396982,
        org: "Google LLC",
        date: "2026-06-29",
        path_count: 30,
        notes: "NEW CONTENT TIER: .git/config route-prefix wordlist (/app/.git/config, /html/.git/config, ...). One of 4 GCP IPs (with 34.125.114.107, 136.114.238.36, 34.85.109.71), each 30 reqs / 30 identical paths / ~30 UAs (ratio ~1.0), all pairs jaccard 1.0, different /24s",
      },
      {
        ip: "34.26.26.57",
        asn: 396982,
        org: "Google LLC",
        date: "2026-06-29",
        path_count: 9,
        notes: "NEW CONTENT TIER: GravitySMTP WP-plugin recon (/wp-json/gravitysmtp/v1/tests/mock-data, /settings, /config, /wp-json/wp/v2/settings). One of 4 GCP IPs (with 34.178.121.43, 34.158.29.142, 34.155.82.29), 9-10 paths each, all pairs jaccard 1.0, different /24s. NOTE: UA diversity ratio ~0.5, below the 0.8 indicator - small-N relaxation",
      },
    ],
    signature_paths: [
      "/actuator/heapdump",
      "/actuator/env",
      "/api/credentials.json",
    ],
  },
  {
    id: "rotating-ua-env-sweep",
    aliases: ["gcp-env-ua-rotation"],
    description:
      "Sibling of rotating-ua-actuator-sweep predicted by that entry's maintainer note: same per-request User-Agent rotation tradecraft, but the target wordlist is .env variants instead of Spring Actuator paths. Confirmed recurring 2026-06: 8 GCP IPs (AS396982), 166 requests / 166 distinct UAs / 166 identical paths, cross-IP path jaccard 1.0.",
    first_observed: "2026-06-12",
    last_observed: "2026-06-30",
    severity: "high",
    detection: {
      type: "single_ip_high_volume",
      indicators: {
        min_unique_paths: 166,
        time_window_seconds: 9,
        per_ip_ua_diversity_ratio: 0.95,
        cross_ip_path_jaccard: 1.0,
        path_categories: ["env_files"],
        ua_signals: ["per_request_ua_rotation"],
      },
    },
    known_sources: [
      {
        ip: "35.237.251.72",
        asn: 396982,
        org: "Google LLC",
        date: "2026-06-12",
        path_count: 166,
        notes: "One of 8 GCP IPs running the .env UA-rotation wordlist (166 paths / 163 distinct UAs), identical set across IPs (jaccard 1.0)",
      },
      {
        ip: "34.11.86.31",
        asn: 396982,
        org: "Google LLC",
        date: "2026-06-30",
        path_count: 229,
        notes: "230 requests / 221 distinct UAs (ratio 0.96), 229 paths in ~2s. Pure .env suffix wordlist (/src/.env.local, /.env.qa, /.env.pre-production)",
      },
    ],
    signature_paths: [
      "/.env",
      "/.env.local",
      "/.env.production",
    ],
  },
  {
    id: "known-exploit-tooling",
    aliases: ["exploit-tool-ua"],
    description:
      "An IP that presented a self-identifying exploit-tool User-Agent (libredtail-http, opendirme-credhunt, a literal CVE id, etc.). Low standalone severity; catalogued so the ua-reputation strategy can boost confidence when it co-occurs with another strategy on the same IP. Independent of path patterns.",
    first_observed: "2026-06-12",
    last_observed: "2026-06-30",
    severity: "low",
    detection: {
      type: "ua_reputation",
      indicators: {
        exploit_tool_ua: true,
        ua_signals: ["libredtail", "credhunt", "literal_cve_id", "l9explore", "l9tcpid"],
      },
    },
    known_sources: [
      {
        ip: "45.148.10.200",
        asn: 48090,
        org: "Techoff Srv Limited",
        date: "2026-06-28..2026-06-30",
        path_count: 19,
        notes: "l9explore/1.2.2 + l9tcpid/v1.1.0 (LeakIX open-source scanner) UAs over a .env wordlist. 2 IPs from 45.148.10.0/24 this window",
      },
    ],
    signature_paths: [],
  },

  {
    id: "framework-debug-config-recon",
    aliases: ["symfony-yii-debug-probe", "phpinfo-config-census"],
    description:
      "Single IP enumerates framework debug panels, phpinfo dumps, and config.json/parameters.yml disclosure across a fixed ~40-path kit: /phpinfo.php, /info.php, the ownCloud graphapi GetPhpInfo.php RCE probe (CVE-2023-49103), Symfony /app_dev.php/_profiler and /frontend_dev.php, Yii /debug/default/view panels, and a config.*.json / parameters.yml / sftp-config.json sweep. Goal is server config + secret disclosure via exposed dev tooling, not file-wordlist credential harvesting. python-requests UA appears alongside browser UAs. Two cross-ASN observations with path-set jaccard ~0.73",
    first_observed: "2026-06-29",
    last_observed: "2026-06-30",
    severity: "high",
    detection: {
      type: "single_ip_high_volume",
      indicators: {
        min_unique_paths: 40,
        path_categories: [
          "phpinfo",
          "owncloud_graphapi_rce",
          "symfony_profiler",
          "yii_debug_panel",
          "config_json_disclosure",
        ],
        signal_patterns: ["python_requests_ua_mixed_with_browser"],
      },
    },
    known_sources: [
      {
        ip: "146.70.168.74",
        asn: 9009,
        org: "M247 Europe SRL",
        date: "2026-06-29",
        path_count: 73,
        notes: "85 reqs / 73 paths, 11 UAs (python-requests mixed with browser UAs)",
      },
      {
        ip: "185.195.232.176",
        asn: 39351,
        org: "31173 Services AB",
        date: "2026-06-30",
        path_count: 43,
        notes: "Cross-ASN twin, path-set jaccard ~0.73 vs 146.70.168.74; adds Symfony parameters.yml tier",
      },
    ],
    signature_paths: [
      "/phpinfo.php",
      "/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php",
      "/debug/default/view?panel=config",
      "/app_dev.php/_profiler/open?file=app/config/parameters.yml",
      "/config.production.json",
      "/.vscode/sftp.json",
      "/parameters.yml",
    ],
  },

  {
    id: "subnet-enterprise-appliance-fingerprint",
    aliases: ["enterprise-cve-version-census", "sistemas-appliance-probe"],
    description:
      "Multi-IP /24 census probing enterprise product login pages and version/marker endpoints to fingerprint deployed appliances for downstream CVE targeting. One canonical ~30-path set spread across adjacent IPs with a shared single UA: OWA, ColdFusion (/cf_scripts/.../ckeditor.js), Telerik (/Telerik.Web.UI.WebResource.axd?type=rau), Sitecore version.xml, Aspera Faspex, Apache Solr, QNAP (/cgi-bin/authLogin.cgi), ManageEngine (/showLogin.cc), SugarCRM (/sugar_version.json). Distinct from multi-extension-discovery-scan (single IP, file-extension enumeration) - this is multi-IP product/version fingerprinting",
    first_observed: "2026-06-29",
    last_observed: "2026-06-30",
    severity: "medium",
    detection: {
      type: "asn_subnet_spray",
      indicators: {
        same_asn_and_subnet: true,
        asn: 211680,
        subnet_mask: 24,
        min_distinct_ips_in_subnet: 3,
        min_unique_paths: 5,
        shared_fingerprint: true,
        path_categories: [
          "enterprise_appliance_login",
          "product_version_markers",
        ],
      },
    },
    known_sources: [
      {
        ip: "45.156.128.0/24",
        asn: 211680,
        org: "Sistemas Informaticos, S.A.",
        date: "2026-06-29..2026-06-30",
        path_count: 37,
        notes: "5 IPs (.172/.173/.174/.175/.129), 44 reqs / 37 paths total, shared Chrome/123 UA",
      },
    ],
    signature_paths: [
      "/Telerik.Web.UI.WebResource.axd?type=rau",
      "/cf_scripts/scripts/ajax/ckeditor/ckeditor.js",
      "/sitecore/shell/sitecore.version.xml",
      "/cgi-bin/authLogin.cgi",
      "/showLogin.cc",
      "/aspera/faspex/",
      "/sugar_version.json",
      "/solr/",
    ],
  },

  {
    id: "env-suffix-variant-sweep",
    aliases: ["dotenv-permutation-scan", "aws-env-suffix-twins"],
    description:
      "Single IP enumerates ~340 .env FILENAME SUFFIX permutations (/.env.local, /.env.production, /.env.remote, /.env.swp, /.env1, /.env2, /.env_copy, /env.example, ...) plus a leading /.git/config, single browser UA, GET+POST. The identical ~341-path wordlist replays from multiple AWS IPs hours apart (cross-IP jaccard 1.0). Distinct from env-subdirectory-spray (route PREFIXES like /admin/.env) and from rotating-ua-env-sweep (adds per-request UA rotation) - this is single-UA SUFFIX permutation. Candidate to fold into env-subdirectory-spray as its suffix tier",
    first_observed: "2026-06-28",
    last_observed: "2026-06-28",
    severity: "high",
    detection: {
      type: "single_ip_high_volume",
      indicators: {
        min_unique_paths: 300,
        time_window_minutes: 2,
        path_categories: ["env_suffix_permutations", "git_directory"],
        cross_ip_path_jaccard: 1.0,
        ua_signals: ["single_browser_ua"],
      },
    },
    known_sources: [
      {
        ip: "15.237.211.108",
        asn: 16509,
        org: "Amazon.com, Inc.",
        date: "2026-06-28",
        path_count: 341,
        notes: "Mac Chrome/131 UA, ~50s burst (345 reqs)",
      },
      {
        ip: "3.111.38.224",
        asn: 16509,
        org: "Amazon.com, Inc.",
        date: "2026-06-28",
        path_count: 341,
        notes: "Linux Chrome/131 UA, identical wordlist (jaccard 1.0), ~10h later",
      },
    ],
    signature_paths: [
      "/.env",
      "/.env.local",
      "/.env.production",
      "/.env.remote",
      "/.env.swp",
      "/.env1",
      "/.env_copy",
      "/.git/config",
    ],
  },

  {
    id: "doh-open-resolver-probe",
    aliases: ["dnsmeasure-doh-scan", "open-dns-resolver-census"],
    description:
      "Coordinated DNS-over-HTTPS open-resolver probe from many IPs in one ASN (Alibaba AS45102). Each hits /dns-query, /query, /resolve, and / with both name= and RFC8484 base64 dns= params resolving 1.odns.m.dnsmeasure.top, Go-http-client/curl UA. Checks whether the host is an open DoH resolver (measurement-style census; dnsmeasure.top is a known measurement domain, so possibly benign research - catalogued so subnet/ASN strategies don't false-positive and a malicious fork can be correlated)",
    first_observed: "2026-06-29",
    last_observed: "2026-07-05",
    severity: "low",
    detection: {
      type: "asn_subnet_spray",
      indicators: {
        single_asn: 45102,
        target_paths: ["/dns-query", "/query", "/resolve"],
        query_marker: "dnsmeasure.top",
        min_distinct_ips_across_asn: 5,
        max_paths_per_ip: 16,
        ua_signals: ["go_http_client_ua", "curl_ua"],
      },
    },
    known_sources: [
      {
        ip: "47.89.154.16",
        asn: 45102,
        org: "Alibaba US Technology Co., Ltd.",
        date: "2026-07-01",
        path_count: 16,
        notes: "13 IPs active across AS45102 this window (53 reqs total, 2026-06-29..07-05)",
      },
    ],
    signature_paths: [
      "/dns-query?name=1.odns.m.dnsmeasure.top&type=A",
      "/query?name=1.odns.m.dnsmeasure.top&type=A",
      "/resolve?name=1.odns.m.dnsmeasure.top&type=A",
    ],
  },
];
