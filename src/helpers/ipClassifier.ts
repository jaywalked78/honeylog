// Two-tier IP classification: exact ASN number match, then org name regex fallback.
// Returns one of: "hosting", "isp", "corporate", "government", "education", "unknown"
// Returns null if geoData is missing or has no ASN.
//
// Maintenance: same workflow as threatDefinitions.ts - add entries directly, push to master.
// Triage query for unknowns:
//   SELECT ip_location->>'asn' AS asn, ip_location->>'org' AS org, COUNT(*) hits
//   FROM tll.logs_requests WHERE ip_type = 'unknown' GROUP BY 1,2 ORDER BY hits DESC;

export type IpClassification =
  | "hosting"
  | "isp"
  | "corporate"
  | "government"
  | "education"
  | "unknown";

export interface GeoData {
  asn: number | null;
  org: string | null;
}

// === ASN REGISTRY ===

const ASN_REGISTRY = new Map<number, IpClassification>([
  // --- Hosting: Major Cloud / CDN ---
  [63949, "hosting"], // Akamai / Linode
  [16509, "hosting"], // Amazon AWS
  [14618, "hosting"], // Amazon AWS (legacy)
  [8075, "hosting"], // Microsoft Azure
  [396982, "hosting"], // Google Cloud
  [15169, "hosting"], // Google
  [19527, "hosting"], // Google
  [36040, "hosting"], // Google
  [14061, "hosting"], // DigitalOcean
  [24940, "hosting"], // Hetzner Online GmbH
  [21499, "hosting"], // Hetzner (legacy)
  [16276, "hosting"], // OVH SAS
  [22616, "hosting"], // OVH US
  [8560, "hosting"], // IONOS SE / 1&1
  [31898, "hosting"], // Oracle Cloud
  [45102, "hosting"], // Alibaba Cloud US
  [37963, "hosting"], // Hangzhou Alibaba Advertising
  [132203, "hosting"], // Tencent Cloud
  [45090, "hosting"], // Shenzhen Tencent Computer Systems
  [12876, "hosting"], // Scaleway S.a.s.
  [51167, "hosting"], // Contabo GmbH
  [141995, "hosting"], // Contabo Asia Private Limited
  [20473, "hosting"], // Vultr / The Constant Company
  [13335, "hosting"], // Cloudflare
  [54113, "hosting"], // Fastly
  [30633, "hosting"], // Edgio / Limelight Networks
  [36351, "hosting"], // SoftLayer / IBM Cloud
  [136907, "hosting"], // Huawei Cloud
  [135377, "hosting"], // UCLOUD Information Technology HK
  [63199, "hosting"], // CDS Global Cloud Co., Ltd

  // --- Hosting: Colocation / Dedicated / VPS ---
  [6939, "hosting"], // Hurricane Electric LLC
  [9009, "hosting"], // M247 Europe SRL
  [51852, "hosting"], // Private Layer INC
  [212238, "hosting"], // Datacamp Limited
  [44477, "hosting"], // Stark Industries Solutions
  [206728, "hosting"], // Media Land LLC
  [49453, "hosting"], // Global Layer
  [8100, "hosting"], // QuadraNet
  [29802, "hosting"], // Hivelocity
  [36352, "hosting"], // HostPapa / ColoCrossing
  [53667, "hosting"], // FranTech Solutions / BuyVM
  [40676, "hosting"], // Psychz Networks
  [55286, "hosting"], // B2 Net Solutions / ServerCheap
  [15003, "hosting"], // Nobis Technology Group
  [46844, "hosting"], // Sharktech
  [19151, "hosting"], // WebNX
  [27357, "hosting"], // Rackspace
  [33070, "hosting"], // Rackspace (legacy)
  [46562, "hosting"], // Total Server Solutions
  [9370, "hosting"], // Sakura Internet
  [138915, "hosting"], // Dedipath
  [26347, "hosting"], // DreamHost
  [198610, "hosting"], // Beget
  [200019, "hosting"], // AlexHost SRL
  [7489, "hosting"], // Hostway
  [32780, "hosting"], // Limestone Networks
  [62282, "hosting"], // ServerMania
  [47846, "hosting"], // Hostkey
  [49544, "hosting"], // i3D.net
  [8972, "hosting"], // PlusServer
  [24961, "hosting"], // myLoc managed IT
  [35540, "hosting"], // ServerHub
  [203020, "hosting"], // HostRoyale Technologies (IN)
  [207990, "hosting"], // HostRoyale Technologies Pvt Ltd
  [34665, "hosting"], // Petersburg Internet Network ltd.
  [44050, "hosting"], // Petersburg Internet Network ltd. (alt ASN)
  [202425, "hosting"], // IP Volume inc
  [202306, "hosting"], // Hostglobal.plus Ltd
  [215925, "hosting"], // Vpsvault.host Ltd
  [211590, "hosting"], // Bucklog SARL
  [208137, "hosting"], // Feo Prest SRL
  [210558, "hosting"], // 1337 Services GmbH
  [60781, "hosting"], // LeaseWeb Netherlands
  [28753, "hosting"], // LeaseWeb Germany
  [59253, "hosting"], // LeaseWeb UK
  [133296, "hosting"], // LeaseWeb APAC
  [395954, "hosting"], // LeaseWeb USA
  [204770, "hosting"], // UAB Cherry Servers
  [49505, "hosting"], // JSC Selectel
  [9123, "hosting"], // JSC Timeweb
  [197695, "hosting"], // Domain names registrar REG.RU, Ltd
  [214996, "hosting"], // netcup GmbH
  [41079, "hosting"], // Cyber_Folks S.A.
  [40476, "hosting"], // Scala Hosting LLC
  [27715, "hosting"], // Locaweb Servicos de Internet SA
  [17378, "hosting"], // TierPoint, LLC
  [11320, "hosting"], // LightEdge Solutions
  [32475, "hosting"], // Internap Holding LLC
  [29066, "hosting"], // velia.net Internetdienste GmbH
  [20860, "hosting"], // Iomart Cloud Services Limited
  [21859, "hosting"], // Zenlayer Inc
  [10439, "hosting"], // CariNet, Inc.
  [50304, "hosting"], // Blix Solutions AS
  [43350, "hosting"], // NForce Entertainment B.V.
  [64286, "hosting"], // LogicWeb Inc.
  [49825, "hosting"], // Lantek LLC
  [200651, "hosting"], // FlokiNET ehf
  [394474, "hosting"], // WhiteLabelColo
  [19084, "hosting"], // ColoUp
  [201814, "hosting"], // MEVSPACE sp. z o.o.
  [396356, "hosting"], // Latitude.sh
  [149440, "hosting"], // Evoxt Sdn. Bhd.
  [63023, "hosting"], // GTHost

  // --- Hosting: Backbone / Transit (commonly used by scanners) ---
  [174, "hosting"], // Cogent Communications, LLC
  [3356, "hosting"], // Level 3 Parent, LLC / Lumen
  [6461, "hosting"], // Zayo Bandwidth

  // --- Hosting: Production traffic (classified from logs) ---
  [211680, "hosting"], // Sistemas Informaticos, S.A.
  [48090, "hosting"], // Techoff Srv Limited
  [211443, "hosting"], // Sino Worldwide Trading Limited
  [213790, "hosting"], // Limited Network LTD
  [51396, "hosting"], // Pfcloud UG
  [8758, "hosting"], // Iway AG
  [50360, "hosting"], // Tamatiya EOOD
  [42624, "hosting"], // Global-Data System IT Corporation
  [210006, "hosting"], // Shereverov Marat Ahmedovich
  [206264, "hosting"], // Amarutu Technology Ltd
  [214940, "hosting"], // Kprohost LLC
  [44559, "hosting"], // It Hostline Ltd
  [200730, "hosting"], // ISAEV Igor
  [9465, "hosting"], // AGOTOZ PTE. LTD.
  [201002, "hosting"], // PebbleHost Ltd
  [209605, "hosting"], // UAB Host Baltic
  [202412, "hosting"], // Omegatech LTD
  [41745, "hosting"], // Baykov Ilya Sergeevich
  [142002, "hosting"], // Scloud Pte Ltd
  [211298, "hosting"], // Driftnet Ltd
  [49870, "hosting"], // Alsycon B.V.
  [328436, "hosting"], // Flashnet-Technologies-Limited
  [62240, "hosting"], // Clouvider Limited
  [200593, "hosting"], // Prospero Ooo
  [12989, "hosting"], // Black HOST Ltd
  [18779, "hosting"], // EGIHosting
  [207043, "hosting"], // Dedik Services Limited
  [3920, "hosting"], // PUSHPKT OU
  [209334, "hosting"], // Modat B.V.
  [27176, "hosting"], // DataWagon LLC
  [133929, "hosting"], // TWOWIN CO., LIMITED
  [198253, "hosting"], // Kukushkin Anatoly Valerievich
  [62874, "hosting"], // Web2Objects LLC
  [211736, "hosting"], // FOP Dmytro Nedilskyi
  [149020, "hosting"], // WebHorizon Internet Services
  [136180, "hosting"], // Beijing Tiantexin Tech. Co., Ltd.
  [211619, "hosting"], // MAXKO d.o.o.
  [204428, "hosting"], // SS-Net
  [50219, "hosting"], // Valence Technology Co.
  [214238, "hosting"], // Host Telecom Ltd
  [397044, "hosting"], // My Tec Sa
  [136258, "hosting"], // BrainStorm Network, Inc
  [209847, "hosting"], // WorkTitans B.V.
  [131353, "hosting"], // NhanHoa Software company
  [38700, "hosting"], // SMILESERV
  [131471, "hosting"], // Login.Me Pvt Ltd
  [210457, "hosting"], // Kyonix Networks Limited
  [152194, "hosting"], // CTG Server Limited
  [141039, "hosting"], // PacketHub S.A.
  [139366, "hosting"], // PT Higo Fitur Indonesia

  [36926, "hosting"], // CKL1-ASN

  // --- Hosting: Scanning / Research / Security ---
  [398324, "hosting"], // Censys, Inc.
  [398705, "hosting"], // Censys, Inc.
  [398722, "hosting"], // Censys, Inc.
  [213412, "hosting"], // ONYPHE SAS
  [215778, "hosting"], // Alpha Strike Labs GmbH
  [263444, "hosting"], // Servers.com

  // --- ISP: Consumer / Residential / Telecom ---
  [20115, "isp"], // Charter Communications LLC
  [10796, "isp"], // Charter / Spectrum
  [11427, "isp"], // TWC / Spectrum
  [12271, "isp"], // Charter Communications
  [33588, "isp"], // Charter (legacy)
  [7843, "isp"], // Bright House / Charter
  [7922, "isp"], // Comcast Cable Communications, LLC
  [22909, "isp"], // Comcast Business
  [11351, "isp"], // Road Runner / Spectrum
  [7018, "isp"], // AT&T
  [6389, "isp"], // BellSouth / AT&T
  [701, "isp"], // Verizon
  [19262, "isp"], // Verizon Online
  [6167, "isp"], // Verizon Business
  [5650, "isp"], // Frontier Communications
  [6128, "isp"], // Cablevision / Altice
  [6327, "isp"], // Shaw Communications
  [812, "isp"], // Rogers
  [577, "isp"], // Bell Canada
  [5769, "isp"], // Videotron
  [3320, "isp"], // Deutsche Telekom
  [6830, "isp"], // Liberty Global / UPC
  [12322, "isp"], // Iliad / Free SAS
  [15557, "isp"], // SFR
  [5410, "isp"], // Bouygues Telecom
  [3215, "isp"], // Orange France
  [2856, "isp"], // BT / British Telecom
  [5607, "isp"], // Sky UK
  [13184, "isp"], // Mobile TeleSystems (MTS)
  [8359, "isp"], // MTS (legacy)
  [12389, "isp"], // Rostelecom
  [25513, "isp"], // Rostelecom (legacy)
  [45820, "isp"], // Tata Teleservices ISP AS
  [9808, "isp"], // China Mobile Communications Group
  [4134, "isp"], // Chinanet / China Telecom
  [4837, "isp"], // China Unicom China169 Backbone
  [4808, "isp"], // China Unicom Beijing Province Network
  [134810, "isp"], // China Mobile Group Jilin
  [141739, "isp"], // China Telecom
  [9318, "isp"], // SK Broadband Co Ltd
  [4766, "isp"], // KT / Korea Telecom
  [17676, "isp"], // SoftBank Japan
  [2497, "isp"], // IIJ
  [4713, "isp"], // NTT
  [3462, "isp"], // HiNet / Chunghwa Telecom
  [9269, "isp"], // HKT / PCCW
  [7545, "isp"], // TPG Telecom
  [1221, "isp"], // Telstra
  [22884, "isp"], // Total Play Telecomunicaciones SA DE CV
  [34984, "isp"], // Superonline Iletisim Hizmetleri A.S.
  [18881, "isp"], // Telefonica Brasil S.A.
  [6147, "isp"], // Telefonica del Peru
  [8151, "isp"], // UNINET / Telmex
  [8048, "isp"], // CANTV Venezuela
  [24757, "isp"], // Ethiopian Telecommunication Corporation
  [6697, "isp"], // Beltelecom
  [7602, "isp"], // Sai Gon Postel Corporation
  [12400, "isp"], // Partner Communications Ltd. (Israel)
  [61826, "isp"], // Nethouse Telecom
  [27947, "isp"], // Telconet S.A
  [137963, "isp"], // MT Microtel Technology Sdn Bhd
  [135763, "isp"], // Gayatri Communications
  [137654, "isp"], // Netstra Communications Pvt Ltd
  [58715, "isp"], // Earth Telecommunication Pvt Ltd
  [264393, "isp"], // NetBrasil Telecom LTDA
  [263289, "isp"], // Palmasnet Informatica LTDA
  [265210, "isp"], // OSCAR M DE CARVALHO - ME
  [263740, "isp"], // Corporacion Laceibanetsociety
  [264567, "isp"], // Jose das Gracas Soares de Lima EIRELI
  [38235, "isp"], // Angkor Data Communication

  // --- Education ---
  [12816, "education"], // Leibniz-Rechenzentrum (LRZ)
  [17716, "education"], // National Taiwan University
  [11442, "education"], // North Carolina State University

  // --- Government ---
  [138050, "government"], // Dinas Komunikasi Provins Jawa Barat
]);

interface OrgPattern {
  pattern: RegExp;
  type: IpClassification;
}

const ORG_PATTERNS: OrgPattern[] = [
  // Hosting - infrastructure keywords
  {
    pattern:
      /\bhost(ing)?\b|cloud|server|vps|data\s*cent(er|re)|colocation|\bcolo\b|dedicated/i,
    type: "hosting",
  },
  { pattern: /\bcdn\b|\bproxy\b|\bvpn\b/i, type: "hosting" },
  // Education - before ISP to catch "university telecom" correctly
  {
    pattern:
      /university|universit[eä]|college|akadem|school|institu(te|t\b)|polytechnic|\bedu\b/i,
    type: "education",
  },
  { pattern: /rechenzentrum/i, type: "education" },
  // Government
  {
    pattern: /government|department\s+of|ministry|federal|municipal|\bdinas\b/i,
    type: "government",
  },
  { pattern: /military|armed\s+forces|defen[cs]e/i, type: "government" },
  // ISP - telecom carriers
  {
    pattern: /telecom|broadband|cable|wireless|mobile|fiber|celular/i,
    type: "isp",
  },
  {
    pattern: /communications?\s+(corp|co\.?|ltd|llc|inc|group|plc)\b/i,
    type: "isp",
  },
];

// Classify an IP from its ASN/org data. Exact ASN match first, then org-name
// regex fallback. Returns "unknown" if nothing matches, or null if there's no
// ASN at all to work with.

export function classifyIp(
  geoData: GeoData | null | undefined,
): IpClassification | null {
  if (!geoData || !geoData.asn) return null;

  const asnType = ASN_REGISTRY.get(geoData.asn);
  if (asnType) return asnType;

  if (geoData.org) {
    for (const { pattern, type } of ORG_PATTERNS) {
      if (pattern.test(geoData.org)) return type;
    }
  }

  return "unknown";
}

// === TOR EXIT NODES ===

const torExitNodes = new Set<string>();

export async function fetchTorExitNodes(): Promise<void> {
  try {
    const response = await fetch(
      "https://check.torproject.org/torbulkexitlist",
    );
    if (!response.ok) {
      console.error(`[ipClassifier] Tor fetch failed: HTTP ${response.status}`);
      return;
    }
    const text = await response.text();
    torExitNodes.clear();
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (trimmed) torExitNodes.add(trimmed);
    }
    console.log(`[ipClassifier] Tor exit nodes loaded: ${torExitNodes.size}`);
  } catch (error) {
    console.error("[ipClassifier] Tor fetch error:", error);
  }
}

export function startTorRefreshInterval(): NodeJS.Timeout {
  return setInterval(fetchTorExitNodes, 1000 * 60 * 60 * 12);
}

export function isTorExitNode(ip: string | null | undefined): boolean {
  if (!ip) return false;
  return torExitNodes.has(ip.trim());
}
