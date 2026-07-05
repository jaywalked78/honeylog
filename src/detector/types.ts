export interface IpLocation {
  asn: number | null;
  org: string | null;
  city: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
}

export interface ForwardingChain {
  chain?: string[];
  cf_connecting_ip?: string | null;
  cf_ip_country?: string | null;
  spoofed?: boolean;
  claimed_ip?: string;
}

export interface ThreatDetail {
  category: string;
  severity: "low" | "medium" | "high";
  description: string;
  [key: string]: unknown;
}

export type IpType =
  | "hosting"
  | "isp"
  | "corporate"
  | "government"
  | "education"
  | "unknown";

export type ThreatLevel = "none" | "low" | "medium" | "high";

export interface HoneyRequest {
  id: bigint;
  ip: string;
  route: string;
  method: string;
  user_agent: string | null;
  created_at: Date;
  ip_location: IpLocation | null;
  ip_type: IpType | null;
  is_tor: boolean;
  forwarding_chain: ForwardingChain | null;
  threat_level: ThreatLevel;
  threat_details: ThreatDetail[];
}

export interface CampaignCandidateFromStrategy {
  strategy_id: string;
  default_campaign_type: string; // catalog id the strategy thinks this campaign should match
  identifier: string;
  confidence: number; // 0..1
  campaign_threat_level: ThreatLevel; // classifyConfidence(confidence) - informational band for dashboards
  evidence: Record<string, unknown>;
  related_strategy_tags: string[]; // for cross-referencing
  time_range: { first: Date; last: Date };
  sample_paths_probed: string[];
  sample_user_agents: string[];
  contributing_ips: string[];
}
