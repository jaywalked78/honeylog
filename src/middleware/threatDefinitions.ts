/**
 * Threat Definitions - centralized pattern registry for the honey middleware
 *
 * All detection patterns live here. When new attack vectors are discovered
 * in production logs, add them to the appropriate category below.
 *
 * Categories:
 *   BOT_PATTERNS  - user agent strings that identify scanners/bots
 *   PATH_THREATS   - URL paths that indicate probing
 *   METHOD_THREATS - HTTP methods used for scanning
 *   BODY_THREATS   - request body patterns for injection/malware
 */

export type Severity = "low" | "medium" | "high";

export interface PathThreat {
  pattern: RegExp;
  severity: Severity;
  description: string;
}

export interface MethodThreat {
  method: string;
  severity: Severity;
  description: string;
}

export interface BodyThreat {
  pattern: RegExp;
  severity: Severity;
  description: string;
}

export const BOT_PATTERNS: RegExp[] = [
  // Generic bot/crawler identifiers
  /bot\b/i,
  /crawl/i,
  /spider/i,
  /slurp/i,
  /scraper/i,
  // HTTP client libraries (not browsers)
  /wget/i,
  /python-requests/i,
  /httpx/i,
  /axios/i,
  /node-fetch/i,
  /go-http-client/i,
  /java\//i,
  /libwww/i,
  /http\.rb/i,
  /fasthttp/i,
  // Security scanners
  /masscan/i,
  /nmap/i,
  /nikto/i,
  /sqlmap/i,
  /dirbuster/i,
  /gobuster/i,
  /nuclei/i,
  /zgrab/i,
  // Research/intelligence platforms
  /censys/i,
  /shodan/i,
  /internetmeasurement/i,
  /palo[\s-]?alto/i,
  /cortex/i,
  // Discovered from production traffic
  /silver\.inc/i,
  /visionheight/i,
  /^-$/,
  /nvdorz/i,
  /CMS-Checker/i,
  /PAN GlobalProtect/i,
  /curl\//i,
  /fasthttp/i,
  /^python-urllib/i,
  /^Mozilla\/5\.0$/,
  /aiohttp/i,
  /zern\.io/i,
  /AnyConnect/i,
  /Scrapy/i,
  /Odin/i,
  /HeadlessChrome/i,
  /Crusader\//i,
  /Laravel\s*Reaver/i,
  /internal-scan/i,
  // Research/scanning platforms (from production traffic)
  /ipip\.net/i,
  /l9(explore|tcpid)/i,
  /onlyscans\.com/i,
  /BitSightBot/i,
  /xmco\.fr/i,
  /ModatScanner/i,
  /RecordedFuture/i,
  /moltbot/i,
  /SecurityScanner\b/i,
  /recon-engine/i,
  /GPTBot/i,
  /Project-Resonance/i,
  /Infrawatch/i,
  // Malformed UAs - real browsers don't truncate mid-token or send minimal "(compatible)"
  /\(KHTML$/,
  /^Mozilla\/5\.0 \(compatible\)$/,
  /AppleWebKit\/537\.36$/,
  // MCP endpoint scanner
  /gitmc-org-mcp-scanner/i,
  // Ancient/impossible UAs - scanner spoofing as decade-old browsers/OSes
  /Windows NT 5\.[012]/,
  /PPC Mac OS X/,
  /Gecko\/200[0-5]/,
  /Android [1-4]\./,
  // Generic scanner/probe identifiers
  /scanner/i,
  /probe/i,
  /check/i,
  /monitor/i,
  /survey/i,
  // More signatures from production traffic
  /CVE-\d{4}-\d+/i, // literal CVE id in UA (Cisco IOS XE implant scanners)
  /libredtail/i, // libredtail-http exploit toolkit
  /^okhttp\//i, // Java/Android HTTP client used by scanners
  /Openwave|UCWEB/i, // ancient feature-phone UA - scanner spoof
];

export const PATH_THREATS: PathThreat[] = [
  // HIGH - env files (any variant: .env, .env.local, .env.production, .envrc, .flaskenv, sendgrid.env, etc.)
  {
    pattern: /\.env(\b|_)/i,
    severity: "high",
    description: "config file probe",
  },
  {
    pattern: /\/\.flaskenv/i,
    severity: "high",
    description: "config file probe",
  },
  { pattern: /\/\.envrc/i, severity: "high", description: "config file probe" },
  {
    pattern: /\/env\.(json|js|txt|ya?ml)\b/i,
    severity: "high",
    description: "config file probe",
  },
  // HIGH - framework config files (DB creds, API keys, connection strings)
  {
    pattern: /\/(application|bootstrap)\.(yml|yaml|properties)\b/i,
    severity: "high",
    description: "Spring Boot config probe",
  },
  {
    pattern: /\/appsettings(\.\w+)?\.json\b/i,
    severity: "high",
    description: ".NET config file probe",
  },
  {
    pattern: /\/hibernate\.cfg\.xml\b/i,
    severity: "high",
    description: "Java ORM config probe",
  },
  {
    pattern: /\/(database|config)\.(js|ts)\b/i,
    severity: "high",
    description: "Node.js config file probe",
  },
  // HIGH - Java heap dump (full memory disclosure, often probed with URL-encoded path)
  {
    pattern: /\/heapdump\b/i,
    severity: "high",
    description: "Java heap dump probe",
  },
  // HIGH - git exposure (any .git path, incl. .gitconfig/.gitignore/.gitattributes
  // which have no word boundary after "git" so the bare /\.git\b rule missed them)
  {
    pattern: /\/\.git(config|attributes|ignore|modules|keep)?\b/i,
    severity: "high",
    description: "git exposure probe",
  },
  // HIGH - VCS exposure (Mercurial, SVN - same class as .git)
  {
    pattern: /\/(\.svn|\.hg)\b/i,
    severity: "high",
    description: "VCS exposure probe",
  },
  // HIGH - URL-encoded dot bypass (scanners use %2e instead of . to evade dotfile rules)
  {
    pattern: /%2e(env|git|svn|hg|aws|htaccess|htpasswd|npmrc|dockerenv|ssh|kube|docker|vscode|cursor|aider)\b/i,
    severity: "high",
    description: "dotfile probe (encoded dot bypass)",
  },
  // HIGH - URL-encoded extension bypass (scanners encode the dot before file extensions to evade rules)
  {
    pattern:
      /%2e(sql|bak|backup|old|sav|swp|swo|orig|dump|conf|cnf|cfg|ini|ya?ml|json|toml|tar|zip|gz|tgz|rar|7z|key|pem|crt|p12|pfx|env|properties|tfvars|tfstate)\b/i,
    severity: "high",
    description: "config/backup file probe (encoded extension bypass)",
  },
  // HIGH - double-URL-encoded path traversal (%252e = encoded %2e = encoded '.') - layered encoding to evade ../ filters
  // Sample: /%252e%252e/
  {
    pattern: /%252e/i,
    severity: "high",
    description: "double-encoded path traversal",
  },
  // HIGH - Cisco IOS privilege-15 EXEC RCE (libwww-perl scanners hit /level/15/exec/-/sh/run/CR for running-config disclosure)
  {
    pattern: /\/level\/\d+\/exec\b/i,
    severity: "high",
    description: "Cisco IOS privileged EXEC RCE probe",
  },
  // HIGH - /etc/* config file LFI in URL path (VPN/tunnel/mail server credentials)
  {
    pattern:
      /^\/etc\/(exim4|mail|postfix|ssmtp|openvpn|wireguard|ipsec|nebula|cloudflared|headscale|netbird|twingate|strongswan|squid|haproxy|nginx|apache2|httpd)\b/i,
    severity: "high",
    description: "/etc service config LFI probe",
  },
  // HIGH - Docker CLI config directory (.docker/config.json contains registry credentials + auth tokens)
  {
    pattern: /\/\.docker\/(config|daemon)\b/i,
    severity: "high",
    description: "Docker CLI config probe (registry credentials)",
  },
  // HIGH - Magento app/etc directory (env.php holds encryption key, DB creds, admin paths)
  {
    pattern: /\/app\/etc\/(env|local|config)\.(php|xml|ya?ml)\b/i,
    severity: "high",
    description: "Magento app/etc config probe",
  },
  // HIGH - Bitrix CMS admin/backup paths (DB connection in bitrix/php_interface/dbconn.php, full backup restore via bitrix/restore.php)
  {
    pattern: /\/bitrix\/(admin|backup|restore\.php|php_interface\/dbconn|\.settings)/i,
    severity: "high",
    description: "Bitrix CMS admin/credential probe",
  },
  // HIGH - cloud instance metadata SSRF (AWS IMDSv1, GCP metadata server)
  {
    pattern: /\/(latest|computeMetadata)\/(meta-data|user-data|v1)/i,
    severity: "high",
    description: "cloud instance metadata SSRF",
  },
  {
    pattern: /169\.254\.169\.254/i,
    severity: "high",
    description: "cloud metadata SSRF (link-local IP)",
  },
  // HIGH - shell history/config (reveals commands, credentials, paths)
  {
    pattern:
      /\.(bash_history|zsh_history|sh_history|bash_profile|bashrc|zshrc)\b/i,
    severity: "high",
    description: "shell history/config probe",
  },
  // HIGH - other secrets/config
  {
    pattern: /\.(htaccess|htpasswd|npmrc|dockerenv)(?:\?|$)/i,
    severity: "high",
    description: "config file probe",
  },
  {
    pattern: /\.(sql|db|sqlite|bak|backup|dump|old|orig|save|swp)(?:\?|$)/i,
    severity: "high",
    description: "database/backup file probe",
  },
  {
    pattern: /\.(php|conf|cfg|ini|yml|json|xml|env)~(?:\?|$)/i,
    severity: "high",
    description: "editor backup file probe (tilde)",
  },
  // HIGH - WordPress (wp-config contains DB creds, wp-content/wp-includes expose internals)
  {
    pattern: /wp-(login|admin|config|content|includes)|xmlrpc\.php/i,
    severity: "high",
    description: "WordPress probe",
  },
  // HIGH - PHP
  {
    pattern: /phpmyadmin|adminer|phpinfo|phpversion|info\.php/i,
    severity: "high",
    description: "PHP admin probe",
  },
  // HIGH - admin panels
  {
    pattern: /\/admin\b|\/manager\b|\/console\b/i,
    severity: "high",
    description: "admin panel probe",
  },
  // HIGH - Adobe ColdFusion CFIDE admin (CFIDE/administrator and componentutils have known auth bypass + RCE history)
  {
    pattern: /\/CFIDE\b/i,
    severity: "high",
    description: "Adobe ColdFusion CFIDE admin probe",
  },
  // HIGH - IoT/device exploits
  {
    pattern: /\/SDK\/webLanguage/i,
    severity: "high",
    description: "Hikvision camera CVE probe",
  },
  {
    pattern: /\/update\/picture\.cgi/i,
    severity: "high",
    description: "IP camera CGI exploit",
  },
  // HIGH - GPON router web shell backdoor (CVE-2018-10561 / CVE-2018-10562 RCE)
  {
    pattern: /\/web_shell_cmd\.gch\b/i,
    severity: "high",
    description: "GPON router RCE probe (CVE-2018-10561)",
  },
  // HIGH - ONVIF camera service (IP camera enumeration + auth bypass)
  {
    pattern: /\/(ONVIF|onvif)\/(device_service|media\.cgi|media|Media|Events)/i,
    severity: "high",
    description: "ONVIF IP camera probe",
  },
  // HIGH - Redfish API (server hardware management - iLO/iDRAC/IPMI bare-metal access)
  {
    pattern: /\/redfish\/v\d+(\/|\b)/i,
    severity: "high",
    description: "Redfish server management API probe",
  },
  // HIGH - Python virtualenv directory (leaks installed packages, site-packages, sometimes secrets)
  {
    pattern: /\/\.venv(\/|\b)/i,
    severity: "high",
    description: "Python virtualenv directory probe",
  },
  // HIGH - AI tool config exposure
  {
    pattern:
      /\.(cline|continue|openclaw)\/|open-interpreter\/|\.aider|litellm\//i,
    severity: "high",
    description: "AI tool config probe",
  },
  // HIGH - Streamlit secrets (credential file, same class as .env)
  {
    pattern: /\.streamlit\/secrets/i,
    severity: "high",
    description: "Streamlit secrets probe",
  },
  // HIGH - AI/ML credential files
  {
    pattern: /huggingface\/token\b/i,
    severity: "high",
    description: "HuggingFace API token probe",
  },
  // HIGH - secrets files (Python, JSON, YAML, TOML)
  {
    pattern: /\/secrets\.(py|json|ya?ml|toml|env)\b/i,
    severity: "high",
    description: "secrets file probe",
  },
  // HIGH - Django/Python settings (SECRET_KEY, DB credentials, API keys) - covers settings.py, local_settings.py, prod_settings.py, etc.
  {
    pattern: /\/[\w]*settings\.py\b/i,
    severity: "high",
    description: "Django/Python settings probe",
  },
  // HIGH - Telerik UI deserialization RCE (CVE-2017-9248, CVE-2019-18935)
  {
    pattern: /Telerik\.Web\.UI/i,
    severity: "high",
    description: "Telerik UI exploit probe",
  },
  // HIGH - ASP.NET/IIS config (can leak connection strings, API keys)
  {
    pattern: /\/web\.config\b/i,
    severity: "high",
    description: "ASP.NET config file probe",
  },
  // HIGH - IBM Aspera Faspex RCE (CVE-2022-47986)
  {
    pattern: /\/aspera\/faspex/i,
    severity: "high",
    description: "IBM Aspera Faspex RCE probe",
  },
  // HIGH - IDE config exposure (sftp.json contains server credentials)
  {
    pattern: /\/\.vscode\//i,
    severity: "high",
    description: "VS Code config probe",
  },
  // HIGH - SSH key/config exposure (private keys, authorized_keys, config)
  {
    pattern: /\/\.ssh\//i,
    severity: "high",
    description: "SSH key/config exposure probe",
  },
  // HIGH - SSH/SSL private keys at common drop locations (id_rsa.pem, server.key, putty.ppk, etc.)
  {
    pattern:
      /\/(id_(rsa|dsa|ed25519|ecdsa)(\.pem|\.pub)?|server\.key|server\.crt|cert\.pem|key\.pem|self\.key|private\.(key|pem)|privatekey\.key|[\w.-]+\.ppk)\b/i,
    severity: "high",
    description: "SSH/SSL private key file probe",
  },
  // HIGH - PuTTY config directory (.ppk private keys)
  {
    pattern: /\/\.putty\//i,
    severity: "high",
    description: "PuTTY private key directory probe",
  },
  // HIGH - Terraform state/config (leaks cloud credentials, DB passwords)
  {
    pattern: /terraform\.(tfstate|tfvars)|\/\.terraform\b/i,
    severity: "high",
    description: "Terraform state/config probe",
  },
  // HIGH - AI service credential files
  {
    pattern: /\/openai\.json\b/i,
    severity: "high",
    description: "OpenAI API credential probe",
  },
  // HIGH - framework secret extraction (JeecgBoot, RuoYi - /common-api/system/getSecret)
  {
    pattern: /\/getSecret\b/i,
    severity: "high",
    description: "API secret extraction probe",
  },
  // HIGH - cloud provider credential files
  {
    pattern: /\.aws\/(credentials|config)/i,
    severity: "high",
    description: "AWS credentials file probe",
  },
  // HIGH - PostgreSQL/network/AWS Boto credential files
  {
    pattern: /\/\.pgpass\b/i,
    severity: "high",
    description: "PostgreSQL password file probe",
  },
  {
    pattern: /\/\.netrc\b/i,
    severity: "high",
    description: "network credentials (.netrc) probe",
  },
  {
    pattern: /\/\.boto\d?\b/i,
    severity: "high",
    description: "AWS Boto credential probe",
  },
  // HIGH - Cursor IDE config exposure
  {
    pattern: /\/\.cursor\//i,
    severity: "high",
    description: "Cursor IDE config probe",
  },
  // HIGH - WordPress oembed SSRF (CVE-2017-9064 family)
  {
    pattern: /\/wp-json\/oembed\/[\d.]+\/proxy/i,
    severity: "high",
    description: "WordPress oembed SSRF probe",
  },
  // HIGH - UEditor RCE/SSRF (action=catchimage with source[] array)
  {
    pattern: /\/ueditor\/(php|jsp|net|asp)\/controller\.(php|jsp|ashx|asp)/i,
    severity: "high",
    description: "UEditor file upload RCE/SSRF probe",
  },
  // HIGH - generic PHP shell drop names (i.php, pi.php, php.php commonly hold uploaded shells)
  {
    pattern: /\/(i|pi|php|p)\.php\b/i,
    severity: "high",
    description: "PHP shell drop probe",
  },
  // HIGH - Spring Cloud Gateway RCE (CVE-2022-22947) - actuator endpoint allows SpEL injection via route definitions
  {
    pattern: /\/actuator\/gateway\/(routes|refresh)/i,
    severity: "high",
    description: "Spring Cloud Gateway RCE probe (CVE-2022-22947)",
  },
  // HIGH - AI service config files (Python module + JSON/YAML variants)
  {
    pattern:
      /\/(ai|openai|anthropic|claude|cohere|mistral|gemini|together|groq)[_-]?config\.(py|json|ya?ml|env)\b/i,
    severity: "high",
    description: "AI service config file probe",
  },
  {
    pattern:
      /\/\.(openai|anthropic|claude|cohere|gemini|mistral|groq|together|lobechat|ollama|chatgpt)\//i,
    severity: "high",
    description: "AI service credential directory probe",
  },
  // HIGH - generic PHP config files (DB credentials, framework configs)
  // env-suffixed variants too: config.dev.php, database.local.php, settings.prod.php
  {
    pattern: /\/(config|settings|database|db|configuration)(\.[\w-]+)?\.php\b/i,
    severity: "high",
    description: "generic PHP config file probe",
  },
  // HIGH - Composer auth.json (contains GitHub tokens, private repo credentials)
  {
    pattern: /\/auth\.json\b/i,
    severity: "high",
    description: "Composer auth.json probe (GitHub tokens)",
  },
  // HIGH - Webmin password_change.cgi RCE (CVE-2019-15107)
  {
    pattern: /\/password_change\.cgi\b/i,
    severity: "high",
    description: "Webmin password_change RCE probe (CVE-2019-15107)",
  },
  // HIGH - PHP-CGI argument injection (CVE-2024-4577) - %AD soft-hyphen bypass to set dangerous PHP options
  {
    pattern: /\/php-cgi\/php-cgi\.exe\b/i,
    severity: "high",
    description: "PHP-CGI argument injection probe (CVE-2024-4577)",
  },
  // HIGH - GCP service account key (contains private keys for GCP API access)
  {
    pattern: /\/(serviceAccountKey|(firebase-|google-)?service-account(-key)?|firebase-adminsdk)\.json\b/i,
    severity: "high",
    description: "GCP/Firebase service account key probe",
  },
  // HIGH - Google API private key (Pimcore-style buried path)
  {
    pattern: /\/google-api-private-key\.json\b/i,
    severity: "high",
    description: "Google API private key probe",
  },
  // HIGH - cloud CLI credential directories (Azure, Heroku, Fly, Cargo, Gem, OCI, Pulumi, Linode, OVH, Maven)
  {
    pattern:
      /\/\.(azure|heroku|fly|cargo|gem|oci|pulumi|s3cfg|passwd-s3fs|linode-cli|ovh\.conf|m2\/settings|terraformrc|terraform\.d)\b/i,
    severity: "high",
    description: "cloud CLI credential file probe",
  },
  // HIGH - cloud CLI config directories (gcloud, doctl, scaleway, civo, exoscale, hcloud, openstack)
  {
    pattern:
      /\/\.config\/(gcloud|doctl|scw|civo|exoscale|hcloud|openstack|fly)\//i,
    severity: "high",
    description: "cloud CLI config directory probe",
  },
  // HIGH - AWS access key CSV exports (rootkey.csv, accessKeys.csv, new_user_credentials.csv)
  {
    pattern: /\/(accessKeys|rootkey|new_user_credentials|credentials)\.csv\b/i,
    severity: "high",
    description: "AWS access keys CSV probe",
  },
  // HIGH - Rails secrets/credentials (secret_token.rb is session signing key, credentials.yml.enc + master.key = full decryption)
  {
    pattern:
      /\/(secret_token\.rb|database\.yml|credentials\.yml\.enc|master\.key)\b/i,
    severity: "high",
    description: "Rails credential/config probe",
  },
  // HIGH - Kubernetes admin config (.kube/config = full cluster admin)
  {
    pattern: /\/\.kube\/(config|cache)|\/kubeconfig\b/i,
    severity: "high",
    description: "Kubernetes admin config probe",
  },
  // HIGH - MCP config (Model Context Protocol - holds API keys for AI services)
  {
    pattern: /\/\.mcp\.json\b/i,
    severity: "high",
    description: "MCP config probe (AI service keys)",
  },
  // HIGH - PHP-FPM .user.ini (per-directory PHP config injection - can enable auto_prepend_file RCE)
  {
    pattern: /\/\.?user\.ini\b/i,
    severity: "high",
    description: "PHP .user.ini config injection probe",
  },
  // HIGH - Serverless Framework config (AWS creds, API keys, infrastructure config)
  {
    pattern: /\/serverless\.ya?ml\b/i,
    severity: "high",
    description: "Serverless Framework config probe",
  },
  // HIGH - Docker Compose (can contain DB passwords, API keys in environment sections)
  {
    pattern: /docker-compose[^/]*\.ya?ml/i,
    severity: "high",
    description: "Docker Compose config probe",
  },
  // HIGH - Symfony credentials (parameters.yml contains DB passwords, API keys, SMTP creds)
  {
    pattern: /\/parameters\.yml/i,
    severity: "high",
    description: "Symfony credentials file probe",
  },
  // HIGH - cloud/API credential files
  {
    pattern: /credentials\.json\b/i,
    severity: "high",
    description: "credentials file probe",
  },
  // HIGH - service/API credential files (SMTP, SendGrid, Twilio, MongoDB GUI, AWS key files)
  {
    pattern:
      /\/(smtp|sendgrid|twilio|mailgun|robomongo|aws)\.(json|env|ya?ml)\b/i,
    severity: "high",
    description: "service credential file probe",
  },
  {
    pattern: /\/(api[_-]?keys?|client[_-]?secrets?)\.(json|env|txt|ya?ml)\b/i,
    severity: "high",
    description: "API key/secret file probe",
  },
  // HIGH - Docker Engine API (unauthenticated container listing/exec)
  {
    pattern: /\/containers\/json|\/v[\d.]+\/(containers|images|volumes)\b/i,
    severity: "high",
    description: "Docker API exposure probe",
  },
  // HIGH - Kubernetes API (cluster compromise if exposed)
  {
    pattern: /\/namespaces\/\w+\/(deployments|pods|secrets|configmaps)\b/i,
    severity: "high",
    description: "Kubernetes API probe",
  },
  // HIGH - LFI via /static/ prefix path normalization bypass (etc/passwd, proc/self/environ, ~/.ssh, K8s tokens, var/log)
  {
    pattern:
      /\/static\/+(\.{2,}|%2[Ee]|%2[Ff]|\.%2[Ee])*\/?(etc|proc|root|home|var|run|app|sys|tmp)\b/i,
    severity: "high",
    description: "LFI path traversal via /static/ prefix",
  },
  // HIGH - Docker registry catalog enumeration (lists all hosted images, often unauthenticated)
  {
    pattern: /\/v2\/_catalog/i,
    severity: "high",
    description: "Docker registry catalog enumeration",
  },
  // HIGH - Jolokia JMX (CVE-2018-1000130 RCE via MBean invocation)
  {
    pattern: /\/jolokia(\b|\/)/i,
    severity: "high",
    description: "Jolokia JMX RCE probe",
  },
  // HIGH - WS_FTP server log/config probe (CVE-2023-40044 RCE via .NET deserialization)
  {
    pattern: /\/WS_FTP\.(LOG|ini)\b/i,
    severity: "high",
    description: "WS_FTP RCE probe (CVE-2023-40044)",
  },
  // HIGH - dompdf setup script (precursor to dompdf LFI/RCE via php:// input_file)
  {
    pattern:
      /\/dompdf\/.*setup\.php|\/(www|libraries\/dompdf|dompdf)\/setup\.php/i,
    severity: "high",
    description: "dompdf RCE/LFI probe",
  },
  // HIGH - FileZilla saved credentials (FTP server passwords in plaintext XML)
  {
    pattern: /\/(filezilla|sitemanager|recentservers)\.xml\b/i,
    severity: "high",
    description: "FileZilla saved credentials probe",
  },
  // HIGH - Oracle SQL*Net log (leaks DB connection strings, host/SID, error traces)
  {
    pattern: /\/sqlnet\.log\b/i,
    severity: "high",
    description: "Oracle SQL*Net log probe",
  },
  // HIGH - Apache OFBiz XML-RPC endpoint (CVE-2023-49070 / CVE-2023-51467 auth bypass + RCE)
  {
    pattern: /\/webtools\/control\/(xmlrpc|main|ProgramExport)/i,
    severity: "high",
    description: "Apache OFBiz RCE probe (CVE-2023-49070)",
  },
  // HIGH - framework session storage directory (listing = session hijack material)
  {
    pattern:
      /\/(storage\/(framework\/)?sessions|files\/_sessions|_sessions)\/?$/i,
    severity: "high",
    description: "session storage directory probe",
  },
  // HIGH - server log file disclosure (error_log, access.log, laravel.log, system.log)
  {
    pattern:
      /\/(error_log|access\.log|error\.log|laravel\.log|debug\.log|system\.log)\b/i,
    severity: "high",
    description: "server log file probe",
  },
  // HIGH - ASP.NET Trace handler (leaks session cookies, request headers, view state)
  {
    pattern: /\/Trace\.axd\b/i,
    severity: "high",
    description: "ASP.NET Trace handler probe",
  },
  // HIGH - Spring Boot Actuator sensitive endpoints (heapdump leaks JVM memory incl. secrets; env leaks env vars)
  {
    pattern:
      /\/actuator\/(heapdump|env|configprops|threaddump|httptrace|sessions|loggers|auditevents|mappings|beans|scheduledtasks)\b/i,
    severity: "high",
    description: "Spring Boot Actuator sensitive endpoint probe",
  },
  // HIGH - SQL backup files (backup.sql, db.sql.gz, www.sql, etc.)
  {
    pattern:
      /\/(backup|database|db|dump|www|site|prod|production)\.sql(\.(gz|bz2|lz|rar|tar(\.(gz|z|bz2))?|xz|zip|z))?\b/i,
    severity: "high",
    description: "SQL backup file probe",
  },
  // HIGH - PHP config file (exposes error display settings, session paths, DB config)
  {
    pattern: /\/php\.ini\b/i,
    severity: "high",
    description: "PHP config file probe",
  },
  // MEDIUM - infrastructure probing
  {
    pattern: /autodiscover\.json[^"]*powershell/i,
    severity: "high",
    description: "Exchange ProxyShell exploit (CVE-2021-34473)",
  },
  {
    pattern: /actuator|autodiscover|\.well-known\/security/i,
    severity: "medium",
    description: "infrastructure probe",
  },
  {
    pattern: /cgi-bin|server-status|server-info/i,
    severity: "medium",
    description: "server info probe",
  },
  {
    pattern: /\/remote\/login|\/vpn|\/sslvpn/i,
    severity: "medium",
    description: "VPN/remote access probe",
  },
  {
    pattern: /global-protect|ssl-vpn\/(prelogin|login\.esp)|\/sonicos\/|\/sonicui\//i,
    severity: "medium",
    description: "Palo Alto/SonicWall VPN probe",
  },
  {
    pattern: /\/dana-na\/|\/dana-cached\//i,
    severity: "medium",
    description: "Juniper/Pulse Secure VPN probe",
  },
  {
    pattern: /\/dns-query|\/resolve\?|\/query\?(?:dns|name)=/i,
    severity: "medium",
    description: "DNS-over-HTTPS resolver probe",
  },
  // MEDIUM - router/device admin protocols
  {
    pattern: /\/HNAP1\b/i,
    severity: "medium",
    description: "D-Link HNAP router probe",
  },
  {
    pattern: /\/developmentserver\/metadatauploader/i,
    severity: "high",
    description: "SAP NetWeaver RECON probe (CVE-2020-6287)",
  },
  {
    pattern: /\/_ignition\/execute-solution/i,
    severity: "high",
    description: "Laravel Ignition RCE (CVE-2021-3129)",
  },
  {
    pattern: /\/ecp\/Current\/exporttool\/microsoft\.exchange\.ediscovery/i,
    severity: "high",
    description: "Exchange ProxyLogon probe (CVE-2021-26855)",
  },
  {
    pattern: /webui|geoserver|developmentserver|\/webclient\//i,
    severity: "medium",
    description: "web management probe",
  },
  {
    pattern: /\/ReportServer/i,
    severity: "medium",
    description: "SQL Server Reporting Services probe",
  },
  {
    pattern: /\/enhancecp/i,
    severity: "medium",
    description: "hosting control panel probe",
  },
  {
    pattern: /\/internal\//i,
    severity: "medium",
    description: "internal API probe",
  },
  {
    pattern: /conf(ig)?\.(json|py|yml|yaml|xml|toml|ini)\b/i,
    severity: "medium",
    description: "config file probe",
  },
  {
    pattern: /\/owa\/|\/ecp\/|\/exchange\//i,
    severity: "medium",
    description: "Exchange/Outlook probe",
  },
  {
    pattern:
      /\/(Microsoft-Server-ActiveSync|ews\/exchange\.asmx|mapi\/(nspi|emsmdb))/i,
    severity: "medium",
    description: "Exchange ActiveSync/EWS/MAPI probe",
  },
  {
    pattern: /\/\+CSCOE\+|\/\+webvpn\+|\/webvpn\.html|\/CSCOSSLC\/tunnel/i,
    severity: "medium",
    description: "Cisco VPN/AnyConnect probe",
  },
  {
    pattern: /\/RDWeb/i,
    severity: "medium",
    description: "Remote Desktop Web Access probe",
  },
  {
    pattern: /\/wsman\b/i,
    severity: "medium",
    description: "WS-Management/WinRM probe",
  },
  {
    pattern: /\/mcp\b|\/sse\b/i,
    severity: "medium",
    description: "MCP/AI infrastructure probe",
  },
  {
    pattern: /^\/sdk(\b|\/)/i,
    severity: "medium",
    description: "ESXi/Java SDK scanner probe",
  },
  {
    pattern: /\/ui_config\.json/i,
    severity: "medium",
    description: "UI configuration probe",
  },
  {
    pattern: /XDEBUG_SESSION_START/i,
    severity: "medium",
    description: "PHP debug session hijacking",
  },
  // MEDIUM - Laravel/PHP framework probing
  {
    pattern: /\/telescope|\/horizon|\/nova\b|\/nova-api\//i,
    severity: "medium",
    description: "Laravel debug/admin probe",
  },
  {
    pattern: /\/_?debugbar|\/_?_?ignition/i,
    severity: "medium",
    description: "Laravel debug probe",
  },
  // MEDIUM - Symfony debug profiler (exposes phpinfo, DB credentials via parameters.yml)
  {
    pattern: /\/_profiler\b|\/app_dev\.php|\/_(wdt)\b/i,
    severity: "medium",
    description: "Symfony debug profiler probe",
  },
  {
    pattern: /\/clockwork\b/i,
    severity: "medium",
    description: "PHP Clockwork debug probe",
  },
  {
    pattern: /\/sanctum\/|\/livewire\//i,
    severity: "medium",
    description: "Laravel auth/component probe",
  },
  {
    pattern: /\/broadcasting\/auth/i,
    severity: "medium",
    description: "Laravel broadcasting probe",
  },
  {
    pattern:
      /\/artisan|\/composer\.(json|lock)|\/package\.json|\/webpack\.mix\.js/i,
    severity: "medium",
    description: "framework config file probe",
  },
  // MEDIUM - build/dependency file exposure
  {
    pattern: /\/(pom\.xml|build\.gradle|Gemfile|Cargo\.toml)\b/i,
    severity: "medium",
    description: "build/dependency file probe",
  },
  // MEDIUM - API specification exposure
  {
    pattern: /\/(openapi|swagger)\.(json|ya?ml)\b|\/api-docs\b/i,
    severity: "medium",
    description: "API spec exposure probe",
  },
  // MEDIUM - config/debug dump endpoints
  {
    pattern: /\/config_dump\b|\/debug\/vars\b/i,
    severity: "medium",
    description: "config dump endpoint probe",
  },
  {
    pattern: /\/_environment\b/i,
    severity: "medium",
    description: "CakePHP environment dump probe",
  },
  {
    pattern: /\/debug\/default\/view/i,
    severity: "medium",
    description: "Yii2 debug panel probe",
  },
  // MEDIUM - Java framework probes (Struts, Spring MVC - .action/.do endpoints)
  {
    pattern: /\.(action|do)\b/i,
    severity: "medium",
    description: "Apache Struts/Java servlet probe",
  },
  // MEDIUM - VMware ESXi/vSphere probes
  {
    pattern: /\/evox\/about/i,
    severity: "medium",
    description: "VMware ESXi version probe",
  },
  // MEDIUM - enterprise software probes
  {
    pattern: /\/solr\b/i,
    severity: "medium",
    description: "Apache Solr probe",
  },
  {
    pattern: /\/sitecore\b/i,
    severity: "medium",
    description: "Sitecore CMS probe",
  },
  {
    pattern: /\/zabbix\b/i,
    severity: "medium",
    description: "Zabbix monitoring probe",
  },
  {
    pattern: /\/cf_scripts\b/i,
    severity: "medium",
    description: "Adobe ColdFusion probe",
  },
  {
    pattern: /\/OA_HTML\b/i,
    severity: "medium",
    description: "Oracle E-Business Suite probe",
  },
  {
    pattern: /\/jasperserver/i,
    severity: "medium",
    description: "JasperReports Server probe",
  },
  {
    pattern: /\/jira\b/i,
    severity: "medium",
    description: "Atlassian Jira probe",
  },
  // MEDIUM - installer/setup wizards (account hijack on un-installed apps)
  {
    pattern:
      /\/(install(er)?\/(index\.php|index\.html|checks?|database|config|step\d)|install(er)?\/?$|install\.php|setup\/(wizard|register|license|index)|index\.php\/install)/i,
    severity: "medium",
    description: "installer/setup wizard probe",
  },
  // MEDIUM - Postman/AsyncAPI/OpenAPI collections (often embed API tokens, internal endpoints)
  {
    pattern:
      /\/(postman[_-]?(collection)?|asyncapi|openapi|swagger)\.(json|ya?ml)\b|\/(postman|asyncapi)\b/i,
    severity: "medium",
    description: "API collection/spec probe",
  },
  // MEDIUM - dev tooling configs (CI, linters, build tools - leak paths, tokens, infra hints)
  {
    pattern:
      /\/(\.travis\.yml|\.codekit\d?|config\.codekit\d?|behat\.ya?ml(\.dist)?|phpcs\.xml|\.editorconfig|go\.mod|Cargo\.lock|Gemfile(\.lock)?)\b/i,
    severity: "medium",
    description: "dev tooling config probe",
  },
  // MEDIUM - cPanel backup/config exposure
  {
    pattern: /\/\.?cpbackup-exclude\.conf\b|\/cpanel(_config)?\b/i,
    severity: "medium",
    description: "cPanel config probe",
  },
  // MEDIUM - GLPI asset manager (multiple auth-bypass + SQLi CVEs)
  { pattern: /\/glpi(\/|\b)/i, severity: "medium", description: "GLPI probe" },
  // MEDIUM - PHP PEAR registry (package metadata, install paths)
  {
    pattern: /\/PEAR\/\.registry\//i,
    severity: "medium",
    description: "PHP PEAR registry probe",
  },
  // MEDIUM - ESPEasy IoT firmware admin (ESP8266/ESP32 devices)
  {
    pattern: /\/ESPEasy\b/i,
    severity: "medium",
    description: "ESPEasy IoT firmware probe",
  },
  // MEDIUM - generic backup archive probes at common names
  {
    pattern:
      /\/(backup|tmp|test|package|site|dump|public|private|archive)\.(zip|rar|7z|tar|tar\.(gz|bz2|xz|z)|gz|bz2|xz|lz|z)\b/i,
    severity: "medium",
    description: "backup archive file probe",
  },
  // MEDIUM - JWKS/OpenID auth keystore enumeration
  {
    pattern: /\/(\.well-known\/)?(jwks(\.json)?|openid-configuration)/i,
    severity: "low",
    description: "JWKS/OpenID auth metadata probe",
  },
  {
    pattern: /\/partymgr\//i,
    severity: "medium",
    description: "Apache OFBiz probe",
  },
  {
    pattern: /\/xmldata\?item=/i,
    severity: "medium",
    description: "HP iLO info disclosure probe",
  },
  // MEDIUM - macOS metadata (reveals directory structure/filenames)
  {
    pattern: /\/\.DS_Store\b/i,
    severity: "medium",
    description: "macOS directory listing probe",
  },
  // MEDIUM - Liferay JSON web services (CVE-2020-7961 - unauthenticated RCE via deserialization)
  {
    pattern: /\/jsonws\b/i,
    severity: "medium",
    description: "Liferay JSON web services probe",
  },
  // MEDIUM - CMS/cloud version fingerprinting
  {
    pattern: /\/(owncloud|nextcloud)\/status/i,
    severity: "medium",
    description: "cloud storage fingerprinting",
  },
  {
    pattern: /\/sugar_version/i,
    severity: "medium",
    description: "SugarCRM fingerprinting",
  },
  {
    pattern: /\/(storage\/)?logs\/.*\.log\b/i,
    severity: "medium",
    description: "log file probe",
  },
  {
    pattern: /\/(debug|error|app|trace)\.log\b/i,
    severity: "medium",
    description: "debug log file probe",
  },
  {
    pattern: /\/\.moltbot\b/i,
    severity: "low",
    description: "scanner signature file (moltbot)",
  },
  {
    pattern: /\/vendor\/phpunit\//i,
    severity: "high",
    description: "PHPUnit RCE probe",
  },
  {
    pattern: /eval-stdin\.php/i,
    severity: "high",
    description: "PHPUnit RCE probe (eval-stdin)",
  },
  // MEDIUM - Citrix NetScaler / EPA
  {
    pattern: /\/logon\/LogonPoint\//i,
    severity: "medium",
    description: "Citrix NetScaler probe",
  },
  {
    pattern: /\/epa\/scripts\//i,
    severity: "medium",
    description: "Citrix EPA client probe",
  },
  // MEDIUM - long encoded/obfuscated path payloads (base64url spray, never legitimate)
  {
    pattern: /\/[A-Za-z0-9_-]{80,}/,
    severity: "medium",
    description: "encoded/obfuscated path payload",
  },
  // MEDIUM - scanner probe parameter (scanners test paths via ?probe=<encoded_path>)
  {
    pattern: /\?probe=/i,
    severity: "medium",
    description: "scanner probe parameter",
  },
  // MEDIUM - phishing kit fingerprinting (scanners checking if server hosts phishing pages)
  {
    pattern: /\/bot-connect\.js/i,
    severity: "medium",
    description: "phishing kit probe (bot-connect)",
  },
  {
    pattern: /\/js\/(twint|lkk)[\w_]*\.js/i,
    severity: "medium",
    description: "phishing kit probe (banking kit JS)",
  },
  {
    pattern: /\/static\/style\/(protect|sys_files)\//i,
    severity: "medium",
    description: "phishing kit probe (kit assets)",
  },
  // MEDIUM - Indonesian banking phishing kit assets (tahuwin family + chat-app icons + daftar=register)
  {
    pattern:
      /\/img\/(tahuwin|whatsapp|telegram|livechat|daftar|toa|favico-tahuwin|logo-tahuwin)\b/i,
    severity: "medium",
    description: "phishing kit probe (Indonesian banking kit assets)",
  },
  // MEDIUM - generic PHP debug/test files (often left by devs, scanned by everyone)
  {
    pattern: /\/(test|debug)\.php\b/i,
    severity: "medium",
    description: "generic PHP debug/test probe",
  },
  // MEDIUM - WordPress JSON API probe (REST plugin enumeration)
  {
    pattern: /\/wp-json\b/i,
    severity: "medium",
    description: "WordPress REST API probe",
  },
  // MEDIUM - Asterisk PBX recordings probe
  {
    pattern: /\/recordings\/index\.php\b/i,
    severity: "medium",
    description: "Asterisk PBX recordings probe",
  },
  // MEDIUM - API spec discovery (separate from /api-docs)
  {
    pattern: /\/api\/(swagger|documentation)\b/i,
    severity: "medium",
    description: "API discovery probe",
  },
  // MEDIUM - generic API version/info/config discovery probes (any depth: /api/version, /api/v1/info, /api/v2.0/systeminfo, /api/4/config, etc.)
  {
    pattern:
      /\/api(\/[\w.-]+)?\/(version|status|info|config|meta|about|environment|systeminfo|check-version|cluster\/summary|namespaces)\b/i,
    severity: "medium",
    description: "API version/info discovery probe",
  },
  // MEDIUM - misc API discovery endpoints (api-description, apisix gateway, allversions)
  {
    pattern: /\/(api-description|apisix\/|allversions\b)/i,
    severity: "medium",
    description: "API/gateway discovery probe",
  },
  // MEDIUM - login.* extension enumeration (scanners hit /login.php, /login.aspx, /login.jsp, /admin.X, /default.X, /index.X across many extensions to fingerprint framework)
  {
    pattern: /\/(login|admin|default|index|home|base)\.(asp|aspx|cfm|cgi|jhtml|jsa|jsp|jspx|do|action|pl|shtml)\b/i,
    severity: "medium",
    description: "framework fingerprinting via filename extension probe",
  },
  // MEDIUM - JSP/JHTML template files (.jhtml is ATG Dynamo / .jsp/.jspx is Tomcat - rarely legitimate at root on non-Java apps)
  {
    pattern: /\.(jhtml|jspx)\b/i,
    severity: "medium",
    description: "Java template file probe",
  },
  // MEDIUM - Symfony/Laravel app config layout (app/config/parameters.yml, application/configs/application.ini)
  {
    pattern:
      /\/(app|application)\/configs?\/(parameters|config|database|application)(_[\w-]+|\.[\w-]+)?\.(yml|ya|php|ini|xml|json)\b/i,
    severity: "medium",
    description: "PHP framework app/config probe",
  },
  // LOW - reconnaissance
  {
    pattern: /\/security\.txt/i,
    severity: "low",
    description: "security.txt reconnaissance",
  },
  {
    pattern: /\/llms\.txt/i,
    severity: "low",
    description: "LLM/AI config reconnaissance",
  },
  {
    pattern: /robots\.txt|sitemap\.xml/i,
    severity: "low",
    description: "reconnaissance",
  },
  // LOW - ad-tech reconnaissance (ads.txt, app-ads.txt, sellers.json - ad-fraud-prevention industry files)
  {
    pattern: /\/(ads\.txt|app-ads\.txt|sellers\.json)\b/i,
    severity: "low",
    description: "ad-tech reconnaissance",
  },
  {
    pattern: /^\/version$|\/global\/health|\/check_health|\/metrics\b/i,
    severity: "low",
    description: "version/health fingerprinting",
  },
  {
    pattern: /\/cdn-cgi\/trace/i,
    severity: "low",
    description: "Cloudflare fingerprinting",
  },
  // LOW - scanner fingerprinting
  {
    pattern: /\/nmaplowercheck/i,
    severity: "low",
    description: "Nmap HTTP fingerprinting",
  },
  // LOW - cloud/WAF catchall probe (scanners check randomized path to detect blanket catchall WAF rules)
  {
    pattern: /^\/_zz_catchall_/i,
    severity: "low",
    description: "WAF catchall detection probe",
  },
  {
    pattern: /\/odinhttpcall/i,
    severity: "low",
    description: "Odin scanner HTTP fingerprinting",
  },
  {
    pattern: /\/_next\/static/i,
    severity: "medium",
    description: "Next.js framework probe",
  },

  // === Discovered from production traffic ===
  // HIGH - ThinkPHP 5.x invokefunction RCE (distributed across many ASNs)
  {
    pattern: /invokefunction\b.*call_user_func_array/i,
    severity: "high",
    description: "ThinkPHP RCE probe (invokefunction)",
  },
  // HIGH - GCP/Firebase service-account & client-secret JSON (plain variants the
  // existing serviceAccountKey/firebase-adminsdk rule does not cover)
  {
    pattern:
      /\/(firebase|google-services|gcp-service-account|sa-key|sa-private-key|service-principal|keyfile|client_secret)\.json\b/i,
    severity: "high",
    description: "GCP/Firebase service key probe",
  },
  // HIGH - mailer/SMTP credential files (transactional-email API keys, SMTP creds)
  {
    pattern: /\/(mail|email|sendmail|nodemailer|mailer|smtp)(\.config)?\.(js|php|json)\b/i,
    severity: "high",
    description: "mailer/SMTP credential file probe",
  },
  // HIGH - Cisco IOS XE Web UI implant (CVE-2023-20198) - double-encoded webui_wsma_Http
  {
    pattern: /%2577eb%2575i|\/webui_wsma_Http/i,
    severity: "high",
    description: "Cisco IOS XE Web UI implant probe (CVE-2023-20198)",
  },
  // HIGH - Spring profile config (application-{prod,dev,staging}.yml/properties - DB creds, secrets)
  {
    pattern: /\/application-(dev|prod|production|staging|development|test|local)\.(ya?ml|properties)\b/i,
    severity: "high",
    description: "Spring profile config probe",
  },
  // HIGH - IaC secrets (Terraform vars, Vault token/password file)
  {
    pattern: /\.tfvars\b|\/\.vault-token\b|vault-pass\.txt/i,
    severity: "high",
    description: "IaC secret file probe (tfvars/vault token)",
  },
  // HIGH - VPN tunnel keys/config (OpenVPN, WireGuard, Tailscale, ZeroTier)
  {
    pattern: /\.ovpn\b|\/wg0\.conf\b|tailscaled\.state|zerotier-one\/(identity|authtoken)\.secret/i,
    severity: "high",
    description: "VPN tunnel key/config probe",
  },
  // HIGH - shell/DB history & credential files (psql/mysql history, my.cnf, pypirc, composer auth)
  {
    pattern: /\/\.(psql_history|mysql_history|my\.cnf|pypirc|composer-auth\.json)\b/i,
    severity: "high",
    description: "shell/DB history & credential file probe",
  },
  // HIGH - FTP/Docker credential dotfiles (.dockercfg = registry auth, .ftpconfig = FTP creds)
  {
    pattern: /\/\.(dockercfg|ftpconfig)\b|\/\.remote-sync\.json\b/i,
    severity: "high",
    description: "FTP/Docker credential dotfile probe",
  },
  // HIGH - IoT router RCE (TOTOLINK/Netgear goform, device.rsp command exec)
  {
    pattern: /\/device\.rsp\?opt=sys|\/goform\/(AdvSetMacMtuWan|setSysAdm|WifiBasicSet)/i,
    severity: "high",
    description: "IoT router RCE probe",
  },
  // MEDIUM - IaC/Helm/K8s manifests (Helm values, k8s secret manifests, Ansible playbooks)
  {
    pattern: /\/(values|template|skaffold|playbook)\.ya?ml\b|\/(k8s|helm)\/.*secret/i,
    severity: "medium",
    description: "IaC/Helm/K8s manifest probe",
  },
  // MEDIUM - CI/CD pipeline config (GitHub Actions, GitLab CI, Jenkins, CodeBuild, Cloud Build)
  {
    pattern:
      /\/(\.github\/workflows\/|\.gitlab-ci\.yml|\.drone\.yml|bitbucket-pipelines\.yml|azure-pipelines\.yml|Jenkinsfile|cloudbuild\.ya?ml|buildspec\.ya?ml|\.circleci\/)/i,
    severity: "medium",
    description: "CI/CD pipeline config probe",
  },
  // MEDIUM - HashiCorp Consul/Vault/Nomad agent API (cluster secrets, seal status)
  {
    pattern:
      /\/v1\/(sys\/(seal-status|health|init|mounts)|agent\/(self|services|members|metrics)|status\/(leader|peers))\b/i,
    severity: "medium",
    description: "Consul/Vault/Nomad agent API probe",
  },
  // MEDIUM - open redirect / SSRF via absolute-URL redirect parameter (relative values do not match)
  {
    pattern: /[?&](url|redirect|redirect_uri|goto|next|dest|destination|return|returnurl|continue|u)=(https?(:|%3a)|\/\/|%2f%2f)/i,
    severity: "medium",
    description: "open redirect / SSRF parameter probe",
  },
  // MEDIUM - source map disclosure (leaks original JS/CSS source)
  {
    pattern: /\.(js|css|mjs|cjs)\.map\b/i,
    severity: "medium",
    description: "source map disclosure probe",
  },
  // MEDIUM - webroot source archive (full site source in a zip/tarball)
  {
    pattern: /\/(www|web|webroot|public_html|htdocs|wwwroot|source|src|release|html)\.(zip|tar\.gz|tgz|tar|rar|7z|gz)\b/i,
    severity: "medium",
    description: "webroot source archive probe",
  },
  // MEDIUM - Spring Boot 1.x Actuator bare endpoints (no /actuator/ prefix)
  {
    pattern: /^\/(api\/)?(configprops|threaddump|beans|mappings|httptrace|auditevents|scheduledtasks|env)(?:\?|$)/i,
    severity: "medium",
    description: "Spring Actuator bare endpoint probe",
  },
  // HIGH - Jupyter Notebook/Lab unauthenticated API (kernel exec = RCE)
  // Sample: GET /api/kernels, /api/kernelspecs, /api/contents/
  {
    pattern: /\/api\/(kernels|kernelspecs|contents)(\/|\b)/i,
    severity: "high",
    description: "Jupyter unauthenticated API probe",
  },
  // HIGH - MLflow tracking server (CVE-2023-6014 auth bypass, CVE-2024-37052+ model deserialization RCE)
  // and Milvus vector DB. Sample: POST /api/2.0/mlflow/experiments/search, /api/v1/milvus/version
  {
    pattern: /\/api\/2\.0\/mlflow\/|\/milvus\//i,
    severity: "high",
    description: "MLflow / Milvus ML-infra probe",
  },
  // MEDIUM - Ollama unauthenticated LLM API (model exfil/abuse). /api/tags is somewhat generic
  // but only fires alongside /generate /pull here; revisit if a consumer reports a false positive.
  {
    pattern: /\/api\/(tags|generate|pull)\b/i,
    severity: "medium",
    description: "Ollama LLM API probe",
  },
  // MEDIUM - Docker Registry v2 API enumeration (catalog/manifest scraping)
  {
    pattern: /^\/v2\/?$/i,
    severity: "medium",
    description: "Docker Registry v2 enumeration",
  },
  // MEDIUM - botnet/agent C2 enumeration (heartbeat/machine/p2p endpoints from miner & RAT agents)
  // Sample: /api/v1/heartbeat, /api/v1.3/machine, /api/p2p, /apiv2/server/info
  {
    pattern: /\/api(v2)?\/(v[\d.]+\/)?(machine|heartbeat|p2p)\b|\/apiv2\/server\/info/i,
    severity: "medium",
    description: "botnet/agent C2 enumeration probe",
  },
  // HIGH - secrets exposed via API path (settings/keys/secrets/credentials JSON/YAML)
  // Sample: /api/keys.json, /api/secrets.json, /api/settings.yml
  {
    pattern: /\/api\/(settings|keys|secrets|credentials)\.(json|ya?ml)\b/i,
    severity: "high",
    description: "API secrets file probe",
  },
  // MEDIUM - Magento REST recon (storeConfigs precedes CVE-2022-24086 RCE chains)
  {
    pattern: /\/rest\/V1\/store\/storeConfigs/i,
    severity: "medium",
    description: "Magento REST recon probe",
  },
  // MEDIUM - Rails dev-mode info disclosure (/rails/info/properties exposes env + gem versions)
  {
    pattern: /\/rails\/info\/(properties|routes)/i,
    severity: "medium",
    description: "Rails info disclosure probe",
  },
  // MEDIUM - JetBrains IDE config (.idea/dataSources.local.xml holds DB creds)
  {
    pattern: /\/\.idea\//i,
    severity: "medium",
    description: "JetBrains IDE config probe",
  },
  // MEDIUM - Go pprof debug endpoint (heap/goroutine/cmdline disclosure)
  {
    pattern: /\/debug\/pprof/i,
    severity: "medium",
    description: "Go pprof debug endpoint probe",
  },
  // MEDIUM - WHM/cPanel proxy login
  {
    pattern: /___proxy_subdomain_whm|\/whm\b/i,
    severity: "medium",
    description: "WHM/cPanel proxy login probe",
  },
  // MEDIUM - AWS/Azure client config JS (Amplify aws-exports leaks pool IDs/endpoints)
  {
    pattern: /\/aws[-.]?(exports|config)\.js\b|\/azure\.json\b/i,
    severity: "medium",
    description: "AWS/Azure client config probe",
  },
  // MEDIUM - GraphQL endpoint discovery
  {
    pattern: /\/graphql\b/i,
    severity: "medium",
    description: "GraphQL endpoint probe",
  },
  // MEDIUM - Rundeck automation API
  {
    pattern: /\/rundeck\b/i,
    severity: "medium",
    description: "Rundeck API probe",
  },
  // MEDIUM - app debug log files (npm/yarn/pnpm/firebase/php debug logs)
  {
    pattern: /\/(npm-debug|yarn-error|pnpm-debug|firebase-debug|php-error|php_error)\.log\b/i,
    severity: "medium",
    description: "app debug log file probe",
  },
  // LOW - login-page enumeration (framework sign-in path variants; bare /login excluded to avoid SPA false positives)
  {
    pattern: /\/(signin|user\/login|users\/sign_in|account\/login|manage\/account\/login|showLogin\.cc)\b/i,
    severity: "low",
    description: "login page enumeration probe",
  },
  // LOW - DNS-over-HTTPS / DNS-tunnel query on bare root (prefixed forms caught above)
  {
    pattern: /^\/\?(dns|name)=[A-Za-z0-9_%+-]{10,}/i,
    severity: "low",
    description: "DoH/DNS-tunnel query probe",
  },
];

export const METHOD_THREATS: MethodThreat[] = [
  { method: "PROPFIND", severity: "medium", description: "WebDAV scan" },
  { method: "TRACE", severity: "high", description: "XST attack vector" },
  { method: "CONNECT", severity: "high", description: "open proxy test" },
  {
    method: "PRI",
    severity: "medium",
    description: "HTTP/2 prior-knowledge / smuggling probe",
  },
  {
    method: "SSTP_DUPLEX_POST",
    severity: "low",
    description: "Microsoft SSTP VPN handshake probe",
  },
];

export const BODY_THREATS: BodyThreat[] = [
  // SQL injection
  {
    pattern: /('|"|;)\s*(OR|AND)\s+[\d'"].*?[=<>]/i,
    severity: "high",
    description: "SQL injection (boolean)",
  },
  {
    pattern: /UNION\s+(ALL\s+)?SELECT/i,
    severity: "high",
    description: "SQL injection (UNION)",
  },
  {
    pattern: /;\s*(DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT)\s/i,
    severity: "high",
    description: "SQL injection (destructive)",
  },
  {
    pattern: /SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY/i,
    severity: "high",
    description: "SQL injection (time-based)",
  },
  {
    pattern: /\/\*.*?\*\/|--\s/i,
    severity: "medium",
    description: "SQL comment injection",
  },
  // XSS
  {
    pattern: /<script[\s>]/i,
    severity: "high",
    description: "XSS (script tag)",
  },
  {
    pattern: /on(error|load|click|mouseover|focus)\s*=/i,
    severity: "high",
    description: "XSS (event handler)",
  },
  {
    pattern: /javascript\s*:/i,
    severity: "high",
    description: "XSS (javascript: URI)",
  },
  {
    pattern: /eval\s*\(/i,
    severity: "high",
    description: "code injection (eval)",
  },
  // Path traversal
  { pattern: /(\.\.\/){2,}/g, severity: "high", description: "path traversal" },
  {
    pattern: /\.\.%2[fF]/g,
    severity: "high",
    description: "path traversal (encoded)",
  },
  { pattern: /%00/g, severity: "high", description: "null byte injection" },
  {
    pattern: /%c[01]/i,
    severity: "high",
    description: "overlong UTF-8 encoding attack",
  },
  // Command injection
  {
    pattern: /;\s*(ls|cat|whoami|id|pwd|uname|curl|wget)\b/i,
    severity: "high",
    description: "command injection",
  },
  {
    pattern: /\$\(.*?\)|`.*?`/i,
    severity: "high",
    description: "command substitution",
  },
  {
    pattern: /\|\s*(cat|ls|id|whoami|curl|bash|sh)\b/i,
    severity: "high",
    description: "pipe injection",
  },
  // Local file inclusion (LFI)
  {
    pattern: /\/proc\/(self|\d+)\/environ/i,
    severity: "high",
    description: "LFI - /proc/*/environ (env variable theft)",
  },
  {
    pattern: /\/proc\/(self|\d+)\/cmdline/i,
    severity: "high",
    description: "LFI - /proc/*/cmdline (process args theft)",
  },
  {
    pattern: /\/etc\/passwd/i,
    severity: "high",
    description: "LFI - /etc/passwd",
  },
  {
    pattern: /\/etc\/shadow/i,
    severity: "high",
    description: "LFI - /etc/shadow",
  },
  // XML-RPC introspection/exploitation
  {
    pattern: /<methodCall>|<methodName>/i,
    severity: "medium",
    description: "XML-RPC probe",
  },
  // Known malware signatures
  {
    pattern: /androxgh0st/i,
    severity: "high",
    description: "Androxgh0st malware (credential harvester)",
  },
  {
    pattern: /gnixoer/i,
    severity: "high",
    description: "GNIXOER malware (credential harvester)",
  },
  {
    pattern: /xterminate/i,
    severity: "high",
    description: "Xterminate scanner",
  },
  {
    pattern: /"need_fuck"/i,
    severity: "high",
    description: "IoT botnet payload signature",
  },
  // Cryptocurrency mining proxy abuse (JSON-RPC mining methods)
  {
    pattern:
      /(eth_getWork|eth_submitWork|eth_submitHashrate|"getwork"|mining\.(subscribe|authorize|notify))/i,
    severity: "high",
    description: "cryptocurrency mining proxy abuse",
  },
  // Type-confusion auth bypass (array-typed credentials defeat strict comparisons in PHP/Laravel)
  {
    pattern: /"(email|username|user|login)"\s*:\s*\[/i,
    severity: "high",
    description: "type-confusion auth bypass (array-typed credential)",
  },
  // Webmin RCE marker (CVE-2019-15107) - exploit payload contains literal "WEBMIN_VULN" string
  {
    pattern: /WEBMIN_VULN/i,
    severity: "high",
    description: "Webmin RCE exploit marker (CVE-2019-15107)",
  },
  // PHPUnit eval-stdin RCE marker
  {
    pattern: /phpunit_rce/i,
    severity: "high",
    description: "PHPUnit eval-stdin RCE exploit marker",
  },
  // PHP-CGI %AD bypass payload (CVE-2024-4577) - soft-hyphen tricks argv into accepting -d flags
  {
    pattern:
      /%ADd\+(allow_url_include|auto_prepend_file|cgi\.force_redirect|disable_functions)/i,
    severity: "high",
    description: "PHP-CGI argument injection payload (CVE-2024-4577)",
  },
  // Cryptominer agent signature (XMRig - often delivered in a malformed method line)
  {
    pattern: /XMRig\//i,
    severity: "high",
    description: "cryptominer agent signature (XMRig)",
  },
  // Mirai/Gafgyt/NjRAT botnet C2 check-in (pipe-delimited |'|'| beacon)
  {
    pattern: /\|'\|'\|/,
    severity: "high",
    description: "botnet C2 check-in beacon (pipe-delimited)",
  },
  // root/default credential POST (credential stuffing with a root user)
  {
    pattern: /"(user(name)?|login)"\s*:\s*"root"\b/i,
    severity: "low",
    description: "root/default credential POST probe",
  },
];
