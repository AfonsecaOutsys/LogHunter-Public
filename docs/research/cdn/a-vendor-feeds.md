# A. Vendor-published CDN / proxy IP range feeds

Research angle: **what the vendors themselves publish** in machine-readable form, so LogHunter can mark an IP as
"CDN/WAF/proxy edge of vendor X" offline, with in-app auto-update.

- Research date / access date for every URL below: **2026-11-22**.
- "Verified" means the endpoint was fetched with an HTTP GET on 2026-11-22 and the size / count shown was measured then.
- **UNVERIFIED** marks anything taken from secondary sources or not confirmed against a primary vendor page.
- Licence column: no vendor feed below has an explicit open-data licence. All of them are published so customers can
  automate firewall allowlists. IP prefixes are factual data. **Before redistributing a bundled snapshot inside the .exe,
  get a quick legal check (UNVERIFIED legal position).** Fetching the feed live from the vendor, in-app, avoids the
  redistribution question entirely.

---

## 0. Two classification facts that drive the design

1. **The IP that ALB `client:port` / IIS `c-ip` shows is the vendor's _origin-facing_ (egress-to-origin) address.**
   Some vendors publish only that set (Akamai Origin IP ACL, CloudFront `CLOUDFRONT_ORIGIN_FACING`, AFD `Backend`).
   Others publish one list that covers both directions (Cloudflare, Fastly, Imperva). Use the origin-facing set where one exists. The
   client-facing sets (AFD `Frontend`, CloudFront edge anycast) matter only to explain odd hits.
2. **"Forward proxy" is a different verdict from "CDN edge".** Zscaler, Netskope, Cloudflare WARP and iCloud Private Relay
   egress IPs carry real, attributable user traffic. A Zscaler IP that hammers `/login` is _a corporate user population_,
   not a CDN hop that hides the attacker. LogHunter should label these `forward-proxy:<vendor>`, not `cdn-edge:<vendor>`.
   This also means **ASN-only Cloudflare detection (AS13335) is wrong**: WARP users egress from AS13335 but are not in
   the published proxy list.

---

## 1. Per-vendor feed tables

Reliability rating: **High** means an official, documented, unauthenticated, machine-readable feed that LogHunter can use as-is.
**Med** means official but undocumented or awkward (HTML scrape, stale metadata, product-scoped). **Low** means no feed: ASN, scrape, or
per-customer only.

### 1.1 AWS CloudFront

| Field | Value |
|---|---|
| URL (primary) | `https://ip-ranges.amazonaws.com/ip-ranges.json` filter `service == "CLOUDFRONT_ORIGIN_FACING"` (origin side) and `service == "CLOUDFRONT"` (all CF) |
| URL (CF-only) | `https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips` (keys `CLOUDFRONT_GLOBAL_IP_LIST`, `CLOUDFRONT_REGIONAL_EDGE_IP_LIST`) |
| Format | JSON. `prefixes[]` (IPv4) and `ipv6_prefixes[]`, each with `service`, `region`, `network_border_group`. The CF-only URL is IPv4 only. |
| Auth | None |
| Size (verified) | ip-ranges.json **2.76 MB** (10,769 v4 / 7,063 v6 prefixes, syncToken 1795352225, createDate 2026-11-22-12-57-05). `CLOUDFRONT` = 217 v4 / 35 v6. `CLOUDFRONT_ORIGIN_FACING` = 52 v4 / 37 v6. list-cloudfront-ips = **4.1 KB** (117 global + 100 regional-edge, v4 only). |
| Update cadence | Changes several times a week (whole file). Change detection uses `syncToken` (epoch) / `createDate`. Push notification goes to SNS topic `arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged` (payload includes md5 and URL). |
| Licence | No explicit licence. Documented for programmatic use ("If you access this file programmatically…verify the TLS certificate"). |
| Reliability | **High** |
| Notes | All 52 origin-facing v4 CIDRs are contained in `CLOUDFRONT` CIDRs (verified by subnet containment). Every subset is also in `AMAZON`, so **never classify by `AMAZON`**. That would flag every EC2 attacker as "CDN". The **managed prefix lists** `com.amazonaws.global.cloudfront.origin-facing` / `com.amazonaws.global.ipv6.cloudfront.origin-facing` hold the same data but need AWS credentials (EC2 `GetManagedPrefixListEntries`), so they don't suit an offline operator tool. Use the JSON. **CloudFront VPC origins**: the ALB sees a _private_ ENI IP in the customer VPC, not a CloudFront IP (UNVERIFIED, community sources only). Treat RFC1918 `client` IPs on an internet-facing ALB as "possible VPC-origin / internal proxy". `GLOBALACCELERATOR` (134 v4) is a separate service. Vercel's `76.76.21.0/24` and Netlify's `75.2.60.0/24` anycast ingress sit in AS16509 (verified via RIPEstat), probably Global Accelerator (UNVERIFIED). |

Sources: [AWS IP ranges](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html), [JSON syntax / range overlaps](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html), [SNS notifications](https://docs.aws.amazon.com/vpc/latest/userguide/subscribe-notifications.html), [CloudFront edge locations & IP ranges / managed prefix list](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html), feed endpoints above (all accessed 2026-11-22).

### 1.2 Cloudflare

| Field | Value |
|---|---|
| URL | `https://www.cloudflare.com/ips-v4`, `https://www.cloudflare.com/ips-v6` (plain text). API: `https://api.cloudflare.com/client/v4/ips` (JSON, includes `etag`). Option `?networks=jdcloud` adds `jdcloud_cidrs` (China network). |
| Format | TXT, one CIDR per line / JSON `result.ipv4_cidrs`, `result.ipv6_cidrs`, `result.etag` |
| Auth | None (verified unauthenticated GET → 200) |
| Size (verified) | ips-v4 **230 B** (15 CIDRs), ips-v6 **104 B** (7 CIDRs), API **505 B** |
| Update cadence | Rare (years between changes, per community threads). The official docs say only that new ranges "are added to our list of IP ranges before being put into production". There is no notification service and no fixed notice period. Change detection uses the `etag` field. The text files carry `Cache-Control: s-maxage=86400`. |
| Licence | No explicit licence. Docs recommend using the API to keep configuration current. |
| Reliability | **High** |
| Notes | The list is the set of IPs that proxy to origins. Cloudflare: "uses other IP ranges for various products and services, but these addresses will not make connections to your origin." **Enterprise BYOIP and static-IP customers are not in the list** (customer-specific). **WARP / Private Relay egress (AS13335) is not in the list.** These are real users, so don't do ASN-based Cloudflare matching. JD Cloud (China) ranges come only from the `networks=jdcloud` call. Include them for customers with China-network enabled. |

Sources: [Cloudflare IP addresses](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/), [API: IP details](https://developers.cloudflare.com/api/resources/ips/methods/list/), [community: no change alerts](https://community.cloudflare.com/t/whitelist-ip-range-change-notifications/193570) (all accessed 2026-11-22).

### 1.3 Akamai (CDN / Ion / Kona / App & API Protector)

| Field | Value |
|---|---|
| URL | Origin IP ACL lists: `https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.txt`, `.../akamai_ipv6_CIDRs.txt`, plus `.csv` and zipped variants |
| Format | TXT / CSV, one CIDR per line |
| Auth | None for the Origin IP ACL list. **Site Shield maps are per-customer** and need Control Center or API (EdgeGrid) auth. |
| Size (verified) | IPv4 **90 B** (6 CIDRs: 2.16.0.0/13, 23.0.0.0/12, 23.32.0.0/11, 23.192.0.0/11, 95.100.0.0/15, 184.24.0.0/13). IPv6 **44 B** (3 CIDRs: 2a02:26f0::/32, 2600:1400::/24, 2405:9600::/32). |
| Update cadence | Infrequent. Akamai announces changes "through alerts sent from the Firewall Rules Notification tool" (Control Center subscription). The page records that several older IPv4 blocks were retired and reallocated as of 2025-07-01. |
| Licence | No explicit licence. Public TechDocs download. |
| Reliability | **Med**. Official and machine-readable, but it covers **only** properties with Origin IP ACL enabled. Classic Akamai delivery without Origin IP ACL / Site Shield can reach the origin from any Akamai edge. |
| Notes | Fallback for non-ACL customers is the Akamai ASN set (see section 2). Akamai also runs edge servers **inside ISP networks with ISP address space** (UNVERIFIED in this research, widely reported). ASN matching cannot catch those. The authoritative per-customer answer is the customer's Site Shield map. LogHunter could let an engineer paste a customer-specific CIDR list. |

Sources: [Akamai Origin IP ACL: Update your origin server](https://techdocs.akamai.com/origin-ip-acl/docs/update-your-origin-server), list files above (accessed 2026-11-22).

### 1.4 Fastly

| Field | Value |
|---|---|
| URL | `https://api.fastly.com/public-ip-list` |
| Format | JSON `addresses[]` (v4), `ipv6_addresses[]` |
| Auth | None (verified) |
| Size (verified) | **451 B**, 21 v4 / 3 v6 CIDRs |
| Update cadence | Rare. Changes are pre-announced as "IP address announcement" posts on the Fastly status page (subscribable). The response carries `Cache-Control: no-store`. |
| Licence | No explicit licence. Documented API. |
| Reliability | **High** |
| Notes | Fastly says the list "is exhaustive and includes all Fastly-owned IP ranges". It covers client, log-streaming and origin connections. |

Sources: [Fastly API: public IP list](https://www.fastly.com/documentation/reference/api/utils/public-ip-list/), endpoint (accessed 2026-11-22).

### 1.5 Imperva (Incapsula) Cloud WAF

| Field | Value |
|---|---|
| URL | `https://my.imperva.com/api/integration/v1/ips` (legacy host `my.incapsula.com` still works). Optional `resp_format=json` or `text`. |
| Format | JSON `ipRanges[]`, `ipv6Ranges[]` (or text) |
| Auth | None. Documented by third parties as a **POST** endpoint, but a plain **GET returns the same JSON** (verified 2026-11-22). |
| Size (verified) | **298 B**, 11 v4 / 1 v6 (2a02:e980::/29) |
| Update cadence | Infrequent. Notification mechanism UNVERIFIED (the Imperva/Thales doc portal did not render for fetch). |
| Licence | No explicit licence (UNVERIFIED) |
| Reliability | **High** (endpoint stable for years; official doc page text UNVERIFIED) |
| Notes | The response includes `res`/`res_message`. Treat `res != 0` as a failed fetch. Imperva (Thales) official doc URL `docs.imperva.com/bundle/cloud-application-security/page/more/restricting-direct-access.htm` redirects to `docs-cybersec.thalesgroup.com` and is JS-rendered, so its content is **UNVERIFIED**. |

Sources: endpoint (accessed 2026-11-22), [Imperva Cloud WAF IP ranges doc (redirects to Thales portal)](https://docs.imperva.com/bundle/cloud-application-security/page/more/ip-ranges.htm) (UNVERIFIED content), [jonhadfield/ip-fetcher imperva provider](https://pkg.go.dev/github.com/jonhadfield/ip-fetcher/providers/imperva) (secondary).

### 1.6 Azure Front Door

| Field | Value |
|---|---|
| URL | Landing page `https://www.microsoft.com/en-us/download/details.aspx?id=56519` holds a link to `https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_YYYYMMDD.json`. Current file (verified): `ServiceTags_Public_20261116.json`. |
| Format | JSON. `values[]` with `name`, `properties.addressPrefixes[]` (v4+v6 mixed), per-tag `changeNumber`, and a top-level `changeNumber`. |
| Auth | None for the download. The Service Tag Discovery API (REST / `Get-AzNetworkServiceTag`) **needs an Azure subscription login**, so it doesn't suit LogHunter. |
| Size (verified) | **4.67 MB** (3,398 tags, top-level changeNumber 427). `AzureFrontDoor.Backend` = **249 prefixes (157 v4)**. `AzureFrontDoor.Frontend` = 229 (126 v4). `AzureFrontDoor.FirstParty` = 74. `AzureFrontDoor.MicrosoftSecurity` = 7. |
| Update cadence | **Weekly** publication with a new filename each week. "When new IP addresses are added to service tags, they aren't used in Azure for at least one week." |
| Licence | Microsoft Download Center terms. No explicit open licence (UNVERIFIED). |
| Reliability | **Med**. The data is authoritative, but the URL is unstable and must be discovered by scraping HTML. |
| Notes | **Use `AzureFrontDoor.Backend`.** That is the "IP addresses that Azure Front Door uses to access your origins". `Frontend` is the client-facing anycast set. `FirstParty` / `MicrosoftSecurity` are reserved for Microsoft's own services on AFD. **Stable fetch recipe:** (1) GET the details page, regex `https://download\.microsoft\.com/[^"]+/ServiceTags_Public_\d{8}\.json`, (2) GET that file, (3) accept only if top-level `changeNumber` ≥ the cached value, (4) otherwise keep the cache. The `/download/7/1/d/71d86715-…/` GUID path has been the same for a long time, but Microsoft does not guarantee it (UNVERIFIED stability). Extract the 1-2 tags at fetch time and cache only those (≈10 KB), not 4.7 MB. The `confirmation.aspx?id=56519` URL (used by cdncheck) returns the same HTML page. |

Sources: [Azure service tags overview](https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview), [download page](https://www.microsoft.com/en-us/download/details.aspx?id=56519), JSON file above (accessed 2026-11-22).

### 1.7 Google (Cloud CDN, Media CDN, external Application Load Balancer)

| Field | Value |
|---|---|
| URL | `https://www.gstatic.com/ipranges/goog.json` (all Google user-facing ranges), `https://www.gstatic.com/ipranges/cloud.json` (customer GCP external IPs). **Proxy-to-origin ranges:** documented static `130.211.0.0/22`, `35.191.0.0/16` (GFE → instance-group / NEG backends). For **internet NEG** origins (the case for an OutSystems app hosted elsewhere) the ranges are in the DNS TXT record `_cloud-eoips.googleusercontent.com`. |
| Format | JSON `prefixes[]` with `ipv4Prefix`/`ipv6Prefix`, plus `syncToken` and `creationTime`. The DNS TXT record is SPF-style. |
| Auth | None |
| Size (verified) | goog.json **6.3 KB**, cloud.json **118 KB** (creationTime 2026-11-22T12:07:11). TXT record resolved to `v=spf1 ip4:34.96.0.0/20 ip4:34.127.192.0/18 ~all`. |
| Update cadence | "Change often" (goog.json/cloud.json, no fixed schedule). Change detection uses `syncToken`. The GFE / internet-NEG ranges change rarely. |
| Licence | No explicit licence (UNVERIFIED) |
| Reliability | **Med**. The JSON feeds are official but **not CDN-specific**. The CDN-specific origin ranges are tiny and come from docs or DNS, not a JSON feed. |
| Notes | **Do not use "goog.json minus cloud.json" as "Google CDN".** That set is all Google services (Googlebot-adjacent, Workspace, etc.). cdncheck does use it as "google CDN" (see section 3), which over-matches. For LogHunter, hard-code or fetch the 4 GFE/internet-NEG CIDRs: `130.211.0.0/22`, `35.191.0.0/16`, `34.96.0.0/20`, `34.127.192.0/18`. Optionally refresh the latter two via a DNS TXT lookup. `35.191.0.0/16` is also the health-check source. |

Sources: [Google: obtain Google IP address ranges](https://knowledge.workspace.google.com/admin/security/obtain-google-ip-address-ranges), [External Application Load Balancer: firewall rules / X-Forwarded-For](https://docs.cloud.google.com/load-balancing/docs/https#firewall-rules), feeds and DNS TXT above (accessed 2026-11-22).

### 1.8 F5 Distributed Cloud (XC, ex-Volterra)

| Field | Value |
|---|---|
| URL | `https://docs.cloud.f5.com/docs-v2/downloads/platform/reference/network-cloud-ref/ips-domains.json` and `.../ips-domains.txt`. (The page's relative links `/docs-v2/ips-domains.json` return 404 or 308. Use the `/downloads/...` path.) |
| Format | JSON manifest (`manifest_type: firewall_proxy_allowlist`, `services.regional_edges.regions.{americas,europe,asia}.ipv4_cidrs`, `services.cdn.ipv4_cidrs`, and others) / TXT |
| Auth | None |
| Size (verified) | JSON **14.3 KB**, TXT **7.1 KB**. Regional Edges = **42 v4 CIDRs** (no IPv6). CDN = 8 v4 CIDRs (159.60.187-191.0/24, 159.60.252-254.0/24). |
| Update cadence | Unknown. The HTML page says "Last modified November 20, 2026", but the JSON `generated_at` is `2025-09-10`. Either the field is not maintained or the file is stale (**UNVERIFIED which**). The JSON RE list did match the HTML list on the spot-check. |
| Licence | No explicit licence |
| Reliability | **Med** |
| Notes | **Use only `regional_edges` + `cdn`.** Exclude `secondary_dns`, `global_log_receiver`, `dnslb_health_checks`, `data_intelligence`. Those are AWS/GCP IPs used for control-plane functions and would mislabel AWS/GCP attackers. Owner ASN is **AS35280** (F5 Networks SARL). |

Sources: [F5 XC Network Cloud reference](https://docs.cloud.f5.com/docs-v2/platform/reference/network-cloud-ref), JSON/TXT above (accessed 2026-11-22).

### 1.9 Bunny.net

| Field | Value |
|---|---|
| URL | `https://api.bunny.net/system/edgeserverlist` (v4 JSON array), `/plain` (newline TXT), `/ipv6` (v6). Legacy `bunnycdn.com/api/system/edgeserverlist` still works. |
| Format | JSON array of **single IPs** (not CIDRs) / TXT |
| Auth | None |
| Size (verified) | v4 **9.7 KB** (594 IPs), v6 **8.3 KB** (340 IPs) |
| Update cadence | "Dynamic", changes often. Bunny docs say to "update it periodically as the network changes". Refresh at least daily. |
| Licence | No explicit licence |
| Reliability | **High** (official, documented on bunny.net docs, but churns) |
| Notes | Exact-IP matching only. Bunny sends `Via: BunnyCDN` upstream (secondary source). Many Bunny edges sit in **Datacamp/CDN77 ASNs (AS60068, AS212238)**, so ASN cannot tell Bunny from CDN77. Bunny's own ASN is **AS200325**. |

Sources: [bunny.net docs: CDN connectivity](https://bunny.net/docs/cdn/connectivity), endpoints above (accessed 2026-11-22).

### 1.10 Gcore

| Field | Value |
|---|---|
| URL | `https://api.gcore.com/cdn/public-ip-list` (per-server /32 and /128). `https://api.gcore.com/cdn/public-net-list` (aggregated CIDRs). |
| Format | JSON `addresses[]`, `addresses_v6[]` |
| Auth | None ("This request does not require authorization") |
| Size (verified) | ip-list **42 KB** (996 v4 + 843 v6 host entries). net-list **12.3 KB** (355 v4 + 226 v6 CIDRs). |
| Update cadence | Continuous. "New IP addresses are added to the list 30–60 minutes prior to launching a new server." Gcore recommends an automated updater. |
| Licence | No explicit licence |
| Reliability | **High** |
| Notes | **Prefer `public-net-list`** (fewer, aggregated entries). **Sanitise:** the ip-list contained the private address `172.31.0.24/32` on 2026-11-22. Drop RFC1918, CGNAT and bogon entries from every feed. Gcore Cloud egress is a different feed (`/cloud/public/v1/ipranges/egress`) and must not be mixed in. Gcore bought StackPath's WAF tech in 2024. Owner ASN is AS199524. |

Sources: [Gcore: Allow Gcore CDN access to an origin](https://docs.gcore.com/cdn/getting-started/configure-an-origin/add-cdn-servers-to-the-origin-acl-whitelist), [Gcore API: get CDN servers IP addresses](https://docs.gcore.com/api-reference/cdn/ip-addresses-list/get-cdn-servers-ip-addresses), endpoints (accessed 2026-11-22).

### 1.11 CDN77

| Field | Value |
|---|---|
| URL | `https://prefixlists.tools.cdn77.com/public_lmax_prefixes.json` |
| Format | JSON `{updated_at, prefixes:[{prefix}]}` |
| Auth | None |
| Size (verified) | **2.4 KB**, 38 v4 prefixes, 0 v6, `updated_at` 2026-11-05 |
| Update cadence | Unknown (has `updated_at`) |
| Licence | No explicit licence |
| Reliability | **Med**. The host is an official cdn77.com domain and MISP uses it, but **no CDN77 documentation page referencing it was found (UNVERIFIED as an official contract)**. |
| Notes | ASN fallback **AS60068** (CDN77 Datacamp), **AS212238** (CDNEXT Datacamp). Shared with Bunny edges, so it can only be labelled "Datacamp CDN (CDN77/Bunny)". |

Sources: endpoint (accessed 2026-11-22), [MISP warninglist cdn77](https://github.com/MISP/misp-warninglists/tree/main/lists/cdn77) (secondary).

### 1.12 KeyCDN

| Field | Value |
|---|---|
| URL | `https://www.keycdn.com/shield-prefixes.json` |
| Format | JSON `{prefixes:[...]}` |
| Auth | None |
| Size (verified) | **51 B**, 2 v4 CIDRs (68.70.192.0/20, 185.172.148.0/22) |
| Update cadence | Unknown |
| Licence | No explicit licence |
| Reliability | **Low-Med**. The endpoint exists on keycdn.com, but **no KeyCDN doc page links to it (UNVERIFIED)**. It covers **Origin Shield servers only**. Without Origin Shield, edges pull directly and are not covered. |
| Notes | KeyCDN sends `X-Pull: KeyCDN` to origin. Low priority for OutSystems customers. |

Sources: endpoint (accessed 2026-11-22), [KeyCDN Origin Shield](https://www.keycdn.com/support/origin-shield).

### 1.13 Sucuri (GoDaddy) Website Firewall

| Field | Value |
|---|---|
| URL | **No machine-readable feed.** Ranges are given in HTML on the troubleshooting guide. |
| Ranges (as published) | `192.88.134.0/23`, `185.93.228.0/22`, `66.248.200.0/22`, `208.109.0.0/22`, `2a02:fe80::/29` |
| Auth | n/a |
| Update cadence | Rare. No notification mechanism documented. |
| Licence | n/a |
| Reliability | **Low-Med** (official text, must be hard-coded or scraped) |
| Notes | The page's own Apache 2.2 snippet omits `208.109.0.0/22`, so the page is inconsistent. ASN **AS30148** (SUCURI-SEC). Ship as a static list in the bundled baseline. |

Sources: [Sucuri Firewall troubleshooting guide](https://docs.sucuri.net/website-firewall/sucuri-firewall-troubleshooting-guide/) (accessed 2026-11-22).

### 1.14 Zscaler (forward proxy, not CDN)

| Field | Value |
|---|---|
| URL | `https://config.zscaler.com/api/<cloud>/cenr/json` for each cloud: `zscaler.net`, `zscalerone.net`, `zscalertwo.net`, `zscalerthree.net`, `zscloud.net`, `zscalerbeta.net`. Gov: `config.zscaler.us/zscalergov.net`. Hubs: `.../api/zscaler.net/hubs/cidr/json/recommended`. Upcoming: `.../api/zscaler.net/future/json`. |
| Format | JSON, nested by continent and city, with `range` entries |
| Auth | None |
| Size (verified) | zscaler.net cenr **132 KB** (~947 range entries). zscalertwo.net 135 KB. zscloud.net 134 KB. hubs 1.9 KB. future 1.1 KB. |
| Update cadence | Periodic. The `future` endpoint lists ranges before activation. |
| Licence | No explicit licence (UNVERIFIED) |
| Reliability | **High** (official Zscaler config portal; help.zscaler.com doc page did not render, **UNVERIFIED** doc text) |
| Notes | Label `forward-proxy:zscaler`. Merging all public clouds is simplest. ASNs AS22616, AS53813, AS62044. |

Sources: [config.zscaler.com zscaler.net CENR](https://config.zscaler.com/zscaler.net/cenr), JSON endpoints above, [zscaler-hero/zscaler-retrieve-whitelist-subnets](https://github.com/zscaler-hero/zscaler-retrieve-whitelist-subnets) (secondary, endpoint patterns) (accessed 2026-11-22).

### 1.15 Netskope (forward proxy, not CDN)

| Field | Value |
|---|---|
| URL | **No public machine-readable feed.** HTML doc lists NewEdge ranges. A "consolidated IP range list" is "accessible only to authorized customer contacts via login". |
| Ranges (as published) | `8.36.116.0/24`, `8.39.144.0/24`, `31.186.239.0/24`, `163.116.128.0/17`, `162.10.0.0/17` ("used for both ingress and egress of NewEdge DCs") |
| Reliability | **Low-Med** (static hard-code) |
| Notes | Label `forward-proxy:netskope`. ASN fallback **AS55256**. Dedicated egress IPs and BYOIP customers are outside the list. |

Sources: [Netskope NewEdge IP ranges for allowlisting](https://docs.netskope.com/en/newedge-ip-ranges-for-allowlisting) (accessed 2026-11-22).

### 1.16 Alibaba Cloud CDN / ESA

| Field | Value |
|---|---|
| URL | **No public feed.** API `DescribeL2VipsByDomain` (origin-fetch IPs) needs signed Alibaba Cloud credentials, ≥1 Gbps daily peak bandwidth, and a ticket to enable. One domain per call. |
| Reliability | **Low** |
| Notes | Alibaba recommends `ali-cdn-real-ip` / `X-Forwarded-For` instead of source IP. ASN fallback **AS45102**, **AS37963** (these are shared with Alibaba Cloud ECS, so they over-match). cdncheck carries an "aliyun" CIDR set (1,602 entries) from a community `sources_china.json` dataset (provenance UNVERIFIED). |

Sources: [Alibaba Cloud CDN: query IP addresses of POPs](https://help.aliyun.com/en/cdn/support/query-ip-addresses-of-pops-for-a-cdn-domain) (accessed 2026-11-22).

### 1.17 Tencent EdgeOne

| Field | Value |
|---|---|
| URL | **No public feed.** Per-site API `DescribeOriginACL` (teo, version 2022-09-01) returns `CurrentOriginACL` / `NextOriginACL` (with `PlannedActiveTime`). Needs Tencent Cloud API credentials and origin protection enabled on the zone. |
| Update cadence | Tencent recommends polling "at a low-frequency (recommended every three days)". `NextOriginACL` gives advance notice. |
| Reliability | **Low** (customer-specific, auth) |
| Notes | ASN fallback **AS132203** (shared with Tencent Cloud). |

Sources: [EdgeOne DescribeOriginACL](https://edgeone.ai/document/71118) (accessed 2026-11-22).

### 1.18 Others with no usable public feed

| Vendor | Status (2026-11-22) | Best fallback |
|---|---|---|
| **StackPath / Highwinds** | CDN shut down **2023-11-22**. Company liquidated **June 2024**. Akamai took ~100 enterprise contracts. MISP's stackpath list is now empty. | **None, and don't use the old ASNs.** RIPEstat now shows **AS12989 = "BlackHOST"** and **AS33438 = "Datum"**. Both were reallocated, so ASN matching would mislabel unrelated hosts. Ex-StackPath customers are now on Akamai or Gcore. |
| **Edgio / Limelight / Edgecast** | Edgio CDN went offline **2025-01-15** (Chapter 11). Akamai bought customer contracts. Edgecast brand/tech sold to Parler Cloud Technologies in 2025. | **AS22822 (LLNW)** and **AS15133 (Edgecast)** are **not announced** on RIPEstat today, so there is nothing to match. Old tickets only: treat as historical. |
| **Akamai Prolexic** | Routed mode: the customer's _own_ prefixes are advertised via Akamai and clean traffic returns over GRE, **so the origin sees real client IPs**. Proxy mode (IP Protect) is per-customer VIP mapping. | No feed. **AS32787** (PROLEXIC, Akamai) for proxy-mode egress. Customer-specific otherwise. |
| **Radware Cloud WAF** | No public list. The support article uses placeholder ranges. The real list is in the customer portal. | **AS25773** (RADWARE-CLOUD-SERVICES). Med confidence. |
| **Vercel** | Publishes no edge or origin-pull ranges. Default egress is a shared dynamic pool. Static IPs are a paid per-project option. | None. Anycast ingress `76.76.21.0/24` is in AS16509 (AWS). Vercel rewrite/proxy egress to an origin comes from AWS dynamic space, which is indistinguishable from AWS. Recommend header-based detection (`x-vercel-*`, UNVERIFIED header names). |
| **Netlify** | "We do not publish that address list anywhere (and it changes a lot)" (support forum, not docs). | None. Ingress `75.2.60.0/24` is in AS16509. |
| **CacheFly** (bonus) | `https://cachefly.cachefly.net/ips/cdn.txt` exists (verified **165 B**, 10 v4 CIDRs). No doc page found (**UNVERIFIED**). | Feed above, low priority. |

Sources: [DCD: StackPath to close](https://www.datacenterdynamics.com/en/news/stackpath-to-close-down-liquidate-assets/), [DCD: StackPath quits CDN, Akamai buys contracts](https://www.datacenterdynamics.com/en/news/stackpath-quits-cdn-business-akamai-buys-enterprise-customer-contracts/), [Edgio (Wikipedia)](https://en.wikipedia.org/wiki/Edgio), [DCD: Akamai acquires Edgio contracts](https://www.datacenterdynamics.com/en/news/akamai-acquires-customer-contracts-from-bankrupt-cdn-firm-edgio/), [Akamai Prolexic routed BGP sessions API](https://techdocs.akamai.com/prolexic/reference/post-routed-bgp-sessions), [Radware support a_id 1018574](https://support.radware.com/app/answers/answer_view/a_id/1018574/), [Vercel static IPs KB](https://vercel.com/kb/guide/how-to-allowlist-deployment-ip-address), [Netlify forum: IP list](https://answers.netlify.com/t/list-of-netlify-ip-adresses-for-whitelisting/1338), RIPEstat `as-overview` / `prefix-overview` API `https://stat.ripe.net/data/as-overview/data.json?resource=ASxxxx` (all accessed 2026-11-22).

---

## 2. Vendors with no feed: ASN fallback list

ASN matching is a **fallback with a lower-confidence verdict** (`likely-cdn:<vendor> (ASN)`). Expand ASNs to prefixes offline at build time
(RIPEstat `announced-prefixes`, or a CC0 aggregator, see section 3). Don't do live BGP lookups in the tool. All holders below were verified
on RIPEstat 2026-11-22.

| Vendor | ASN(s) | Holder (RIPEstat) | Use? / caveat |
|---|---|---|---|
| Akamai | **AS20940**, **AS16625**, AS35994, AS26008 (+ ~35 more in cdncheck's list) | Akamai International B.V. / Akamai Technologies | Yes, as fallback. Akamai also owns Linode cloud ASNs (AS63949, in cdncheck's Akamai WAF list), which carry **customer VMs = possible attackers**. Exclude AS63949. AS18680 is not announced. |
| Akamai Prolexic | **AS32787** | PROLEXIC-TECHNOLOGIES (Akamai) | Proxy mode only |
| Sucuri | **AS30148** | SUCURI-SEC | Yes (published ranges preferred) |
| Radware | **AS25773** | RADWARE-CLOUD-SERVICES | Yes, Med |
| Netskope | **AS55256** | NETSKOPE | Yes, label forward-proxy |
| Zscaler | AS22616, AS53813, AS62044 | ZSCALER | Feed preferred |
| F5 XC | **AS35280** | F5 Networks SARL | Feed preferred |
| CDN77 / Bunny (Datacamp) | AS60068, AS212238 | Datacamp Limited | Label "Datacamp CDN" only |
| Bunny | AS200325 | BUNNYWAY | Feed preferred |
| Gcore | AS199524 | G-Core Labs | Feed preferred. Gcore also sells cloud VMs from this ASN (UNVERIFIED), so it may over-match. |
| Imperva | AS19551 | INCAPSULA | Feed preferred |
| Fastly | AS54113 | FASTLY | Feed preferred. Fastly Compute egress shares the ASN. |
| Cloudflare | AS13335, AS209242 | CLOUDFLARENET / Cloudflare London | **Never use ASN.** WARP / Private Relay / Workers egress are real clients. |
| Alibaba | AS45102, AS37963 | Alibaba | **Don't use.** Shared with ECS, which over-matches attackers. |
| Tencent | AS132203 | Tencent | **Don't use.** Shared with Tencent Cloud. |
| Microsoft | AS8075 | Microsoft | **Don't use.** Use the AFD service tag. |
| Google | AS15169, AS396982 | Google | **Don't use.** AS396982 is GCP customer space. |
| Amazon | AS16509, AS14618 | Amazon | **Don't use.** Use CloudFront service tags. |
| StackPath / Highwinds | ~~AS12989~~, ~~AS33438~~ | now BlackHOST / Datum | **Reallocated, so never use** |
| Limelight / Edgecast | ~~AS22822~~, ~~AS15133~~ | not announced | Dead |

---

## 3. Aggregators

| Project | Licence | Update | Coverage | Pros | Cons |
|---|---|---|---|---|---|
| **projectdiscovery/cdncheck** (`sources_data.json`, generated from `cmd/generate-index/provider.yaml`) | **MIT** (verified via GitHub API) | GitHub Action `fingerprint-update.yml`, cron `0 0 * * 0` (**weekly, Sunday**). Pulls vendor URLs and expands ASNs via the ipinfo API (`IPINFO_TOKEN` secret). Last data commit 2026-11-02. F5 XC added 2026-10-25. China CDNs added 2026-10-20. | `cdn`: cloudfront (211), fastly (21), gcore (1,821), google (401), f5 (43), aliyun, tencent, wangsu, baidu, and others. `waf`: cloudflare (1,078), incapsula (12), f5 (43). `cloud`: aws, azure (95,557), google, oracle, zscaler (935), office365. File **2.5 MB**. | One MIT file and a single fetch (raw.githubusercontent). Already has F5 XC and China CDNs. Has a CNAME/FQDN suffix map for later use. | **Akamai, Sucuri, Bunny, AFD, Imperva-v6 and Netskope are absent or broken** in the current `sources_data.json`: Akamai/Sucuri are defined by ASN in `provider.yaml` but produced 0 entries in the generated file. Cloudflare (1,078 entries) is ASN/ipinfo-derived (`ipinfo.io/widget/demo/cloudflare.com?dataset=ranges`), so it **includes WARP and non-proxy space**, the exact false positive we need to avoid. "google CDN" = all goog.json (over-matches). CloudFront uses `CLOUDFRONT` from list-cloudfront-ips (v4 only). Azure = whole cloud, no AFD split. Third-party pipeline with no SLA. |
| **MISP/misp-warninglists** (`lists/<vendor>/list.json`) | **CC0 1.0** (README) | Regenerated periodically. Versions seen: 20261014. | akamai (346, "from BGP search"), cloudflare, fastly, gcore, imperva, bunny-net, cdn77, sucuri, zscaler, microsoft-azure, amazon-aws, google, stackpath (empty). | Public domain, so it is safe to bundle. Per-vendor files with clear provenance in `description`. | Month-level lag. Akamai is BGP-derived. No AFD-Backend-only list (whole Azure). |
| **rezmoss/cloud-provider-ip-addresses** | **CC0 1.0** | "Daily-updated" (last push 2026-11-22) | 60+ providers incl. akamai (10,767 CIDRs, BGP), bunny (48, BGP), cachefly, cloudflare (22, official), fastly, gcore, imperva, sucuri (31, BGP), zscaler | CC0. Daily. jsDelivr mirror (`fastly.jsdelivr.net/gh/...`) as a fallback host. | Several vendors are **BGP-derived** rather than vendor lists (Bunny-via-BGP misses the Datacamp-hosted edges). Single maintainer. |
| **lord-alfred/ipranges** | **CC0 1.0** | Daily (pushed 2026-11-22) | Google, Bing, AWS, Microsoft, Oracle, DigitalOcean, GitHub, Facebook, Twitter, Linode, and others. Mostly cloud and bots. | CC0, popular (1.2k stars) | Little CDN-edge specificity |
| **tobilg/public-cloud-provider-ip-ranges** | MIT | Daily (pushed 2026-11-22) | AWS, Azure, CloudFlare, GCP, and others | Unified schema | Cloud-centric |
| **SecOps-Institute/Akamai-ASN-and-IPs-List** | MIT | "Hourly checked" via RADB (pushed 2026-11-09) | Akamai only (ASN-derived) | Only maintained Akamai ASN expansion | RADB-derived, so it includes Linode/customer space unless filtered |
| femueller/cloud-ip-ranges, disposable/cloud-ip-ranges | **No licence** | — | Cloud | — | **Not licence-safe to bundle** (no licence = all rights reserved) |
| client9/ipcat | MIT | **Archived** (2023) | — | — | Dead |

**Licence verdict:** MIT (cdncheck, tobilg, SecOps) and CC0 (MISP, rezmoss, lord-alfred) are safe to bundle in a closed internal .exe. MIT needs the copyright notice reproduced in an About / THIRD-PARTY file. Repos without a licence must not be bundled. The **vendor facts themselves** have no licence. Fetching them directly from the vendor is the cleanest option.

Sources: [cdncheck repo](https://github.com/projectdiscovery/cdncheck), [cdncheck provider.yaml](https://raw.githubusercontent.com/projectdiscovery/cdncheck/main/cmd/generate-index/provider.yaml), [cdncheck sources_data.json](https://raw.githubusercontent.com/projectdiscovery/cdncheck/main/sources_data.json), [cdncheck fingerprint-update.yml](https://raw.githubusercontent.com/projectdiscovery/cdncheck/main/.github/workflows/fingerprint-update.yml), [MISP warninglists](https://github.com/MISP/misp-warninglists), [rezmoss/cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses), [lord-alfred/ipranges](https://github.com/lord-alfred/ipranges), [tobilg/public-cloud-provider-ip-ranges](https://github.com/tobilg/public-cloud-provider-ip-ranges), [SecOps-Institute/Akamai-ASN-and-IPs-List](https://github.com/SecOps-Institute/Akamai-ASN-and-IPs-List), GitHub REST API repo metadata (all accessed 2026-11-22).

---

## 4. Recommended v1 feed set

Goal: top coverage of what OutSystems customers actually put in front of ALB/IIS, with the least maintenance. Every live feed below is
unauthenticated HTTPS GET and needs no keys or sign-ups.

### Tier 1: live fetch from the vendor (auto-update, High reliability)

| # | Vendor | Feed | Extract | Refresh check |
|---|---|---|---|---|
| 1 | Cloudflare | `api.cloudflare.com/client/v4/ips` (+ `?networks=jdcloud`) | ipv4/ipv6 (+ jdcloud) | `etag` |
| 2 | CloudFront | `ip-ranges.amazonaws.com/ip-ranges.json` | `service` ∈ {`CLOUDFRONT`} (tag the `CLOUDFRONT_ORIGIN_FACING` subset) | `syncToken`. Cache only the ~340 extracted prefixes, not 2.8 MB. |
| 3 | Akamai | techdocs `akamai_ipv4_CIDRs.txt` / `akamai_ipv6_CIDRs.txt` | all | content hash |
| 4 | Azure Front Door | Download Center scrape → `ServiceTags_Public_*.json` | `AzureFrontDoor.Backend` (+ `Frontend` tagged as client-side) | top `changeNumber` |
| 5 | Fastly | `api.fastly.com/public-ip-list` | all | hash |
| 6 | Imperva | `my.imperva.com/api/integration/v1/ips` | all (`res==0`) | hash |
| 7 | Gcore | `api.gcore.com/cdn/public-net-list` | all (drop bogons) | hash |
| 8 | Bunny | `api.bunny.net/system/edgeserverlist` + `/ipv6` | exact IPs | hash |
| 9 | F5 XC | `docs.cloud.f5.com/docs-v2/downloads/.../ips-domains.json` | `regional_edges` + `cdn` only | hash |
| 10 | Zscaler | `config.zscaler.com/api/<cloud>/cenr/json` for the 6 public clouds | all `range` → **forward-proxy** | hash |

### Tier 2: static baseline shipped in the .exe (hand-maintained, reviewed on each LogHunter release)

- Sucuri (4 v4 + 1 v6), Netskope NewEdge (5 v4, forward-proxy), Google GFE / internet NEG (`130.211.0.0/22`, `35.191.0.0/16`,
  `34.96.0.0/20`, `34.127.192.0/18`), CDN77 snapshot (38), KeyCDN shield (2).
- Low-confidence ASN-derived prefixes (expanded at build time from a CC0 aggregator such as rezmoss/MISP): Akamai AS20940/AS16625 (minus
  Linode AS63949), Radware AS25773, Prolexic AS32787. Label these `likely-<vendor> (ASN)`.

### Engineering rules for the updater (vendor-agnostic)

1. **Bundled snapshot first.** The .exe ships with the full Tier 1 + Tier 2 data as of build date, so it works offline on day one.
2. **Background refresh** at most once per 24 h per feed (Bunny/Gcore churn daily, the others rarely). Use `If-None-Match`/hash and never block the UI.
3. **Validate before swap**: valid JSON, parse every CIDR, reject empty results or a >50% shrink versus the cached copy (a guard like cdncheck's "category dropped to zero" check), strip RFC1918, CGNAT, loopback and bogon entries (Gcore shipped `172.31.0.24/32`).
4. **Per-feed last-good cache** in `%LOCALAPPDATA%\LogHunter\cdn\`, with `fetched_at` and vendor version token (syncToken / etag / changeNumber), shown in the UI as data age.
5. **Verdict carries provenance**: `cdn-edge:cloudflare (vendor feed, 2026-11-22)` versus `likely-cdn:akamai (ASN)` versus `forward-proxy:zscaler`.
6. **Never classify by** `AMAZON`, AS16509, AS8075, AS15169/AS396982, AS13335, Alibaba or Tencent ASNs. All of these hold customer compute = real attackers.
7. **RFC1918 `client` on an internet-facing ALB** means a "private hop" hint (CloudFront VPC origin, internal proxy). Show the X-Forwarded-For guidance.

### Why not just consume cdncheck?

It is the right _shape_ (one MIT file, weekly CI), but today it **misses Akamai, Sucuri, Bunny and AFD-Backend**, which are the vendors we
most need beyond Cloudflare. Its **Cloudflare set is ASN-derived and over-matches WARP users**, and its "google CDN" is all Google. If
the team wants zero vendor-specific code, cdncheck could be a secondary/backfill source (MIT, keep the notice) layered _under_ the Tier 1 vendor
feeds, never over them.
