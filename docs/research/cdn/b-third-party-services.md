# B. Third-party services and databases for CDN / proxy / hosting IP classification

Research angle: can an external service or database tell LogHunter that an IP from an ALB/IIS log (or a customer hostname) belongs to a CDN, WAF, reverse proxy, or hosting provider, in bulk, and stay current inside the app?

All URLs accessed 2026-11-22 unless stated otherwise. **UNVERIFIED** marks claims taken from vendor marketing, third-party summaries, or memory that I could not confirm on a primary page.

---

## 1. TL;DR

- **"CDN Finder" tools classify a hostname, not a client IP.** CDN Planet CDN Finder, turbobytes/cdnfinder, whatCDN/findcdn, BuiltWith and Wappalyzer take a URL or hostname and look at DNS CNAME chains and HTTP response headers. They answer "is `app.customer.com` behind Cloudflare?", not "is `172.70.100.1` in my ALB log a Cloudflare edge?". That still helps as a **pre-check** (if the customer's hostname resolves to Cloudflare, every log IP is suspect). It does not help with **per-IP classification**.
- **Only a few IP datasets label "CDN" explicitly.** These are AbuseIPDB `usageType = "Content Delivery Network"` (we already have a key, data sourced from IPinfo), IP2Location / IP2Location.io `usage_type = CDN` (paid tiers), MaxMind GeoIP `user_type = content_delivery_network` (paid Enterprise / Insights), ipgeolocation.io `network.is_cdn` + `cdn_provider_name` (paid), Shodan InternetDB tag `cdn`, ProjectDiscovery `cdncheck` (cdn / waf / cloud plus provider name), and GreyNoise Business Services (ex-RIOT). Most of the others give only "hosting / datacenter" or a raw ASN.
- **Scan-based data misses the IPs that matter.** I tested Shodan InternetDB live. It returns `tags:["cdn"]` for Fastly `151.101.1.1`, but **"No information available"** for Cloudflare `172.70.100.1` and `162.158.1.1`. Those are exactly the origin-pull egress IPs that show up in customer ALB logs. Egress IPs do not listen on ports, so scanners never index them.
- **ASN-level "CDN" tags are too coarse for a block / don't-block decision.** The bgp.tools CDN tag (111 ASNs) includes AS16509 Amazon, AS15169 Google, AS16276 OVH, AS4134 China Telecom and AS22773 Cox. Those ASNs also host real attackers (EC2, GCE, OVH VPS) and real home users.
- **Recommendation:** use offline, provider-published ranges plus an embedded refreshable dataset as the primary source (ProjectDiscovery `cdncheck` `sources_data.json`, MIT, weekly bot refresh), with **iptoasn.com** (PDDL, hourly, no token) or **IPinfo Lite** (CC BY-SA, daily, free token) for ASN and org name. Use **AbuseIPDB `usageType`** as the online second opinion, since we already have the key and client. The best paid option is **IPinfo Core/Plus** (`as_type`, `is_anycast`, `is_hosting`, downloadable DB). The alternative is **MaxMind GeoIP Enterprise** (`user_type = content_delivery_network`, `is_anycast`, offline MMDB).

---

## 2. Comparison table

Legend: **Input** IP / Host. **CDN label** = explicit CDN classification, not just "hosting". **Offline** = downloadable DB usable without per-lookup network calls.

| # | Service | Input | Explicit CDN label? | Bulk | Offline DB | Update freq | Free tier | Paid ballpark | Licence for internal commercial use | Privacy (data leaves us?) |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | CDN Planet CDN Finder | Host / URL | Yes (CDN name) | No public bulk. API "contact us" | No | n/a | Web UI only | Unknown (sales) | Web tool ToS. API by contract | **Sends customer hostname** |
| 2 | turbobytes/cdnfinder (OSS) | Host / URL | Yes (CNAME + headers) | Self-host server | Yes (self-host) | **Deprecated** | Free (MIT) | n/a | MIT | Local, but resolves DNS / fetches site |
| 3 | whatCDN / cisagov findcdn / cdn-detector.js | Host | Yes | Library | Yes | Community, irregular | Free OSS | n/a | OSS | Local DNS / HTTP to the customer site |
| 4 | BuiltWith Domain API | Host | Yes (tech category "CDN") | 16 domains/call | No | Crawl-based | Free API = counts only | $295-$995/mo | Commercial subscription | **Sends customer hostname** |
| 5 | Wappalyzer Lookup API | URL | Yes (tech category) | 10 URLs/req | No | Crawl / live | 50 credits (no API) | Business ~$450/mo | Commercial subscription | **Sends customer URL** |
| 6 | **ProjectDiscovery cdncheck** | **IP** + host | **Yes: cdn / waf / cloud + provider** | Library / CLI, unlimited local | **Yes** (embedded `sources_data.json`) | Weekly bot "fingerprints update" + PRs | Free | n/a | **MIT** | None at lookup time |
| 7 | Shodan InternetDB | IP | Tag `cdn`, `cloud` | 1 IP/call, no key | No | Weekly | Free, **non-commercial only** | Enterprise licence | **Non-commercial**. Our use needs an enterprise licence | Sends IP |
| 8 | Censys (Platform) | IP / host | No explicit CDN flag found (UNVERIFIED) | Multi-host lookup | No | Continuous scan | Free: lookups only, about 250/mo (UNVERIFIED) | Credits from $100 | Commercial ToS | Sends IP |
| 9 | **AbuseIPDB `check`** | IP | **Yes: `usageType` "Content Delivery Network"** | No bulk check (1 IP/call) | No | Live | **1,000 checks/day** (Standard) | Paid tiers higher | Already in use | Sends IP (already done today) |
| 10 | IPinfo Lite | IP | No (ASN, AS name, AS domain, country) | Unlimited API + DB | **Yes** (MMDB / CSV / JSON / Parquet) | **Daily** | **Free, unlimited** | n/a | **CC BY-SA 4.0** (attribution + ShareAlike) | None if DB used |
| 11 | IPinfo Core / Plus / Max | IP | Partial: `as_type` hosting/isp/business/edu/gov, `is_hosting`, `is_anycast`. No literal "CDN" field found | Batch API + DB | Yes | Daily | No | Quote / tiered (UNVERIFIED pricing) | Commercial licence | None if DB used |
| 12 | IP2Location.io API | IP | **Yes: `usage_type` CDN** (Starter+), `as_usage_type` (Security) | Bulk on paid | No (API) | Live | 50k queries/mo, **no usage_type** | $49 / $249 / $499 per mo | Commercial ToS, attribution on free tier | Sends IP |
| 13 | IP2Location DB (commercial) / IP2Proxy | IP | **Yes: usage type CDN** (DB23+ / PX-series) | Offline | Yes (BIN / CSV) | Monthly (LITE). Commercial daily/monthly (UNVERIFIED) | IP2Proxy LITE = public proxies only | Commercial DB pricing (UNVERIFIED) | LITE free with attribution | None |
| 14 | MaxMind GeoLite2 ASN | IP | No (ASN + org) | Offline | Yes (MMDB) | Twice weekly (UNVERIFIED) | Free with account; 30 downloads/day | n/a | GeoLite EULA, attribution, delete within 30 days of a new release | None |
| 15 | MaxMind GeoIP Enterprise / Insights / Anonymous IP | IP | **Yes: `user_type = content_delivery_network`**, `is_anycast`, `is_hosting_provider` | Offline (Enterprise) / API (Insights) | Yes (Enterprise, Anonymous IP) | Weekly or more (UNVERIFIED) | No | Anon IP ~$150-300/mo, Insights ~$0.002/query (third-party estimates, UNVERIFIED) | Commercial EULA | None if DB used |
| 16 | ipapi.is | IP | No (`is_datacenter` + datacenter provider name, `is_anycast`) | POST 100 IPs/call (1,000 on higher tiers) | Self-host on Business ($200/mo) | Daily (Business) | 1,000/day | Credits from $1 (30k req/$) | Commercial allowed | Sends IP (unless self-hosted) |
| 17 | ipgeolocation.io | IP | **Yes: `network.is_cdn`, `cdn_provider_name`** (paid) | Bulk on paid | DB sold separately (UNVERIFIED) | Live | Free tier has no CDN fields | From $19/mo for 150k credits | Commercial ToS | Sends IP |
| 18 | ipdata | IP | No (`is_datacenter`, `asn.type = hosting`) | 100 IPs/call | No | Threat data hourly | 1,500/day, **commercial use restricted** | $10-$120/mo (third-party) | Free tier not for commercial | Sends IP |
| 19 | IPQualityScore | IP | No (`connection_type = Data Center`) | API. Flat-file DB on enterprise | Enterprise | Live | ~1,000/mo (35/day) | Up to $1,150/mo+ | Commercial ToS | Sends IP |
| 20 | Spur.us | IP | No CDN label found (`infrastructure: DATACENTER`, tunnels / VPN) | Feeds (Enterprise) | Feeds (Enterprise) | Daily feeds | Community: 0 API calls | Teams ~$200/mo, Pro ~$1,600/mo | Commercial | Sends IP |
| 21 | DB-IP IP-to-ASN Lite | IP | No (ASN + org) | Offline | Yes (CSV / MMDB) | **Monthly** | Free | Commercial ISP DB | **CC BY 4.0** | None |
| 22 | **iptoasn.com** | IP | No (ASN, country, AS description) | Offline TSV | **Yes** | **Hourly** | Free, **no token** | n/a | **PDDL (public domain)** | None |
| 23 | Team Cymru IP-to-ASN | IP | No (origin ASN, prefix, AS name) | WHOIS bulk (`begin`/`end`, ~10k IPs/min) / DNS TXT | No | Live BGP | Free | n/a | Free community service, no explicit ToS on page | Sends IP |
| 24 | RIPEstat Data API | IP / ASN | No (prefix, origin ASN) | No limit; 8 concurrent | No | Live | Free; register `sourceapp` if >1,000/day | n/a | RIPEstat T&C (not reviewed) | Sends IP |
| 25 | bgp.tools | IP / ASN | ASN tag `cdn` (111 ASNs), `vpsh` hosting, `ddosm`, `anycast` | `table.jsonl`, `asns.csv` (with `class`), tag `.csv`, WHOIS bulk | Yes (dumps) | Table ~30 min, ASN CSV daily | Free with a proper User-Agent | Paid plans exist (not reviewed) | Terms not reviewed (UNVERIFIED) | None for dumps |
| 26 | PeeringDB | ASN | `net.info_type` "Content" (self-declared, UNVERIFIED value list) | 150 ASNs/query, 20 req/min anonymous | Local cache (`peeringdb-py`) | Live | Free | n/a | PeeringDB AUP (not reviewed) | None (ASN only) |
| 27 | GreyNoise Business Services (ex-RIOT) | IP | **Yes: category incl. CDN, cloud, public_dns** + trust level | Enterprise only | No | Regular | Community: 10/day anonymous, 50/week with business email | Enterprise (quote) | Unclear for free tier | Sends IP |

---

## 3. What "CDN Finder" can and cannot do for us

**What CDN Planet CDN Finder actually does** ([cdnplanet.com/tools/cdnfinder](https://www.cdnplanet.com/tools/cdnfinder/)):
- Input is a **website hostname or URL**. It can scan a whole page for all CDNs or check a single host.
- Method: HTTP response headers, then the DNS CNAME chain, then, as a last resort, the ASN of the resolved server IP (via IPtoASN, per [CDN Planet blog](https://www.cdnplanet.com/blog/all-new-cdn-finder/)).
- **No public API, no documented bulk mode.** It says "Contact us to learn more about the CDN Finder API with Multi-CDN detection" (info@cdnplanet.com).
- The open-source predecessor [turbobytes/cdnfinder](https://github.com/turbobytes/cdnfinder) (MIT, CNAME + header matching, self-hostable JSON server on :1337) is **marked deprecated** and points users back to CDN Planet.

**Can do for LogHunter:**
1. **Front-door check per incident:** "Is the customer's public hostname behind Cloudflare / Akamai / CloudFront / Imperva?" If yes, the ALB `client:port` column is almost certainly CDN egress, and LogHunter should warn before the operator publishes a top-N IP list. A local CNAME + header check (our own code, or the cnamechain approach from cdnfinder / cdncheck `common.fqdn`) does this **without sending the hostname to a third party**.
2. **Name the CDN vendor** so the operator knows which header to ask for (`CF-Connecting-IP`, `True-Client-IP`, `X-Forwarded-For`).

**Cannot do:**
1. **Classify individual client IPs from a 40 GB log.** It takes no IP input.
2. **Bulk:** web UI only. The API is sales-gated.
3. **Offline / always current in-app:** it is an online service, and the OSS version is unmaintained.
4. **Multi-CDN or mixed traffic:** a host can be behind a CDN while some traffic still hits the ALB directly (origin bypass). Hostname classification cannot tell which log lines came through the CDN. Only per-IP classification can.

Same story for **BuiltWith** (Domain API, $295+/mo, 16 domains/call) and **Wappalyzer** (Lookup API needs Business ~$450/mo): hostname-in, technology-out, paid, and they require sending customer hostnames to a third party. **"WhatCDN"** is not a hosted service. The name matches a ~6-year-old Python library ([Pascal-0x90/whatCDN](https://github.com/Pascal-0x90/whatCDN)) that points to [cisagov/findcdn](https://github.com/cisagov/findcdn).

**Bottom line:** CDN-finder tools are a nice pre-flight hint, but the real requirement (bulk, per-IP, in-app, current) needs IP-range or IP-intelligence data.

---

## 4. Per-service notes

### 4.1 ProjectDiscovery cdncheck (strongest free per-IP fit)
- Repo: [github.com/projectdiscovery/cdncheck](https://github.com/projectdiscovery/cdncheck). **MIT**. Go library + CLI. Input: IPs or DNS names. Output: category (cdn / waf / cloud) + provider name.
- Data is compiled from `cmd/generate-index/provider.yaml` into `sources_data.json` ([provider.yaml](https://raw.githubusercontent.com/projectdiscovery/cdncheck/main/cmd/generate-index/provider.yaml)):
  - **CDN (URL sources):** CloudFront (`list-cloudfront-ips`), Fastly (`api.fastly.com/public-ip-list`), Google (`goog.json`), Gcore (`api.gcore.com/cdn/public-ip-list`), plus China CDN CIDRs (Aliyun, Wangsu, Tencent, Baidu) added Oct 2026.
  - **WAF:** Cloudflare (`api.cloudflare.com/client/v4/ips`), Akamai (**ASN list**), Sucuri (AS30148), ArvanCloud, F5 (static CIDR). Imperva / Incapsula appears **only as an FQDN** (`impervadns.net`), with no IP ranges. That is a gap: AS19551 should be added on our side.
  - **Cloud:** AWS, Google, Oracle, Azure, Zscaler, Office365, plus Korean clouds.
- **Freshness:** a GitHub Actions bot commits "Weekly fingerprints update" to `sources_data.json` almost every Sunday. There was a gap Sep 6 to Oct 19 2026, and the Nov 22 2026 scheduled run **failed** ([commits](https://github.com/projectdiscovery/cdncheck/commits/main/sources_data.json), [actions](https://github.com/projectdiscovery/cdncheck/actions)). So it is usable, but not something to depend on blindly.
- **How LogHunter could use it from C#:** fetch the raw `sources_data.json` from GitHub at startup or on a daily refresh, cache it locally, and keep the last-known-good copy embedded as a fallback. Lookup is a CIDR match. No Go dependency needed. Licence is MIT, so a copy can be embedded in the public exe with notice.
- Caveat: Cloudflare is classed as "waf", not "cdn". For our purposes treat cdn and waf both as "edge proxy, do not block".

### 4.2 AbuseIPDB `usageType` (reuses our existing key)
- [docs.abuseipdb.com](https://docs.abuseipdb.com/): the `check` endpoint returns `usageType`. Possible values: Commercial, Organization, Government, Military, University/College/School, Library, **Content Delivery Network**, Fixed Line ISP, Mobile ISP, **Data Center/Web Hosting/Transit**, Search Engine Spider, Reserved.
- AbuseIPDB says: "Geolocation, usage type, ISP, and domain name are sourced from the IPinfo." So this is IPinfo classification delivered through a key we already have.
- Limits (Standard / free): **check 1,000/day**, check-block (subnet) 100/day, bulk-report 5/day. **No bulk check endpoint.** That is fine for top-N (10 to 100 IPs). It is not enough for 10,000-IP lists.
- The app already sends IPs to AbuseIPDB, so this adds no new privacy exposure.
- Accuracy: I could not fetch AbuseIPDB pages for Cloudflare egress IPs (HTTP 403 to automated GET). Whether `172.70.0.0/15` returns "Content Delivery Network" or "Data Center/Web Hosting/Transit" is **UNVERIFIED**. Verify in-app with the existing key before relying on it.

### 4.3 IPinfo
- **Lite** ([blog](https://ipinfo.io/blog/ipinfo-lite-free-accurate-unlimited-ip-data), [Lite DB](https://ipinfo.io/developers/ipinfo-lite-database), [FAQ](https://community.ipinfo.io/t/ipinfo-lite-faq/6768)):
  - Free and unlimited, API and download (CSV / MMDB / JSON / Parquet, MMDB ~26 MB), **updated daily**.
  - Fields: country, continent, ASN, AS name, AS domain.
  - Licence: **CC BY-SA 4.0**. Commercial use allowed with attribution, and ShareAlike applies to adapted databases.
  - Download needs a free account token.
  - **No `as_type`, no hosting flag**: those are Core/Plus only.
- **Core / Plus / Max** ([Core](https://ipinfo.io/products/core), [Core API](https://ipinfo.io/developers/core-api), [Privacy DB](https://ipinfo.io/products/anonymous-ip-database)):
  - `as.type` ∈ {hosting, isp, education, government, business}, plus `is_hosting`, `is_anycast`, and VPN / proxy / tor / relay flags.
  - Example from the docs: 1.1.1.1 shows Cloudflare AS13335, type hosting, `is_anycast: true`.
  - **No literal "CDN" value** in Core, even though AbuseIPDB (sourced from IPinfo) shows "Content Delivery Network". IPinfo's enterprise data may hold a finer company type (UNVERIFIED).
  - Downloadable DB available, so there are no per-lookup privacy concerns.
- `ipinfo.io` refused TLS from this environment (WebFetch and curl both failed, probably the corporate proxy). Worth checking that the LogHunter host can reach it before choosing it.

### 4.4 IP2Location / IP2Proxy
- Usage type codes ([web service page](https://www.ip2location.com/web-service/ip2location)): COM, ORG, GOV, MIL, EDU, LIB, **CDN**, ISP, MOB, **DCH** (data center / hosting / transit), SES, RSV.
- The legacy Web Service is **closed to new registrations**. Use [IP2Location.io](https://www.ip2location.io/pricing) instead:
  - Free: 50k/mo, **no usage_type**.
  - Starter $49/mo adds `usage_type` and bulk.
  - Security $499/mo adds `as_usage_type` and datacenter detection.
- **IP2Proxy LITE PX11** ([page](https://lite.ip2location.com/database/px11-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential-provider)) includes `usage_type`, but **only covers public proxy IPs**, so it is useless for CDN classification. Free with attribution. BIN is 1.45 GB.
- The commercial IP2Location DB23+ (offline, includes usage type) is a viable paid offline option. Pricing not checked (UNVERIFIED).

### 4.5 MaxMind
- **GeoLite2 ASN** ([page](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)): free, account + licence key, 30 downloads/day, GeoLite EULA with attribution, and you must **delete old DBs within 30 days of a new release**. ASN and org only.
- **GeoIP Enterprise** ([docs](https://dev.maxmind.com/geoip/docs/databases/enterprise/)): offline. `user_type` includes **`content_delivery_network`** and `hosting`. Also `is_anycast`, `connection_type`, isp / organization. Also available in GeoIP Insights / City Plus web services ([responses](https://dev.maxmind.com/geoip/docs/web-services/responses/)).
- **Anonymous IP** ([docs](https://dev.maxmind.com/geoip/docs/databases/anonymous-ip/binary/)): `is_hosting_provider`, VPN / proxy / tor. Estimated ~$150-300/mo ([Vendr](https://www.vendr.com/buyer-guides/maxmind), UNVERIFIED).
- A first-party .NET reader exists (`MaxMind.GeoIP2` / `MaxMind.Db` NuGet), so integration is low effort.

### 4.6 ipapi.is
- [ipapi.is](https://ipapi.is/): `is_datacenter` + `datacenter` object (provider name, network), plus `is_anycast`, `is_proxy`, `is_vpn`, and more. **No CDN flag.**
- Free 1,000/day; unauthenticated calls get only 10 fields. Bulk POST 100 IPs/call. Self-hosted DB on Business ($200/mo).
- Live test of `172.70.100.1` (unauthenticated) returned company "Cloudflare, Inc.", AS13335, Chicago, but no datacenter flag in the reduced response.

### 4.7 ipgeolocation.io
- `network.is_cdn` and `network.cdn_provider_name` (e.g. "Cloudflare"), alongside `is_anycast` and `security.is_cloud_provider`. **Paid plans only**, from $19/mo ([pricing](https://ipgeolocation.io/pricing.html), [docs](https://ipgeolocation.io/documentation/ip-location-api.html)).
- One of the few APIs with a literal CDN boolean plus provider name. Accuracy is unknown (UNVERIFIED).

### 4.8 ipdata, IPQualityScore, Spur
- **ipdata** ([docs](https://docs.ipdata.co/docs/proxy-tor-and-threat-detection)): `threat.is_datacenter`, `asn.type = hosting`, no CDN label. Free tier 1,500/day, but **commercial use restricted**.
- **IPQualityScore** ([response params](https://www.ipqualityscore.com/documentation/proxy-detection-api/response-parameters)): `connection_type` ∈ Residential / Corporate / Education / Mobile / **Data Center**. Fraud-focused, no CDN label, free tier ~1,000/mo.
- **Spur** ([Context API](https://docs.spur.us/context-api), [pricing](https://spur.us/pricing)): anonymisation and VPN intelligence (`infrastructure: DATACENTER`, tunnels). No CDN label, no free API (Teams ~$200/mo).
- None of the three solves "is this a CDN edge?" better than cheaper options.

### 4.9 Free ASN sources (feed a curated CDN-ASN list)
- **iptoasn.com** ([site](https://iptoasn.com/)): `ip2asn-v4.tsv.gz` / `-v6` / `-combined` with range, ASN, country, AS description. **Updated hourly. PDDL v1.0 (public domain). No token.** The public API was retired at the end of 2020, so download only. The easiest source to auto-refresh in-app.
- **DB-IP ASN Lite** ([page](https://db-ip.com/db/download/ip-to-asn-lite)): CC BY 4.0, **monthly**, CSV / MMDB. Attribution plus a backlink is required for web apps.
- **Team Cymru** ([page](https://www.team-cymru.com/ip-asn-mapping)): WHOIS bulk (`begin` / `verbose` / IPs / `end` over TCP 43, ~10k IPs/min) or DNS TXT (`origin.asn.cymru.com`). Free. Floods of single queries get null-routed. Good online fallback for 10,000-IP lists, but it sends IPs out.
- **RIPEstat** ([Data API](https://stat.ripe.net/docs/data_api)): `network-info` and `prefix-overview`. No request cap, 8 concurrent, register a `sourceapp` above 1,000/day.
- **bgp.tools** ([API kb](https://bgp.tools/kb/api), [tags](https://bgp.tools/tags/)): `table.jsonl` (prefix to origin, refreshed ~30 min), `asns.csv` (with `class`), and tag exports such as `/tags/cdn.csv`. A custom User-Agent is mandatory. The **CDN tag has 111 ASNs**, defined as ">10 Gbit/s of CDN traffic". It also includes AS16509 Amazon, AS15169 Google, AS16276 OVH, AS4134 China Telecom, AS22773 Cox and AS714 / AS6185 Apple ([tag list](https://bgp.tools/tags/cdn)). **Too broad to use as-is**, so curate it.
- **PeeringDB** ([query limits](https://docs.peeringdb.com/howto/work_within_peeringdbs_query_limits/)): `net.info_type` (e.g. "Content", "NSP", "Cable/DSL/ISP") is self-declared by the network operator; the exact value list is UNVERIFIED. 20 req/min anonymous, 150 ASNs per query. Useful only as a weak hint at the ASN level.

### 4.10 Scanner / threat-intel datasets
- **Shodan InternetDB** ([internetdb.shodan.io](https://internetdb.shodan.io/)): no key, tags include `cdn` and `cloud`, updated weekly. **Free for non-commercial use only.**
  - Live test (2026-11-22): Fastly `151.101.1.1` and `23.235.33.1` returned `tags:["cdn"]`.
  - **Cloudflare `172.70.100.1`, `162.158.1.1` and AWS `54.239.1.1` returned "No information available".**
  - Scan-based data does not cover CDN egress / origin-pull IPs, which are exactly what appear in origin logs.
- **Censys:** the free tier has lookups only (1 concurrent, ~250/mo per third-party sources, UNVERIFIED). I found no explicit CDN label ([tiers](https://docs.censys.com/docs/data-access-tiers-entitlements)). Same scan-coverage problem as Shodan.
- **GreyNoise Business Services (ex-RIOT)** ([docs](https://docs.greynoise.io/docs/riot-data)): ~150 M IPs of CDNs, update servers, public DNS / NTP, SaaS, and cloud security, with trust levels 1-3. Conceptually the closest match to "known-benign infrastructure, don't block", and the Community API returns `riot: true/false`. But the free tier gives **10 lookups/day anonymous or 50/week** with a business email ([community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api)). Bulk needs Enterprise. GreyNoise itself says the dataset "should not be used as a network Access Control List".

---

## 5. Privacy and compliance

- **IP addresses are personal data under GDPR** when they can be linked to a person (CJEU *Breyer*, C-582/14). Processing for network and information security is a recognised legitimate interest (GDPR Recital 49). Sending **attacker / scanner IPs** to a reputation service is common practice, and LogHunter already does it with AbuseIPDB. Still:
  - Some IPs in a top-N list will be **legitimate end users of a bank's app** (real customers behind NAT / mobile CGNAT). Sending 10,000 IPs, including customers' clients, to a US third party is a data-transfer question for regulated customers (DPA, SCCs). Prefer **offline databases for bulk** and online lookups only for the short top-N list.
  - Offline DBs (cdncheck JSON, iptoasn, IPinfo Lite, GeoLite2, DB-IP, MaxMind / IP2Location commercial) cause **zero data egress at lookup time**. Only the DB download leaves the machine, and it carries no customer data.
- **Customer hostnames are more sensitive than attacker IPs.** Submitting `bank-x.outsystemsenterprise.com` to CDN Planet, BuiltWith or Wappalyzer discloses a customer relationship and an incident in progress. Hostname checks should run **locally** (DNS CNAME resolution plus a local suffix table such as cdncheck `common.fqdn` or cdnfinder `cnamechain.json`). Even a local DNS lookup goes to the configured resolver. Acceptable, but don't use third-party "finder" web services.
- **Licence obligations (LogHunter is also mirrored to the public repo `LogHunter-Public`):**
  - **MIT** (cdncheck data): embed and redistribute freely, keep the notice.
  - **PDDL** (iptoasn): no obligations.
  - **CC BY 4.0** (DB-IP Lite): attribution in the About / credits screen.
  - **CC BY-SA 4.0** (IPinfo Lite): attribution, plus ShareAlike if we redistribute a derived DB. Prefer **downloading at runtime with the user's own free token** over committing the DB to the public repo.
  - **GeoLite EULA:** account / licence key needed, redistribution restricted (UNVERIFIED), 30-day deletion rule. Runtime download only, never bundle.
  - **Shodan InternetDB:** non-commercial. OutSystems support use counts as commercial, so **do not integrate** without an enterprise licence.
  - **ipdata free tier:** commercial use restricted. Do not use.
  - **GreyNoise Community:** free-email accounts get no key, quota too small, terms for commercial use not confirmed (UNVERIFIED).
  - **Team Cymru, RIPEstat, bgp.tools, PeeringDB:** free community services. Terms not fully reviewed (UNVERIFIED). Set an identifying User-Agent / `sourceapp`.
- **Secrets:** any API key or token (AbuseIPDB, IPinfo) must stay in user settings, never in source. That matches the current AbuseIPDB client pattern.

---

## 6. Accuracy evidence and pitfalls

1. **Egress vs. anycast front-end ranges.** CDNs publish the ranges their **edges use to reach origins** (e.g. Cloudflare `ips-v4`, which includes 172.64.0.0/13 and 162.158.0.0/15, and CloudFront `CLOUDFRONT_ORIGIN_FACING` in AWS `ip-ranges.json`). Published lists are authoritative for our use case. Scan datasets (Shodan / Censys) are not, as the live test showed.
2. **Akamai does not publish general edge egress ranges.** Customer-specific "SiteShield" maps exist (UNVERIFIED detail), so Akamai detection falls back to **ASN** (cdncheck uses an Akamai ASN list). Expect some false positives from Akamai-hosted (Linode) VMs. Linode / Akamai Connected Cloud runs under AS63949 (UNVERIFIED), which should **not** be treated as CDN.
3. **Same ASN, different meaning.** Real users also egress from CDN ASNs. Examples: Cloudflare WARP (AS13335), iCloud Private Relay (egress operated by Cloudflare, Akamai and Fastly; Apple publishes an egress CSV), and Google / Amazon infrastructure. ASN-level "CDN" (bgp.tools tag, PeeringDB "Content") must not auto-suppress an IP. Range-level data is required, and even then Private Relay egress is a real user (UNVERIFIED that Private Relay and Cloudflare proxy ranges are disjoint).
4. **"Hosting" ≠ "CDN".** IPinfo Core, ipapi.is, ipdata and IPQS put Cloudflare and EC2 attackers in the same "hosting / datacenter" bucket. For our goal (don't block the CDN, do block the attacker VPS) these flags are **insufficient**. Only explicit CDN labels or provider ranges work.
5. **Vendor accuracy claims** (IPinfo "most accurate", ipgeolocation.io, IP2Location) are all **UNVERIFIED** marketing. No independent benchmark of CDN labelling was found. The pragmatic test: run the candidate source over a known sample (published Cloudflare / Fastly / CloudFront ranges plus a few EC2 / OVH attacker IPs) and measure.

---

## 7. Ranked recommendation

### Best free / offline (primary, in-app, always current): curated ranges + cdncheck data + iptoasn
1. **Provider-published ranges + ProjectDiscovery `cdncheck` `sources_data.json`** (MIT). Fetch on startup or daily from GitHub raw, cache locally, ship an embedded last-known-good copy. Covers Cloudflare, CloudFront, Fastly, Google, Gcore, Akamai (ASN), Sucuri, F5, and more, with category and provider name, per IP, offline, in bulk.
   - Add AS19551 (Imperva) ourselves, since cdncheck has no IP ranges for it.
   - Monitor staleness: the bot run failed on 2026-11-22, so show "data age" in the UI.
2. **iptoasn.com** `ip2asn-combined.tsv.gz` (PDDL, hourly, no token) for ASN + AS name on every IP. Lets the UI show "AS13335 Cloudflare" even for providers not in the range set, plus a curated CDN-ASN shortlist as a lower-confidence "possible edge" hint.
   - Alternative: **IPinfo Lite** (daily, CC BY-SA, free token) if better org names are wanted.

### Best second-opinion online lookup: AbuseIPDB `usageType` (reuse existing key)
- Zero new vendor, zero new privacy exposure, explicit "Content Delivery Network" label (IPinfo-sourced).
- 1,000 checks/day, so use it only on the **top-N** list. Never use it for 10,000-IP lists.
- Display as "AbuseIPDB: Content Delivery Network". Verify actual labels for Cloudflare egress IPs first (UNVERIFIED).
- Fallbacks for bulk ASN-only lookups when offline data is missing: Team Cymru bulk WHOIS / DNS. Accept that this sends IPs out.

### Best paid option
1. **IPinfo Core/Plus (downloadable DB)**: `as_type`, `is_hosting`, `is_anycast`, daily updates, offline MMDB, and the same lineage as AbuseIPDB's usageType. The strongest data quality story, but no literal CDN field in Core, so it still needs the range set above.
2. **MaxMind GeoIP Enterprise**: offline MMDB with an explicit `user_type = content_delivery_network`, `is_anycast`, and a first-party .NET reader. Best if a literal CDN label offline is the priority.
3. **IP2Location DB23 / IP2Location.io Starter ($49/mo)** or **ipgeolocation.io paid ($19/mo+)**: cheapest explicit CDN labels, API-based (privacy cost). Fine as a budget online second opinion.

### Not recommended for this use case
- CDN Planet CDN Finder, BuiltWith, Wappalyzer, whatCDN, turbobytes/cdnfinder: hostname-only, sends customer hostnames out, or deprecated. **Reimplement the hostname check locally** with a CNAME-suffix table instead.
- Shodan InternetDB: non-commercial licence, and misses Cloudflare egress IPs.
- Censys: no CDN label found, same scan-coverage gap.
- GreyNoise Community: 50/week quota.
- ipdata free: commercial use restricted.
- Spur and IPQS: wrong problem (anonymiser / fraud) and expensive.
- bgp.tools CDN tag and PeeringDB `info_type` used raw: ASN-level, includes Amazon / Google / OVH / ISPs. Too many false positives for a do-not-block decision.

---

## 8. Sources (accessed 2026-11-22)

- CDN Planet CDN Finder: https://www.cdnplanet.com/tools/cdnfinder/ ; blog: https://www.cdnplanet.com/blog/all-new-cdn-finder/
- turbobytes/cdnfinder: https://github.com/turbobytes/cdnfinder
- whatCDN: https://github.com/Pascal-0x90/whatCDN ; findcdn: https://github.com/cisagov/findcdn ; cdn-detector.js: https://github.com/nicjansma/cdn-detector.js/
- ProjectDiscovery cdncheck: https://github.com/projectdiscovery/cdncheck ; provider.yaml: https://raw.githubusercontent.com/projectdiscovery/cdncheck/main/cmd/generate-index/provider.yaml ; commits: https://github.com/projectdiscovery/cdncheck/commits/main/sources_data.json ; actions: https://github.com/projectdiscovery/cdncheck/actions
- BuiltWith plans: https://builtwith.com/plans ; Wappalyzer lookup API: https://www.wappalyzer.com/docs/api/v2/lookup/
- Shodan InternetDB: https://internetdb.shodan.io/ (plus live GET tests on 2026-11-22)
- Censys tiers: https://docs.censys.com/docs/data-access-tiers-entitlements
- AbuseIPDB API: https://docs.abuseipdb.com/
- IPinfo Lite: https://ipinfo.io/lite ; https://ipinfo.io/blog/ipinfo-lite-free-accurate-unlimited-ip-data ; https://ipinfo.io/developers/ipinfo-lite-database ; https://community.ipinfo.io/t/ipinfo-lite-faq/6768
- IPinfo Core / Privacy: https://ipinfo.io/products/core ; https://ipinfo.io/developers/core-api ; https://ipinfo.io/products/anonymous-ip-database
- IP2Location web service: https://www.ip2location.com/web-service/ip2location ; IP2Location.io pricing: https://www.ip2location.io/pricing ; IP2Proxy LITE PX11: https://lite.ip2location.com/database/px11-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential-provider
- MaxMind GeoLite: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/ ; web service responses: https://dev.maxmind.com/geoip/docs/web-services/responses/ ; Enterprise DB: https://dev.maxmind.com/geoip/docs/databases/enterprise/ ; Anonymous IP: https://dev.maxmind.com/geoip/docs/databases/anonymous-ip/binary/ ; Vendr estimate: https://www.vendr.com/buyer-guides/maxmind
- ipapi.is: https://ipapi.is/ (plus live GET test)
- ipgeolocation.io: https://ipgeolocation.io/pricing.html ; https://ipgeolocation.io/documentation/ip-location-api.html
- ipdata: https://docs.ipdata.co/docs/proxy-tor-and-threat-detection ; https://ipdata.co/pricing.html
- IPQualityScore: https://www.ipqualityscore.com/documentation/proxy-detection-api/response-parameters ; https://www.ipqualityscore.com/proxy-vpn-tor-detection-service
- Spur: https://docs.spur.us/context-api ; https://spur.us/pricing
- DB-IP ASN Lite: https://db-ip.com/db/download/ip-to-asn-lite
- iptoasn: https://iptoasn.com/
- Team Cymru: https://www.team-cymru.com/ip-asn-mapping
- RIPEstat: https://stat.ripe.net/docs/data_api
- bgp.tools: https://bgp.tools/kb/api ; https://bgp.tools/tags/ ; https://bgp.tools/tags/cdn
- PeeringDB limits: https://docs.peeringdb.com/howto/work_within_peeringdbs_query_limits/
- GreyNoise: https://docs.greynoise.io/docs/riot-data ; https://docs.greynoise.io/docs/using-the-greynoise-community-api
