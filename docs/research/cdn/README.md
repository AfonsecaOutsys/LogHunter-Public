# CDN / proxy identification — research synthesis and recommendation

2026-11-22 · Inputs: [a-vendor-feeds](a-vendor-feeds.md) · [b-third-party-services](b-third-party-services.md) · [c-detection-methods](c-detection-methods.md) · [d-update-architecture](d-update-architecture.md) · [e-customer-cdn-census](e-customer-cdn-census.md)

## Answer in one paragraph

**Don't outsource the decision to a "CDN finder" service.** CDN Finder, BuiltWith, Wappalyzer and whatCDN classify a *hostname* (DNS + headers), not the client IPs in our logs. They have no bulk API, and using them means sending customer hostnames to third parties. Scanner-based IP databases (Shodan, Censys) can't see the origin-facing edge IPs that actually appear in ALB / IIS logs: Shodan had no data for Cloudflare `172.70.x`.

The reliable source is **the vendors' own published IP lists, fetched in-app**, refreshed every 24 h, validated, and backed by a snapshot embedded in the exe for offline / first run. Ten of the vendors our customers use publish free, unauthenticated feeds. Akamai, the hard one, is covered by its Origin IP ACL list + ASN fallback + per-ticket customer ranges. An **online second opinion** is optional and uses the **AbuseIPDB key we already have** (`usageType = Content Delivery Network`), on top-N IPs only.

## Coverage vs what our customers use

| Vendor (customer orgs, 12 mo) | Source in app | Verdict strength |
|---|---|---|
| **Cloudflare** (144) | `api.cloudflare.com/client/v4/ips` (+ China / JD Cloud list) | Confirmed. Validated on 3476636: 20 / 20 top IPs matched |
| **Akamai** (53) | Akamai Origin IP ACL text lists (only covers customers who enabled it) → ASN AS20940 / AS16625 (exclude Linode AS63949) → **customer-supplied Site Shield ranges pasted per ticket** | Confirmed if ACL / pasted match, otherwise Likely (ASN) |
| **Imperva** (31) | Imperva IP ranges endpoint (+ AS19551 fallback) | Confirmed |
| **Azure Front Door** (15) | Azure Service Tags, `AzureFrontDoor.Backend` only. The download URL changes weekly, so scrape the link and accept only an increased `changeNumber` | Confirmed (best effort) |
| AWS CloudFront (customer-managed, ≈ 41 O11 orgs) | `ip-ranges.json`, **`CLOUDFRONT_ORIGIN_FACING`** (what an origin sees) | Confirmed |
| F5 Distributed Cloud (1 confirmed case) | F5 XC published JSON (check freshness: `generated_at` looks stale) | Confirmed / Likely |
| Fastly, Gcore, Bunny | Published lists | Confirmed |
| Sucuri, CDN77, KeyCDN, Google LB / CDN origin ranges | Small hard-coded lists shipped with each release | Confirmed |
| **Zscaler** (50), **Netskope** (16), Cloudflare WARP | Zscaler feed; Netskope NewEdge hard-coded | **Corporate proxy** (separate verdict: real users, not a CDN) |

**Never classify by the broad Amazon / Microsoft / Google / Cloudflare AS13335 ASNs.** Attackers rent servers there, and WARP users sit in AS13335.

## Verdict model (what operators see)

| Level | Rule | UI wording |
|---|---|---|
| **Confirmed** | ≥ 80 % of top-N hits in one vendor's published ranges, **or** IIS XFF hop pattern, **or** hostname probe header + IP match | "Fronted by Cloudflare. ALB shows edges, not users. Use IIS IP summary." |
| **Likely** | 50–80 %, or ASN-only match (Akamai) | "Likely fronted by Akamai (network match). Check IIS OriginalIP." |
| **Possible** | Behavioural only (many UAs per ALB connection, `conn_trace_id`) | "Traffic pattern looks proxied. Confirm before blocking." |
| Tags per IP | `cdn-edge:<vendor> (feed, date)`, `likely-cdn:<vendor> (ASN)`, `corporate-proxy`, `monitoring` (e.g. Elastic Heartbeat), `private-hop`, `xff-forged` | Badge + Excel column; every tag names its source and dataset date |

Extra signal from the hostname probe: the customer domain shows a CDN, but the ALB traffic does **not** come from it. That means the origin is reachable directly and the CDN can be bypassed, which is worth telling the customer (relevant to 3549928).

## Bug found in shipped code (fix first)

`LogHunter/Services/IisClientIpResolver.cs`:

1. `ResolvePreferredClientIp` returns the **leftmost** public hop. The client controls that hop.
   - 3367120 shows a forged `106.106.198.131` instead of the real `219.153.113.105`.
   - 3522405's chain `0.0.0.0,+82.158.196.58` resolves to `0.0.0.0`.
2. `IsPrivateOrLoopback` misses `0.0.0.0/8`, CGNAT `100.64.0.0/10`, and all IPv6 private / link-local / ULA ranges.

**Fix:** walk the chain **right to left**. Skip platform loopback / private hops and IPs inside the CDN ranges detected for this dataset. The first remaining hop is the client. Flag `xff-forged` when public hops to the left of it disagree. Pseudo-code is in [c-detection-methods.md](c-detection-methods.md).

This changes IIS IP summary, burst and AbuseIPDB results today, so ship it as its own patch with tests.

## In-app "always updated" design (summary of d)

- **Feeds:**
  - Refreshed in the background at startup (never blocks a scan), plus a "Refresh now" button.
  - Rechecked every 24 h; Azure and ASN every 7 days.
  - Uses ETag / If-Modified-Since / AWS `syncToken`.
- **Safety:**
  - Strict validation: parse, strip private / too-wide ranges, ±50 % size guard. Keep the last good copy on any failure.
  - HTTPS + host allow-list + size caps.
  - Uses the system proxy (works on WorkSpaces / corp network).
- **Offline:** raw feeds embedded in the exe (+0.6–1 MB), refreshed by a release-time script.
- **Lookup:**
  - Sorted non-overlapping ranges with binary search (`uint` / `UInt128`), ~20–50 ns per lookup, ~1 MB.
  - The **same engine** backs the G1 IOC sweep CIDR matching (`Utils/IpRangeSet`).
- **UI:** "IP ranges · 3 h" pill next to Runtime on every page → `/ip-ranges` page (provider table, last updated, Refresh now). The console gets a header line and a menu entry.

## Phased plan

| Phase | Scope | Size | Done when |
|---|---|---|---|
| **P0 patch** | Resolver fix (right-to-left, 0.0.0.0 / CGNAT / IPv6), new `LogHunter.Tests` project | S/M | 3367120 and 3522405 chains resolve to the real client; unit tests green |
| **P1** | `IpRangeSet` engine; feeds: Cloudflare, CloudFront origin-facing, Imperva, Fastly, F5 XC, Akamai ACL, Zscaler, hard-coded Netskope / Sucuri / CDN77 / KeyCDN / Google LB; embedded snapshot; background refresh + validation; status pill + `/ip-ranges` page; badges + "Fronted by" banner in ALB Top-50, Top-for-endpoint, IP summary, IOC sweep | M/L | 3476636 export shows "Confirmed: Cloudflare"; 3483741's blocked IPs are tagged Cloudflare; offline start works from the snapshot |
| **P2** | Azure Front Door scrape; ASN table (iptoasn.com, public domain) for Akamai / Imperva "Likely"; **paste customer ranges per ticket**; AbuseIPDB `usageType` second opinion on top-N; local hostname probe (DNS CNAME + headers, no third party) | M | An Akamai-fronted dataset shows Likely without a pasted list and Confirmed with one |
| **P3** | Per-connection UA heuristic (validate on the next CDN ticket with raw ALB logs first); CDN analyzer for old exports | M | Heuristic false-positive rate measured on ≥ 2 CDN and ≥ 2 non-CDN datasets |

## Decisions / checks before building

1. **Bundling licence:** vendor feeds carry no explicit licence. Ask Legal once whether embedding a snapshot in an internal exe is fine. The fallback is to fetch on first run and ship only the hard-coded small lists.
2. **ASN download on by default?** iptoasn is public domain (~600k ranges). The proposal is on, with a 7-day refresh.
3. **Reachability:** ipinfo.io failed TLS from this machine (corp proxy?), and AbuseIPDB pages 403'd automated GETs. Test every feed host from a GS laptop and an AWS WorkSpace before release.
4. **Ask CloudOps** whether IIS on O11 Cloud can log `True-Client-IP` / `CF-Connecting-IP`. Akamai setups that send the client only there are unrecoverable today (3522405).
5. **cdncheck** (MIT, weekly): useful as a cross-check in tests, **not** as the primary source. It has gaps (no Akamai / Front Door), its run on 2026-11-22 failed, and its Cloudflare set catches WARP users.
