# Which CDN / WAF / proxy vendors our customers use

Source: Zendesk search across all tickets created **2025-11-22 → 2026-11-22** (12 months). Matches are on subject and description only; comment bodies are not indexed. Counted per **customer organisation**. Excluded: the `OutSystems (…)` internal org, `Amazon` (AWS support case mirrors), and tickets with no org (mostly CloudOps / AWS notifications). The O11 vs ODC split comes from ticket tags (any `odc*` tag ⇒ ODC), so treat it as approximate.

| Vendor | Customer tickets | Customer orgs | O11 orgs | ODC orgs | Confidence |
|---|---:|---:|---:|---:|---|
| **Cloudflare** | 231 | **144** | 96 | 64 | High. `cloudflare WAF` alone matches 106 tickets |
| **AWS CloudFront** | 196 | 131 | 41 | 101 | **Low as a customer-CDN signal.** Mostly OutSystems' own ODC edge ("403 Error from cloudfront"), not a customer CDN |
| **Akamai** | 82 | **53** | 38 | 20 | High (Site Shield, EdgeWorkers, Akamai WAF migrations) |
| Zscaler (egress proxy, not CDN) | 73 | 50 | 36 | 19 | High. Shows up as the *source* of corporate users, not in front of the app |
| Azure Application Gateway WAF | 43 | 36 | 22 | 15 | Medium (mostly self-managed / ODC questions) |
| **Imperva / Incapsula** | 70 | **31** | 25 | 13 | High (Santander, DIEZ, Bancolombia, MTI…) |
| F5 (XC / Volterra / BIG-IP) | 96 | 79 | 58 | 23 | **Low.** Exact `volterra` / `F5 XC` / `BIG-IP` queries return 0–2 tickets, so most hits are loose phrase matches. The one confirmed F5 XC case is 3531098 (AIA, ODC) |
| Netskope (egress proxy) | 21 | 16 | 9 | 8 | Medium |
| **Azure Front Door** | 17 | **15** | 8 | 8 | Medium |
| Radware | 5 | 3 | 2 | 2 | Medium |
| Google Cloud Armor / CDN, FortiWeb, Fastly, Barracuda, Alibaba / Tencent | 1–2 each | ≤ 2 each | | | Low volume |
| Sucuri, StackPath, Gcore | 0 | 0 | | | — |

## Seen in the 105 security tickets analysed

| Vendor | Ticket(s) | Effect on the analysis |
|---|---|---|
| Cloudflare | 3476636, 3483741, 3549928 (ODC), 3475183 | ALB top IPs were Cloudflare edges, and Cloudflare IPs were being brute-force-blocked |
| Imperva | 3387376 | Multi-hop XFF chain |
| Akamai | 3522405 (after the incident) | Customer is moving in front, and `True-Client-IP` is not read |
| F5 Distributed Cloud | 3531098 (ODC) | XFF ≠ WAF client IP; the F5 proxy was blamed first |
| AWS ranges as top talkers | 3418205 | Unclear whether they were a proxy or real clients |

## What this means for LogHunter

1. **Must cover on day one:**
   - **Cloudflare**, ≈ 100 O11 orgs: published feed, easy.
   - **Akamai**, ≈ 40 O11 orgs: no public edge feed, so it needs ASN-based or Site Shield-based classification.
   - **Imperva**, ≈ 25 O11 orgs: published feed.
   - **Azure Front Door**: Service Tags.
   - **AWS CloudFront**: `ip-ranges.json`. Customers can put CloudFront in front of O11 too.
2. **Corporate egress proxies** (Zscaler ≈ 50 orgs, Netskope ≈ 16) are the second false-positive class. They are not CDNs, but one IP carries thousands of real users. Tag them as "corporate proxy", not "attacker".
3. **Akamai is the hard one.** It is the second most common vendor and the only big one without a public edge-IP feed. See the vendor-feed and third-party research.
4. **ODC** customers also put their own CDN / WAF in front (Cloudflare 64, Akamai 20 orgs), but LogHunter has no ODC access logs today. This matters only once the WAF JSON / HAR input (gap G8) exists.

Raw data (outside the repo): `C:/Users/cvh/AppData/Local/Temp/zd-research/cdn_census.json`, `org_names.json`.
