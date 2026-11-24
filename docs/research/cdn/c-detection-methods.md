# CDN fronting: detection methods and real-client recovery

Angle C of the CDN research. This doc builds on `LogHunter/docs/cdn-detection-future-directions.md`, which covers the module split, the IP-feed layer and the export-annotation design, and on `docs/research/cdn/e-customer-cdn-census.md`, which covers which vendors customers use. It does not repeat them. It covers:

1. What the logs we actually have can prove.
2. How to pick the right hop from `OriginalIP`.
3. Signals beyond IP-range matching.

The doc ends with a confidence model and the wording operators would see.

Access date for all URLs: **2026-11-22**. All local data was read-only. Scripts live outside the repo, in `%TEMP%\cdnresearch_scripts`, and feeds were downloaded to `%TEMP%\cdnresearch_dl`.

---

## 1. ALB access logs: what they contain and what they signal

### 1.1 Facts from the AWS docs

Source: [ALB access log entries][aws-alb-logs].

| Field (pos) | What AWS says | CDN relevance |
|---|---|---|
| `client:port` (4) | "The IP address and port of the requesting client. **If there is a proxy in front of the load balancer, this field contains the IP address of the proxy.**" | With a CDN in front, this is the CDN edge. It is the TCP peer, so it can't be spoofed. |
| `"request_line"` (13) | Method + `protocol://host:port/uri` + version. | Gives the Host header value, which is needed for the SNI/Host comparison. |
| `"user_agent"` (14) | The User-Agent string, truncated at 8 KB. | Cloudflare, Akamai and Imperva pass the end-user UA through. CloudFront replaces it with `Amazon CloudFront` unless the UA is in the cache key ([CloudFront custom-origin behaviour][aws-cf-origin]). |
| `ssl_cipher` / `ssl_protocol` (15/16) | Cipher and protocol of the client↔ALB TLS session. | Behind a CDN, this is the **CDN's** TLS stack, not the browser's. |
| `"trace_id"` (18) | "The contents of the **X-Amzn-Trace-Id** header". | Opaque. Not a client IP. |
| `"domain_name"` (19) | "The SNI domain provided by the client during the TLS handshake"; `-` if no SNI or no matching cert. | The SNI the CDN chose for the origin pull. |
| `"chosen_cert_arn"` (20) | `session-reused` when the TLS session is resumed. | Weak signal: proxies resume sessions heavily. |
| `"classification"` / `"classification_reason"` (28/29) | Desync-mitigation classes (Acceptable / Ambiguous / Severe) for RFC 7230 violations. | Not a CDN signal. CDNs normalise requests, so expect `-`. |
| `conn_trace_id` (30) | "unique opaque ID used to identify each connection… subsequent requests from this client will contain this ID". | **Key field.** It lets us count user agents per TCP connection (heuristic H3 in section 2). |
| `ip_address` (34) | The ALB node IP. | Not relevant. |

**Is X-Forwarded-For in the ALB log? No.** The documented field list (36 fields as of 2026-11-22) contains no request header except User-Agent, X-Amzn-Trace-Id (`trace_id`) and Host (inside `request_line`). The ALB *writes* XFF towards the target. In the default `append` mode it "appends the client IP address to the existing header" ([ALB X-Forwarded headers][aws-alb-xff]). It never logs XFF. **The real client behind a CDN cannot be recovered from ALB logs alone.** ALB logs can only *detect* fronting, and the operator then has to go to IIS `OriginalIP`.

A consequence of `append` mode that the IIS section relies on: the **rightmost** XFF entry the front end receives is always the ALB's own TCP-peer observation, so it is trustworthy.

### 1.2 Signals available from ALB logs only

| # | Signal | Strength | Notes |
|---|---|---|---|
| A1 | `client` IP is in a vendor-published range (Cloudflare, CloudFront `CLOUDFRONT_ORIGIN_FACING`, Fastly, Imperva, AFD `AzureFrontDoor.Backend`, F5 XC RE/CDN subnets) | **Strong** per request | This is the existing design. Prefer CloudFront `CLOUDFRONT_ORIGIN_FACING` over the broad `CLOUDFRONT` list. |
| A2 | Many user agents multiplexed on **one** `conn_trace_id` | **Strong** | Browsers send one UA per connection. A CDN pools origin connections across visitors. Section 2, H3. |
| A3 | Top-N IPs spread over many /24s inside few /16s owned by one ASN | Medium | 3476636: 20 IPs, 17–19 /24s, 7 /16s, all Cloudflare. |
| A4 | Many distinct UAs per IP | Weak alone | UA-rotating scanners and NAT gateways trip it. Section 2, H4. |
| A5 | A single TLS cipher/protocol across many UAs, including legacy UAs | Weak–medium | The TLS session belongs to the CDN. Section 2, H5/H6. |
| A6 | `domain_name` (SNI) ≠ Host in `request_line`, or SNI = `*.outsystemsenterprise.com` while Host is the custom domain | Medium | The CDN's origin-pull settings override SNI. Direct browsers send SNI = Host. |
| A7 | High `session-reused` ratio plus long connections (requests per `conn_trace_id`) | Weak | Corporate proxies show the same pattern (see the control data). |
| A8 | Source-port distribution | **Not useful** | Edges use ordinary ephemeral ports. Listed only so nobody spends time on it. |
| A9 | `elb_status_code` 403 + `actions_executed` containing `waf` on vendor IPs | Consequence, not detection | The OutSystems WAF or brute-force protection is blocking a CDN edge: collateral damage for every user behind that edge (3483741 / 3392385). |

---

## 2. Behavioural heuristics: thresholds and false positives

Use these only on **public** source IPs. The 3375138 data shows that an internal ALB can be 98 % private sources. Those are VPN or on-prem paths, not CDNs.

| ID | Rule | Proposed threshold | Main false positives | How to tell them apart |
|---|---|---|---|---|
| H1 | Vendor-feed share of top-N hits | ≥ 50 % of top-20 hits in one vendor's feed → *Likely*. ≥ 80 % → supports *Confirmed* | None for the IP itself. "Came via vendor X" ≠ "customer's own zone" (anyone can route through Cloudflare Workers or WARP) | Use volume: a stray vendor IP is not fronting |
| H2 | Edge spread | ≥ 10 distinct /24s among the top-20, all one vendor or ASN | Botnets in residential ranges | Require H1 or the same ASN |
| H3 | **Multi-UA connections**: for one IP, count connections (`conn_trace_id`) that carry ≥ 3 distinct UAs | ≥ 10 such connections, **or** ≥ 20 % of the IP's connections → *Likely proxy*. Add H1 → vendor | Customer reverse proxies, corporate TLS-intercepting proxies that pool upstream connections (not observed in our data) | Feed or ASN lookup. Private IP → internal proxy |
| H4 | Distinct UAs per IP | ≥ 50 UAs **and** ≥ 500 requests | **UA-rotating scanners** (control: 34.248.127.242 had 136 UAs on 174 requests), corporate NAT (Zscaler, Netskope) | Scanners run 1 request per connection with no multi-UA connections. NAT IPs match Zscaler or Netskope feeds. Never use H4 without H3 |
| H5 | UA ↔ TLS mismatch: UAs that can't do the logged protocol (MSIE ≤ 10, Android ≤ 4.3 on TLSv1.3) | ≥ 5 % of the IP's requests | Bots faking old UAs (common: a fake MSIE 7 UA appears in the 3367120 IIS data) | Use only as a tie-breaker |
| H6 | TLS uniformity: exactly 1 cipher + 1 protocol over ≥ 1 000 requests and ≥ 50 UAs | as stated | Large NAT behind one TLS-intercepting proxy | Weak. Supporting evidence only |
| H7 | SNI/Host mismatch per IP | ≥ 90 % of ≥ 100 HTTPS requests | IP-direct scanners (`domain_name = -`, 1.6 % of requests in the control) | Scanners hit few paths and have no session continuity |
| H8 | No single dominant IP: many vendor IPs, each with a small share | Top IP < 20 % of hits while ≥ 10 vendor IPs carry traffic | — | Useful only for the banner text ("the top IP is not an actor") |

**Control results for H3/H4.** In the no-CDN raw ALB data (3367120: 400 files, 288 242 requests, 215 public IPs), **no IP had ≥ 3 UAs on one connection**. The maximum was 2, on a single connection. The two highest-UA IPs were scanners: 136 and 74 UAs, one request per connection. Corporate egress IPs (114.141.x) carried 160 k requests with ≤ 5 UAs and never more than 1 UA per connection. H3 therefore looks discriminating with no false positives in the control. **Caveat:** we have no raw ALB logs from a CDN-fronted customer on disk. Pooled origin connections are documented CDN behaviour ([CloudFront persistent connections][aws-cf-origin]), but H3 is **not yet validated on positive data**. Validate it on the next Cloudflare ticket that comes with raw logs.

---

## 3. IIS `OriginalIP`: picking the right hop

### 3.1 What `OriginalIP` looks like (observed)

IIS `#Fields:` on OutSystems Cloud front ends end with `… time-taken OriginalIP`. No other forwarded-IP field is present (seen in 3367120 and 3466228). Profile from 3367120 (19 files, 2 255 935 rows):

| Shape | Share | Example |
|---|---:|---|
| `-` (did not come through the ALB) | 16.7 % | internal calls, health checks |
| single IP (sometimes `ip:port`) | 82.0 % | `3.211.38.142` |
| multi-hop | 1.25 % | `114.141.126.89,+127.0.0.1,+127.0.0.1:56384` (platform loopback hops, UA `OutSystemsPlatform`) |

The format details matter for parsing:

- Separators are `,+` because IIS encodes the space as `+`.
- The **last** hop can carry `:port`.
- Internal hops (`127.0.0.1`, `10.x`) are appended to the **right** of the real client.

**Header path:** client (optional client-supplied XFF) → CDN (appends or sets) → OutSystems ALB (`append`: adds its TCP peer) → FE (may add loopback or internal hops) → IIS logs the whole chain as `OriginalIP`.

### 3.2 What vendors put in XFF and which side headers they add

| Vendor | XFF behaviour toward origin | Single-IP header | Other origin-side headers | Source |
|---|---|---|---|---|
| Cloudflare | Sets XFF = client if absent. If the client sent XFF, **appends** the connecting IP | `CF-Connecting-IP` (all plans). `True-Client-IP` (Enterprise, Managed Transform) | `CF-Ray`, `CF-IPCountry`, `CF-Visitor`, `CDN-Loop: cloudflare`, `CF-Connecting-IPv6` (Pseudo IPv4) | [CF headers][cf-headers] |
| Akamai | XFF "added automatically if not present, and routinely modified by proxies". The exact append behaviour **is not documented** | `True-Client-IP` (name configurable; option "allow clients to set" defaults to off) | `Akamai-Origin-Hop`, `Via` (config-dependent) | [Akamai origin server][ak-origin], [Terraform origin][ak-tf] |
| Imperva | XFF carries the visitor IP | `Incap-Client-IP` (name configurable, e.g. to `True-Client-IP`) | — | [imperva-rails README][imp-rails], [Akamai→Incapsula guide][imp-guide] |
| Azure Front Door | **Appends** the client socket IP to an existing XFF | `X-Azure-ClientIP` (can be overwritten by the user), `X-Azure-SocketIP` (TCP peer) | `X-Azure-FDID` (profile GUID: proves *which* AFD), `X-Azure-Ref`, `Via: 1.1 Azure`, `X-Forwarded-Host` | [AFD headers][afd-headers] |
| CloudFront | **Appends** the viewer IP. Example `192.0.2.4,192.0.2.3,192.0.2.2` | — (`CloudFront-Viewer-Address` is opt-in) | `X-Amz-Cf-Id`, `Via`, UA replaced by `Amazon CloudFront`, `X-Real-IP` stripped | [CloudFront origin behaviour][aws-cf-origin] |
| F5 XC | Not confirmed in this research | — | `x-volterra-location` on responses | [F5 XC server header][f5-hdr] |

**Does OutSystems log any of the single-IP headers? No, based on the evidence available.**

- IIS `#Fields:` contain only `OriginalIP`.
- The L3 answer in 3522405 (ticket.md lines 4105-4106) is explicit: "The platform determines the client IP only from the `X-Forwarded-For` header… `True-Client-IP` is not evaluated."
- Nothing in the LogHunter repo references `CF-Connecting-IP`, `True-Client-IP`, `Incap-Client-IP` or `X-Azure-*`.
- **Unknown:** whether CloudOps could add custom IIS log fields for these headers. Not found in tickets or docs.

Practical consequence: if a customer's Akamai config sends the client only in `True-Client-IP`, the client IP is **unrecoverable** from our logs. The REF #2929071 case in 3522405 is exactly that: some Akamai edges didn't populate XFF.

### 3.3 Spoofing: real evidence

- **3522405** (`_findings.md` line 504 and `_atk_82.log`): the attacker 82.158.196.58 forged XFF about 40 times. Examples include `127.0.0.1`, `10.0.0.1`, `172.16.0.1`, `192.168.1.1`, `0.0.0.0` and the FE IPs `10.15.109.65` / `.110`. The ALB appended the real IP on the right:
  - `0.0.0.0,+82.158.196.58`
  - `127.0.0.1:80,+82.158.196.58`
  - `10.15.109.65,+140.238.32.108`

  AdminUserManager returned 200 twice, which raises the question of whether the customer's IP check trusts the first hop.
- **3367120** (a no-CDN customer): out of 49 public multi-hop rows, **3 have leftmost-public ≠ rightmost-public**:
  - 2 × `106.106.198.131,+219.153.113.105`, with a fake `MSIE 7.0` UA. The left value is client-supplied, the right value is the ALB-observed socket.
  - 1 × `2a06:98c0:3600::103,+172.68.102.9`. Both are Cloudflare ranges (`2a06:98c0::/29`, `172.64.0.0/13`): a request routed through Cloudflare's network to a customer that does **not** use Cloudflare. This is the "vendor edge ≠ customer CDN" case.

**Current `IisClientIpResolver` behaviour** (`LogHunter/Services/IisClientIpResolver.cs`). It returns the **leftmost** valid non-private hop. MDN calls this the choice that is "untrustworthy and *not* for security-related purposes" ([MDN XFF][mdn-xff]). Findings from the code and the data above:

1. **Bug:** `IsPrivateOrLoopback` does not treat `0.0.0.0/8` as non-public. For `0.0.0.0,+82.158.196.58` the resolver returns **`0.0.0.0`** as the client.
2. It also misses `100.64.0.0/10` (CGNAT), IPv6 ULA `fc00::/7`, IPv6 link-local `fe80::/10` and `::`.
3. A forged **public** first hop wins: `106.106.198.131` is reported instead of `219.153.113.105`. An attacker can put any victim's IP into our IP summary.
4. Behind a CDN without a forged hop, leftmost = real client. That is correct, and it is why the resolver *appears* to work.

No code change was made in this research task. This is a recommendation.

### 3.4 Algorithm: rightmost-untrusted with provider-aware trust

```text
ALWAYS_SKIP = loopback, 0.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16,
              100.64/10, ::1, ::, fc00::/7, fe80::/10, (OutSystems VPC CIDRs if known)

resolve(originalIp, cIp, feeds, trustedProviders):
    hops = parse(originalIp)   # split ',', strip '+', quotes, [v6], trailing :port
                               # keep unparseable tokens as INVALID (do not drop)
    if hops is empty:
        return { client: cIp if public(cIp) else null, basis: "c-ip" }

    via = []
    for i from len(hops)-1 down to 0:     # rightmost = appended by OutSystems ALB = trusted
        h = hops[i]
        if h is INVALID:  break           # everything left of garbage is client-controlled
        if h in ALWAYS_SKIP: continue
        p = feeds.provider(h)             # Cloudflare / CloudFront-origin-facing / Fastly /
                                          # Imperva / AFD / F5XC / operator-pasted ranges
        if p != null and p in trustedProviders:
            via.append(p); continue       # known edge: keep walking left
        claimed = leftmostPublic(hops)
        return { client: h,
                 via: via,                                  # e.g. ["Cloudflare"]
                 edge: p,                                   # non-null = vendor edge NOT trusted for this dataset
                 claimedClient: claimed if claimed != h,
                 spoofSuspect: claimed != null and claimed != h and claimed not in via }

    return { client: rightmostPublic(hops) ?? cIp, via: via, basis: "edge-only" }  # health probes etc.
```

How the design choices play out:

- **`trustedProviders`** is the set of vendors detected for *this* dataset (H1 ≥ 50 %, a hostname probe, or the operator's choice). It is **not** every CDN globally. Without that limit, the 3367120 Cloudflare request would resolve "through" Cloudflare and blame `2a06:98c0:3600::103`, which is another Cloudflare address. With the limit, the result is `172.68.102.9`, badge "Cloudflare edge", which is correct.
- **Akamai** has no complete public edge feed (Origin IP ACL CIDRs are shared and documented only for enabled properties: [Akamai Origin IP ACL][ak-oipacl]). Let the operator **paste ranges** per ticket. In 3522405 the customer actually supplied its Akamai Origin IP ACL list (ticket.md line 4172).
- Results on the real data:
  - 3522405: always 82.158.196.58 / 140.238.32.108. Fixes the `0.0.0.0` case.
  - 3367120: `219.153.113.105`, plus `claimedClient = 106.106.198.131` and `spoofSuspect`.
  - Platform loopback rows: `114.141.126.89`.
  - Cloudflare-fronted customer (`spoofed, client, cfEdge`): `client`.
- **Keep both columns in exports:** `ClientIp` (trusted) and `ClaimedClientIp` (leftmost, filled only when different). Investigators still need the claimed value: it is sometimes the genuine user behind a corporate proxy that adds XFF. They need to see it labelled as unverified.

---

## 4. Hostname probe: signature table

Input: the hostname from ALB `domain_name`, the Host part of `request_line`, or the ticket. Run DNS first (no traffic to the customer), then one `HEAD /` or `GET /` with redirects off.

| Vendor | DNS (CNAME / NS) | Response headers | Cookies / body | IP feed | ASN (verify before use) |
|---|---|---|---|---|---|
| Cloudflare | Full setup: NS `*.ns.cloudflare.com`, A in CF ranges. Partial: CNAME `<host>.cdn.cloudflare.net` | `server: cloudflare`, `cf-ray: <hex>-<COLO>`, `cf-cache-status` | `__cf_bm`, `cf_clearance`; 52x error pages | [ips-v4][cf-ips4] / [ips-v6][cf-ips6] | AS13335 |
| Akamai | CNAME `*.edgekey.net` → `e####.(a\|g).akamaiedge.net`; `*.edgesuite.net` → `*.akamai.net`; `*.akamaized.net`; staging `*-staging.net` | `Server: AkamaiGHost` (mostly on edge-generated responses), `Akamai-GRN`, `X-Akamai-*`, `Server-Timing: cdn-cache; desc=…, edge; dur=…` (mPulse on). With Pragma debug: `X-Cache: TCP_… from a…deploy.static.akamaitechnologies.com` | `_abck`, `bm_sz`, `ak_bmsc` (Bot Manager); "Reference #18.…" error pages | None public. Origin IP ACL or Site Shield per customer | AS20940, AS16625 ([is-antibot PR][isantibot]) |
| Imperva | CNAME `*.incapdns.net` (e.g. `xxxx.x.incapdns.net`) | `X-Iinfo` (definitive), `X-CDN: Imperva` / `Incapsula` | `visid_incap_*`, `incap_ses_*`, `nlbi_*`, `reese84`; "Incapsula incident ID" | [Imperva IP API][imp-api] (POST) | AS19551 |
| Azure Front Door | CNAME `*.azurefd.net` (Std/Premium `*.z01.azurefd.net`), then `*.t-msedge.net` | `x-azure-ref`, `x-cache` (`TCP_MISS`, `CONFIG_NOCACHE`), `x-fd-int-roxy-purgeid` | — | Service tag `AzureFrontDoor.Backend` ([AFD lock-down][afd-lock]) | AS8075 (shared with all of Microsoft) |
| CloudFront | CNAME `d*.cloudfront.net` | `via: 1.1 <id>.cloudfront.net (CloudFront)`, `x-amz-cf-pop`, `x-amz-cf-id`, `x-cache: Miss from cloudfront` | 403 "Request blocked… Generated by cloudfront" | `ip-ranges.json` `CLOUDFRONT` / `CLOUDFRONT_ORIGIN_FACING` | AS16509 (shared with all of AWS) |
| Fastly | CNAME `*.fastly.net`, `*.global.ssl.fastly.net`, `*.fastlylb.net` | `x-served-by: cache-…`, `x-cache`, `x-timer`, `via: 1.1 varnish` | — | [public-ip-list][fastly-ips] | AS54113 |
| F5 Distributed Cloud | CNAME `ves-io-<uuid>.ac.vh.ves.io` (pattern not confirmed in docs) | `server: volt-adc` (LB default) / `volt-cdn` (CDN), `x-volterra-location`, `x-envoy-upstream-service-time`, all-lowercase header names | — | [F5 XC IP reference][f5-ips] (RE + CDN subnets) | not verified |
| OutSystems direct (baseline) | CNAME/A to the OutSystems ALB (`*.elb.amazonaws.com`) or `*.outsystemsenterprise.com` / `*.outsystemscloud.com` | No vendor headers. ALB `server: awselb/2.0` on ALB-generated errors | — | AWS `EC2` ranges | AS16509 |

**Probe verdict rules:**

- **CNAME or NS match plus a header match** → the hostname is fronted. Header matches alone count too, if they are definitive (`cf-ray`, `X-Iinfo`, `x-azure-ref`, `x-amz-cf-pop`, `volt-adc`).
- **Resolved IP in a feed but no header match** → only "likely". The customer may serve the hostname from that vendor without proxying the OutSystems origin.
- **Hostname probe positive but ALB top IPs not in any feed** → fronting is **bypassable**: the OutSystems origin is still reachable directly. Report this as a finding in its own right, because the customer's CDN WAF rules are not protecting the origin.

---

## 5. Validation on sample files

Feeds were downloaded on 2026-11-22: Cloudflare v4/v6, AWS `ip-ranges.json`, Fastly, Imperva and Zscaler. Script: `%TEMP%\cdnresearch_scripts\validate.py` (xlsx parsed as a zip with `python -I`).

| Ticket / file | What it is | Result |
|---|---|---|
| 3476636 `…ForFragment…(setpassword).xlsx` | Top-20 IPs for `setpassword` | **20 / 20 IPs Cloudflare (595 / 595 hits, 100 %)**. 17 distinct /24s, 7 /16s. The same URI was hit from 11 different edge IPs, so the "top IP" is not an actor. |
| 3476636 `…(register).xlsx` | Top-20 IPs for `register` | **20 / 20 Cloudflare (981 / 981 hits, 100 %)**. 19 /24s, 7 /16s. The ticket's "AbuseIPDB reports on these IPs" (line 357) is expected noise on shared Cloudflare edges. |
| 3475183 `ALB_Top50_IPs` | Top-50 for the environment | **0 / 50 CDN.** 2 AWS EC2 eu-west-2 IPs (18.169.78.110, 3.11.160.214) carry **88 %** of hits: unidentified non-CDN concentrators that need H3. Others: 3.211.38.142 = `Elastic-Heartbeat` monitor (also top in 3367120 and 3375138; whitelist it as monitoring); 147.161.166.177 = **Zscaler** (147.161.166.0/23); 54.76.45.192 = AWS eu-west-1 UA-rotating scanner (74 UAs, 1 request per connection in 3367120). |
| 3475183 `alb_ip_summary_multi` | 161.97.132.38, 64 742 requests | Not in any feed. 14 UAs (Chrome/120 and /124 strings without patch versions, `curl/7.88.1`): attacker tooling, not a CDN. |
| 3397404 `alb_ip_summary_multi` | 46.225.63.188, 45 458 requests | Not in any feed. 1 UA (`HeadlessChrome/148`): automation, not a CDN. |
| 3483741 (ticket text) | IPs blocked by brute-force protection in #3392385 | 104.23.243.132 ∈ 104.16.0.0/13 and 162.159.114.99 ∈ 162.158.0.0/15: **both Cloudflare**. |
| 3367120 raw ALB (400 / 3 171 files) | Negative control: ticket says "they dont have any setup" (CDN) | 288 242 requests, 0 feed matches, 0 IPs with ≥ 3 UAs on one connection. 1.6 % `domain_name = -`. |
| 3375138 raw ALB (391 files) | Internal ALB | 98.3 % private sources. The heuristics must skip private IPs. |
| 3367120 IIS (19 files, 2.26 M rows) | `OriginalIP` profile | See section 3.1. 3 rows where leftmost ≠ rightmost: 2 spoof-like, 1 Cloudflare chain. |
| 3522405 IIS extracts | Spoofed XFF | 12 forged chains from 82.158.196.58 and 140.238.32.108. The current resolver returns `0.0.0.0` for one of them. |

**Ticket grep** (`C:/Zendesk/workspace/*/ticket.md`): 37 of 271 tickets mention XFF or a CDN vendor. Themes that recur:

- Cloudflare edges brute-force-blocked (3483741 → #3392385). The workaround is `EnableBruteForceProtectionPerIP = False` ([Using a CDN with OutSystems][os-cdn]).
- Akamai `True-Client-IP` not evaluated, and Trusted proxy addresses not supported on O11 Cloud (3522405, L3 answer).
- Customers allowlisting Cloudflare ranges and hitting intermittent 52x errors (3388527).
- XFF trusted-proxy confusion (3397404).
- CloudFront 403/429 errors that are OutSystems' own ODC edge, not a customer CDN (3531098).

---

## 6. Recommended layered model

### 6.1 Layers (cheapest first; each runs on demand, per the existing design)

1. **L1, peer IP vs feeds** (ALB `client`, IIS rightmost hop): per-row badge.
2. **L2, dataset aggregate**: H1 share, H2 spread, H8.
3. **L3, behaviour** (needs raw ALB with `conn_trace_id`): H3 first, then H4–H7 as support.
4. **L4, IIS chain**: in the resolver from section 3.4, the rightmost hop is in the feed **and** a public hop sits left of it.
5. **L5, hostname probe** (optional, online): the section 4 table.

### 6.2 Confidence levels

| Level | Rule | Operator wording (banner) | Row badge |
|---|---|---|---|
| **Confirmed** | (L2 ≥ 80 % of top-20 hits in one vendor feed) **or** (L1 + L4 on ≥ 10 % of IIS multi-hop rows) **or** (L5 definitive header **and** L1 match) | **Fronted by Cloudflare.** ALB shows edges, not users. Use IIS IP summary. | `Cloudflare edge` |
| **Likely** | L2 50–80 % **or** L5 DNS/IP match without a header **or** H3 + same-ASN spread (Akamai without a feed) | **Likely fronted by Akamai.** Check IIS client IPs. | `Akamai (ASN)` |
| **Possible** | H3 alone, **or** H4 + H6/H7 with no feed or ASN match, **or** a feed match on < 50 % of hits | **Shared proxy in front.** Top IPs may not be actors. | `Proxy` |
| — (side class) | IP in Zscaler or Netskope feeds | (no banner) | `Corporate proxy` |
| — (side class) | Known monitoring IPs (e.g. 3.211.38.142 `Elastic-Heartbeat`) | (no banner) | `Monitoring` |
| — | Probe positive but ALB not matching | **Origin reachable without the CDN.** | — |
| — | IIS resolver `spoofSuspect` | (no banner) | `XFF forged` + the claimed IP shown greyed in its own column |

**Reconciliation with the existing note.** The future-directions doc says to avoid "Confirmed CDN" "unless future correlation data supports it". The *Confirmed* level above requires that correlation: either the share or the IIS hop pattern, or a probe header combined with a feed match. It is never asserted from a single signal.

**Wording rules** (from the CLAUDE.md UI guardrails):

- Keep each line to one sentence with one action.
- No hedging paragraphs.
- No "preview" or roadmap language.
- Provider name first, action second.

### 6.3 Operator actions per result

- **Confirmed / Likely:**
  - Hide vendor IPs from the "block this IP" and AbuseIPDB hand-offs, or mark them.
  - Pivot to the IIS IP summary. It resolves through the section 3.4 algorithm with `trustedProviders = {vendor}`.
  - Suggest the customer-facing notes: block at the CDN; `EnableBruteForceProtectionPerIP`; Akamai must populate XFF.
- **Possible:** show the H3 numbers (connections with ≥ 3 UAs) so the operator can judge.
- **XFF forged:** list the rows. Recommend checking any customer IP-allowlist logic that reads the first hop (3522405).

---

## 7. Gaps and open items

- H3 has no positive validation yet. The next Cloudflare or Akamai ticket with raw ALB logs should be used to tune the thresholds.
- Akamai and F5 XC: no complete public edge feeds; the F5 XC CNAME pattern is not confirmed. Rely on operator-pasted ranges plus ASN.
- ASN numbers in section 4 are partly from general knowledge. Verify them against an RDAP or ASN dataset before shipping (G3 in `ticket-gap-plan.md` plans an RDAP column).
- Whether OutSystems Cloud could log `CF-Connecting-IP`, `True-Client-IP` or `X-Azure-FDID` as extra IIS fields is unknown. It is a CloudOps question.
- `ALWAYS_SKIP` should include the environment's VPC CIDR (e.g. `10.15.109.0/24` in 3522405) when it is known. It is already covered by RFC 1918 in all cases seen so far.

---

## Sources (accessed 2026-11-22)

[aws-alb-logs]: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
[aws-alb-xff]: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/x-forwarded-headers.html
[aws-cf-origin]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html
[cf-headers]: https://developers.cloudflare.com/fundamentals/reference/http-headers/
[cf-ips4]: https://www.cloudflare.com/ips-v4
[cf-ips6]: https://www.cloudflare.com/ips-v6
[afd-headers]: https://learn.microsoft.com/en-us/azure/frontdoor/front-door-http-headers-protocol
[afd-lock]: https://learn.microsoft.com/en-us/azure/networking/design-guide/internet-ingress
[ak-origin]: https://techdocs.akamai.com/property-mgr/docs/origin-server
[ak-tf]: https://techdocs.akamai.com/terraform/docs/origin
[ak-oipacl]: https://techdocs.akamai.com/origin-ip-acl/docs/welcome
[imp-rails]: https://rubydoc.info/gems/imperva-rails
[imp-guide]: https://www.imperva.com/blog/wp-content/uploads/sites/9/2015/09/Guide-Akamai-to-Incapsula-Migration-Guide.pdf
[imp-api]: https://my.imperva.com/api/integration/v1/ips
[fastly-ips]: https://api.fastly.com/public-ip-list
[f5-hdr]: https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/load-balance/create-http-load-balancer
[f5-ips]: https://docs.cloud.f5.com/docs-v2/platform/reference/network-cloud-ref
[mdn-xff]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For
[isantibot]: https://github.com/microlinkhq/is-antibot/pull/92
[os-cdn]: https://success.outsystems.com/documentation/11/setup_outsystems_infrastructure_and_platform/setting_up_outsystems/using_a_cdn_with_outsystems/

- AWS ALB access log entries: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
- AWS ALB X-Forwarded headers: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/x-forwarded-headers.html
- AWS CloudFront custom-origin request/response behaviour: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html
- AWS IP ranges: https://ip-ranges.amazonaws.com/ip-ranges.json
- Cloudflare HTTP headers: https://developers.cloudflare.com/fundamentals/reference/http-headers/
- Cloudflare IP lists: https://www.cloudflare.com/ips-v4, https://www.cloudflare.com/ips-v6
- Azure Front Door HTTP headers: https://learn.microsoft.com/en-us/azure/frontdoor/front-door-http-headers-protocol
- Azure internet ingress (AFD service tag and X-Azure-FDID): https://learn.microsoft.com/en-us/azure/networking/design-guide/internet-ingress
- Akamai Origin Server behaviour (True-Client-IP): https://techdocs.akamai.com/property-mgr/docs/origin-server
- Akamai Terraform `origin` (true_client_ip options): https://techdocs.akamai.com/terraform/docs/origin
- Akamai Origin IP ACL: https://techdocs.akamai.com/origin-ip-acl/docs/welcome
- Imperva IP list API: https://my.imperva.com/api/integration/v1/ips
- imperva-rails (Incap-Client-IP, spoofing warning): https://rubydoc.info/gems/imperva-rails
- Imperva Akamai→Incapsula migration guide: https://www.imperva.com/blog/wp-content/uploads/sites/9/2015/09/Guide-Akamai-to-Incapsula-Migration-Guide.pdf
- Imperva X-Iinfo and cookie fingerprints (third party): https://www.aethyn.io/solutions/imperva-incapsula-which-engine-blocked-you
- Fastly public IP list: https://api.fastly.com/public-ip-list
- F5 XC HTTP LB (server header `volt-adc`): https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/load-balance/create-http-load-balancer
- F5 XC service chaining (`volt-cdn`, `x-volterra-location`): https://community.f5.com/kb/technicalarticles/use-f5-distributed-cloud-to-service-chain-waap-and-cdn/303142
- F5 XC IP and domain reference: https://docs.cloud.f5.com/docs-v2/platform/reference/network-cloud-ref
- Zscaler cloud enforcement node ranges: https://config.zscaler.com/api/zscaler.net/cenr/json
- MDN X-Forwarded-For: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For
- is-antibot Akamai detection (ASNs 20940/16625): https://github.com/microlinkhq/is-antibot/pull/92
- Akamai debug headers gist: https://gist.github.com/brunohenrique/0e9d2a2b40aa9f499390d30f744ffd75
- OutSystems, Using a CDN with OutSystems: https://success.outsystems.com/documentation/11/setup_outsystems_infrastructure_and_platform/setting_up_outsystems/using_a_cdn_with_outsystems/
- OutSystems, Implementing an Akamai WAF: https://success.outsystems.com/documentation/11/security_and_compliance/web_application_firewall_in_outsystems/implementing_a_akamai_waf_for_an_outsystems_web_app/
- OutSystems, configurations in reverse proxy scenarios: https://success.outsystems.com/documentation/how_to_guides/infrastructure/using_outsystems_in_reverse_proxy_scenarios/outsystems_configurations_in_reverse_proxy_scenarios/
