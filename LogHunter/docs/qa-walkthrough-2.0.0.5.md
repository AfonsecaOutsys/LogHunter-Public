# QA walkthrough: LogHunter 2.0.0.5

**Date:** 2026-11-25, 23:36–23:59 UTC
**Build:** `C:\espaces\LogHunter.exe` 2.0.0.5, signed, published 23:30. Branch `feature/usage-tracking` (49b457d).
**How it was run:** `--web --no-browser`, driven in the in-app browser. Every workflow used the **default folders**: `C:\espaces\ALB` (132 files, 3.3 MB), `C:\espaces\IIS` (1 file, 2.7 MB) and `C:\espaces\PlatformLogs` (6 CSVs, 121 MB).
**Checked against:** independent counts from the raw logs (Python/awk) for every number that could be recomputed.
**Out of scope:** ALB download (excluded on request). Anything behind a native Windows dialog: Select folder/files, "From output file", "From burst results" and the SQLite Viewer. Console mode. Open report/Excel/CSV, which open desktop apps.

Severity: **High** = broken feature or wrong result. **Medium** = misleading output or a visible defect. **Low** = polish or consistency.

---

## 1. Bugs

| ID | Sev | Where | What happens | Evidence / cause |
|---|---|---|---|---|
| B1 | **High** (regression) | ALB / Requests over time | After a scan completes the page shows nothing: no chart, no table, no **Open chart**. The chart only auto-opens once, in the external default browser, and can't be reopened from the page. | `AlbPageBuilder.cs:775` renders `albReqOverTimeOpenChart` with a static `hidden` attribute, and `alb.js:2315-2319` only toggles `disabled`. Before cc8e19c added the global `[hidden]{display:none}` rule, `.button-like` showed the button anyway. The fix made it permanently hidden. The results section is also suppressed on purpose (`alb.js:2339`). |
| B2 | Medium | ALB / Top IPs + paths (empty fragment); Platform / Authenticated activity (empty cache) | The validation error shows, but the status panel stays stuck on "queued / Scanning ALB logs… / Preparing scan" (Platform: "PHASE queued / Starting authenticated activity check…"). | `alb.js:1057-1075` sets the queued text **before** validating and resets only `State` to idle. Platform auth shows the same pattern. Likely in the other run handlers too. |
| B3 | Medium | ALB generic scans: status count pill | The pill shows a different metric from its label. **Top 50 IPs:** "IPS 4479" is total requests (12 unique IPs). **Top 50 by URI:** "PAIRS 1797" is the sum of the top 50 rows' hits (1,392 pairs). **Top 50 AVG duration:** "URIS 634" (835 URIs). No thousands separator. | `alb.js:1911` binds `result.totalMatches`, and `AlbGenericScanFunctions.cs` sets `TotalMatches` to something different per scan (e.g. `:242` `top.Sum(hits)`). |
| B4 | Medium | IIS / Uploads & Payloads | The ranking looks wrong: #2 52.52.102.154 at **9.1 KB**, #3 3.73.213.149 at **85 KB**. | The sort key is `MaxCsBytes`, the largest single payload (`IisBytesIntelJobManager.cs:346`), but the web list only shows total cs-bytes. The console shows both. Show "max payload" in the web line. |
| B5 | Medium | Platform / Suspicious requests: extract IPs | It reports "No matching suspicious rows were found. Files matched: 0", but `errors2.csv` has **242** "A potentially dangerous Request" rows. | A row that matches a pattern but has no extractable IP is dropped silently (`PlatformScanner.cs:117-118`), and broken files are skipped with an empty `catch` (`:60`). In this case `errors2.csv` has a misaligned header (duplicated `id` column, every column after it shifted by one), so the env-info column holds `7`. That's a dataset problem, but the tool should say "242 rows matched, no IP found" or "columns don't line up". |
| B6 | Low | Count charts (Requests over time HTML, ALB IP Summary report) | The y-axis starts below zero (−11, −3). Ticks are non-round (22, 55, 88…). The last x-axis label is clipped at the right edge. | The chart script pads 8% below `yMin` (`yPad = (yMax - yMin) * 0.08`). Clamp at 0 for count series. |

## 2. Data and analysis gaps

| ID | Sev | Where | Finding |
|---|---|---|---|
| G1 | Medium | ALB / IP Summary (page and report) | **No CDN/proxy badges.** 23.50.62.15 is an Akamai edge and 163.116.207.138 a Netskope proxy (the range store says so), but nothing is shown. IIS IP Summary, ALB Top 50 and the sweep do show them. |
| G2 | Low | IP sweep page | A CIDR or range gets a badge only when exactly one IP matched. `163.116.0.0/16` is labelled "Netskope proxy", while `23.50.62.0/24` (6 Akamai edges) shows nothing on the page, even though the HTML report says "Akamai edge (6 IPs)". The IPs column is blank when 1 IP matched (`ipsweep.js:193-200`). |
| G3 | Low (design) | IIS / Burst Patterns | 0 candidates at both 60 s and 10 s, although 35.75.252.136 makes **318 requests in 10 s / 699 per minute** (92 × 500). This is by design: only strong enumeration or **4xx** errors make a candidate (`IisBurstScoring.cs:46-56`), and 5xx doesn't count. But the page gives no hint of the spike. Consider a "top buckets by volume" list when there are 0 candidates, or counting 5xx. |
| G4 | Low | ALB / IP Summary | FE (target) totals don't add up to the total: 2,037 vs 2,041 for 40.81.204.182. The 4 × 460 with target status `-` fall into no row. Add a "no backend response" row. |
| G5 | Low | ALB + IIS IP Summary (page and report) | Per-IP cards are sorted **lexically by IP string** (127… / 3.211… / 3.73… / 35.75…). The report's default selected IP is the first string (163.116.207.138, 341 hits), not the top one (40.81.204.182, 2,041). The "Per-IP row counts" list next to it is sorted by hits. |
| G6 | Low | ALB Requests over time, AbuseIPDB Check IPs | Invalid input is dropped silently (`999.1.1.1`, `abc`). IP sweep shows "Ignored input"; these don't. |
| G7 | Low | AbuseIPDB / Check IPs | Private or reserved IPs (`10.0.0.1`) are sent to AbuseIPDB and spend quota. The sweep hand-off already skips CDN edges; manual entry skips nothing. |
| G8 | Low | ALB / Top 50 by AVG duration | Paths aren't normalised: `/FactoryConfiguration` vs `/FactoryConfiguration/`, `/ATMinquiryAdmin` vs `/ATMInquiryAdmin` are separate rows. |
| G9 | Low | IP ranges page | Built-in static ranges (Google Cloud LB, **Netskope**, Sucuri; `IpIntelFeeds.cs:231`) label IPs but aren't listed. After a customer range is saved, the headline stays "8 providers · 8,229 ranges". |
| G10 | Low | Platform / Authenticated activity | The "Hits by log type" rows (General / Traditional / Screen / Error) don't cover the Integrations and Service Actions files in the folder. |

## 3. UI, visual and consistency

| ID | Sev | Where | Finding |
|---|---|---|---|
| V1 | Medium | IIS Status Pivot, Top Bandwidth, Uploads; both Platform workflows | There's **no Log source section**: no folder or file count and no Select folder/files. Every other IIS/ALB workflow has one. |
| V2 | Low | IIS Top Bandwidth, Uploads | The status button says **"Open CSV"** but the export is `.xlsx`. The results panel says "Open export". |
| V3 | Low | IP sweep | Folder-label inputs (`.ip-sweep-label`) use browser defaults: grey `rgb(59,59,59)`, 1.6 px inset border. They don't match the other fields. |
| V4 | Low | Every workflow page; Home | The title and description appear twice (page header, then a hero card saying the same thing), which pushes the inputs below the fold. Home shows "LogHunter 2.0" twice. (Guardrail 8.) |
| V5 | Low | ALB / Top IPs + paths | The top IPs render as one run-on line ("#1 … 1081 hits #2 …") instead of a list or table. |
| V6 | Low | IIS / IP Summary | Top URIs are truncated, so `…/openid-configuration` and `…/openid-configuration/jwks` look identical (there is a tooltip). |
| V7 | Low | Source chips, sweep folders | "1 files". |
| ~~V8~~ | — | ALB / Top IPs + paths | Withdrawn: the checkbox is wrapped in its `<label>` (`AlbPageBuilder.cs:413`). The "on" came from the accessibility tool. |
| V9 | Low | ALB / IP Summary | The placeholder shows private IPs (`10.0.0.1 192.168.1.100 …`). ALB clients are public. |

## 4. Copy (UI guardrails)

| ID | Where | Text |
|---|---|---|
| C1 | ALB landing; Home | "…and **future** drill-down tools"; "Start here to navigate the **new** browser-based shell for LogHunter." (Guardrail 2.) |
| C2 | WAF blocks over time | "No blocked entries found **(per current definition)**." |
| C3 | Platform / Suspicious extract | "Results are saved to session selections and update the suspicious-IP cache for downstream use." (Dev wording, guardrail 7.) |
| C4 | Status Pivot, Platform auth errors | Raw `Error:` prefix ("Error: Invalid status filter."). The status-filter error doesn't say which token is bad or what format is expected. |
| C5 | Platform auth | "Found 6554 authenticated rows" (unformatted) next to "6,554". |
| C6 | Console banner (redirected stdout) | "Andr\uFFFD Fonseca" mojibake. Not checked in a real console window. |

## 5. Performance

All timings are wall-clock from click to "completed", or the server job `createdUtc` → `updatedUtc`.

| Workflow | Data | Time | Note |
|---|---|---|---|
| ALB Top IPs + paths | 132 files / 4,479 lines | < 3 s | |
| ALB IP Summary, export mode | 3 IPs | < 4 s | |
| **ALB IP Summary, chart-only mode** | same 3 IPs | **9.6 s** | **P1 (unconfirmed):** one measurement only, and the export-mode run had no server timestamps. On a code read chart-only should be faster (`SummaryOnly` retention, no SQLite). Re-measure before acting. |
| ALB IP sweep | 133 files / 22,075 lines | < 4 s | |
| ALB Top 50 ×3, 5xx, WAF ×2 | 132 files | < 3 s each | |
| ALB Requests over time | 4 IPs | 0.1 s server | |
| IIS workflows (all 6) | 17,596 lines | < 5 s each | |
| Platform suspicious extract | 6 files / 121 MB | ≈ 5 s | |
| Platform authenticated activity | 6 files / 121 MB | ≈ 6 s | |
| IP ranges Refresh now | 12 feeds | 2–19 s | Button disables while running |
| Page loads | | ≈ 10 ms | |

**P2 (Low):** in the trace, the 4 s `/api/app/info` heartbeat writes 3 lines per poll (`http begin`, `http end`, `client fetch`): about 970 of 1,645 lines (59%) in 21 minutes, roughly 5 MB per 8-hour session. Consider not tracing the heartbeat.

## 6. Usage tracking (new in 2.0.0.5)

**What it does** (per `docs/usage-tracking-plan.md`, `README.md` § Usage counts, `UsageReporter.cs`):
- One `AppStart` per launch and one `FeatureUse` per started workflow.
- Sent to `LogHunterUsage_IS/rest/Usage` with the `X-LogHunter-Key` header.
- Payload: install id (`config\install-id`), session id, version, mode, and the feature key.
- Runs in the background with a 3 s timeout. Failures are swallowed and traced locally as `usage sent|failed`.
- Release builds only. `LOGHUNTER_NO_USAGE=1` turns it off. The console prints a one-line notice; the web UI shows none, by design.

**What was verified:** 27 events, **all HTTP 200**, each with the right key:
- `alb.top-ips-endpoint`, `alb.ip-summary` ×2, `alb.ip-sweep`, `alb.5xx-mismatch`, `alb.top50-ips` ×2, `alb.top50-ips-by-uri`, `alb.top50-avg-duration`, `alb.requests-over-time`, `alb.waf-blocked-summary`, `alb.waf-blocks-over-time`
- `iis.ip-summary`, `iis.ip-sweep`, `iis.status-pivot` ×2, `iis.burst-patterns` ×2, `iis.top-bandwidth`, `iis.uploads-payloads`
- `platform.suspicious-ips`, `platform.auth-activity`
- `abuseipdb.check`, `ipranges.refresh`, `ipranges.custom-ranges` ×2 (Clear counts too, as planned)

Runs rejected by validation are **not** counted, which is correct: the empty fragment, the empty Platform cache and the invalid status filter all sent nothing. ALB and IIS sweeps are told apart correctly.

**Not verified:** `tools.sqlite-viewer` (native dialog), console mode, the `LOGHUNTER_NO_USAGE` opt-out, offline behaviour.

**Suggestions:**
- U1: put the `SessionId` in the `usage sent` trace line. Without it, test rows can only be told apart by time.
- U2: these 27 walkthrough events are now in the usage DB under **install `def45ed2-feb0-4d90-b107-aa986a39ec25`, 2026-11-25 23:36–23:59 UTC**, which is the same install as normal use on this machine. Delete them if they shouldn't count.

## 7. Checked and working

Everything below matched the independent counts.
- **ALB:** Top IPs + paths (1081/209/136/57). IP Summary per-IP totals (2,041 / 341 / 300). IP sweep (all target types, IPv6, ranges, bad input flagged, hand-off with 10 IPs + folder, reload restores the form). 5xx mismatch (0). Top 50 IPs and the "Likely fronted by Akamai" banner. Top 50 by URI. AVG duration (top row exact: 21.403 s avg, 30 requests, 265.263 s max). Requests over time totals (3,077). WAF summary and chart (0 blocked, correct for this dataset).
- **IIS:** IP Summary resolved-client counts, including `+`-encoded XFF chains, loopback hops and `ip:port` OriginalIP values (3,451 / 1,699 / 975 / 215). IP sweep (consistent with IP Summary; 10.15.109.0/24 = 11,253). Status Pivot (94 × 500 → 2 IPs, 1,820 pivot lines). Top Bandwidth (19 MB / 8.1 MB / 6.3 MB).
- **Platform:** Authenticated activity (General 4,442 / 2,092 exactly). Cache page.
- **AbuseIPDB:** Check IPs (3 checked, 0 failures, CSV written). Settings page.
- **IP ranges:** All 12 feeds OK after refresh. The headline now matches the table. Customer ranges save, clear and report bad lines.
- The fixes from cc8e19c that show up in the UI are confirmed: empty sweep panels hidden, target counter flags `12345`, sweep report Network column, form restore after reload, no "migration" footer.
- Light theme: clean and readable, badges legible.

## 8. Side effects of this walkthrough

- 20 files in `C:\espaces\output` with timestamps between `20261125_233818` and `20261125_235839`.
- The Requests-over-time chart auto-opened in the default desktop browser.
- AbuseIPDB looked up 3 IPs (8.8.8.8, 1.1.1.1, 10.0.0.1), using the built-in key. No dataset IPs were sent.
- IP range feeds were refreshed at 23:56 UTC. Customer ranges were saved and then cleared; the server is back to empty.
- 27 usage events (see U2). Trace: `C:\espaces\logs\trace-20261125-233633-49564.jsonl`.
