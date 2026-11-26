# QA re-check: hotfix/v2.0.0.6-qa-fixes

**Date:** 2026-11-26, 09:14–09:27 UTC
**Build:** `C:\espaces\LogHunter.exe` 2.0.0.5 (signed), published **09:13:04**. Built from the uncommitted working tree of `hotfix/v2.0.0.6-qa-fixes` (base `8eb5a95`), which also contains the new feedback page and usage On/Off switch.
- An earlier `2.0.0.5+feedback-test` build (01:02) was replaced mid-session, and another `--web --no-browser` instance closed my first launch once. Everything below is from the 09:13 build.

**Checks against:** `handoff-qa-fixes-2.0.0.6.md` (A1–A8, L1–L17, D1–D4) and its regression oracle. The same default folders as before, except `PlatformLogs` now has 5 files (`errors2.csv` was removed at 08:10).

**Usage data:**
- The main run used `LOGHUNTER_NO_USAGE=1`, which sent nothing. That verified the opt-out: `/api/usage/settings` returned `{"available":false,"enabled":false}`.
- The usage switch was tested on a **copy** of the exe in a scratch folder, with its own config. It sent one `AppStart` from throwaway install `587d5446-e870-475f-af5c-1e3e4bd38673` at 09:25:23Z.

**Feedback:** nothing was submitted.

---

## 1. Handoff items

| ID | Result | Evidence |
|---|---|---|
| A1 Requests over time page | ✅ Fixed | Open chart visible and enabled; "Top time buckets" table rendered (20 rows, sorted by total); 3,077 hits. |
| A2 Stuck "queued" | ✅ Fixed | ALB empty fragment and Platform auth on an empty cache: error shown, status stays idle. |
| A3 Count pills | ✅ Fixed | 12 IPs / 1,385 pairs / 807 URIs, with thousands separators. |
| A4 Uploads ranking display | ✅ Fixed | "#1 35.75.252.136 — max 22 KB · total 1.1 MB (1,012 POST/PUT)". The order matches the first number. |
| A5 Platform silent drops | ✅ Fixed | The dataset no longer exercises it (`errors2.csv` removed). Verified on synthetic data in an isolated copy: "1 rows matched but had no client IP (errors_synthetic.csv: 1). 1 file skipped (wrong_columns.csv: message or environment info column not found)", and the row with an IP was extracted. |
| A6 ALB IP Summary badges | ✅ Fixed on the page | "Netskope proxy", "Akamai edge". The HTML report still has no CDN labels (this part was optional). |
| A7 Log source | ✅ Fixed | Status Pivot, Top Bandwidth and Uploads show `C:\espaces\IIS \| 1 file \| 2.7 MB` with Select folder/files. Platform pages show `C:\espaces\PlatformLogs \| 5 files \| 120 MB`. |
| A8 IP input parser | ✅ Fixed at the 4 sites | ALB IP Summary "Ignored input: abc". Requests over time "999.1.1.1, 12345". IIS IP Summary `ignored: ['12345']`. AbuseIPDB "Ignored input: abc, 12345 \| Skipped private/reserved (not sent): 10.0.0.1, 192.168.1.1", and only 8.8.8.8 was checked. **Gap:** Platform auth manual input (N2). |
| L1 Charts below zero | ⚠️ Partial | Fixed in `Charts.cs`, `AlbOption3IpSummaryMulti.cs` and `IisOption_IpSummary.cs` (Requests-over-time chart now starts at 0, last x label not clipped). **Not fixed in the web IP Summary reports**: `Web/Orchestration/AlbIpSummaryJobManager.cs:743` and `IisIpSummaryJobManager.cs:702` have their own minified chart (`const yP=(yMax-yMin)*.08`). The ALB report still shows a **−5** tick and a clipped last x label. *The handoff missed these two files.* Ticks are still non-round (optional). |
| L2 Per-IP order | ✅ Fixed | Page cards and report dropdown sorted by hits; the report selects 40.81.204.182 (2,041) by default. |
| L3 `Error:` prefix | ✅ Fixed | "Invalid status code: abc, 999, 50. Use 4xx, 5xx, 4xx+5xx or comma-separated codes from 100 to 599 (e.g. 401,403,404)." |
| L4 "Open CSV" on xlsx | ✅ Fixed | "Open Excel". |
| L5 Sweep label inputs | ✅ Fixed | Dark field style, 14 px radius. |
| L6 "1 files" | ✅ Fixed | "1 file" in sweep and source chips. |
| L7 Roadmap and dev copy | ✅ Fixed | None of the 28 routes contain "future", "coming soon", "migration", "Option N" or "new browser-based". The WAF empty message is "No WAF-blocked requests found.". |
| L8 "Found 6554" | ✅ Fixed | "Found 6,554 authenticated rows…" |
| L9 Sweep CIDR badge | ✅ Fixed | "23.50.62.0/24 Akamai edge (6 IPs)". IPS column shows 1. |
| L10 FE no response | ✅ Fixed on the page | "No response 4". Not in the HTML report. |
| L11 Path normalisation | ✅ Fixed | `/FactoryConfiguration` and `/FactoryConfiguration/` merged (avg 10.667, n = 2). Counts moved as expected (pairs 1,392→1,385, URIs 835→807). |
| L12 Built-in ranges | ✅ Fixed | Google Cloud LB, Sucuri, Netskope listed as "built-in · ships with LogHunter". Headline "… · 3 built-in". |
| L13 Top IPs list | ✅ Fixed | Now a table with `data-ip`. Nit: hits unformatted ("1081"), see N9. |
| L14 Placeholders | ✅ Fixed | `203.0.113.7 / 198.51.100.20 / 192.0.2.15`. |
| L15 Duplicate title / hero | ✅ Fixed on workflow pages | Hero card gone, inputs above the fold. Home still shows "LogHunter 2.0" twice (brand + page title). |
| L16 Session id in trace | ✅ Fixed | `{"kind":"AppStart","sessionId":"d76a558f-…","status":200}` |
| L17 Heartbeat tracing | ✅ Fixed | 0 `/api/app/info` lines. The trace was 512 lines for this session vs ~1,000 for a comparable one before. |
| D1 Chart-only timing | ✅ Closed, not reproducible | Server timings: chart-only 0.70 / 0.59 s, export 1.87 / 2.41 / 1.23 s. Chart-only is the faster mode. |
| D2 Burst 0 candidates | ⏸ Deferred (by decision) | Still 0 at 60 s and 10 s. |
| D3 Platform log types | ✅ Fixed | "Skipped (no client IP column): Integrations_…152212.csv, Integrations_…154628.csv". |
| D4 `errors2.csv` | ⏸ Deferred | The file was removed from the dataset. |

## 2. Regression oracle (all unchanged unless noted)

| Workflow | Result |
|---|---|
| ALB Top IPs + paths `Butterfly` | 1,081 / 209 / 136 / 57 ✅ |
| ALB IP Summary | 2,041 / 341 / 300; ELB 2xx/3xx 1,988, FE 4xx 49, no response 4 ✅ |
| ALB IP sweep | 133 files, 22,075 lines; /24 1,339 from 6 IPs; range 608 from 2 IPs ✅ |
| ALB 5xx / WAF ×2 | 0 / 0 of 4,479 ✅ |
| ALB Top 50 IPs | 12 IPs; 2,041, 395 ✅ |
| ALB Top 50 by URI | **1,385 pairs** (was 1,392, expected change from L11); top row 308 ✅ |
| ALB AVG duration | **807 URIs** (was 835, expected from L11); #1 21.403 s / 30 / 265.263 s ✅ |
| ALB Requests over time | 3,077 hits, 90 buckets ✅ |
| IIS IP Summary | 3,451 / 1,699 / 975 / 215 ✅ |
| IIS Status Pivot 5xx | 92 + 2 → 1,820 lines ✅ |
| IIS Top Bandwidth | 19,656,977 / 8,526,231 / 6,654,738 / 3,535 B. Matches an independent recount with the full resolver. (The QA doc's "19,456,972" came from a rough count that didn't strip ports.) ✅ |
| IIS Uploads | max 23,002 / 8,952 / 1,925 B order ✅ |
| IIS Burst 60 s / 10 s | 0 / 0 (D2 deferred) ✅ |
| Platform auth manual | 4,462 (General 4,442 + Error 20) / 2,092 ✅ |

**Timings:** all scans run in 0.1–2.4 s. First runs are slower on a cold file cache: Requests over time took 2.3 s cold and 0.09–0.15 s warm.

## 3. New findings

| ID | Sev | Where | Finding | Suggested fix |
|---|---|---|---|---|
| N1 | **Medium** (pre-existing) | `Services/AppFolders.cs:9-16`; `Program.cs:202-204` | **`--root` is ignored.** `AppFolders` is `static readonly` and built from `AppContext.BaseDirectory`, so ALB, IIS, PlatformLogs, output, config and logs always come from the exe folder. A `--root <scratch>` run scanned `C:\espaces\PlatformLogs` and wrote its trace to `C:\espaces\logs`; only the trace's `mode.root` showed the override. This also made the handoff's `dotnet run … --root C:\espaces` instruction wrong (now corrected there). | Initialise `AppFolders` from the resolved root before first use (e.g. `AppFolders.Initialize(root)` right after `Program.cs:204`, with lazy fields), or drop the flag from `--help`. |
| N2 | Low | `Web/Api/PlatformApi.cs` (auth run) | Platform auth manual input isn't covered by A8: `not-an-ip` is counted ("Suspicious IPs input: 4") and there's no "Ignored input" notice. | Use `IpTargetParser.ParseIpList` and return `ignored`. |
| N3 | **Medium** (pre-existing) | `Services/PlatformAuthScanner.cs:297` (`TryResolveScreen`) | Uses `log.attributes.net.host.ip` as the **client** IP. In the ODC `Service_Actions` export that column is **always `127.0.0.1`** (30,001 of 30,001 rows sampled): it's the server's own address. The file is classified as "Screen" logs keyed by the server IP. Checking `127.0.0.1` would report false authenticated activity, and real client IPs never match. | Don't treat `net.host.ip` as a client IP. Report Service Actions as "skipped: no client IP column", like Integrations. Keep `source` for real O11 screen exports. |
| N4 | Low | `abuseip.js`, `alb.js` (IP Summary, Requests over time) | "Ignored input" / "Skipped private/reserved" notices use the red `inline-error` style on **successful** runs, so they read as failures. | Show them with the neutral note style the sweep uses for "Ignored input". |
| N5 | Low | `Web/Orchestration/PlatformSuspiciousJobManager.cs` message + `platform.js` summary | With ODC exports every scan lists the same 4 skipped files in full, **twice** (status message and summary). | One short line ("4 files skipped: no message/environment columns") plus a details list, shown once. |
| N6 | Low | `PlatformSuspiciousJobManager.cs` completion message | "Found 1 suspicious rows … 1 distinct IPs … 1 rows matched" | Pluralise. |
| N7 | Low | Requests-over-time results table (`alb.js`, columns from `AlbGenericScanFunctions.cs` ~`:476`) | Header shows the raw key "BucketStartUtc" (rendered "BUCKETSTARTUTC"). | Label it "Bucket (UTC)". |
| N8 | Low | Feedback page (`site.js:367+`) | Under 10 characters the button is just disabled ("5 / 1000"), with no hint of the minimum. | "5 / 1000 · min 10" or a hint once the field is touched. |
| N9 | Low | ALB Top IPs + paths (`alb.js`) | Hits unformatted in the new table and breakdown ("1081"). | `toLocaleString('en-US')`. |
| N10 | Low | Requests-over-time chart (`Services/Charts.cs`) | "Source hits" column is all "—" for manual entry (carried over from the first QA). | Hide the column when there's no source file. |
| N11 | Cosmetic | `ipsweep.js` (Check reputation hand-off) | Private zero-hit targets (`10.15.109.52`) are handed to AbuseIPDB. The server now skips them, so nothing is sent. | Filter private addresses in the hand-off too. |

## 4. Still open from the handoff

- **L1 remainder:** clamp the y-axis and right-align the last x label in `AlbIpSummaryJobManager.cs:743` and `IisIpSummaryJobManager.cs:702` (the web IP Summary reports).
- Optional parts that weren't done: CDN labels and the "No response" row in the ALB IP Summary **report** (A6, L10); "nice" tick steps (L1); Home double title (L15).
- D2 and D4 were deliberately deferred.

## 4b. Fixes applied after the re-check (2026-11-26, same branch, uncommitted)

Verified against a local **Release build in `bin`** (not a publish), run with `--root C:\espaces` and `LOGHUNTER_NO_USAGE=1`. `dotnet test`: **168/168 pass**, and 13 consecutive full runs are green.

| ID | Fix | Files | Verified |
|---|---|---|---|
| N1 | `AppFolders` folders are now properties over a root that `Program` sets with `AppFolders.UseRoot(root)` right after parsing `--root`. The ALB download child already received `--root`, so it follows too. | `Services/AppFolders.cs`, `Program.cs` | The `bin\Release` exe with `--root C:\espaces` traced to `C:\espaces\logs` and scanned `C:\espaces\IIS` and `PlatformLogs`; nothing was written next to the exe. Tests: `AppFoldersTests` (own non-parallel collection). |
| L1 remainder | The web IP Summary report charts clamp `yMin` at 0 for non-negative data and keep x labels inside the canvas. | `Web/Orchestration/AlbIpSummaryJobManager.cs`, `IisIpSummaryJobManager.cs` | ALB and IIS reports: axis starts at 0, last label fully visible, no console errors. |
| N2 | Platform auth manual input goes through `IpTargetParser.ParseIpList`. A list with nothing valid is rejected instead of silently falling back to the cache. `ignored` is returned and shown as a note. | `Web/Api/PlatformApi.cs`, `Web/Assets/platform.js` | "Ignored input: not-an-ip" in the neutral style; check runs on 3 IPs. |
| N3 | `TryResolveScreen` no longer treats `log.attributes.net.host.ip` (the server's own address) as the client IP; only `source` remains. | `Services/PlatformAuthScanner.cs` | Service_Actions is now under "Skipped (no client IP column)". Test `PlatformAuthScannerTests` failed before the fix (2 false hits for 127.0.0.1) and passes after. 10.98.3.19 / 10.98.4.230 unchanged (6,554). |
| N4 | New `.inline-error.is-note` style. "Ignored input" / "Skipped private" notices use `showNote`, and the error setters clear the modifier. | `site.css`, `alb.js`, `iis.js`, `abuseip.js`, `platform.js` | ALB IP Summary note: `inline-error is-note`, soft accent background, muted text. |
| N5, N6 | The completion message groups skipped files by reason (the reason is written once) and pluralises counts. The Results overview no longer repeats the message. | `Web/Orchestration/PlatformSuspiciousJobManager.cs`, `platform.js` | "4 files skipped (message or environment info column not found): General…, Integrations…, Integrations…, Service_Actions…". Test `CompletionMessage_PluralisesAndGroupsSkippedFilesByReason`. |
| N7 | Bucket column label "Bucket (UTC)". | `Web/Orchestration/AlbGenericScanFunctions.cs` | Requests-over-time columns: `['Bucket (UTC)', …]`. |
| N8 | Feedback counter shows "· min 10" while the text is too short. | `Web/Assets/site.js` | "5 / 1000 · min 10" → "21 / 1000"; nothing sent. |
| N9 | Hit counts in Top IPs + paths use thousands separators (`formatCount`). | `Web/Assets/alb.js` | "1,081". |
| N10 | The chart's "Source hits" column only shows when a series has a source count. | `Services/Charts.cs` | Columns: IP, Total requests, Peak, Visible. |
| N11 | Check reputation also drops private/reserved IPs before the hand-off. | `Web/Assets/ipsweep.js` | Hand-off is `35.75.252.136, 1.2.3.4` (10.15.109.x and 127.0.0.1 dropped; Akamai still skipped). |
| Test flake | `IpIntelStoreTests` joined the `SharedIpIntelState` collection. Its `RefreshFeedAsync` tests write the same feed files as `IpIntelApiTests`, which intermittently failed with "Access to the path is denied" (2 of ~24 runs). | `LogHunter.Tests/Services/IpIntelStoreTests.cs` | 0 failures in 13 full runs afterwards. |

**Still not done (optional, from the handoff):** CDN labels and "No response" in the ALB IP Summary **report**, "nice" tick steps, Home double title. D2 and D4 remain deferred.

## 5. Side effects of this re-check

- 23 files in `C:\espaces\output` stamped `20261126_0915`–`0921`.
- The Requests-over-time chart auto-opened once in the default desktop browser (09:15).
- AbuseIPDB looked up one IP (8.8.8.8).
- One `AppStart` from the throwaway install `587d5446-e870-475f-af5c-1e3e4bd38673`. Nothing from the real install.
- Real config untouched: no `usage-settings.json` in `C:\espaces\config`.
- The scratch workspace (with a 53 MB exe copy) is at `C:\Users\cvh\AppData\Local\Temp\claude\86b07d1bdcb25076\cc5eee11-5ce1-4f9b-99ff-646500f80803\scratchpad\qa-root` and can be deleted.
