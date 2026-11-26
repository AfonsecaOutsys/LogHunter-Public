# Handoff: QA bug fixes for 2.0.0.6

**For:** the agent that will create and work the bugfix branch.
**From:** the QA walkthrough of 2.0.0.5 on 2026-11-25. The full findings, with evidence, are in `LogHunter/docs/qa-walkthrough-2.0.0.5.md`. Read it first.
**Goal:** fix the bugs and misleading output it found, without changing any result that is already correct (section 4 lists the numbers that must stay the same).

---

## 0. Setup

### 0.1 Branch

- **Base:** `main` @ `8eb5a95` (v2.0.0.5). `main` is checked out in the worktree `C:\Users\cvh\source\repos\LogHunter-hotfix`.
- **Branch name:** `hotfix/v2.0.0.6-qa-fixes`. This follows the existing `hotfix/v2.0.0.x-…` names.
- Every file:line in this document was checked on `8eb5a95`. Code there is identical to `feature/usage-tracking` @ `49b457d`; only docs and the version differ.

From the main repo folder, either of these works:

```powershell
git switch -c hotfix/v2.0.0.6-qa-fixes main
```

```powershell
git worktree add ..\LogHunter-qa-fixes -b hotfix/v2.0.0.6-qa-fixes main
```

This handoff and `qa-walkthrough-2.0.0.5.md` are **untracked** in the `feature/usage-tracking` worktree (`C:\Users\cvh\source\repos\LogHunter\LogHunter\docs\`). If you use a new worktree, copy both files into its `LogHunter\docs\`.

### 0.2 Rules from `CLAUDE.md` (they apply to this branch)

- Activate `andrej-karpathy-skills:karpathy-guidelines` at the start. Make surgical changes: no refactors beyond what an item needs.
- **No commit, push, merge or Release publish unless the user asks.** If the user says `testmode on`, the loop is: fix → Release `.exe` per the Release Publish Rules → stop for feedback.
- Respect the **UI/UX guardrails** in `CLAUDE.md`. Items C1–C3 below exist because of rules 2, 7 and 8.
- When this is merged to `main` (only when the user asks), bump to **2.0.0.6**:
  - update the README release notes;
  - add `LogHunter/docs/patch-notes/<date>-v2.0.0.6.md`;
  - update the carry-forward backnote `LogHunter/docs/patch-notes/2026-10-23-v2.1-backnote.md`.

### 0.3 Build, test, run

```powershell
dotnet build LogHunter.sln
```

```powershell
dotnet test LogHunter.Tests
```

Run it against the QA dataset in web mode. Debug builds don't send usage events, which keeps test runs out of the usage DB. In a Release build, set `LOGHUNTER_NO_USAGE=1` first.

**Correction (2026-11-26):** `--root` is currently ignored. `AppFolders` always uses the exe's own folder; see `qa-recheck-2.0.0.6.md` N1. To test against the dataset, run the published exe from `C:\espaces`, or copy the `ALB`, `IIS` and `PlatformLogs` folders next to the build output.

```powershell
$env:LOGHUNTER_NO_USAGE = "1"; & C:\espaces\LogHunter.exe --web
```

The dataset lives in the default folders under `C:\espaces`:
- `ALB\`: 132 files in two subfolders. The day folder holds 00:00–08:45 and a second folder holds 09:45–10:00. They don't overlap.
- `IIS\`: 1 file, 17,596 lines, with `OriginalIP` XFF chains like `3.73.213.149,+127.0.0.1,+127.0.0.1:55343` and `ip:port` values.
- `PlatformLogs\`: 6 CSVs, 121 MB.

The test project has 69 tests, with stub-handler patterns in `LogHunter.Tests/Web/IpIntelApiTests.cs` and `Services/IpIntelStoreTests.cs`. There are no JS tests, so JS fixes are verified in the browser (section 4).

---

## 1. Must fix (High / Medium)

Do these in order. A2 and A8 add shared helpers that later items use.

### A1. Requests over time shows nothing after a scan (High, regression)

- **Repro:** go to ALB → Requests over time, enter `40.81.204.182`, Run scan. It completes ("3,077 total hits…"), but no chart, no table and no Open chart button appear. The chart opens once in the external default browser and can't be reopened.
- **Cause:**
  - `Web/Pages/AlbPageBuilder.cs:775` renders `albReqOverTimeOpenChart` with a static `hidden` attribute.
  - `Web/Assets/alb.js:2315-2319` (`renderSnapshot` in `initializeReqOverTimePage`) only toggles `disabled`, never `hidden`.
  - Before cc8e19c added the global `[hidden]{display:none!important}`, `.button-like`'s `display` rule overrode `hidden`, so the button showed.
  - The bucket table is suppressed on purpose (`alb.js:2339`, "Suppress bucket table — chart is the primary output").
- **Fix:**
  1. In `renderSnapshot`, `setHidden(openChartBtn2, !chartPath)` as well as setting `disabled`.
  2. Un-hide `albReqOverTimeResults` on completion and render the top buckets from `result.rows`/`result.columns`. The server already returns 20 rows and the section has the heading "Top time buckets by total requests". Reuse the generic results-table render from the generic-scan initializer around `alb.js:1900-2035`.
  3. Keep the one-time auto-open.
- **Also check:** whether any other element relies on CSS overriding `hidden`. Static-`hidden` buttons in `Web/Pages/*.cs` were reviewed: the `*ClearSelection` buttons are toggled with `setHidden(clearBtn, …)` and are fine.
- **Done when:** after a run, the page shows the Open chart button (enabled) and a bucket table. Clicking Open chart opens the HTML.

### A2. Status panel stuck on "queued" after a validation error (Medium)

- **Repro:**
  - ALB → Top IPs + paths, empty fragment, Run scan. The error shows, but the status says "PHASE queued / Scanning ALB logs… / Preparing scan / Waiting for the job to start".
  - Platform → Authenticated activity, source "Suspicious cache" with 0 cached IPs, Run check. The error shows, and the status says "PHASE queued / Starting authenticated activity check…".
- **Cause:**
  - `Web/Assets/alb.js:1053-1075` (`runAlbOption2`) writes the queued texts **before** validating, and on failure resets only `albOption2State`.
  - `Web/Assets/platform.js:465-489` (`runAuthCheck`) and `platform.js:248-271` (`runSuspiciousScan`) write the queued texts, and when the server rejects the run (`!payload.ok` or a thrown 400) they reset only `State`.
- **Fix:**
  - In `runAlbOption2`, move the queued `setText` block (lines 1058-1069) after the three validation `return`s.
  - In both platform run functions, on every failure branch restore Phase, Message and progress to the idle texts, using the same strings as the "idle" branch of each render function.
  - Scan the other run functions for the same shape (`alb.js:1504, 2154, 2514`; `iis.js:351, 664, 954, 1193`; `ipsweep.js:127`; `abuseip.js`) and apply the same rule: **validate first, write queued state only after the server accepts the run**.
- **Done when:** every validation or server error leaves the status panel in its idle state, with only the error banner showing.

### A3. ALB status count pill shows the wrong metric (Medium)

- **Repro:**

  | Scan | Pill | Message |
  |---|---|---|
  | Top 50 IPs overall | "IPS 4479" | "12 unique IPs found" |
  | Top 50 by URI | "PAIRS 1797" | "1,392 unique IP+URI pairs" |
  | Top 50 by AVG duration | "URIS 634" | "835 unique URIs" |

- **Cause:** `alb.js:1911` and `alb.js:2314` bind `result.totalMatches`. In `Web/Orchestration/AlbGenericScanFunctions.cs`, `TotalMatches` is the **sum of hits over the top 50 rows** for the three Top-50 scans (`:146` + `:155`, `:233` + `:242`, `:345`). The pill labels come from `AlbPageBuilder.cs:79/87/95` ("IPs", "Pairs", "URIs"). The 5xx and WAF scans are consistent ("Matches", "Blocked").
- **Fix:**
  - Set `TotalMatches` to the unique count each label promises: `ipCounts.Count` (Top 50 IPs), `pairCounts.Count` (IP+URI), `stats.Count` (AVG duration). Leave the other scans alone.
  - Format the pill with `Number(...).toLocaleString('en-US')` at `alb.js:1911` and `:2314`.
- **Tests:** if any test covers `AlbGenericScanResult.TotalMatches`, update it. Otherwise add a small test for one Top-50 function using a temp log file.
- **Done when:** the pills read 12 / 1,392 / 835 on the QA dataset.

### A4. IIS Uploads & Payloads ranking looks wrong (Medium)

- **Repro:** IIS → Uploads / Payloads, Run scan. The list shows #2 `52.52.102.154 — 9.1 KB` above #3 `3.73.213.149 — 85 KB`.
- **Cause:**
  - The ranking key is the largest single payload, `MaxCsBytes` (`Web/Orchestration/IisBytesIntelJobManager.cs:346`), and that's deliberate.
  - The web list shows only total cs-bytes (`Web/Assets/iis.js:1301`, `primaryBytes = ... ip.totalCsBytes`).
  - The max value already reaches the client, but in a misnamed field: `MaxScBytes: a.MaxCsBytes` at `IisBytesIntelJobManager.cs:411`.
  - Hits in uploads mode are `PostPutCount`.
- **Fix:**
  1. In uploads mode, render `#1 35.75.252.136 — max 23 KB · total 1.1 MB (1,012 POST/PUT)`. Show the sort key first.
  2. Optionally rename the DTO field to `MaxBytes` and use it in both modes. Bandwidth mode ranks by total sc-bytes, so its line is fine.
  3. Keep the console version (`Services/IisOption_BytesIntel.cs:695`) as the reference; it already prints both.
- **Done when:** the uploads list order matches the visible primary number.

### A5. Platform suspicious scan drops matched rows silently (Medium)

- **Repro:** Platform → Suspicious requests: extract IPs, Run scan. It reports "No matching suspicious rows were found. Files matched: 0", but `C:\espaces\PlatformLogs\errors2.csv` has **242** rows whose `message` contains "A potentially dangerous Request.".
- **Cause:**
  - In `Services/PlatformScanner.cs`, rows that match a pattern but have no extractable IP are skipped silently: `:117-118` (CSV) and `:158-159` (XLSX).
  - Files whose columns aren't found (`TryResolveColumns` returns false, `:91`) or that throw are skipped by an empty `catch` (`:60`). Unparseable rows are skipped at `:104`.
  - In this dataset, `errors2.csv` is malformed: its header repeats `id`, so every column after it is shifted by one and the env-info column holds `7`. The data is wrong, but the tool must not call it "no matches".
- **Fix:**
  1. Add counters to `PlatformSuspiciousScanResult` (`PlatformScanner.cs:242`): `MatchedRowsWithoutIp`, plus `FilesSkipped` with a reason (`columns not found`, `unreadable`).
  2. Carry them through `Web/Orchestration/PlatformSuspiciousJobManager.cs` (snapshot record) and render them in `platform.js`.
  3. Example message: `242 rows matched but had no client IP (errors2.csv: environment info column not found or empty).`
- **Tests:** add `LogHunter.Tests/Services/PlatformScannerTests.cs` covering:
  - a matching row with an empty env column → counted in `MatchedRowsWithoutIp`;
  - a file without message/env columns → `FilesSkipped`;
  - a tab-delimited file → parsed. Delimiter detection at `:71-79` already handles tabs, so cover it.
- **Done when:** the QA dataset shows "0 IPs extracted · 242 matched rows without an IP · 1 file with misaligned columns" (or similar), not "No matching suspicious rows".

### A6. ALB IP Summary has no CDN/proxy badges (Medium)

- **Repro:** ALB → IP Summary with `40.81.204.182`, `23.50.62.15`, `163.116.207.138`. No badges, although `/api/ip-ranges/lookup` returns "Akamai edge" and "Netskope proxy" for the last two. IIS IP Summary, ALB Top 50 and IP sweep all show badges.
- **Cause:** `Web/Assets/alb.js:1712-1758` renders the per-IP cards with plain `${escHtml(ip.ip)}`: the 0-hit card at `:1714` and the `<summary>` at `:1719`. There's no `data-ip` span and no `lhIpRanges.annotate` call. Compare `iis.js` `annotateIps()` and its `data-ip` spans.
- **Fix:**
  1. Wrap the IP in `<span data-ip="…">` at both places.
  2. After the `innerHTML` assignment, call `if (window.lhIpRanges) window.lhIpRanges.annotate(container).catch(() => {});`.
  3. Optionally add the same CDN/proxy note to the HTML report: `Services/AlbOption3IpSummaryMulti.cs` or `AlbIpSummaryJobManager.cs` report section. The IP sweep report already has a Network column (`IocSweepReport.cs`), so reuse that wording.
- **Done when:** "Akamai edge" and "Netskope proxy" badges show on those two cards.

### A7. IIS workflows without a Log source section (Medium)

- **Repro:** IIS → Status Pivot, Top Bandwidth and Uploads / Payloads (and both Platform workflows) show no folder or file count and no Select folder/files. Every other ALB/IIS workflow does.
- **Cause:**
  - `Web/Orchestration/IisStatusPivotJobManager.cs:41` and `IisBytesIntelJobManager.cs:52` hard-code `AppFolders.IIS`.
  - Their request records (`Web/Api/IisApi.cs:587-590` `IisStatusPivotRunRequest`, `:598-599` `IisBytesIntelRunRequest`) have no source fields.
  - Burst Patterns already has the full pattern: `IisApi.cs:384-388` (`SourceType` / `ServerPath` / `ServerFilePaths`), the `browse-folder` / `browse-files` routes at `:410+`, and the source chip and buttons in `IisPageBuilder.cs` + `iis.js`.
- **Fix:**
  - Copy the Burst Patterns source plumbing (request fields → job manager `files` resolution → page builder source section → JS selection and chip) to Status Pivot and Bytes Intel. Bandwidth and uploads share one page template (`IisPageBuilder.cs:461` region, `{{prefix}}`).
  - For Platform pages, at minimum show the scanned folder and file count (`AppFolders.PlatformLogs`, "6 files · 121 MB") in a meta endpoint and on the page. Folder selection there is optional.
- **Done when:** all six IIS workflows show `C:\espaces\IIS | 1 file | 2.7 MB` and accept a selected folder or files. Platform pages show their folder summary.

### A8. One IP-input parser for manual IP lists (Medium)

- **Repro:**
  - Requests over time with `999.1.1.1` is dropped with no notice.
  - AbuseIPDB with `abc` is dropped with no notice.
  - AbuseIPDB with `10.0.0.1` is **sent to AbuseIPDB**, which spends quota on a private IP.
  - `IPAddress.TryParse` accepts `12345` as `0.0.48.57`. cc8e19c fixed that for the sweep only (`IpTargetParser`).
- **Cause:** four handlers use `System.Net.IPAddress.TryParse(...)` and `continue` on failure:

  | Handler | Location |
  |---|---|
  | AbuseIPDB check | `Web/Api/AbuseIpApi.cs:77` |
  | ALB IP Summary | `Web/Api/AlbApi.cs:395` |
  | ALB Requests over time | `Web/Api/AlbApi.cs:612` |
  | IIS IP Summary | `Web/Api/IisApi.cs:79` |

  A fifth call, `Web/Orchestration/AlbIpExtractorHelper.cs:252`, handles extracted file values and needs review.
- **Fix:**
  1. Add a helper next to `Utils/IpTargetParser.cs`, e.g. `IpTargetParser.ParseIpList(IEnumerable<string>) → (List<string> Valid, List<string> Invalid)`. Single addresses only, full dotted quad via `TryParseAddress` (`:69`), normalised, de-duplicated.
  2. Use it at the four sites. Return `ignored` in each run response, and show "Ignored input: …" the way the sweep does (`ipsweep.js`).
  3. In AbuseIPDB only, also put private, loopback and reserved addresses into a `skipped` list (reuse `IisClientIpResolver.IsPrivateOrLoopback`) and don't send them.
- **Tests:** extend `LogHunter.Tests/Utils/IpTargetParserTests.cs` with `12345`, `999.1.1.1`, `abc`, `1.2.3.4`, `2001:db8::1`, duplicates and whitespace.
- **Done when:** all four inputs report what was ignored or skipped, and `10.0.0.1` never reaches AbuseIPDB.

---

## 2. Low priority (polish)

| ID | Item | Where | Fix |
|---|---|---|---|
| L1 | Count charts go below zero (−11, −3) and ticks are non-round; the last x label is clipped | 8% padding below `yMin`: `Services/Charts.cs:480-481`, `Services/AlbOption3IpSummaryMulti.cs:703-705`, `Services/IisOption_IpSummary.cs:927-929` | `yMin = Math.max(0, yMin - yPad)` (JS inside the C# strings). Optionally use "nice" tick steps. Right-align or inset the last x label. |
| L2 | Per-IP cards sorted as strings (127…, 3.211…, 3.73…, 35.75…); the report's default selected IP is the first string, not the top IP | `Web/Orchestration/AlbIpSummaryJobManager.cs:348-350`, `IisIpSummaryJobManager.cs:353-355` (`OrderBy(r => r.RequestedIp, OrdinalIgnoreCase)`) | `OrderByDescending(r => r.TotalRows).ThenBy(r => r.RequestedIp)`. This also fixes the report dropdown default. |
| L3 | Raw `Error:` prefix on errors ("Error: Invalid status filter.") | ~30 `String(err)` calls in `abuseip.js`, `alb.js`, `iis.js`, `platform.js`, `site.js` | Shared `errorText(err) => err && err.message ? err.message : String(err)`. The status-filter error should also name the bad token and the expected format (`IisApi` status-pivot run). |
| L4 | "Open CSV" on an `.xlsx` export | `Web/Pages/IisPageBuilder.cs:461` | Rename to "Open Excel". Keep "Open CSV" in `AbuseIpPageBuilder.cs:164`: that one really is a CSV. |
| L5 | Sweep folder-label inputs unstyled (browser grey, inset border) | `.ip-sweep-label` (`Web/Assets/site.css:1669`) gets no input styling; input styles only apply under `.field` (`site.css:831-880`) | Add the `.field input` declarations to `.ip-sweep-label`, including hover and focus. |
| L6 | "1 files" | `Web/Assets/ipsweep.js:99`, `alb.js:875` (and the C# `inputSourceSummary` builders, e.g. `AlbTopIpsInputSourceResolver`) | Pluralise. |
| L7 | Copy against guardrails 2 and 7 | `AlbPageBuilder.cs:30` "future drill-down tools"; `WebShellPageBuilder.cs:14` "new browser-based shell", `:15` "future drill-down flows", `:17-18` "Future home for…"; `AlbGenericScanFunctions.cs:656` and `Services/AlbOption_WafBlockedChart.cs:111` "(per current definition)"; `PlatformPageBuilder.cs:145` "…for downstream use." | Short, final-product wording. |
| L8 | Unformatted count "Found 6554 authenticated rows" | `Web/Orchestration/PlatformAuthJobManager.cs:169` | `{result.TotalMatchedRows:N0}`. |
| L9 | Sweep page: a CIDR/range gets a badge only if exactly one IP matched; `23.50.62.0/24` (6 Akamai edges) shows nothing while the HTML report says "Akamai edge (6 IPs)"; the IPs column is blank when 1 IP matched | `Web/Assets/ipsweep.js:193-200` | Use the report's Network logic: a badge when all or most matched IPs share a provider ("Akamai edge · 6 IPs"). Show `1` in the IPs column. |
| L10 | ALB IP Summary FE totals don't add up (2,037 vs 2,041: 4 × 460 with target `-`) | `AlbIpSummaryJobManager.cs:364-366` plus card render `alb.js:1712+` | Add an "FE no response" row, e.g. `TotalRows - (Fe2xx3xx + Fe4xx + Fe5xx)`. |
| L11 | AVG-duration paths not normalised (`/FactoryConfiguration` vs `/FactoryConfiguration/`, `/ATMinquiryAdmin` vs `/ATMInquiryAdmin`) | `AlbGenericScanFunctions.cs:366-376` (`stats` keyed by `ExtractAlbUriNoQuery`) | Trim a trailing `/` (not on root) and use `StringComparer.OrdinalIgnoreCase` for `stats`. OutSystems URLs are case-insensitive. Apply the same to Top 50 by URI (`:626-627`) for consistency. |
| L12 | Static built-in ranges (Google Cloud LB, Netskope, Sucuri) label IPs but aren't listed on the IP ranges page | `Services/IpIntelFeeds.cs:~225-235` (`"static"` feed id), status payload `Web/Api/IpIntelApi.cs` `BuildStatusPayload`, render `site.js:~300` | Add a "Built-in" row per static provider (no Last updated). Decide whether the headline counts them, and whether it counts customer ranges. |
| L13 | ALB Top IPs + paths lists its top IPs as one run-on line | `alb.js:~760-772` | Render as `<ol>` or the mini-table used elsewhere. Keep the `data-ip` spans. |
| L14 | Private-IP placeholders where clients are public | `AlbPageBuilder.cs:503, 735`; `AbuseIpPageBuilder.cs:104` | Use documentation IPs (`203.0.113.7`, `198.51.100.20`). Leave IIS (`IisPageBuilder.cs:145`) as is: private clients are realistic there. |
| L15 | Page title and description shown twice (header + hero card); inputs below the fold (guardrail 8) | Shared layout `WebShellPageBuilder.BuildLayout` plus each page's hero block (`AlbPageBuilder`, `IisPageBuilder`, `PlatformPageBuilder`, `AbuseIpPageBuilder`) | Drop the hero card or the header description. Larger visual change: do it last, in one consistent pass. |
| L16 | Usage trace lines don't include the session id, so test rows can't be filtered | `Services/UsageReporter.cs:137, 142` | Add `sessionId` to the `TraceLog.Write` payload. It's random and local, so no privacy change. |
| L17 | The 4 s `/api/app/info` heartbeat writes 3 trace lines per poll (59% of trace lines, ~5 MB per 8 h) | client `site.js:154`; server `WebAppHost.cs:158`; client-fetch tracing in `site.js` | Skip tracing for `/api/app/info`, or trace only status changes. |

## 3. Investigate or decide first (don't fix blindly)

| ID | Topic | Notes |
|---|---|---|
| D1 | ALB IP Summary chart-only timing | Measured once: 9.6 s for 3 IPs (job `createdUtc` 23:40:19.96 → `updatedUtc` 23:40:29.57), against "<4 s" for export mode with no server timestamps. Chart-only should be **faster** (`AlbIpSummaryJobManager.cs:209-211` sets `SummaryOnly` and skips SQLite). Re-measure both modes 3× on the QA dataset before changing anything. It may be noise or report generation. |
| D2 | Burst Patterns finds 0 candidates on a real spike | 35.75.252.136: 318 req / 10 s, 699 req / min, 92 × 500 on one SOAP endpoint. By design, `Services/IisBurstScoring.cs:46-56` makes candidates only for strong enumeration or **4xx** errors at volume; 5xx doesn't count. **Ask the user** whether to (a) count 5xx toward `isError`, (b) show "top buckets by volume" when there are 0 candidates, or (c) leave it. Don't change the thresholds (`BurstThresholds.ForBucket`, `:209-231`) without that decision. |
| D3 | Platform auth "Hits by log type" ignores Integrations / Service Actions | Those exports have no client-IP column (`Services/PlatformAuthScanner.cs:235-237` classifies by headers). Report them as "skipped: no client IP column" rather than adding empty rows. |
| D4 | `errors2.csv` in the dataset | The header is misaligned (duplicate `id`). Ask the user whether it's a hand-edited test file. A5 makes the tool report it either way. |

## 4. Regression oracle (QA dataset, must stay the same)

Recomputed independently from the raw logs during QA. Use these to confirm that fixes don't change results.

| Workflow | Input | Expected |
|---|---|---|
| ALB Top IPs + paths | fragment `Butterfly` | 4 IPs: 40.81.204.182 **1,081**, 133.159.89.20 **209**, 153.139.234.236 **136**, 133.159.89.21 **57** |
| ALB IP Summary | `40.81.204.182`, `23.50.62.15`, `163.116.207.138` | **2,041** / **300** / **341**. 40.81.204.182: ELB 2xx/3xx 1,988, ELB 4xx 53, FE 4xx 49 |
| ALB IP sweep | default folders | 133 files, 22,075 lines (ALB 4,479 + IIS 17,596). `23.50.62.0/24` 1,339 hits from 6 IPs; `133.159.89.20-133.159.89.25` 608 from 2 IPs |
| ALB 5xx mismatch | default | 0 |
| ALB Top 50 IPs | default | 12 unique IPs. Top: 40.81.204.182 2,041; 133.159.89.21 395 |
| ALB Top 50 by URI | default | 1,392 unique pairs. Top: 40.81.204.182 `/ServiceCenter/ServiceStudio.asmx` 308 |
| ALB AVG duration | default | 835 unique URIs. #1 `…/Subscriptions/DataActionGetSubscriptions`: avg **21.403 s**, count 30, max 265.263 s. (L11 normalisation may lower the URI count; that change is expected.) |
| ALB Requests over time | 4 IPs: `40.81.204.182`, `133.159.89.21`, `23.50.62.15`, `163.116.207.138` | **3,077** hits, 90 buckets |
| ALB WAF summary / chart | default | 0 blocked of 4,479 |
| IIS IP Summary | `3.211.38.142`, `35.75.252.136`, `3.73.213.149`, `127.0.0.1` | **3,451** / **1,699** / **215** / **975** (resolver handles `+`, ports, loopback hops) |
| IIS IP sweep | `10.15.109.0/24` | 11,253 hits from 4 IPs |
| IIS Status Pivot | 5xx | 2 IPs: 35.75.252.136 **92**, 3.73.213.149 **2**. Pivot 2xx: 1,607 + 213 = **1,820** lines |
| IIS Top Bandwidth | default | 35.75.252.136 19 MB, 3.73.213.149 8.1 MB, 3.211.38.142 6.3 MB, 52.52.102.154 3.5 KB |
| IIS Uploads | default | Order by max single payload: 35.75.252.136 (23,002 B), 52.52.102.154 (8,952 B), 3.73.213.149 (1,925 B) |
| IIS Burst Patterns | 60 s and 10 s | 0 candidates (unless D2 changes the design) |
| Platform auth activity | manual `10.98.3.19`, `10.98.4.230`, `8.8.8.8` | 2 IPs: **4,462** (General 4,442 + Error 20) and **2,092** (General). Total 6,554 |
| Platform suspicious | default | Today 0. After A5: 242 matched rows without an IP, from `errors2.csv` |

## 5. Definition of done

1. `dotnet build` is clean and `dotnet test LogHunter.Tests` passes, including the new tests from A3 (optional), A5 and A8.
2. A browser pass over every workflow except ALB download, on `--root C:\espaces`:
   - section 4 numbers unchanged;
   - each item above visibly fixed;
   - no console errors other than the expected 400s from validation.
3. Light theme checked on at least one results page.
4. Nothing committed, pushed or published unless the user asks. When the user asks to merge, follow `CLAUDE.md`: version 2.0.0.6, README notes, patch note, backnote.

## 6. Out of scope

- ALB download.
- Usage tracking behaviour. It was verified correct: 27 events, all 200, the right keys, rejected runs not counted. The only change here is L16, adding the session id to the trace.
- Burst scoring thresholds (see D2).
- Native-dialog flows ("Select folder/files", "From output file", "From burst results", SQLite Viewer) were not exercised in QA. Smoke-test them after A7.
