# Usage tracking: implementation plan

2026-11-25. Builds on `../docs/usage-tracking-options.md` (option 2, an OutSystems app) and the endpoint spec agreed in chat.
**Status:** the OutSystems API was built, **published and smoke-tested live** on 2026-11-25 (section 1). All 12 cases in section 1.3 pass. The `UsageApiKey` set now is a **test key**: rotate it in Service Center before the key goes into the exe.

**Feedback (added 2026-11-25):** `POST /rest/Usage/Feedback` on the same API stores into entity `Feedback`. It has validation, duplicate suppression and rate limits of 10 per install and 300 in total per 24h (429), and it was tested live. The client contract is in [`handoff-feedback-api.md`](handoff-feedback-api.md). The monitor's Admin-only **Feedback** screen lists the messages with period and area filters. The LogHunter side (section 2) is not started; another session will do it.

## 0. Decisions before building

| # | Decision | Recommendation |
|---|---|---|
| D1 | **Decided 2026-11-25: every build sends events.** Internal engineers get the exe from the public GitHub release, so the single `LogHunter.exe` keeps the endpoint embedded and there is no silent publish. The README notice and the `LOGHUNTER_NO_USAGE` opt-out are therefore required, not optional. Original question: **Which builds send usage events.** Today there is only one `LogHunter.exe`: the copy in `C:\espaces` is also attached to the public GitHub release, and `ReleaseUpdateChecker` points everyone to that release. "Public builds stay silent" therefore means a second publish without the endpoint for GitHub. It also means anyone who updates from GitHub stops being counted. | First, find out where internal engineers get the exe. **From the GitHub release:** internal-only pinging would record almost nothing, so ship the ping in the one exe, with a start notice and opt-out. **From `C:\espaces` or a share:** keep the spec default and make the public publish silent (section 2.2). |
| D2 | Rate limit per InstallId in v1 | **No.** Add it only if spam shows up. It costs one extra query per call and an index on `InstallId` + `CreatedOn`. |
| D3 | Error responses have a body | **Accepted.** 401 and 400 come back with OutSystems' standard error JSON, for example `{"Errors":["Unauthorized"],"StatusCode":401}`. The client ignores every response anyway. |
| D4 | Where the API lives | **Decided:** the API and its data are in the service module `LogHunterUsage_IS`. The Reactive module `LogHunterUsage` is kept for a dashboard later, and it reads the entities, which are public and read-only. |
| D5 | `platform.auth-cache` has no job of its own. The cache is a side effect of auth-activity, and the web page loads it automatically on every Platform page visit. | **Drop the key from v1.** Counting it would mean counting page visits rather than deliberate use. |

## 1. OutSystems side: as built (`LogHunterUsage_IS`, service module)

App **LogHunter Usage** on `andrec-fonseca.outsystemscloud.com`:
- `LogHunterUsage_IS` (Service) holds the API and its data. Its dependencies are HTTPRequestHandler (`GetRequestHeader`, `SetStatusCode`) and Text (`Regex_Search`).
- `LogHunterUsage` (Reactive) is empty for now and reserved for a dashboard.

### 1.1 Contract for the client (what the LogHunter side must send)

| | |
|---|---|
| App start | `POST https://andrec-fonseca.outsystemscloud.com/LogHunterUsage_IS/rest/Usage/AppStart` |
| Feature use | `POST https://andrec-fonseca.outsystemscloud.com/LogHunterUsage_IS/rest/Usage/FeatureUse` |
| `UsageEndpoint` (publish-time) | `https://andrec-fonseca.outsystemscloud.com/LogHunterUsage_IS/rest/Usage` |
| Header | `X-LogHunter-Key: <value of the UsageApiKey site property>` |
| Content type | `application/json` |
| AppStart body | `{"InstallId":"<guid>","SessionId":"<guid>","Version":"2.0.0.4","Mode":"web"}` |
| FeatureUse body | the same four fields plus `"Feature":"alb.download"` |
| Rules | GUIDs are in `8-4-4-4-12` hex form. `Mode` is exactly `web` or `console` in lowercase. `Version` uses `[0-9A-Za-z.+-]`, 1 to 30 characters. `Feature` uses `[a-z0-9.-]`, 1 to 50 characters |
| Responses | **200** with an empty body when stored. **401** for a missing or wrong key, or while `UsageApiKey` is empty. **400** for a body that breaks the rules. Both errors carry OutSystems' standard error JSON. The client ignores all of them |

### 1.2 What is in the module

| Element | Definition |
|---|---|
| Entity `AppStart` | `Id` (Long Integer, auto-number), `InstallId` Text(36), `SessionId` Text(36), `Version` Text(30), `Mode` Text(10), `CreatedOn` DateTime. All mandatory. Index `IX_CreatedOn`. **Public, Expose Read Only** |
| Entity `FeatureUse` | The same as `AppStart` plus `Feature` Text(50). Indexes `IX_CreatedOn` and `IX_Feature`. **Public, Expose Read Only** |
| Structures `AppStartRequest`, `FeatureUseRequest` | The JSON bodies above (not public). An O11 exposed REST method accepts only one Body input, so each method takes one structure |
| Site property `UsageApiKey` | Text, **Is Secret**, no default value |
| User exception `UsageRequestRejected` | Raised for both rejections |

REST API `Usage` (`/rest/Usage`) has `Authentication = Custom`, `HttpSecurity = SSL`, `ShowDocumentation = No` and `CrossSiteRequests = Restrict`. Its flows:

- **OnAuthentication:** `GetRequestHeader("X-LogHunter-Key")` → If `Site.UsageApiKey <> "" and GetKeyHeader.Value = Site.UsageApiKey` → End. Otherwise `SetStatusCode(401)` (node `SetUnauthorized`) runs and `UsageRequestRejected` is raised. The `SetStatusCode` call is required: without it this platform answered **500**, not the 401 that the OutSystems docs promise (verified live 2026-11-25).
- **`POST AppStart` / `POST FeatureUse`:** the fields are joined with `|`, in the order `InstallId|SessionId|Mode|Version[|Feature]`, and checked with a single `Regex_Search` against one anchored pattern ending in `\z`. `IgnoreCase`, `MultiLine` and `SingleLine` are explicitly `False`. When left empty, `IgnoreCase` defaulted to case-insensitive, so `"WEB"` was accepted (found in the smoke test and fixed). No allowed character can be `|`, so the join is unambiguous. When the check fails, `SetStatusCode(400)` runs and `UsageRequestRejected` is raised. When it passes, the request is assigned to `Row` with `CreatedOn = CurrDateTime()` (server UTC) and then `Create<Entity>`.
- This replaces the `Usage_IsValid` action from the first draft: one regex per method does the same job with fewer elements.

The build took one dry run (0 TrueChange messages), one apply, a read-back and `omlMerge` (merged: true). `getValidationMessages` reports nothing.

### 1.3 After publishing (operator, Service Center)

1. Set the site property `UsageApiKey` to a random string of 32 or more characters, and keep a copy for `certs\usage.props` (section 2.2).
2. Factory → LogHunter Usage → module `LogHunterUsage_IS` → Integrations → Exposed REST API `Usage` → **Logging Level = Default** (the lowest of Default, Troubleshoot and Full). Even Default logs every call, and the Integration log's **Source** column holds the caller's IP. Neither can be turned off from the module. Our own tables never store the IP, and the platform log retention ages it out.
3. Smoke test. **Done 2026-11-25**, run live with the test key, all as expected:

| Case | Result |
|---|---|
| Valid `AppStart`, valid `FeatureUse` | 200 |
| `Mode` `WEB`, `Feature` `ALB.DOWNLOAD`, `Feature` with a space | 400 |
| Bad GUID, junk line before the GUID, missing `Version`, `Version` with a trailing newline, missing `Feature` | 400 |
| Body that isn't JSON | 400 (`Failed to parse JSON request content.`) |
| No key or wrong key, on both endpoints | 401 |
| `GET` | 405 |

**Test rows to delete before real use:** all have `InstallId = 00000000-0000-4000-8000-000000000001` and `Version = 0.0.0-test`. There are 3 in `AppStart`, one of them the `WEB` row stored before the case fix, and 2 in `FeatureUse`.

## 2. LogHunter side

### 2.1 New class `Services/UsageReporter.cs` (static, like `ReleaseUpdateChecker`)

| Member | Behaviour |
|---|---|
| `Start(string version, string mode)` | Called once after the startup mode is resolved. Creates a new `SessionId` and sends `AppStart` |
| `Track(string feature)` | Sends `FeatureUse` without waiting for the result. Does nothing until `Start` has run or when the reporter is disabled |
| Enabled when | Release build, the endpoint is embedded, and `LOGHUNTER_NO_USAGE` is not `1` |
| Install id | `config\install-id` (`AppFolders.Config`), a GUID in `D` format. If the file is missing or invalid, a new id is created and saved. If saving fails, the process uses an id that lives only until exit |
| HTTP | One static `HttpClient` set up like `IpIntelStore.CreateClient`: system proxy plus `DefaultProxyCredentials` (corporate network and WorkSpaces), 3 s timeout, `User-Agent: LogHunter/<version>`, header `X-LogHunter-Key`. It has an `internal` handler overload for tests |
| Failures | Swallowed inside `Task.Run`. One local `TraceLog.Write("usage", "sent" \| "failed", new { kind, feature, status })` per call, so problems can be diagnosed from the trace without any UI |
| Payload | `System.Text.Json` serialisation of an anonymous object with PascalCase names (`InstallId`, `SessionId`, `Version`, `Mode`, `Feature`), the same as the spec |

Feature keys live in a static class `UsageFeature` with one `const string` per key from the spec. Call sites can't mistype a key, and a test checks every key against the server pattern.

### 2.2 Embedding the endpoint at publish time (never in git)

```xml
<!-- LogHunter.csproj -->
<Import Project="..\certs\usage.props" Condition="Exists('..\certs\usage.props')" />
<ItemGroup Condition="'$(Configuration)' == 'Release' and '$(UsageEndpoint)' != ''">
  <AssemblyMetadata Include="UsageEndpoint" Value="$(UsageEndpoint)" />
  <AssemblyMetadata Include="UsageKey" Value="$(UsageKey)" />
</ItemGroup>
```

- `certs\usage.props` holds `UsageEndpoint` (the base URL ending in `/rest/Usage`) and `UsageKey`. Add `certs/*.props` to `.gitignore`. Today `.gitignore` covers only `*.pfx` and `*.p12` in that folder.
- The `Release` condition keeps Debug runs from polluting the data.
- A silent publish (D1) passes `-p:UsageEndpoint=`. A global property overrides the imported file.
- `UsageReporter` reads the values with `Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()`.

### 2.3 AppStart call site

`Program.cs`, immediately after `TraceLog.Write("app", "mode", ...)`:

```csharp
UsageReporter.Start(version, consoleMode ? "console" : "web");
```

The child-process paths (`--run-alb-download-job`, `--viewer-sqlite`) return before that line, so they never count as starts.

### 2.4 FeatureUse call sites

There is no shared job base class, and web and console mode share no code path, so each key gets its own one-line `UsageReporter.Track(UsageFeature.X)` in each mode.

- **Web:** the call goes in the API handler, immediately after `TryStart(...)` succeeds. That keeps the web calls in 7 files instead of 13 managers, and the handler already has the request body that tells variants apart.
- **Console:** the call goes on the first line after the prompts and validation. Runs the user cancels at a prompt, or that stop on "no files", are not counted, which matches web.

| Key | Web (after a successful `TryStart` unless noted) | Console (start of the scan) |
|---|---|---|
| alb.download | `Web/Api/AlbApi.cs:99` (in the parent process, never in the `--run-alb-download-job` child) | `Services/AlbDownload.cs:194` |
| alb.top-ips-endpoint | `Web/Api/AlbApi.cs:185` | `Services/AlbOption2TopIpsForEndpoint.cs:66` |
| alb.ip-summary | `Web/Api/AlbApi.cs:424` | `Services/AlbOption3IpSummary.cs:70` |
| alb.5xx-mismatch, alb.top50-ips, alb.top50-ips-by-uri, alb.top50-avg-duration, alb.waf-blocked-summary, alb.waf-blocks-over-time | One line in `AlbApi.TryHandleGenericScanAsync` after `:1034`. A new `feature` parameter is passed at its 6 registrations (`AlbApi.cs:532-554`) | `AlbOption_StatusMismatch.cs:45`, `AlbOption_Top50IpsOverall.cs:47`, `AlbOption_Top50IpUri.cs:47`, `AlbOption_Top50AvgDuration.cs:68`, `AlbOption_WafBlockedSummary.cs:51`, `AlbOption_WafBlockedChart.cs:43` |
| alb.requests-over-time | `Web/Api/AlbApi.cs:647` (its own handler) | `Services/AlbOption_RequestsPerIp5Min.cs:136` |
| alb.ip-sweep, iis.ip-sweep | `Web/Api/IocSweepApi.cs:98`. Both pages post to the same endpoint, so `ipsweep.js:134` sends a new body field `section` (from the existing `moduleBase()`), and the key is chosen from it | web only |
| iis.ip-summary | `Web/Api/IisApi.cs:99` | `Services/IisOption_IpSummary.cs:88` |
| iis.status-pivot | `Web/Api/IisApi.cs:308` | `Services/IisOption_4xxPivot2xx3xx.cs:54` |
| iis.burst-patterns | `Web/Api/IisApi.cs:386` | `Services/IisOption_FindBurstPatterns.cs:139` |
| iis.top-bandwidth, iis.uploads-payloads | `Web/Api/IisApi.cs:516`, with the key taken from `body.Mode` (`bandwidth` or `uploads`) | `IisOption_BytesIntel.cs:57` and `:149` |
| platform.suspicious-ips | `Web/Api/PlatformApi.cs:59` | `Services/PlatformOption_SuspiciousExtractIps.cs:29` |
| platform.auth-activity | `Web/Api/PlatformApi.cs:107` | `Services/PlatformOption_AuthenticatedActivity.cs:53` |
| abuseipdb.check | `Web/Api/AbuseIpApi.cs:92` | `Menu/AbuseIpOption_CheckIps.cs:17` (covers all 3 sources) |
| ipranges.refresh | `Web/Api/IpIntelApi.cs:34` (the Refresh button). **Not** in `IpIntelStore.RefreshAsync`, which the startup auto-refresh also calls | web only |
| ipranges.custom-ranges | `Web/Api/IpIntelApi.cs:42` (save; Clear counts too) | web only |
| tools.sqlite-viewer | In both `*SqliteViewerLauncher.Launch` methods, after the process starts. That covers the home card, "Open export" on a `.db`, and the console auto-launch. Not in the `--viewer-sqlite` child, which starts before the reporter | same `Launch` methods |
| platform.auth-cache | See D5 | See D5 |

**Not tracked in v1** (intentionally): AbuseIPDB key configuration, IP-range lookups (result pages call these automatically), importing IPs from CSV/XLSX, the "open report/export/folder" actions, console saved selections, and startup or background tasks.

### 2.5 Transparency

- Console: print one dim line under the trace notice: `Anonymous usage counts (version, mode, workflow). LOGHUNTER_NO_USAGE=1 turns them off.`
- Web: no UI text, per the UI guardrails.
- README: add a short "Usage counts" section next to "Diagnosis trace" that lists exactly what is sent and how to opt out.

### 2.6 Tests (`LogHunter.Tests/Services/UsageReporterTests.cs`, stub handler as in `IpIntelStoreTests`)

- When the endpoint is empty or the opt-out is set, no request is sent.
- `AppStart` and `FeatureUse` bodies have the exact field names, and the key header is present.
- The install id is reused across runs and replaced when the file is corrupt.
- A handler that throws or times out never surfaces an exception.
- Every `UsageFeature` constant matches `^[a-z0-9.\-]{1,50}$`.

## 3. Order of work

1. Settle D1 to D5.
2. OutSystems: complete 1.1, build 1.2 via MCP, merge, publish (operator, or `omlPublish` when asked), then complete 1.3 and run the curl smoke test.
3. Create `certs\usage.props` locally.
4. App: add the class, the csproj change, the call sites and the tests on a new branch `feature/usage-tracking`. Base it on `main` after `feature/ioc-sweep-cdn` lands, or on the current branch if you prefer.
5. End to end: run `dotnet run -c Release`, start each workflow once in web and console mode, and confirm that the rows and keys arrive.
6. Update the README and patch notes according to the Release Notes Workflow, and bump the version on the merge to `main`.

## 4. Later (not v1)

- ~~A dashboard screen in `LogHunterUsage`~~ **Built 2026-11-25, merged, not yet published.** It has three Admin-only screens (`Overview`, `Workflows`, `Launches`) with a 7/30/90/365-day period switch, OutSystemsCharts charts, and the LogHunter dark look in the theme stylesheet. Distinct installs per workflow come from the SQL server action `Usage_GetWorkflowStats`. Grant the `Admin` role (LogHunterUsage) in the Users app to get in.
- `Outcome` (started, completed, failed) on `FeatureUse`.
- A rate limit, if D2 changes.
- Export, or a move to a team environment. Personal environments sleep, can be reclaimed after inactivity, have a small database limit, and their terms of use need checking for internal company use.

## 5. Service Studio MCP: how to connect (for the build)

- Server **`servicestudio`** is already registered in Claude Code at user scope: `http://127.0.0.1:41820/mcp`. The port is shown in the MCP Server window and may change.
- Only the module currently open in Service Studio can be read or written.
- The write tools (`applyModelApiCode`, `omlMerge`, `omlReset`, `omlRefreshReferences`, `omlPublish`) are a Beta Feature.
- Keep write permissions on **"Manual review changes in compare and merge"**. `omlPublish` is called only when you ask for it.
- Fallback client if the MCP tool wrapper misbehaves: `C:\Users\cvh\Service Studio\tools\mcp\ssmcp.py`, with the commands `token` and `call <tool> '<json>'`.
- Reference recipe: skill `servicestudio-mcp-oml`, `reference/logic-and-integrations.md` § Exposed REST APIs, and `examples/AddExposedRestApi.cs`.
