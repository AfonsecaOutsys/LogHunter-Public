# Handoff: usage API is live, LogHunter client is next

2026-11-25. From: the session that built the OutSystems side. To: the agent wiring LogHunter.

The server side is **done, published and tested live**. Your job is the client: a `UsageReporter` class, the call sites, the publish-time endpoint and key, and the tests.

The full design (class shape, call-site table with file:line, csproj snippet, tests) is in [`usage-tracking-plan.md`](usage-tracking-plan.md) section 2. This note covers what you can't get from the code: the live contract, decisions already made, and traps found in testing.

## 1. The contract (live, do not change it without asking the user)

| | |
|---|---|
| Base URL (`UsageEndpoint`) | `https://andrec-fonseca.outsystemscloud.com/LogHunterUsage_IS/rest/Usage` |
| App start | `POST {base}/AppStart` |
| Workflow run | `POST {base}/FeatureUse` |
| Auth header | `X-LogHunter-Key: <key>`. **Ask the user for the key.** The value set now is a test key and will be rotated before release. Never commit it, log it, or write it into a doc |
| Content type | `application/json` |
| AppStart body | `{"InstallId":"<guid>","SessionId":"<guid>","Version":"2.0.0.4","Mode":"web"}` |
| FeatureUse body | the same four fields plus `"Feature":"alb.download"` |

Note the `_IS` in the URL. It is **not** `/LogHunterUsage/rest/Usage` as the first spec said.

### Field rules (enforced by one regex per endpoint, case-sensitive)

| Field | Rule | What LogHunter should send |
|---|---|---|
| `InstallId`, `SessionId` | `[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}` | `Guid.ToString()`, the default `D` format. No braces, no `N` format |
| `Mode` | exactly `web` or `console`, **lowercase** | `consoleMode ? "console" : "web"` |
| `Version` | `[0-9A-Za-z.+-]{1,30}` | `AssemblyInformationalVersion`, which is `2.0.0.3` today. Keep `IncludeSourceRevisionInInformationalVersion=false` in the csproj: a `+<sha>` suffix could push it past 30 characters and every call would get a 400 |
| `Feature` | `[a-z0-9.-]{1,50}`, **lowercase** | one of the keys in section 3 |

- All fields are required. A missing field, an empty value or a trailing newline gets a 400.
- Use the exact PascalCase JSON names shown. `System.Text.Json` with an anonymous object `new { InstallId, SessionId, Version, Mode }` produces them by default; don't set a camelCase naming policy.

### Responses (the client ignores all of them, but you'll see them while debugging)

| Status | When | Body |
|---|---|---|
| 200 | stored | empty |
| 400 | body breaks a rule | `{"Errors":["Invalid usage event"],"StatusCode":400}` |
| 400 | body isn't JSON | `{"Errors":["Failed to parse JSON request content."],"StatusCode":400}` |
| 401 | missing or wrong key | `{"Errors":["Unauthorized"],"StatusCode":401}` |
| 405 | any verb other than POST | — |

The server sets `CreatedOn` in UTC, so don't send a timestamp. There is no read endpoint.

## 2. Decisions already made (don't reopen)

1. **Every build sends events, the public GitHub exe included.** Internal engineers update from the public release, so there is no silent publish. That makes these **required**:
   - the `LOGHUNTER_NO_USAGE=1` opt-out
   - the README "Usage counts" section (what is sent, how to turn it off)
   - one dim console line at start (plan 2.5)
   - nothing in the web UI (UI guardrails)
2. **Only Release builds embed the endpoint**, so Debug runs never send events (the csproj condition in plan 2.2).
3. **The key is a plain shared secret, with no obfuscation or encryption in the exe.** The user decided this is internal and not worth it. Don't add HMAC or token schemes.
4. **The key lives in `..\certs\usage.props`**, which is gitignored: add `certs/*.props` to `.gitignore`, because today only `*.pfx`/`*.p12` are ignored there. The props file is imported by the csproj and read at runtime from `AssemblyMetadata`.
5. **`platform.auth-cache` is dropped from v1.** It has no job of its own, only an automatic page load.
6. **No rate limit and no `Outcome` field in v1.**

## 3. Final feature keys (23)

- **ALB:**
  - `alb.download`, `alb.top-ips-endpoint`, `alb.ip-summary`, `alb.ip-sweep`, `alb.5xx-mismatch`
  - `alb.top50-ips`, `alb.top50-ips-by-uri`, `alb.top50-avg-duration`, `alb.requests-over-time`
  - `alb.waf-blocked-summary`, `alb.waf-blocks-over-time`
- **IIS:** `iis.ip-summary`, `iis.ip-sweep`, `iis.status-pivot`, `iis.burst-patterns`, `iis.top-bandwidth`, `iis.uploads-payloads`
- **Platform:** `platform.suspicious-ips`, `platform.auth-activity`
- **Other:** `abuseipdb.check`, `ipranges.refresh`, `ipranges.custom-ranges`, `tools.sqlite-viewer`

Put them in one `UsageFeature` constants class, and unit-test every constant against `^[a-z0-9.-]{1,50}$`. Where each key is called, in web and console mode, is in plan **2.4**, verified against the code on 2026-11-25. Re-check the line numbers if `main` has moved. The traps:
- The ALB and IIS sweep share `/api/ip-sweep/run`. `ipsweep.js` must send a `section` field so the two keys can be told apart.
- Track `ipranges.refresh` in the API handler, **not** in `IpIntelStore.RefreshAsync`: the startup auto-refresh calls that too.
- Track `alb.download` in the parent process, never in the `--run-alb-download-job` child.
- Track `tools.sqlite-viewer` in the two `*SqliteViewerLauncher.Launch` methods, never in the `--viewer-sqlite` child.
- Send `AppStart` right after the startup mode is resolved in `Program.cs`. The child-process paths return before that point.

## 4. Client behaviour checklist

- [ ] Send in the background, without blocking: 3 s timeout, every exception swallowed. A failure must never reach the UI or slow startup.
- [ ] Use the system proxy plus `DefaultProxyCredentials`, copying `IpIntelStore.CreateClient` (that works on the corporate network and WorkSpaces).
- [ ] `config\install-id` holds one GUID, created once and reused. If the file is unreadable or invalid, regenerate it. If it can't be written, use an id that lives only for the process.
- [ ] Generate a new `SessionId` per launch.
- [ ] Do nothing when the endpoint is empty, it's a Debug build, or `LOGHUNTER_NO_USAGE=1`.
- [ ] Log the outcome locally with `TraceLog.Write("usage", "sent" | "failed", new { kind, feature, status })`. Never log the key or the URL with the key.
- [ ] Unit tests use a stub `HttpMessageHandler`, as `IpIntelStoreTests` does. **Unit tests must never call the live endpoint.**

## 5. Checking end to end

1. Build Release with `certs\usage.props` in place and run it. Start once in web mode and once in console mode, and run a couple of workflows.
2. Check `logs\trace-*.jsonl` for the `usage` events with status 200.
3. Ask the user to confirm the rows in Service Studio: `LogHunterUsage_IS` → Data → `AppStart` / `FeatureUse` → View data. The agent has no read access to the database.

For a manual probe without the app (bash), substitute the key the user gives you:

```bash
curl -s -w " -> %{http_code}\n" -X POST -H "Content-Type: application/json" -H "X-LogHunter-Key: <key>" \
  --data '{"InstallId":"00000000-0000-4000-8000-000000000001","SessionId":"00000000-0000-4000-8000-0000000000ff","Version":"0.0.0-test","Mode":"web"}' \
  https://andrec-fonseca.outsystemscloud.com/LogHunterUsage_IS/rest/Usage/AppStart
```

Use `Version = 0.0.0-test` for any manual call, so test rows are easy to delete. Five such rows already exist from the server smoke test.

## 6. If the contract has to change

The server lives in the OutSystems module `LogHunterUsage_IS` (Service) on `andrec-fonseca.outsystemscloud.com`. It is edited through Service Studio MCP; see plan section 5 for how to connect. Adding a field or an endpoint is a server change: stop and ask the user rather than working around it on the client.
