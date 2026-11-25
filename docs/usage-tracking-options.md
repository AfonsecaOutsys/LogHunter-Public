# Counting app starts — options

Goal: know each time LogHunter is started. Nothing else: no user name, no machine name, no log content.

## What the app already does (and why it can't count)

- `ReleaseUpdateChecker` calls `api.github.com/repos/AfonsecaOutsys/LogHunter-Public/releases/latest`, but caches the answer for **6 hours** (`CacheDuration`). It is not one call per start, and GitHub gives repo owners no statistics on API calls.
- GitHub release **download counts** (`download_count` on each asset) count downloads of the public build, not starts, and say nothing about internal copies.
- The trace log (`logs\trace-*.jsonl`) records every start, but only on the engineer's own machine.

So counting starts needs one small outbound call at startup.

## Minimum design, whichever endpoint is chosen

| Rule | Why |
|---|---|
| One HTTPS POST at startup, fire-and-forget, 2–3 s timeout, never shown to the user on failure | Must never slow down or break a start (AWS WorkSpaces, corp proxy, offline) |
| Payload: `{ "event": "start", "version": "2.0.0.4", "mode": "web" \| "console" }`, plus optionally a random install id (GUID created once in `config\install-id`) | Counts starts, versions and modes. The install id gives "distinct installs" without identifying anyone. Drop it if even that is too much |
| No user name, machine name, domain, paths or IP in the payload | "Just that a user has started the app" |
| Endpoint URL set at **publish time** (`-p:UsageEndpoint=…`), empty by default | The same exe goes to the public GitHub release. Public builds must not ping an internal endpoint |
| Opt-out: `"usage": false` in config or `LOGHUNTER_NO_USAGE=1` | Air-gapped and cautious users |
| One line in the README and in the console start notice ("LogHunter counts app starts: version and mode only") | Transparency, consistent with the trace notice |
| Reuse the system-proxy `HttpClient` setup from `IpIntelStore` | Already works on the corporate network and WorkSpaces |

Note: whatever receives the request sees the caller's IP at the network level, even if the payload has none. Prefer a service that doesn't store it (Application Insights masks it by default) or ignore it server-side.

## Options

| # | Where the starts go | Effort | Cost / licence | Dashboard | Main risk |
|---|---|---|---|---|---|
| 1 | **Azure Application Insights**: plain HTTPS POST of a `customEvent` to the ingestion endpoint (no SDK needed) | S (half a day) | Free tier is ample (a few KB a day) | KQL / Workbooks: starts per day, per version, distinct installs | Needs an Azure subscription and a resource from the Cloud / IT team. The connection string is designed to sit in client apps, so embedding it is acceptable |
| 2 | **Small OutSystems app** (ODC or internal O11): exposed REST `POST /starts` writing one row, plus a screen with a chart | M (1–2 days) | Uses an internal environment you already have | Built in the app | An unauthenticated endpoint can be spammed: validate the payload and rate-limit. Needs an environment owner |
| 3 | **Slack Workflow webhook** → posts to a private channel or adds a row to a Slack List | XS (under an hour, no code on the receiving side) | Included in Slack | Count rows in the List or channel; export CSV | The webhook URL is a secret baked into the exe: anyone who extracts it can post. Noisy as a channel, fine as a List. Good for tens of users, not hundreds |
| 4 | **Power Automate** "When an HTTP request is received" → SharePoint list or Excel | S | The HTTP trigger is a **premium** connector (licence) | SharePoint / Excel / Power BI | Licence, flow throttling, URL signature is a secret |
| 5 | **Own update manifest**: host `latest.json` somewhere with access logs (S3 + CloudFront logs, Azure Static Web App) and drop the 6 h cache to one call per start | M | Cents | Query access logs | Counts requests, not starts, if anything caches. Needs hosting and log access (AWS rules apply). Combines the update check and counting in one call |
| 6 | **Grafana Cloud (Loki push)** or **Splunk HEC** | S | Existing company tools | Grafana / Splunk | Write tokens are real secrets with broad scope. Owned by Observability / SOC, who would need to agree |

## Recommendation

1. **Quickest, this week: Slack Workflow webhook → Slack List** (option 3). No server, no budget, and the team already lives in Slack. Version, mode and date per row is enough to answer "how many starts, on which version". Accept that the webhook URL can be extracted. Rotate it if it is ever abused.
2. **Proper, long-term: Application Insights** (option 1), if the Cloud team can give you a resource. The ingestion key is meant to be embedded, IP masking is on by default, and you get real dashboards (starts per day, distinct installs, version adoption after each release).
3. **Dogfooding alternative: an OutSystems app** (option 2), if you'd rather own the data and the dashboard yourself.

Whichever is picked, the client side is the same ~60-line class (`UsagePing`): read the publish-time endpoint, skip when empty or opted out, POST in the background, swallow errors. Swapping endpoints later is a one-line change.

## Decision needed

- Which endpoint (Slack List now, App Insights later?).
- Keep or drop the anonymous install id (distinct installs vs starts only).
- Ping from public builds too (into a separate stream), or internal builds only (default above).
