# Handoff: feedback API is live, LogHunter feedback page is next

2026-11-25. From: the session that built the OutSystems side. To: the agent wiring LogHunter.

The server side is **done, published and tested live**. Your job is a feedback page in LogHunter that posts to it. This builds on [`handoff-usage-api.md`](handoff-usage-api.md) (same base URL, key, install id and HTTP setup); read that first.

## 1. What the user asked for

- A **"Feedback" button** in the LogHunter app. It opens a page with:
  1. a dropdown: which page had the issue (**ALB, IIS, Platform logs, AbuseIP, Other**)
  2. a text box describing the issue, with a character limit
  3. a submit button
- The app sends it through the API. **A 200 response means it was submitted.**
- No login. The anti-spam measures are on the server (section 3).

## 2. The contract (live, do not change it without asking the user)

| | |
|---|---|
| URL | `POST {UsageEndpoint}/Feedback`, which is `https://andrec-fonseca.outsystemscloud.com/LogHunterUsage_IS/rest/Usage/Feedback` |
| Headers | `X-LogHunter-Key: <same key as the usage events>`, `Content-Type: application/json; charset=utf-8` |
| Body | `{"InstallId":"<guid>","Version":"2.0.0.4","Mode":"web","Area":"alb","Description":"<text>"}` |

### Fields

| Field | Rule | What to send |
|---|---|---|
| `InstallId` | GUID, `8-4-4-4-12` hex | the same `config\install-id` value the usage events use |
| `Version` | `[0-9A-Za-z.+-]{1,30}` | the same version string as the usage events |
| `Mode` | exactly `web` or `console` | the current mode |
| `Area` | exactly one of the keys below, **lowercase** | the key, not the label |
| `Description` | 10 to 1,000 characters **after trimming**; newlines and any UTF-8 are fine | the user's text |

| Dropdown label (what the user sees) | `Area` key (what you send) |
|---|---|
| ALB | `alb` |
| IIS | `iis` |
| Platform logs | `platform` |
| AbuseIP | `abuseip` |
| Other | `other` |

### Responses: map each one to what the user sees

| Status | Meaning | Show the user |
|---|---|---|
| **200** | stored. Also returned for an identical resend within 24h, which isn't stored twice | "Feedback sent. Thanks." Then close or clear the form |
| **429** | rate limited: 10 per install per 24h, or 300 in total per 24h | "Too much feedback sent today. Try again tomorrow." Keep the text |
| **400** | the body broke a rule. Shouldn't happen if the client validates | "Couldn't send feedback." Keep the text and log the status to the trace |
| **401**, other codes, timeout, no network | key wrong or server unreachable | "Couldn't send feedback. Check your connection and try again." Keep the text |

Error bodies look like `{"Errors":["..."],"StatusCode":429}`. Don't show the raw text to the user.

## 3. Anti-spam, already enforced server-side (nothing to build on the client)

1. The shared key in `X-LogHunter-Key` (same `OnAuthentication` as the usage API).
2. A strict format check, with `Area` limited to the 5 keys and a length cap.
3. Duplicate suppression: the same install sending the same text within 24h returns 200 and isn't stored again.
4. Rate limits: **10 per install per 24h** and **300 in total per 24h**, returning 429.

The client only needs to avoid making it worse: disable the submit button while sending, so one click means one request.

## 4. Client behaviour checklist

- [ ] **Unlike usage events, this call is user-initiated and awaited.** Show a sending state, use about a 10 s timeout, and report the result. Don't run it in the background and swallow it.
- [ ] Validate before sending:
  - an area must be selected
  - the trimmed text must be 10 to 1,000 characters
  - show a live counter (`0 / 1000`) and block submit outside the range
- [ ] Put one short hint under the text box: **"Don't include customer data, IPs or log lines."** This is free text from people working on customer logs, and the server can't filter it.
- [ ] Keep the typed text on every failure, so nothing is lost.
- [ ] Reuse the usage HTTP client setup: system proxy, `DefaultProxyCredentials`, `User-Agent`, and the key header from `AssemblyMetadata`.
- [ ] **When the endpoint isn't embedded** (Debug build, or a Release build without `certs\usage.props`), hide the Feedback button. There is nowhere to send to.
- [ ] `LOGHUNTER_NO_USAGE=1` turns off the automatic usage counts. **It shouldn't hide feedback**, because feedback is a deliberate action by the user. Mention that in the README line if you think it needs saying.
- [ ] Write a trace event: `TraceLog.Write("feedback", "sent" | "failed", new { area, status, length })`. **Never log the description text or the key.**
- [ ] Follow the UI guardrails in `CLAUDE.md`: minimal copy, action-first, consistent with the other web shell pages. The user asked for a button that opens a page in **web mode**. A console equivalent wasn't requested, so ask before adding one.
- [ ] Unit tests use a stub `HttpMessageHandler` that returns 200, 429, 400 and a thrown exception, and check what the user sees in each case. **Unit tests must never call the live endpoint.**

## 5. Manual end-to-end test

Use `Version = 0.0.0-test` so test rows are easy to delete. A probe in bash, using the key the user gives you:

```bash
curl -s -w " -> %{http_code}\n" -X POST -H "Content-Type: application/json; charset=utf-8" -H "X-LogHunter-Key: <key>" \
  --data '{"InstallId":"00000000-0000-4000-8000-0000000000ff","Version":"0.0.0-test","Mode":"web","Area":"other","Description":"Manual test from the LogHunter agent."}' \
  https://andrec-fonseca.outsystemscloud.com/LogHunterUsage_IS/rest/Usage/Feedback
```

After sending from the real app, the user can see the row on the monitor's **Feedback** screen (`/LogHunterUsage`, Admin role).

Test install ids `...0000000000fb`, `...fc` and `...fd` already hold server-test rows, and `...fb` is rate-limited until 2026-11-26. Use a different id.
