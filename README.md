<div align="center">

# LogHunter
### Tool for ALB, IIS, and OutSystems Platform logs analysis

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet)](#)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D4?style=for-the-badge&logo=windows)](#)
[![UI](https://img.shields.io/badge/UI-Console%20%2B%20Local%20Web-111827?style=for-the-badge)](#)

**Fast - Portable - Built for incident triage**

</div>

---

## Context

LogHunter is an external log analysis tool that simplifies investigation of:
- AWS ALB logs (edge traffic + WAF outcomes)
- IIS logs (request behavior)
- OutSystems Platform logs (application/runtime signals)

It provides a high-performance, intuitive workflow to accelerate troubleshooting and deep-dive diagnostics.

---

## Purpose

LogHunter is built for security and incident investigations, turning raw logs into actionable evidence quickly:
- **Who**: top IPs, spikes/bursts, repeat offenders
- **What**: top endpoints/URIs, status codes, scan/probe patterns
- **Likely success**: pivot from 4xx/5xx noise to 2xx/3xx on sensitive paths and correlate with IIS/Platform logs
- **When / impact**: timeline views (for example, 5-minute IP buckets)
- **Handoff**: CSV, Excel, SQLite, and HTML outputs for SOC/customer evidence and follow-up checks

---

## Main benefits

- **Speed**: optimized for large operations, often significantly faster than ad-hoc command-line analysis
- **Capacity**: designed for large datasets (commonly 20GB+)
- **Setup**: portable executable, no heavy local setup for end users of the published build
- **Modes**: supports both the legacy console workflow and a local web shell

---

## Release notes

### 1.6

- Adds AbuseIPDB check workflow with dedicated settings management and IP selection from multiple sources (ALB, IIS burst, Platform suspicious cache).
- Adds IIS Bytes Intel module with Top Bandwidth IPs & URIs (sc-bytes) and Uploads/Payload Attempts (cs-bytes) analysis.
- Adds IIS Burst Patterns detection for identifying high-frequency request bursts.
- Adds IIS Status Pivot for response code analysis across IPs and endpoints.
- Adds Platform authenticated activity check to cross-reference suspicious IPs against authenticated sessions.
- Adds Platform suspicious request extraction from CSV/XLSX log exports.
- Improves ALB scan options with generic scan framework covering Top 50 IPs overall, Top 50 IPs by URI, Top 50 requests by AVG duration, and WAF blocked summary.
- Updates version metadata to `1.6`.

### 1.5.0.1

- Tightens IIS Burst detection so it is less broad and less noisy on normal clustered traffic.
- Adds startup update checking against the `LogHunter-Public` releases repo, with a 6-hour snooze when the operator declines the prompt.
- Keeps the release line on `1.5` while shipping these focused operator-facing improvements as `1.5.0.1`.

### 1.5

- Refines the dark web-shell theme with stronger hierarchy for glossy/OLED and glare-prone viewing conditions.
- Improves ALB download workflow affordance with clearer panel separation, stronger control contrast, and more obvious form boundaries.
- Adds client-side required-field validation for the ALB download form, including inline missing-input warnings and red field highlighting before submission.
- Renames the ALB action to `Open logs folder`, clarifies that `Config name` is optional, and updates the Sentry toggle copy to `Sentry Infrastructure`.
- Improves ALB IP Summary Excel workbook formatting with stronger section structure and clearer summary treatment.
- Updates release metadata to `1.5`.

### 1.4

- Mainline release for the merged ALB and IIS IP Summary work.
- Adds ALB IP Summary multi-IP workflow support with shared HTML reporting, shared workbook output, and aggregated SQLite handling for large detail sets.
- Improves IIS IP Summary workbook presentation and chart inspection, including richer offline hover details and safer automatic bucket selection for shorter time windows.
- Brings ALB chart interactivity up to parity with the IIS hover model, including nearest-point inspection, a dedicated hover info panel, series restore, and legend isolate-on-double-click.
- Adds the application icon asset for the packaged executable and updates release metadata to `1.4`.

### 1.2

- Merge-to-main release for the ALB IP Summary work.
- Includes the option 3 HTML report fix so the chart summary columns render correctly on Windows.
- Establishes the `1.2` version baseline for the next mainline release.

### 1.1.3

- Merge-prep release for the ALB IP Summary feature set and related report/UI polish.
- Establishes the `1.1.3` branch/version baseline before adding the SQLite parser/viewer in the browser.
- No breaking CLI changes; this release is intended as the merge point immediately prior to the browser-based SQLite viewing work.

### 1.1.2

- Patch release for console UX responsiveness improvements.
- AbuseIP: cleaner cancellation messaging and immediate first render in the IP picker.
- Platform scans: visible processing spinner during heavy log analysis to avoid blank-screen confusion.

### 1.1.1

- Version bump for the latest merged branch.
- Documentation refresh to support packaging and publication of the `1.1.1` release.
- No breaking CLI changes; existing module flows and commands remain stable.

---

## Navigation and usage notes

On first run, LogHunter creates these folders:
- `ALB`
- `IIS`
- `PlatformLogs`
- `output`

Place each log type into its respective folder and run the matching module. Generated CSV files and charts are written under `output`.

For ALB, logs can also be downloaded directly from inside the tool.

By default, LogHunter starts in **console mode**. You can explicitly start the local web shell with `--web`.

---

## Prerequisites

### Required for ALB log download
- AWS CLI v2
- Access configured for the target ALB log buckets/timeframe

### Optional
- AbuseIPDB API key (the built-in default key can be used until request limits are reached)

---

## Modules and commands

## ALB tools (AWS Application Load Balancer)

The ALB module focuses on edge traffic triage: who is hitting your edge, what they target, when spikes occurred, whether WAF blocked requests, and where latency increased.

Commands:
1. **Download logs from S3**
2. **Top IPs + top full paths for endpoint/path fragment**
3. **IP Summary**
4. **5xx while backend succeeded**
5. **Top 50 IPs overall**
6. **Top 50 IPs by URI (no query)**
7. **Top 50 requests by AVG duration**
8. **ALB requests over time per selected IP (5-minute buckets)**
9. **WAF blocked summary + top blocked requests**
10. **WAF blocks over time (per minute) (chart)**

## IIS tools (Internet Information Services)

The IIS module focuses on request triage using response behavior and burst detection, then pivots to likely-success traffic.

Commands:
1. **IP Summary**
2. **Status Pivot**
3. **Burst patterns**
4. **Top bandwidth IPs and URIs (`sc-bytes`)**
5. **Uploads and payload attempts (`cs-bytes`)**

## Platform tools (OutSystems Platform logs)

The Platform module processes Platform exports (CSV/XLSX) to extract suspicious source IPs and check authenticated activity signals.

Commands:
1. **Suspicious requests: extract IPs**
2. **Suspicious IPs: authenticated activity check**
3. **Authenticated IP cache**

## IP reputation tools (AbuseIPDB)

This module enriches suspicious IP analysis with external reputation context (supporting evidence, not ground truth).

Commands:
1. **Check IPs from ALB output file (CSV/XLSX)**
2. **Check IPs from IIS burst session**
3. **Check IPs from Platform suspicious cache**
4. **Set or update API key**

Outputs:
- Enriched CSV with score/context
- Confidence tiering (High / Medium / Low) based on behavior + reputation

---

## Run

### Default startup

```powershell
LogHunter.exe
```

Starts the legacy console menu.

### Explicit modes

```powershell
LogHunter.exe --console
LogHunter.exe --web
```

- `--console`: explicitly starts the console menu
- `--web`: explicitly starts the local web shell on `127.0.0.1`
- `--no-browser`: in web mode, do not auto-open the default browser

### Other useful options

```powershell
LogHunter.exe --help
LogHunter.exe --version
LogHunter.exe --root C:\path\to\workspace
```

- `--root <path>`: use a custom workspace instead of the executable folder
- `--viewer-sqlite <path>`: open the SQLite viewer directly for a generated database
- `--viewer-ip <ip>`: optional selected IP shown in viewer metadata

---

## Internal classification note

This tool and related operational documentation are intended for internal use.
