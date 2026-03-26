<div align="center">

# LogHunter 🔎
### Tool for ALB, IIS, and OutSystems Platform logs analysis

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet)](#)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D4?style=for-the-badge&logo=windows)](#)
[![UI](https://img.shields.io/badge/UI-Console%20Interactive-111827?style=for-the-badge)](#)

**Fast • Portable • Built for incident triage**

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
- **Handoff**: CSV/HTML exports for SOC/customer evidence and follow-up checks

---

## Main benefits

- **Speed**: optimized for large operations, often significantly faster than ad-hoc command-line analysis
- **Capacity**: designed for large datasets (commonly 20GB+)
- **Setup**: portable executable, no heavy local setup for end users of the published build

---

## Release notes

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
1. **Download logs**
2. **Top full paths for endpoint/path fragment (no query string)**
3. **Top 50 IPs overall**
4. **Top 50 IPs by URI (no query string)**
5. **Requests ordered by AVG duration (filtered by target)**
6. **Requests per IP per 5 minutes (chart + CSV)**
7. **WAF blocked summary + Top 50 blocked requests**
8. **WAF blocked over time**

## IIS tools (Internet Information Services)

The IIS module focuses on request triage using response behavior and burst detection, then pivots to likely-success traffic.

Commands:
1. **4xx → pick suspicious IPs → pivot to 2xx/3xx**
2. **Burst patterns** (10s, 30s, 60s, 300s buckets)
3. **Top bandwidth IPs and URIs (`sc-bytes`)**
4. **Uploads and payload attempts (`cs-bytes`)**

## Platform tools (OutSystems Platform logs)

The Platform module processes Platform exports (CSV/XLSX) to extract suspicious source IPs and check authenticated activity signals.

Commands:
1. **Suspicious requests: extract IPs**
2. **Suspicious IPs: authenticated activity check**
3. **Authenticated IP cache view**

## IP reputation tools (AbuseIPDB)

This module enriches suspicious IP analysis with external reputation context (supporting evidence, not ground truth).

Commands:
1. **Check IPs from output CSV**
2. **Check IPs from IIS burst session**
3. **Check IPs from Platform suspicious cache**

Outputs:
- Enriched CSV with score/context
- Confidence tiering (High / Medium / Low) based on behavior + reputation

---

## Run

```bash
LogHunter.exe
```

---

## Internal classification note

This tool and related operational documentation are intended for internal use.
