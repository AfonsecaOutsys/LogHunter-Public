# LogHunter Public

Download-only repository for the packaged `LogHunter.exe` releases.

This repo is intended for colleagues who only need the executable build.
Source code, development history, and internal implementation details stay in the main `LogHunter` repository.

## What to download

Use the **Releases** page and download the latest `LogHunter.exe` asset.

Latest release flow:
- open the latest release
- download `LogHunter.exe`
- run it locally on Windows x64

## What LogHunter does

LogHunter helps with investigation and triage of:
- AWS ALB logs
- IIS logs
- OutSystems Platform logs
- IP reputation checks through AbuseIPDB

Typical outputs include:
- CSV exports
- Excel workbooks
- HTML reports
- SQLite databases for larger drill-down workflows

## Requirements

### Platform
- Windows x64

### Required for ALB log download
- AWS CLI v2
- Access to the target ALB log buckets and timeframe

### Optional
- AbuseIPDB API key

## Basic usage

```powershell
LogHunter.exe
```

This starts the console workflow.

Useful options:

```powershell
LogHunter.exe --help
LogHunter.exe --version
LogHunter.exe --console
```

## Workspace folders

On first run, LogHunter creates these folders next to the executable/workspace:
- `ALB`
- `IIS`
- `PlatformLogs`
- `output`

Generated outputs are written under `output`.

## Releases

Release notes are published with each GitHub Release in this repo.
For the latest packaged build, use the latest release asset instead of downloading files directly from the repository tree.
