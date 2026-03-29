# Patch Notes - 2026-03-29

## Included in this merge

- Expanded IIS status pivot filters for broader status-code slicing during analysis.
- Added a new ALB workflow: `5xx while backend succeeded`.
- Normalized the Excel formatting for the ALB mismatch export to match the ALB IP Summary style.
- Fixed the `--web` command-line switch so it actually starts the local web shell.

## ALB: 5xx while backend succeeded

New ALB workflow to find requests where:

- the customer-facing ALB response is `5xx`
- the backend/target response is `2xx` or `3xx`

This helps isolate cases where the backend appears successful but the client still receives an ALB-side failure.

## Excel output

The ALB mismatch Excel export now uses the same visual treatment as the ALB IP Summary export:

- stronger section/header styling
- bordered summary blocks
- table-based summary breakdowns
- cleaner formatting for hits/timing columns

## CLI

- `--web` now correctly launches the local web shell
- help text was aligned with the actual startup behavior
