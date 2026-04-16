# Known Issues

Issues ranked by complexity (low → high).

---

## Low Complexity

### 1. ✅ IP Summary - Remove IIS Burst and Platform Cache Buttons
Both ALB and IIS IP Summary views have IIS Burst and Platform Cache buttons that are not wired up in the web UI. These should be removed.

### 2. ✅ WAF Blocks Over Time - Should Auto-Open Chart
The WAF blocks over time (per minute) scan produces a chart but doesn't open it automatically on completion. Since the chart is the main output of this scan, it should auto-open once ready.

### 3. ✅ ALB - "Open Chart" Button Shown on Pages Without Charts
The "Open chart" button is rendered on all ALB generic scan pages via a shared template, but only two scans actually produce charts. The button should only exist on pages that support it:
- **Requests over time** — has chart (keep button)
- **WAF blocks over time (per minute)** — has chart (keep button)
- **5xx while backend succeeded** — no chart (remove button)
- **Top 50 IPs overall** — no chart (remove button)
- **Top 50 IPs by URI (no query)** — no chart (remove button)
- **Top 50 requests by AVG duration** — no chart (remove button)
- **WAF blocked summary** — no chart (remove button)

### 4. ✅ ALB Option 2 (5xx While Backend Succeeded) - Excel Table Formatting Needs Tightening
The Excel export for the 5xx while backend succeeded scan has tables that need tighter formatting for better readability (column widths, alignment, spacing).

### 5. ✅ ALB Requests Over Time Per Selected IP - Remove CSV Export, Keep Only Chart
The 5-minute bucket CSV output for "Requests over time per selected IP" is meaningless to the user. Remove the CSV export and keep only the chart output.

### 6. ✅ WAF Blocks Over Time Chart - Remove IP Filter
The WAF blocks over time (per minute) chart page has an IP filter dropdown, but this scan only shows blocked requests over time with no IP breakdown. The IP filter should be removed from this page.

### 7. ✅ Web UI IP Summary Chart - Missing Hover Inspect Bucket Feature
The Web UI IP Summary chart is missing the "Hover: inspect bucket" feature that exists in the console-generated HTML chart. The console version shows a "Nearest bucket" detail panel on hover with per-status-code breakdown (ELB 2xx/3xx, FE 2xx/3xx, 4xx, 5xx counts). The Web UI chart needs to be brought to parity with this.

### 8. ✅ Chart Summary - Tooltip Causes Layout Shift
Hovering over the chart causes the tooltip bubble above to expand, shifting the entire page layout. The tooltip should use a fixed-size overlay or absolute positioning to avoid reflowing the page.

---

## Medium Complexity

### Group A — Quick UX Wins (All Scans) ✅

### 9. ✅ All Scans - No Auto-Scroll to Results
When a scan completes, the results section appears but the page does not scroll down to it. This makes it look like nothing happened. The page should auto-scroll to the results section once results are available.

### 10. ✅ All Scans - Lock Inputs While Scan Is Running
The scan input controls (source selection, run button, etc.) should be disabled/locked while a scan is in progress to prevent users from modifying inputs or triggering duplicate scans mid-run.

### 18. ✅ All Scans - Duplicate Action Buttons on Results Card
After auto-scrolling to the results section, the user has no quick access to "Open Chart", "Open SQLite", or "Open Excel" without scrolling back up to the scan status card. Add redundant action buttons (where applicable) to the results card header area so the user can open exports/charts directly from the results view.

### Group B — Excel Export Fixes (CSV → Excel + Formatting)

### 19. Top 50 IPs Overall - Export Should Be Excel Not CSV
The Top 50 IPs Overall scan exports to CSV. Both the UI and console output should produce a well-formatted Excel file instead.

### 20. Top 50 IPs by URI (No Query) - Export Should Be Excel Not CSV
The Top 50 IPs by URI (no query) scan exports to CSV. Both the UI and console output should produce a well-formatted Excel file instead.

### 21. Top 50 Requests by AVG Duration - Export Should Be Excel Not CSV
The Top 50 Requests by AVG Duration scan exports to CSV. Both the UI and console output should produce a well-formatted Excel file instead.

### 22. IIS Top Bandwidth IPs & URIs (sc-bytes) - Export Should Be Excel Not CSV
The IIS Top Bandwidth IPs & URIs scan exports to CSV/HTML. Both the UI and console output should produce a well-formatted Excel file instead.

### 23. IIS Uploads and Payload Attempts (cs-bytes) - Export Should Be Excel Not CSV
Both IIS upload/payload options export to CSV/HTML. Both the UI and console output should produce a well-formatted Excel file instead.

### 13. IIS IP Summary - Excel Export Cell Wrapping
The IIS IP Summary Excel export has cells that wrap text, making rows span multiple lines. All cells should be single-line with no wrapping.

### 14. ALB IP Summary - Excel Export Wrapping on IP Sheets
The ALB IP Summary Excel export is mostly fine, but on sheet 2 onwards (individual IP sheets) the summary section has cell wrapping issues. The data table part of those sheets is OK, only the summary area needs fixing.

### 15. Excel IP Summary - Standardize Visual Layout
All Excel IP Summary exports (ALB and IIS) should share a consistent visual layout. Use the ALB IP Summary first sheet (overview) and the sheet 2+ layout (individual IPs) as the reference style. Apply this same layout to all IP summary Excel exports so they look uniform.

### Group C — IIS / Platform Specific

### 12. IIS IP Summary - SQLite Output Rows Wrapping
The IIS IP Summary SQLite results table has rows that wrap onto multiple lines, making it hard to read. Each record should fit in a single row with horizontal scrolling, matching the ALB IP Summary output style. Compare both implementations to align them.

### 17. Platform Logs Option 2 - Add Manual IP Input
Platform Logs option 2 should support manual IP input as an additional way to specify the IPs to check.

### Group D — IP Summary UI Polish

### 16. IP Summary - Right Panel Layout After Analysis
The right panel layout doesn't flow well after the analysis is complete. Needs visual cleanup and better structure.

### 24. IP Summary - Missing Status Updates During Export
After the scan completes, there is no feedback to the user while the engine builds the .db or Excel file. Add status updates so users know the export phase is in progress.

### Group E — Results Readability

### 11. Top Bandwidth IPs & Upload Payloads - Results Hard to Read
The results for both Top Bandwidth IPs and Upload Payloads scans need to be clearer and more tightened up for easier readability.

---

## High Complexity

### 25. ALB Requests Over Time Per Selected IP - Needs File Picker
The ALB "Requests over time per selected IP" chart should use the same file picker flow as the IP Summary pages (single file picker instead of file list from folder).

### 26. ALB/IIS IP Summary UI - Source File Selection
When selecting "from source" in the ALB IP Summary UI, the current implementation shows a list of files from the folder. This should be tightened to a single selectable file picker instead. The IIS IP Summary is missing the files input form entirely — it needs the same file selection UI that ALB IP Summary has. Additionally, once a file is selected, the IP selection should use a popup modal with a scrollable list of IPs, each showing the hit count for easy identification. The list should be ranked by hits (descending) and support multi-select so the user can choose which IPs to run in one go.

### 27. WAF Blocked Summary + Top Blocked Requests - Improve Output
The WAF blocked summary and top blocked requests outputs need analysis and rework. The blocked summary results are buried in the scan status card and only show a list of top blocks. Both outputs need to be moved to the results section and presented in a more meaningful way (e.g. aggregate stats, visual breakdown). Requires hands-on analysis of the current output before deciding on the approach.

### 28. AbuseIPDB - Pull IPs from IIS Burst Cache
AbuseIPDB IP selection should support pulling IPs from the IIS Burst Identification cache. To enable this:
1. **Burst Identification** should save each distinct IP into a cache along with the number of bursts and total hits (this data doesn't need to be shown in the burst identification results themselves).
2. **AbuseIPDB** should have a source option to use the burst cache. When selected, display a well-formatted list of the cached IPs showing IP address, number of bursts, and total hits, each with a radio button for selection.
