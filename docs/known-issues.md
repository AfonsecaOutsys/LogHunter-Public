# Known Issues

## ALB IP Summary UI - Source File Selection
When selecting "from source" in the ALB IP Summary UI, the current implementation shows a list of files from the folder. This should be tightened to a single selectable file picker instead.

## Chart Summary - Tooltip Causes Layout Shift
Hovering over the chart causes the tooltip bubble above to expand, shifting the entire page layout. The tooltip should use a fixed-size overlay or absolute positioning to avoid reflowing the page.

## IP Summary - Right Panel Layout After Analysis
The right panel layout doesn't flow well after the analysis is complete. Needs visual cleanup and better structure.

## IP Summary - Missing Status Updates During Export
After the scan completes, there is no feedback to the user while the engine builds the .db or Excel file. Add status updates so users know the export phase is in progress.
