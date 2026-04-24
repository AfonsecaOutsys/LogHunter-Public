using System;
using System.Linq;
using System.Net;
using LogHunter.Web.Hosting;

namespace LogHunter.Web.Pages;

internal static class IisPageBuilder
{
    private static readonly IisOptionDefinition[] Options =
    [
        new(0, "/iis/ip-summary", "IP Summary", "Multi-IP summary with per-minute charts, status breakdowns, latency stats, and Excel/SQLite exports.", true),
        new(1, "/iis/status-pivot", "Status Pivot", "Find error IPs by status filter, then pivot into their 2xx/3xx traffic and export raw log lines.", true),
        new(2, "/iis/burst-patterns", "Burst Patterns", "Detect bursty request patterns per IP using configurable time buckets and heuristic scoring.", true),
        new(3, "/iis/top-bandwidth", "Top Bandwidth IPs", "Rank client IPs by sc-bytes (outbound bandwidth) with per-IP top URI breakdown.", true),
        new(4, "/iis/uploads-payloads", "Uploads / Payloads", "Find payload-heavy POST/PUT IPs by cs-bytes with per-IP top endpoint breakdown.", true)
    ];

    public static bool TryBuild(WebAppContext context, string path, out WebPageDefinition page, out string mainContent, out string? extraScriptPath)
    {
        if (string.Equals(path, "/iis", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/iis", "/iis", "IIS", "IIS", "Module Landing", "W3C log analysis, IP summaries, status pivots, burst detection, bandwidth, and payload investigation.");
            mainContent = BuildLandingContent();
            extraScriptPath = null;
            return true;
        }

        if (string.Equals(path, "/iis/ip-summary", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/iis/ip-summary", "/iis", "IIS", "IIS / IP Summary", "Workflow", "Enter client IPs, scan IIS logs, and review per-minute charts with status breakdowns.");
            mainContent = BuildIpSummaryContent();
            extraScriptPath = "/assets/iis.js";
            return true;
        }

        if (string.Equals(path, "/iis/status-pivot", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/iis/status-pivot", "/iis", "IIS", "IIS / Status Pivot", "Workflow", "Find error IPs by status filter and pivot into their successful traffic.");
            mainContent = BuildStatusPivotContent();
            extraScriptPath = "/assets/iis.js";
            return true;
        }

        if (string.Equals(path, "/iis/burst-patterns", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/iis/burst-patterns", "/iis", "IIS", "IIS / Burst Patterns", "Workflow", "Detect bursty request patterns per IP using configurable time buckets.");
            mainContent = BuildBurstPatternsContent();
            extraScriptPath = "/assets/iis.js";
            return true;
        }

        if (string.Equals(path, "/iis/top-bandwidth", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/iis/top-bandwidth", "/iis", "IIS", "IIS / Top Bandwidth IPs", "Workflow", "Rank client IPs by sc-bytes with per-IP top URI breakdown.");
            mainContent = BuildBytesIntelContent("bandwidth", "Top Bandwidth IPs", "Rank client IPs by outbound bandwidth (sc-bytes) and inspect top URIs per IP.");
            extraScriptPath = "/assets/iis.js";
            return true;
        }

        if (string.Equals(path, "/iis/uploads-payloads", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/iis/uploads-payloads", "/iis", "IIS", "IIS / Uploads and Payloads", "Workflow", "Find payload-heavy POST/PUT IPs by cs-bytes with per-IP top endpoint breakdown.");
            mainContent = BuildBytesIntelContent("uploads", "Uploads / Payloads", "Find payload-heavy POST/PUT IPs by cs-bytes and inspect top endpoints per IP.");
            extraScriptPath = "/assets/iis.js";
            return true;
        }

        page = default!;
        mainContent = string.Empty;
        extraScriptPath = null;
        return false;
    }

    public static object BuildOptionsPayload()
        => Options.Select(x => new
        {
            number = x.Number,
            path = x.Path,
            title = x.Title,
            description = x.Description,
            implemented = x.Implemented
        }).ToArray();

    private static string BuildLandingContent()
    {
        var cards = string.Join(Environment.NewLine, Options.Select(BuildOptionCard));

        return $$"""
      <section class="stack">
        <section class="panel">
          <div class="section-heading">
            <div>
              <div class="eyebrow">IIS Workflows</div>
              <h2>Pick a workflow</h2>
            </div>
            <p class="page-copy compact-copy">Choose an IIS action and continue directly into that flow.</p>
          </div>
          <div class="option-grid option-grid--dense">
{{cards}}
          </div>
        </section>
      </section>
""";
    }

    private static string BuildIpSummaryContent()
    {
        return """
      <section class="stack" data-iis-ip-summary-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>IP Summary</h1>
              <p>Enter client IPs, scan IIS logs, and review per-minute charts with status breakdowns.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Scan inputs</h2>
            <div id="iisIpSummaryError" class="inline-error" hidden></div>

            <div class="field-group">
              <label class="field-label">IP input</label>
              <div class="button-row source-action-row">
                <button id="iisIpSummaryModeManual" class="source-btn active" type="button">Manual entry</button>
                <button id="iisIpSummaryModeFile" class="source-btn" type="button">From output file</button>
              </div>
            </div>

            <div id="iisIpSummaryManualSection" class="field-group">
              <div class="field">
                <label for="iisIpSummaryIpText">Client IPs (one per line, max 10)</label>
                <textarea id="iisIpSummaryIpText" rows="5" placeholder="10.0.0.1&#10;192.168.1.100&#10;172.16.0.5"></textarea>
              </div>
            </div>

            <div id="iisIpSummaryFileSection" class="field-group" hidden>
              <div class="field">
                <label>Output file (CSV/XLSX)</label>
                <div class="button-row">
                  <button id="iisIpSummaryBrowseFile" class="button-link primary button-like compact" type="button">Select file &amp; extract IPs</button>
                </div>
                <div id="iisIpSummaryFileChip" class="source-chip" hidden></div>
              </div>
            </div>

            <div class="field-group source-group">
              <label class="field-label">Log source</label>
              <div class="button-row source-action-row">
                <button id="iisIpSummaryUseDefault" class="source-btn active" type="button">Default folder</button>
                <button id="iisIpSummarySelectFolder" class="source-btn" type="button">Select folder</button>
                <button id="iisIpSummarySelectFiles" class="source-btn" type="button">Select files</button>
                <button id="iisIpSummaryClearSelection" class="source-btn source-btn--clear" type="button" hidden>Clear</button>
              </div>
              <div id="iisIpSummarySourceChip" class="source-chip">Loading...</div>
            </div>

            <div class="field-group source-group">
              <label class="field-label">Output mode</label>
              <div class="button-row source-action-row">
                <button id="iisIpSummaryModeExport" class="source-btn active" type="button">Export output</button>
                <button id="iisIpSummaryModeChart" class="source-btn" type="button">Chart summary</button>
              </div>
            </div>

            <div class="button-row">
              <button id="iisIpSummaryRun" class="button-link primary button-like" type="button">Run scan</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Scan status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="iisIpSummaryState">idle</strong></div>
              <div class="status-pill"><span>Phase</span><strong id="iisIpSummaryPhase">idle</strong></div>
              <div class="status-pill"><span>IPs</span><strong id="iisIpSummaryIpCount">0</strong></div>
            </div>
            <p id="iisIpSummaryMessage" class="page-copy">Idle.</p>
            <div id="iisIpSummaryMeta" class="footer-note"></div>
            <div class="export-row">
              <div id="iisIpSummaryExportInfo" class="footer-note"></div>
              <button id="iisIpSummaryOpenReport" class="button-link button-like compact" type="button" disabled>Open report</button>
              <button id="iisIpSummaryOpenExport" class="button-link button-like compact" type="button" disabled>Open Excel</button>
            </div>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label">Scan progress</div>
                <div id="iisIpSummaryStageBadge" class="kicker">idle</div>
              </div>
              <div id="iisIpSummarySummary" class="info-value">Waiting for a scan to start.</div>
              <div class="progress-track"><div id="iisIpSummaryBar" class="progress-fill" style="width:0%"></div></div>
              <div id="iisIpSummaryBarMeta" class="footer-note">No scan running.</div>
            </div>

            <div id="iisIpSummaryIpProgress" class="expandable-stack" hidden>
              <details class="expandable-panel" open>
                <summary>Per-IP row counts</summary>
                <div class="expandable-body">
                  <div id="iisIpSummaryIpRows" class="result-summary-body"></div>
                </div>
              </details>
            </div>
          </section>
        </section>

        <section id="iisIpSummaryResults" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Results</div>
                <h2>Per-IP summary</h2>
              </div>
              <div class="export-row">
                <button id="iisIpSummaryResultsOpenReport" class="button-link button-like compact" type="button" disabled>Open report</button>
                <button id="iisIpSummaryResultsOpenExport" class="button-link button-like compact" type="button" disabled>Open Excel</button>
              </div>
            </div>
            <div id="iisIpSummaryPerIp" class="stack"></div>
          </section>
        </section>
      </section>
""";
    }

    private static string BuildStatusPivotContent()
    {
        return """
      <section class="stack" data-iis-status-pivot-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>Status Pivot</h1>
              <p>Find error IPs by status filter, then pivot into their 2xx/3xx traffic.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Scan inputs</h2>
            <div id="iisStatusPivotError" class="inline-error" hidden></div>

            <div class="field-group">
              <label class="field-label">Error filter</label>
              <div class="button-row source-action-row">
                <button class="source-btn active iis-pivot-filter-btn" type="button" data-filter="4xx">4xx</button>
                <button class="source-btn iis-pivot-filter-btn" type="button" data-filter="5xx">5xx</button>
                <button class="source-btn iis-pivot-filter-btn" type="button" data-filter="4xx+5xx">4xx + 5xx</button>
                <button class="source-btn iis-pivot-filter-btn" type="button" data-filter="custom">Custom codes</button>
              </div>
            </div>

            <div id="iisStatusPivotCustomCodes" class="field-group" hidden>
              <div class="field">
                <label for="iisStatusPivotCodesInput">Exact status codes (comma-separated)</label>
                <input id="iisStatusPivotCodesInput" placeholder="401,403,404,502">
              </div>
            </div>

            <div class="field-group">
              <div class="field">
                <label for="iisStatusPivotAppScope">App scope (optional URI fragment)</label>
                <input id="iisStatusPivotAppScope" placeholder="Leave blank for all, or /ServiceCenter, /LifeTime, etc.">
              </div>
            </div>

            <div class="button-row">
              <button id="iisStatusPivotRun" class="button-link primary button-like" type="button">Run scan</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Scan status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="iisStatusPivotState">idle</strong></div>
              <div class="status-pill"><span>Phase</span><strong id="iisStatusPivotPhase">idle</strong></div>
              <div class="status-pill"><span>Error IPs</span><strong id="iisStatusPivotIpCount">0</strong></div>
            </div>
            <p id="iisStatusPivotMessage" class="page-copy">Idle.</p>
            <div class="export-row">
              <div id="iisStatusPivotExportInfo" class="footer-note"></div>
              <button id="iisStatusPivotOpenExport" class="button-link button-like compact" type="button" disabled>Open export</button>
            </div>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label">Scan progress</div>
                <div id="iisStatusPivotStageBadge" class="kicker">idle</div>
              </div>
              <div id="iisStatusPivotSummary" class="info-value">Waiting for a scan to start.</div>
              <div class="progress-track"><div id="iisStatusPivotBar" class="progress-fill" style="width:0%"></div></div>
              <div id="iisStatusPivotBarMeta" class="footer-note">No scan running.</div>
            </div>
          </section>
        </section>

        <section id="iisStatusPivotResults" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Error-side summary</div>
                <h2>Top error IPs</h2>
              </div>
              <div class="export-row">
                <button id="iisStatusPivotResultsOpenExport" class="button-link button-like compact" type="button" disabled>Open export</button>
              </div>
            </div>
            <div id="iisStatusPivotTopIps" class="result-summary-body"></div>
          </section>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Pivot results</div>
                <h2>2xx/3xx traffic for selected IPs</h2>
              </div>
            </div>
            <div id="iisStatusPivotPivotResults" class="stack"></div>
          </section>
        </section>
      </section>
""";
    }

    private static string BuildBurstPatternsContent()
    {
        return """
      <section class="stack" data-iis-burst-patterns-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>Burst Patterns</h1>
              <p>Detect bursty request patterns per IP using configurable time buckets and heuristic scoring.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Scan inputs</h2>
            <div id="iisBurstError" class="inline-error" hidden></div>

            <div class="field-group source-group">
              <label class="field-label">Log source</label>
              <div class="button-row source-action-row">
                <button id="iisBurstUseDefault" class="source-btn active" type="button">Default folder</button>
                <button id="iisBurstSelectFolder" class="source-btn" type="button">Select folder</button>
                <button id="iisBurstSelectFiles" class="source-btn" type="button">Select files</button>
                <button id="iisBurstClearSelection" class="source-btn" type="button" hidden>Clear</button>
              </div>
              <div id="iisBurstSourceChip" class="source-chip">Default folder</div>
            </div>

            <div class="field-group">
              <div class="field">
                <label for="iisBurstBucket">Bucket size</label>
                <select id="iisBurstBucket">
                  <option value="10">10 seconds (microbursts)</option>
                  <option value="30">30 seconds</option>
                  <option value="60" selected>60 seconds (default)</option>
                  <option value="300">300 seconds (5 minutes)</option>
                </select>
              </div>
            </div>

            <div class="button-row">
              <button id="iisBurstRun" class="button-link primary button-like" type="button">Run scan</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Scan status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="iisBurstState">idle</strong></div>
              <div class="status-pill"><span>Phase</span><strong id="iisBurstPhase">idle</strong></div>
              <div class="status-pill"><span>Candidates</span><strong id="iisBurstCandidates">0</strong></div>
            </div>
            <p id="iisBurstMessage" class="page-copy">Idle.</p>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label">Scan progress</div>
                <div id="iisBurstStageBadge" class="kicker">idle</div>
              </div>
              <div id="iisBurstSummary" class="info-value">Waiting for a scan to start.</div>
              <div class="progress-track"><div id="iisBurstBar" class="progress-fill" style="width:0%"></div></div>
              <div id="iisBurstBarMeta" class="footer-note">No scan running.</div>
            </div>
          </section>
        </section>

        <section id="iisBurstResults" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Results</div>
                <h2>Burst candidates</h2>
              </div>
            </div>
            <div id="iisBurstTable" class="result-summary-body"></div>
          </section>
        </section>
      </section>
""";
    }

    private static string BuildBytesIntelContent(string mode, string title, string description)
    {
        var prefix = string.Equals(mode, "bandwidth", StringComparison.OrdinalIgnoreCase) ? "iisBandwidth" : "iisUploads";

        return $$"""
      <section class="stack" data-iis-bytes-intel-page="true" data-iis-bytes-mode="{{Html(mode)}}">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>{{Html(title)}}</h1>
              <p>{{Html(description)}}</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Scan inputs</h2>
            <div id="{{prefix}}Error" class="inline-error" hidden></div>

            <div class="button-row">
              <button id="{{prefix}}Run" class="button-link primary button-like" type="button">Run scan</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Scan status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="{{prefix}}State">idle</strong></div>
              <div class="status-pill"><span>Phase</span><strong id="{{prefix}}Phase">idle</strong></div>
            </div>
            <p id="{{prefix}}Message" class="page-copy">Idle.</p>
            <div class="export-row">
              <div id="{{prefix}}ExportInfo" class="footer-note"></div>
              <button id="{{prefix}}OpenExport" class="button-link button-like compact" type="button" disabled>Open CSV</button>
            </div>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label">Scan progress</div>
                <div id="{{prefix}}StageBadge" class="kicker">idle</div>
              </div>
              <div id="{{prefix}}Summary" class="info-value">Waiting for a scan to start.</div>
              <div class="progress-track"><div id="{{prefix}}Bar" class="progress-fill" style="width:0%"></div></div>
              <div id="{{prefix}}BarMeta" class="footer-note">No scan running.</div>
            </div>
          </section>
        </section>

        <section id="{{prefix}}Results" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Results</div>
                <h2>Top IPs</h2>
              </div>
              <div class="export-row">
                <button id="{{prefix}}ResultsOpenExport" class="button-link button-like compact" type="button" disabled>Open export</button>
              </div>
            </div>
            <div id="{{prefix}}TopIps" class="result-summary-body"></div>
          </section>
        </section>
      </section>
""";
    }

    private static string BuildOptionCard(IisOptionDefinition option)
    {
        if (option.Implemented)
        {
            return $$"""
            <a class="option-card option-card--action" href="{{Html(option.Path)}}">
              <div class="option-card-head">
                <span class="option-number">Workflow</span>
              </div>
              <h3>{{Html(option.Title)}}</h3>
              <p>{{Html(option.Description)}}</p>
            </a>
""";
        }

        return $$"""
            <div class="option-card option-card--disabled" aria-disabled="true">
              <div class="option-card-head">
                <span class="option-number">Workflow</span>
              </div>
              <h3>{{Html(option.Title)}}</h3>
              <p>{{Html(option.Description)}}</p>
            </div>
""";
    }

    private static string Html(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private sealed record IisOptionDefinition(int Number, string Path, string Title, string Description, bool Implemented);
}
