using System;
using System.Linq;
using System.Net;
using LogHunter.Services;
using LogHunter.Web.Hosting;

namespace LogHunter.Web.Pages;

internal static class AlbPageBuilder
{
    private static readonly AlbOptionDefinition[] Options =
    [
        new(1, "/alb/download-logs", "Download logs from S3", "Download ALB logs into the workspace using AWS CLI and your current credentials/session.", true),
        new(2, "/alb/top-ips-top-paths", "Top IPs + top full paths for endpoint/path fragment", "Match a fragment, rank top IPs, then show top full URI paths per IP.", true),
        new(3, "/alb/ip-summary", "IP Summary", "Review one or more client IPs with shared charts and exports.", true),
        new(4, "/alb/top-50-ips", "Top 50 IPs overall", "Scan logs and show the top 50 client IPs across the selected range.", false),
        new(5, "/alb/top-50-ips-by-uri", "Top 50 IPs by URI (no query)", "Group top IP activity by URI path without query strings.", false),
        new(6, "/alb/top-50-avg-duration", "Top 50 requests by AVG duration", "Find the slowest request paths ordered by average duration.", false),
        new(7, "/alb/requests-over-time", "ALB requests over time per selected IP (5-minute buckets)", "Build a per-IP request timeline from exported ALB selections.", false),
        new(8, "/alb/waf-blocked-summary", "WAF blocked summary + top blocked requests", "Summarize WAF-blocked traffic and blocked request patterns.", false),
        new(9, "/alb/waf-blocks-over-time", "WAF blocks over time (per minute) (chart)", "Chart WAF blocks per minute using the summary definition.", false)
    ];

    public static bool TryBuild(WebAppContext context, string path, out WebPageDefinition page, out string mainContent, out string? extraScriptPath)
    {
        if (string.Equals(path, "/alb", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/alb", "/alb", "ALB", "ALB", "Module Landing", "AWS Application Load Balancer workflows and future drill-down tools.");
            mainContent = BuildLandingContent();
            extraScriptPath = null;
            return true;
        }

        if (string.Equals(path, "/alb/download-logs", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/alb/download-logs", "/alb", "ALB", "ALB / Download logs from S3", "Download Workflow", "Run the ALB S3 download workflow from the browser and monitor its progress.");
            mainContent = BuildDownloadContent(context);
            extraScriptPath = "/assets/alb.js";
            return true;
        }

        if (string.Equals(path, "/alb/top-ips-top-paths", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/alb/top-ips-top-paths", "/alb", "ALB", "ALB / Top IPs + Top Full Paths", "Workflow", "Match an endpoint fragment, rank the top matching IPs, and inspect top full paths per IP.");
            mainContent = BuildTopIpsTopPathsContent();
            extraScriptPath = "/assets/alb.js";
            return true;
        }

        if (string.Equals(path, "/alb/ip-summary", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/alb/ip-summary", "/alb", "ALB", "ALB / IP Summary", "Workflow", "Review one or more client IPs with per-minute charts, status breakdowns, and shared exports.");
            mainContent = BuildIpSummaryContent();
            extraScriptPath = "/assets/alb.js";
            return true;
        }

        var option = Options.FirstOrDefault(x => string.Equals(x.Path, path, StringComparison.OrdinalIgnoreCase));
        if (option is null)
        {
            page = default!;
            mainContent = string.Empty;
            extraScriptPath = null;
            return false;
        }

        page = new WebPageDefinition(option.Path, "/alb", "ALB", $"ALB / {option.Title}", "Workflow", option.Description);
        mainContent = BuildPlaceholderContent(option);
        extraScriptPath = null;
        return true;
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
              <div class="eyebrow">ALB Workflows</div>
              <h2>Pick a workflow</h2>
            </div>
            <p class="page-copy compact-copy">Choose an ALB action and continue directly into that flow.</p>
          </div>
          <div class="option-grid option-grid--dense">
{{cards}}
          </div>
        </section>
      </section>
""";
    }

    private static string BuildDownloadContent(WebAppContext context)
    {
        var savedConfigs = AlbDownload.GetSavedConfigSummaries();
        var configOptions = string.Join(Environment.NewLine, savedConfigs.Select(x =>
            $"""<option value="{Html(x.Name)}">{Html($"{x.Name} | {x.Region} | {x.Scope} | {(x.IsSentry ? "Sentry" : "Standard")}")}</option>"""));

        var now = DateTime.UtcNow;
        var startDefault = new DateTime(now.Year, now.Month, now.Day, 0, 0, 0, DateTimeKind.Utc);
        var endDefault = new DateTime(now.Year, now.Month, now.Day, 23, 55, 0, DateTimeKind.Utc);
        var startHourOptions = BuildHourOptions(startDefault.Hour);
        var endHourOptions = BuildHourOptions(endDefault.Hour);
        var startMinuteOptions = BuildMinuteOptions(startDefault.Minute);
        var endMinuteOptions = BuildMinuteOptions(endDefault.Minute);

        return $$"""
      <section class="stack" data-alb-download-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>Download logs from S3</h1>
              <p>Download ALB logs using AWS CLI credentials and a UTC time window.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Download logs from S3</h2>
            <div id="albDownloadError" class="inline-error" hidden></div>

            <div class="field-group">
              <label class="field-label">Configuration</label>
              <div class="button-row source-action-row">
                <button id="configModeNew" class="source-btn active" type="button" data-config-mode="new">New config</button>
                <button id="configModeSaved" class="source-btn" type="button" data-config-mode="saved">Saved config</button>
              </div>
            </div>

            <div id="savedConfigFields" class="field-group" hidden>
              <div class="field">
                <label for="savedConfigName">Saved configuration</label>
                <select id="savedConfigName">
                  <option value="">Select a saved config</option>
{{configOptions}}
                </select>
              </div>
            </div>

            <div id="newConfigFields" class="field-group" hidden>
              <div class="form-grid">
                <div class="field">
                  <label for="configName">Config name (optional)</label>
                  <input id="configName" placeholder="Defaults from ALB id if blank">
                </div>
                <div class="field">
                  <label for="bucket">S3 bucket</label>
                  <input id="bucket" placeholder="example-eu-west-1-alblogs">
                </div>
                <div class="field">
                  <label for="albId">ALB identifier</label>
                  <input id="albId" placeholder="ALB226963">
                </div>
                <div class="field">
                  <label for="accountId">AWS account ID</label>
                  <input id="accountId" placeholder="123456789012">
                </div>
                <div class="field">
                  <label for="scope">Type of ALB</label>
                  <select id="scope">
                    <option value="external" selected>External</option>
                    <option value="internal">Internal</option>
                  </select>
                </div>
              </div>
              <p class="footer-note">Config name is optional. Leave it blank to default from the ALB identifier. Region is derived automatically from the S3 bucket name on this page.</p>
              <div class="field-row">
                <label class="choice-pill choice-pill--flat"><input id="isSentry" type="checkbox"> Sentry Infrastructure</label>
              </div>
            </div>

            <div class="field-group">
              <div class="field">
                <label for="awsEnvironmentText">AWS credentials block</label>
                <textarea id="awsEnvironmentText" rows="8" placeholder="SET AWS_ACCESS_KEY_ID=...&#10;SET AWS_SECRET_ACCESS_KEY=...&#10;SET AWS_SESSION_TOKEN=..."></textarea>
              </div>
            </div>

            <div class="form-grid">
              <div class="panel">
                <h3>Start time (UTC)</h3>
                <div class="form-grid">
                  <div class="field">
                    <label for="startDateUtc">Date</label>
                    <input id="startDateUtc" type="date" value="{{Html(FormatUtcDateForInput(startDefault))}}">
                  </div>
                  <div class="field">
                    <label for="startHourUtc">Hour</label>
                    <select id="startHourUtc">
{{startHourOptions}}
                    </select>
                  </div>
                  <div class="field">
                    <label for="startMinuteUtc">Minute</label>
                    <select id="startMinuteUtc">
{{startMinuteOptions}}
                    </select>
                  </div>
                </div>
              </div>
              <div class="panel">
                <h3>End time (UTC)</h3>
                <div class="form-grid">
                  <div class="field">
                    <label for="endDateUtc">Date</label>
                    <input id="endDateUtc" type="date" value="{{Html(FormatUtcDateForInput(endDefault))}}">
                  </div>
                  <div class="field">
                    <label for="endHourUtc">Hour</label>
                    <select id="endHourUtc">
{{endHourOptions}}
                    </select>
                  </div>
                  <div class="field">
                    <label for="endMinuteUtc">Minute</label>
                    <select id="endMinuteUtc">
{{endMinuteOptions}}
                    </select>
                  </div>
                </div>
              </div>
            </div>

            <div class="button-row">
              <button id="albDownloadStart" class="button-link primary button-like" type="button">Start download</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Job status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="albJobState">idle</strong></div>
              <div class="status-pill"><span>Stage</span><strong id="albJobStage">idle</strong></div>
            </div>
            <p id="albJobMessage" class="page-copy">Idle.</p>
            <div id="albJobStep" class="footer-note"></div>
            <div class="export-row">
              <div id="albJobMeta" class="footer-note"></div>
              <button id="albOpenRunFolder" class="button-link primary button-like compact" type="button" hidden>Open logs folder</button>
            </div>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label" id="albPrimaryLabel">Overall progress</div>
                <div id="albPrimaryStageBadge" class="kicker">idle</div>
              </div>
              <div id="albPrimarySummary" class="info-value">Waiting for a job to start.</div>
              <div class="progress-track"><div id="albPrimaryBar" class="progress-fill" style="width:0%"></div></div>
              <div id="albPrimaryMeta" class="footer-note">No job running.</div>
            </div>

            <div id="albCurrentDaySection" class="result-summary" hidden>
              <h3>Current day</h3>
              <div id="albCurrentDayCard" class="result-summary-body">
                <div class="footer-note">No current day available yet.</div>
              </div>
            </div>

            <div class="expandable-stack">
              <details id="albDetailsSection" class="expandable-panel">
                <summary>Show details</summary>
                <div id="albDetailsBody" class="expandable-body">
                  <div class="footer-note">Extra run details will appear here.</div>
                </div>
              </details>

              <details id="albAllDaysSection" class="expandable-panel" hidden>
                <summary id="albAllDaysSummary">Show all days</summary>
                <div class="expandable-body">
                  <div id="albDayProgress" class="result-summary-body">
                    <div class="footer-note">No ALB plan has been created yet.</div>
                  </div>
                </div>
              </details>

              <details id="albSampleFilesSection" class="expandable-panel" hidden>
                <summary>Show sample files</summary>
                <div class="expandable-body">
                  <ul id="albSampleFilesList" class="list-clean"></ul>
                </div>
              </details>

              <details class="expandable-panel">
                <summary>Show live output</summary>
                <div class="expandable-body">
                  <div id="albJobOutput" class="terminal-panel">Waiting for a job to start...</div>
                </div>
              </details>
            </div>
          </section>
        </section>
      </section>
""";
    }

    private static string BuildTopIpsTopPathsContent()
    {
        return """
      <section class="stack" data-alb-option2-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>Top IPs + top full paths</h1>
              <p>Rank the top client IPs matching an endpoint fragment, then break each down by full URI path.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Scan inputs</h2>
            <div id="albOption2Error" class="inline-error" hidden></div>

            <div class="field-group">
              <div class="field">
                <label for="albOption2Endpoint">Endpoint/path fragment</label>
                <input id="albOption2Endpoint" placeholder="login or /login/">
              </div>
            </div>

            <div class="field-group source-group">
              <label class="field-label">Log source</label>
              <div class="button-row source-action-row">
                <button id="albOption2UseDefault" class="source-btn active" type="button">Default folder</button>
                <button id="albOption2SelectFolder" class="source-btn" type="button">Select folder</button>
                <button id="albOption2SelectFiles" class="source-btn" type="button">Select files</button>
                <button id="albOption2ClearSelection" class="source-btn source-btn--clear" type="button" hidden>Clear</button>
              </div>
              <input id="albOption2FolderInput" type="file" webkitdirectory directory multiple hidden>
              <input id="albOption2FilesInput" type="file" multiple accept=".log" hidden>
              <div id="albOption2SourceChip" class="source-chip">Loading...</div>
            </div>

            <div class="field-group">
              <label class="choice-pill choice-pill--flat"><input id="albOption2Export" type="checkbox" checked> Export to Excel</label>
            </div>

            <div class="button-row">
              <button id="albOption2Run" class="button-link primary button-like" type="button">Run scan</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Scan status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="albOption2State">idle</strong></div>
              <div class="status-pill"><span>Phase</span><strong id="albOption2Phase">idle</strong></div>
              <div class="status-pill"><span>Matches</span><strong id="albOption2Matches">0</strong></div>
            </div>
            <p id="albOption2Message" class="page-copy">Idle.</p>
            <div id="albOption2Meta" class="footer-note"></div>
            <div class="export-row">
              <div id="albOption2ExportPath" class="footer-note"></div>
              <button id="albOption2OpenExport" class="button-link primary button-like compact" type="button" hidden>Open Excel</button>
            </div>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label">Scan progress</div>
                <div id="albOption2StageBadge" class="kicker">idle</div>
              </div>
              <div id="albOption2Summary" class="info-value">Waiting for a scan to start.</div>
              <div class="progress-track"><div id="albOption2Bar" class="progress-fill" style="width:0%"></div></div>
              <div id="albOption2BarMeta" class="footer-note">No scan running.</div>
            </div>
          </section>
        </section>

        <section id="albOption2Results" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Results</div>
                <h2>Top matching IPs</h2>
              </div>
            </div>
            <div id="albOption2TopIps" class="result-summary-body"></div>
          </section>

          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Breakdown</div>
                <h2>Top full paths per IP</h2>
              </div>
            </div>
            <div id="albOption2TopUris" class="stack"></div>
          </section>
        </section>
      </section>
""";
    }

    private static string BuildIpSummaryContent()
    {
        return """
      <section class="stack" data-alb-ip-summary-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>IP Summary</h1>
              <p>Enter client IPs, scan ALB logs, and review per-minute charts with status breakdowns.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Scan inputs</h2>
            <div id="ipSummaryError" class="inline-error" hidden></div>

            <div class="field-group">
              <label class="field-label">IP input</label>
              <div class="button-row source-action-row">
                <button id="ipSummaryModeManual" class="source-btn active" type="button">Manual entry</button>
                <button id="ipSummaryModeFile" class="source-btn" type="button">From output file</button>
                <button id="ipSummaryModeBurst" class="source-btn" type="button" disabled title="IIS burst session (not yet available)">IIS burst</button>
                <button id="ipSummaryModePlatform" class="source-btn" type="button" disabled title="Platform suspicious cache (not yet available)">Platform cache</button>
              </div>
            </div>

            <div id="ipSummaryManualSection" class="field-group">
              <div class="field">
                <label for="ipSummaryIpText">Client IPs (one per line, max 10)</label>
                <textarea id="ipSummaryIpText" rows="5" placeholder="10.0.0.1&#10;192.168.1.100&#10;172.16.0.5"></textarea>
              </div>
            </div>

            <div id="ipSummaryFileSection" class="field-group" hidden>
              <div class="field">
                <label for="ipSummaryFileSelect">Output file (CSV/XLSX)</label>
                <select id="ipSummaryFileSelect">
                  <option value="">Loading files...</option>
                </select>
              </div>
              <button id="ipSummaryExtractBtn" class="button-link primary button-like compact" type="button">Extract IPs</button>
              <div id="ipSummaryExtractResult" hidden>
                <div id="ipSummaryExtractInfo" class="source-chip"></div>
                <div class="field">
                  <label>Extracted IPs (select up to 10)</label>
                  <div id="ipSummaryExtractedList" class="ip-extract-list"></div>
                </div>
              </div>
            </div>

            <div class="field-group source-group">
              <label class="field-label">Log source</label>
              <div class="button-row source-action-row">
                <button id="ipSummaryUseDefault" class="source-btn active" type="button">Default folder</button>
                <button id="ipSummarySelectFolder" class="source-btn" type="button">Select folder</button>
                <button id="ipSummarySelectFiles" class="source-btn" type="button">Select files</button>
                <button id="ipSummaryClearSelection" class="source-btn source-btn--clear" type="button" hidden>Clear</button>
              </div>
              <div id="ipSummarySourceChip" class="source-chip">Loading...</div>
            </div>

            <div class="field-group">
              <label class="choice-pill choice-pill--flat"><input id="ipSummaryExport" type="checkbox" checked> Export to Excel</label>
            </div>

            <div class="button-row">
              <button id="ipSummaryRun" class="button-link primary button-like" type="button">Run scan</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Scan status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="ipSummaryState">idle</strong></div>
              <div class="status-pill"><span>Phase</span><strong id="ipSummaryPhase">idle</strong></div>
              <div class="status-pill"><span>IPs</span><strong id="ipSummaryIpCount">0</strong></div>
            </div>
            <p id="ipSummaryMessage" class="page-copy">Idle.</p>
            <div id="ipSummaryMeta" class="footer-note"></div>
            <div class="export-row">
              <div id="ipSummaryExportInfo" class="footer-note"></div>
              <button id="ipSummaryOpenReport" class="button-link primary button-like compact" type="button" hidden>Open report</button>
              <button id="ipSummaryOpenExport" class="button-link primary button-like compact" type="button" hidden>Open Excel</button>
            </div>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label">Scan progress</div>
                <div id="ipSummaryStageBadge" class="kicker">idle</div>
              </div>
              <div id="ipSummarySummary" class="info-value">Waiting for a scan to start.</div>
              <div class="progress-track"><div id="ipSummaryBar" class="progress-fill" style="width:0%"></div></div>
              <div id="ipSummaryBarMeta" class="footer-note">No scan running.</div>
            </div>

            <div id="ipSummaryIpProgress" class="expandable-stack" hidden>
              <details class="expandable-panel" open>
                <summary>Per-IP row counts</summary>
                <div class="expandable-body">
                  <div id="ipSummaryIpRows" class="result-summary-body"></div>
                </div>
              </details>
            </div>
          </section>
        </section>

        <section id="ipSummaryResults" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Results</div>
                <h2>Per-IP summary</h2>
              </div>
            </div>
            <div id="ipSummaryPerIp" class="stack"></div>
          </section>
        </section>
      </section>
""";
    }

    private static string BuildPlaceholderContent(AlbOptionDefinition option)
    {
        return $$"""
      <section class="stack">
        <section class="hero">
          <div class="page-header">
            <div class="eyebrow">Workflow</div>
            <h1>{{Html(option.Title)}}</h1>
            <p class="page-copy">{{Html(option.Description)}}</p>
            <div class="kicker-row">
              <div class="kicker">Web route ready</div>
              <div class="kicker">Console workflow available</div>
            </div>
          </div>
        </section>

        <section class="placeholder-grid">
          <div class="placeholder-card">
            <h3>Web page</h3>
            <p>This workflow route is in place so the ALB module can keep a stable structure as each workflow is wired into the browser UI.</p>
          </div>
          <div class="placeholder-card">
            <h3>Current path</h3>
            <p>The browser page is not wired yet, but the existing console implementation is still available for this workflow.</p>
          </div>
          <div class="placeholder-card">
            <h3>Next step</h3>
            <p>When this workflow is migrated, the route and layout are already in place for the actual inputs, progress, and results.</p>
          </div>
        </section>
      </section>
""";
    }

    private static string BuildOptionCard(AlbOptionDefinition option)
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

    private static string BuildHourOptions(int selectedHour)
        => string.Join(Environment.NewLine, Enumerable.Range(0, 24).Select(hour =>
            $"""                      <option value="{hour:00}"{(hour == selectedHour ? " selected" : string.Empty)}>{hour:00}</option>"""));

    private static string BuildMinuteOptions(int selectedMinute)
        => string.Join(Environment.NewLine, Enumerable.Range(0, 12).Select(index =>
        {
            var minute = index * 5;
            var selected = minute == selectedMinute ? " selected" : string.Empty;
            return $"""                      <option value="{minute:00}"{selected}>{minute:00}</option>""";
        }));

    private static string FormatUtcDateForInput(DateTime valueUtc)
        => valueUtc.ToString("yyyy-MM-dd");

    private sealed record AlbOptionDefinition(int Number, string Path, string Title, string Description, bool Implemented);
}
