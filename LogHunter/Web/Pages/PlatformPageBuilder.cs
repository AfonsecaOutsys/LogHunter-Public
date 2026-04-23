using System;
using System.Linq;
using System.Net;
using LogHunter.Web.Hosting;

namespace LogHunter.Web.Pages;

internal static class PlatformPageBuilder
{
    private static readonly PlatformOptionDefinition[] Options =
    [
        new(1, "/platform-logs/suspicious-extract-ips", "Suspicious requests: extract IPs",
            "Scan Platform log exports (CSV/XLSX) for common suspicious patterns and extract effective IPs.", true),
        new(2, "/platform-logs/authenticated-activity", "Suspicious IPs: authenticated activity check",
            "Use the suspicious-IP cache to scan other Platform log exports and count rows where UserId != 0.", true),
        new(3, "/platform-logs/authenticated-cache", "Authenticated IP cache",
            "View the authenticated IP cache populated by the authenticated activity check.", true)
    ];

    public static bool TryBuild(WebAppContext context, string path, out WebPageDefinition page, out string mainContent, out string? extraScriptPath)
    {
        if (string.Equals(path, "/platform-logs", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/platform-logs", "/platform-logs", "Platform Logs", "Platform Logs", "Module Landing",
                "Suspicious activity review and authenticated behavior checks from platform logs.");
            mainContent = BuildLandingContent();
            extraScriptPath = null;
            return true;
        }

        if (string.Equals(path, "/platform-logs/suspicious-extract-ips", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/platform-logs/suspicious-extract-ips", "/platform-logs", "Platform Logs",
                "Platform / Suspicious requests: extract IPs", "Workflow",
                "Scan Platform log exports for suspicious patterns, extract X-Forwarded-For (preferred) or ClientIp addresses.");
            mainContent = BuildSuspiciousExtractContent();
            extraScriptPath = "/assets/platform.js";
            return true;
        }

        if (string.Equals(path, "/platform-logs/authenticated-activity", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/platform-logs/authenticated-activity", "/platform-logs", "Platform Logs",
                "Platform / Authenticated activity check", "Workflow",
                "Scan Platform log exports for authenticated rows (UserId != 0) matching suspicious IPs from the cache.");
            mainContent = BuildAuthenticatedActivityContent();
            extraScriptPath = "/assets/platform.js";
            return true;
        }

        if (string.Equals(path, "/platform-logs/authenticated-cache", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/platform-logs/authenticated-cache", "/platform-logs", "Platform Logs",
                "Platform / Authenticated IP cache", "Info",
                "View the current authenticated IP cache. Run the authenticated activity check to populate or update it.");
            mainContent = BuildAuthenticatedCacheContent(context);
            extraScriptPath = "/assets/platform.js";
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
              <div class="eyebrow">Platform Workflows</div>
              <h2>Pick a workflow</h2>
            </div>
            <p class="page-copy compact-copy">Choose a Platform action and continue directly into that flow.</p>
          </div>
          <div class="option-grid option-grid--dense">
{{cards}}
          </div>
        </section>
      </section>
""";
    }

    private static string BuildOptionCard(PlatformOptionDefinition option)
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

    private static string BuildSuspiciousExtractContent()
    {
        return """
      <section class="stack" data-platform-suspicious-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>Suspicious requests: extract IPs</h1>
              <p>Scan Platform log exports (CSV/XLSX) for suspicious patterns and extract effective IP addresses.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Scan configuration</h2>
            <div id="platformSuspiciousError" class="inline-error" hidden></div>

            <div class="field-group">
              <p class="page-copy">Scans all CSV/XLSX files in the PlatformLogs folder for known suspicious error patterns. Extracts X-Forwarded-For (preferred) or ClientIp from matched rows.</p>
              <p class="footer-note">Results are saved to session selections and update the suspicious-IP cache for downstream use.</p>
            </div>

            <div class="button-row">
              <button id="platformSuspiciousRun" class="button-link primary button-like" type="button">Run scan</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Scan status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="platformSuspiciousState">idle</strong></div>
              <div class="status-pill"><span>Phase</span><strong id="platformSuspiciousPhase">idle</strong></div>
              <div class="status-pill"><span>Matched rows</span><strong id="platformSuspiciousMatchedRows">0</strong></div>
              <div class="status-pill"><span>Distinct IPs</span><strong id="platformSuspiciousDistinctIps">0</strong></div>
            </div>
            <p id="platformSuspiciousMessage" class="page-copy">Idle.</p>
            <div id="platformSuspiciousMeta" class="footer-note"></div>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label">Scan progress</div>
                <div id="platformSuspiciousStageBadge" class="kicker">idle</div>
              </div>
              <div id="platformSuspiciousSummary" class="info-value">Waiting for a scan to start.</div>
              <div class="progress-track"><div id="platformSuspiciousBar" class="progress-fill" style="width:0%"></div></div>
              <div id="platformSuspiciousBarMeta" class="footer-note">No scan running.</div>
            </div>
          </section>
        </section>

        <section id="platformSuspiciousResults" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Summary</div>
                <h2>Scan overview</h2>
              </div>
            </div>
            <div id="platformSuspiciousOverview" class="status-block"></div>
            <div id="platformSuspiciousCacheMeta" class="footer-note"></div>
          </section>

          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Breakdown</div>
                <h2>By error type</h2>
              </div>
            </div>
            <div id="platformSuspiciousErrorTypes" class="result-summary-body"></div>
          </section>

          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Results</div>
                <h2>Top IPs (overall)</h2>
              </div>
            </div>
            <div id="platformSuspiciousTopIps" class="result-summary-body"></div>
          </section>

          <section id="platformSuspiciousPerTypeSection" class="stack" hidden>
          </section>
        </section>
      </section>
""";
    }

    private static string BuildAuthenticatedActivityContent()
    {
        return """
      <section class="stack" data-platform-auth-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>Suspicious IPs: authenticated activity check</h1>
              <p>Scan Platform log exports and count rows where UserId != 0 for IPs from the suspicious cache.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Check configuration</h2>
            <div id="platformAuthError" class="inline-error" hidden></div>

            <div class="field-group">
              <p class="page-copy">Scans all CSV/XLSX files in PlatformLogs and counts authenticated rows (UserId != 0) per IP, broken down by log type.</p>
            </div>

            <div class="field-group">
              <div class="field-label">IP source</div>
              <div class="button-row source-action-row">
                <button id="platformAuthSourceCache" class="source-btn active" type="button">Suspicious cache</button>
                <button id="platformAuthSourceManual" class="source-btn" type="button">Manual input</button>
              </div>
            </div>

            <div id="platformAuthCacheInfo" class="field-group">
              <div class="status-block">
                <div class="status-pill"><span>Suspicious IPs cached</span><strong id="platformAuthSuspiciousCount">0</strong></div>
                <div class="status-pill"><span>Authed IPs cached</span><strong id="platformAuthAuthedCount">0</strong></div>
              </div>
              <p class="footer-note">Populated by the suspicious requests extract step.</p>
            </div>

            <div id="platformAuthManualInput" class="field-group" hidden>
              <div class="field">
                <label for="platformAuthManualIps">IPs to check (one per line)</label>
                <textarea id="platformAuthManualIps" rows="6" placeholder="10.0.0.1&#10;192.168.1.100&#10;203.0.113.55" style="resize:vertical"></textarea>
              </div>
            </div>

            <div class="button-row">
              <button id="platformAuthRun" class="button-link primary button-like" type="button">Run check</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Check status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="platformAuthState">idle</strong></div>
              <div class="status-pill"><span>Phase</span><strong id="platformAuthPhase">idle</strong></div>
              <div class="status-pill"><span>Auth hits</span><strong id="platformAuthTotalHits">0</strong></div>
              <div class="status-pill"><span>Matched IPs</span><strong id="platformAuthMatchedIps">0</strong></div>
            </div>
            <p id="platformAuthMessage" class="page-copy">Idle.</p>
            <div id="platformAuthMeta" class="footer-note"></div>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label">Check progress</div>
                <div id="platformAuthStageBadge" class="kicker">idle</div>
              </div>
              <div id="platformAuthSummary" class="info-value">Waiting for a check to start.</div>
              <div class="progress-track"><div id="platformAuthBar" class="progress-fill" style="width:0%"></div></div>
              <div id="platformAuthBarMeta" class="footer-note">No check running.</div>
            </div>
          </section>
        </section>

        <section id="platformAuthResults" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Summary</div>
                <h2>Authenticated activity overview</h2>
              </div>
              <div class="export-row">
                <button id="platformAuthOpenExport" class="button-link primary button-like compact" type="button" hidden>Open Excel</button>
              </div>
            </div>
            <div id="platformAuthOverview" class="status-block"></div>
            <div id="platformAuthCacheMeta" class="footer-note"></div>
          </section>

          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Breakdown</div>
                <h2>Hits by log type</h2>
              </div>
            </div>
            <div id="platformAuthByKind" class="result-summary-body"></div>
          </section>

          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Results</div>
                <h2>Authenticated IPs</h2>
              </div>
            </div>
            <div id="platformAuthTopIps" class="result-summary-body"></div>
          </section>
        </section>
      </section>
""";
    }

    private static string BuildAuthenticatedCacheContent(WebAppContext context)
    {
        var authedCount = context.Session.PlatformAuthedIpHits?.Count ?? 0;
        var suspiciousCount = context.Session.PlatformSuspiciousIpHits?.Count ?? 0;

        return $$"""
      <section class="stack" data-platform-cache-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>Authenticated IP cache</h1>
              <p>View the current authenticated IP cache. Run the authenticated activity check to populate or update it.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Cache status</h2>

            <div class="status-block">
              <div class="status-pill"><span>Suspicious IPs</span><strong id="cacheSuspiciousCount">{{suspiciousCount}}</strong></div>
              <div class="status-pill"><span>Authenticated IPs</span><strong id="cacheAuthedCount">{{authedCount}}</strong></div>
            </div>

            <div class="field-group">
              <p class="footer-note">Run the authenticated activity check to populate or update this cache.</p>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Cache details</h2>
            <div id="cacheDetails" class="result-summary-body">
              <div class="footer-note">Loading...</div>
            </div>
          </section>
        </section>
      </section>
""";
    }

    private static string Html(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private sealed record PlatformOptionDefinition(int Number, string Path, string Title, string Description, bool Implemented);
}
