using System;
using System.Net;
using LogHunter.Web.Hosting;

namespace LogHunter.Web.Pages;

internal static class AbuseIpPageBuilder
{
    public static bool TryBuild(WebAppContext context, string path, out WebPageDefinition page, out string mainContent, out string? extraScriptPath)
    {
        if (string.Equals(path, "/abuseipdb", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/abuseipdb", "/abuseipdb", "AbuseIPDB", "AbuseIPDB", "Module Landing", "IP reputation checks, enrichment workflows, and export-driven review.");
            mainContent = BuildLandingContent();
            extraScriptPath = null;
            return true;
        }

        if (string.Equals(path, "/abuseipdb/check-ips", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/abuseipdb/check-ips", "/abuseipdb", "AbuseIPDB", "AbuseIPDB / Check IPs", "Workflow", "Enter IP addresses and check their reputation against the AbuseIPDB database.");
            mainContent = BuildCheckIpsContent();
            extraScriptPath = "/assets/abuseip.js";
            return true;
        }

        if (string.Equals(path, "/abuseipdb/settings", StringComparison.OrdinalIgnoreCase))
        {
            page = new WebPageDefinition("/abuseipdb/settings", "/abuseipdb", "AbuseIPDB", "AbuseIPDB / Settings", "Configuration", "View and update AbuseIPDB API key and query settings.");
            mainContent = BuildSettingsContent();
            extraScriptPath = "/assets/abuseip.js";
            return true;
        }

        page = default!;
        mainContent = string.Empty;
        extraScriptPath = null;
        return false;
    }

    private static string BuildLandingContent()
    {
        return """
      <section class="stack">
        <section class="panel">
          <div class="section-heading">
            <div>
              <div class="eyebrow">AbuseIPDB Workflows</div>
              <h2>Pick a workflow</h2>
            </div>
            <p class="page-copy compact-copy">Check IP reputation and review findings.</p>
          </div>
          <div class="option-grid option-grid--dense">
            <a class="option-card option-card--action" href="/abuseipdb/check-ips">
              <div class="option-card-head">
                <span class="option-number">Workflow</span>
              </div>
              <h3>Check IPs</h3>
              <p>Enter IPs manually or paste a list, then check their reputation against AbuseIPDB.</p>
            </a>
            <a class="option-card option-card--action" href="/abuseipdb/settings">
              <div class="option-card-head">
                <span class="option-number">Configuration</span>
              </div>
              <h3>Settings</h3>
              <p>View or update API key, max age, and verbose options for AbuseIPDB queries.</p>
            </a>
          </div>
        </section>
      </section>
""";
    }

    private static string BuildCheckIpsContent()
    {
        return """
      <section class="stack" data-abuseip-check-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>Check IPs</h1>
              <p>Enter one or more IP addresses to check their reputation via AbuseIPDB.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Check inputs</h2>
            <div id="abuseipError" class="inline-error" hidden></div>

            <div class="field-group">
              <div class="field">
                <label for="abuseipIpText">IP addresses (one per line)</label>
                <textarea id="abuseipIpText" rows="6" placeholder="10.0.0.1&#10;192.168.1.100&#10;203.0.113.50"></textarea>
              </div>
              <p class="footer-note">Enter up to 100 IPs. Each will be checked individually against the AbuseIPDB API.</p>
            </div>

            <div class="field-group">
              <div class="form-grid">
                <div class="field">
                  <label for="abuseipMaxAge">Max age (days)</label>
                  <input id="abuseipMaxAge" type="number" min="1" max="365" value="30" placeholder="30">
                </div>
              </div>
            </div>

            <div class="field-group">
              <label class="field-label">API key</label>
              <div class="button-row source-action-row">
                <button id="abuseipKeyDefault" class="source-btn active" type="button">Use saved key</button>
                <button id="abuseipKeyOverride" class="source-btn" type="button">Override for this run</button>
              </div>
              <div id="abuseipKeyInfo" class="source-chip">Loading...</div>
            </div>

            <div id="abuseipKeyOverrideSection" class="field-group" hidden>
              <div class="field">
                <label for="abuseipApiKey">API key (this run only)</label>
                <input id="abuseipApiKey" type="password" placeholder="Paste AbuseIPDB API key">
              </div>
            </div>

            <div class="button-row">
              <button id="abuseipRun" class="button-link primary button-like" type="button">Run check</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Check status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="abuseipState">idle</strong></div>
              <div class="status-pill"><span>Phase</span><strong id="abuseipPhase">idle</strong></div>
              <div class="status-pill"><span>IPs</span><strong id="abuseipIpCount">0</strong></div>
            </div>
            <p id="abuseipMessage" class="page-copy">Idle.</p>
            <div id="abuseipMeta" class="footer-note"></div>
            <div class="export-row">
              <div id="abuseipExportInfo" class="footer-note"></div>
              <button id="abuseipOpenExport" class="button-link button-like compact" type="button" disabled>Open CSV</button>
            </div>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label">Check progress</div>
                <div id="abuseipStageBadge" class="kicker">idle</div>
              </div>
              <div id="abuseipSummary" class="info-value">Waiting for a check to start.</div>
              <div class="progress-track"><div id="abuseipBar" class="progress-fill" style="width:0%"></div></div>
              <div id="abuseipBarMeta" class="footer-note">No check running.</div>
            </div>
          </section>
        </section>

        <section id="abuseipResults" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Results</div>
                <h2>IP reputation summary</h2>
              </div>
            </div>
            <div id="abuseipSummaryCards" class="status-block"></div>
            <div id="abuseipResultTable"></div>
          </section>

          <section id="abuseipFailuresSection" class="panel" hidden>
            <div class="section-heading">
              <div>
                <div class="eyebrow">Issues</div>
                <h2>Check failures</h2>
              </div>
            </div>
            <div id="abuseipFailuresList"></div>
          </section>
        </section>
      </section>
""";
    }

    private static string BuildSettingsContent()
    {
        return """
      <section class="stack" data-abuseip-settings-page="true">
        <section class="hero">
          <div class="hero-grid">
            <div>
              <h1>AbuseIPDB Settings</h1>
              <p>View and update your AbuseIPDB configuration.</p>
            </div>
          </div>
        </section>

        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Configuration</h2>
            <div id="abuseipSettingsError" class="inline-error" hidden></div>
            <div id="abuseipSettingsSuccess" class="inline-success" hidden></div>

            <div class="field-group">
              <div class="field">
                <label for="abuseipSettingsApiKey">API key (leave blank to keep current)</label>
                <input id="abuseipSettingsApiKey" type="password" placeholder="Paste new API key or leave blank">
              </div>
              <div class="field-row">
                <label class="choice-pill choice-pill--flat"><input id="abuseipSettingsClearKey" type="checkbox"> Clear custom key (revert to built-in default)</label>
              </div>
            </div>

            <div class="field-group">
              <div class="form-grid">
                <div class="field">
                  <label for="abuseipSettingsMaxAge">Max age in days (1-365)</label>
                  <input id="abuseipSettingsMaxAge" type="number" min="1" max="365" value="30">
                </div>
              </div>
            </div>

            <div class="field-group">
              <div class="field-row">
                <label class="choice-pill choice-pill--flat"><input id="abuseipSettingsVerbose" type="checkbox"> Verbose responses (heavier API payload)</label>
              </div>
            </div>

            <div class="button-row">
              <button id="abuseipSettingsSave" class="button-link primary button-like" type="button">Save settings</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Current config</h2>
            <div class="status-block">
              <div class="status-pill"><span>Key source</span><strong id="abuseipSettingsKeySource">loading</strong></div>
              <div class="status-pill"><span>Max age</span><strong id="abuseipSettingsCurrentMaxAge">-</strong></div>
              <div class="status-pill"><span>Verbose</span><strong id="abuseipSettingsCurrentVerbose">-</strong></div>
            </div>
            <div id="abuseipSettingsConfigPath" class="footer-note"></div>
          </section>
        </section>

        <section id="abuseipExportHistory" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">History</div>
                <h2>Recent exports</h2>
              </div>
            </div>
            <div id="abuseipExportList"></div>
          </section>
        </section>
      </section>
""";
    }

    private static string Html(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
