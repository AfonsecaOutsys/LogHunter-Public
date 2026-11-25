namespace LogHunter.Web.Pages;

/// <summary>
/// IP sweep page, reachable from both the ALB and the IIS module (one job, files auto-detected).
/// </summary>
internal static class IpSweepPageBuilder
{
    public const string Title = "IP sweep: IPs and ranges";
    public const string Description = "Check any number of IPs, CIDR blocks or IP ranges against ALB and IIS logs. Hit or no hit per target, with a shareable report.";

    public static WebPageDefinition BuildPage(string path, string module, string moduleLabel)
        => new(path, module, moduleLabel, $"{moduleLabel} / IP sweep", "Workflow", Description);

    public static string BuildContent() => """
      <section class="stack" data-ip-sweep-page="true">
        <section class="module-two-column">
          <section class="panel form-panel">
            <h2>Sweep inputs</h2>
            <p class="footer-note">Add one folder per environment. ALB and IIS files are detected automatically.</p>
            <div id="ipSweepError" class="inline-error" hidden></div>

            <div class="field-group">
              <div class="field">
                <label for="ipSweepTargets">Targets (one per line; # starts a comment)</label>
                <textarea id="ipSweepTargets" rows="8" placeholder="203.0.113.7&#10;198.51.100.0/24&#10;192.0.2.10-192.0.2.40&#10;2001:db8::/32"></textarea>
              </div>
              <div id="ipSweepTargetInfo" class="footer-note">0 targets</div>
            </div>

            <div class="field-group source-group">
              <label class="field-label">Log folders</label>
              <div id="ipSweepSources" class="stack"></div>
              <div class="button-row source-action-row">
                <button id="ipSweepAddFolder" class="source-btn" type="button">Add folder</button>
              </div>
            </div>

            <div class="button-row">
              <button id="ipSweepRun" class="button-link primary button-like" type="button">Run sweep</button>
            </div>
          </section>

          <section class="panel panel-tight">
            <h2>Sweep status</h2>
            <div class="status-block">
              <div class="status-pill"><span>Status</span><strong id="ipSweepState">idle</strong></div>
              <div class="status-pill"><span>Targets</span><strong id="ipSweepTargetCount">0</strong></div>
              <div class="status-pill"><span>Lines</span><strong id="ipSweepLines">0</strong></div>
            </div>
            <p id="ipSweepMessage" class="page-copy">Idle.</p>
            <div class="result-card progress-card-compact">
              <div class="progress-card-head">
                <div class="info-label">Progress</div>
                <div id="ipSweepFiles" class="kicker">0 / 0 files</div>
              </div>
              <div class="progress-track"><div id="ipSweepBar" class="progress-fill" style="width:0%"></div></div>
            </div>
            <div class="export-row">
              <button id="ipSweepOpenReport" class="button-link button-like compact" type="button" disabled>Open report</button>
              <button id="ipSweepOpenExport" class="button-link button-like compact" type="button" disabled>Open Excel</button>
            </div>
          </section>
        </section>

        <section id="ipSweepResults" class="stack" hidden>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Results</div>
                <h2 id="ipSweepResultsTitle">Targets</h2>
              </div>
              <div class="export-row">
                <button id="ipSweepToIpSummary" class="button-link button-like compact" type="button" disabled>IP summary for top hits</button>
                <button id="ipSweepToAbuseIp" class="button-link button-like compact" type="button" disabled>Check reputation</button>
                <button id="ipSweepCopyHits" class="button-link button-like compact" type="button" disabled>Copy hit IPs</button>
              </div>
            </div>
            <div id="ipSweepTable" class="result-summary-body"></div>
          </section>
          <section class="panel">
            <div class="section-heading">
              <div>
                <div class="eyebrow">Scope</div>
                <h2>What was searched</h2>
              </div>
            </div>
            <div id="ipSweepScope" class="result-summary-body"></div>
          </section>
        </section>
      </section>
""";
}
