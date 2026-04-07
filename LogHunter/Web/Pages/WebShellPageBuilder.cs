using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using LogHunter.Web.Hosting;

namespace LogHunter.Web.Pages;

internal static class WebShellPageBuilder
{
    private static readonly WebPageDefinition[] Pages =
    [
        new("/", "/", "Home", "LogHunter 2.0", "Local Web UI", "Start here to navigate the new browser-based shell for LogHunter."),
        new("/alb", "/alb", "ALB", "ALB", "Module Landing", "AWS Application Load Balancer workflows and future drill-down flows."),
        new("/iis", "/iis", "IIS", "IIS", "Module Landing", "W3C log analysis, IP summaries, status pivots, burst detection, bandwidth, and payload investigation."),
        new("/platform-logs", "/platform-logs", "Platform Logs", "Platform Logs", "Section Placeholder", "Future home for platform log review, suspicious patterns, and authenticated activity checks."),
        new("/abuseipdb", "/abuseipdb", "AbuseIPDB", "AbuseIPDB", "Section Placeholder", "Future home for IP reputation lookups and export workflows.")
    ];

    public static bool TryBuildPage(WebAppContext context, string path, out string html)
    {
        if (AlbPageBuilder.TryBuild(context, path, out var albPage, out var albContent, out var albScriptPath))
        {
            html = BuildLayout(context, albPage, albContent, albScriptPath);
            return true;
        }

        if (IisPageBuilder.TryBuild(context, path, out var iisPage, out var iisContent, out var iisScriptPath))
        {
            html = BuildLayout(context, iisPage, iisContent, iisScriptPath);
            return true;
        }

        var page = Pages.FirstOrDefault(static x => string.Equals(x.Path, "/", StringComparison.Ordinal));
        if (!string.IsNullOrWhiteSpace(path))
            page = Pages.FirstOrDefault(x => string.Equals(x.Path, path, StringComparison.OrdinalIgnoreCase));

        if (page is null)
        {
            html = string.Empty;
            return false;
        }

        html = BuildLayout(
            context,
            page,
            string.Equals(page.Path, "/", StringComparison.Ordinal)
                ? BuildHomeContent(context)
                : BuildPlaceholderContent(page),
            null);

        return true;
    }

    private static string BuildLayout(WebAppContext context, WebPageDefinition page, string mainContent, string? extraScriptPath)
    {
        var pills = string.Join(Environment.NewLine, Pages.Select(x => BuildTopbarLink(x, page.NavigationPath)));
        var title = Html(page.Path == "/" ? page.Title : $"{page.Title} | {context.AppName}");
        var extraScript = string.IsNullOrWhiteSpace(extraScriptPath)
            ? string.Empty
            : $"""  <script src="{Html(extraScriptPath)}"></script>""";

        return $$"""
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{title}}</title>
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <div class="shell">
    <main class="content">
      <div class="topbar">
        <div class="masthead">
          <div class="brand">
            <div class="brand-kicker">Log Analysis Workbench</div>
            <div class="brand-name">{{Html(context.AppName)}} 2.0</div>
            <div class="brand-copy">Local-first web shell hosted by the executable on 127.0.0.1.</div>
          </div>
          <div class="eyebrow">{{Html(page.Eyebrow)}}</div>
          <h1>{{Html(page.Title)}}</h1>
          <div class="page-copy">{{Html(page.Description)}}</div>
        </div>
        <div class="topbar-actions">
          <div class="topbar-links">
{{pills}}
          </div>
          <button id="runtimeButton" class="runtime-pill" type="button" title="Local web host status">
            <span class="status-dot" data-runtime-light="status"></span>
            <span>Runtime</span>
            <strong data-app-info="status">Ready</strong>
          </button>
          <button id="themeToggle" class="theme-toggle" type="button" aria-label="Switch to light theme">Switch to light</button>
        </div>
      </div>

{{mainContent}}

      <p class="footer-note">{{Html(context.AppName)}} {{Html(context.Version)}}. Current console workflows remain available during the migration.</p>
    </main>
  </div>
  <script src="/assets/site.js"></script>
{{extraScript}}
</body>
</html>
""";
    }

    private static string BuildHomeContent(WebAppContext context)
    {
        return $$"""
      <section class="stack">
        <section class="panel">
          <div class="section-heading">
            <div>
              <div class="eyebrow">Modules</div>
              <h2>Choose a module</h2>
            </div>
            <p class="page-copy compact-copy">Start with the area you want to investigate.</p>
          </div>
          <div class="section-grid section-grid--launchpad">
            <a class="section-card section-card--launch" href="/alb">
              <h3>ALB</h3>
              <p>AWS Application Load Balancer downloads, summaries, and traffic investigation.</p>
            </a>
            <a class="section-card section-card--launch" href="/iis">
              <h3>IIS</h3>
              <p>W3C log analysis, bursts, pivots, bandwidth views, and request inspection.</p>
            </a>
            <a class="section-card section-card--launch" href="/platform-logs">
              <h3>Platform Logs</h3>
              <p>Suspicious activity review and authenticated behavior checks from platform logs.</p>
            </a>
            <a class="section-card section-card--launch" href="/abuseipdb">
              <h3>AbuseIPDB</h3>
              <p>IP reputation checks and export-driven reputation review.</p>
            </a>
          </div>
        </section>

        <section class="subtle-status-row">
          <div class="subtle-status-pill">
            <span class="info-label">Workspace</span>
            <span class="subtle-status-value" data-app-info="rootPath">{{Html(context.RootPath)}}</span>
          </div>
          <div class="subtle-status-pill">
            <span class="info-label">Version</span>
            <span class="subtle-status-value" data-app-info="version">{{Html(context.Version)}}</span>
          </div>
        </section>
      </section>
""";
    }

    private static string BuildPlaceholderContent(WebPageDefinition page)
    {
        return $$"""
      <section class="stack">
        <section class="hero">
          <div class="page-header">
            <div class="eyebrow">{{Html(page.Eyebrow)}}</div>
            <h1>{{Html(page.Title)}}</h1>
            <p class="page-copy">{{Html(page.Description)}}</p>
            <div class="kicker-row">
              <div class="kicker">Scaffolded navigation</div>
              <div class="kicker">Ready for API wiring</div>
              <div class="kicker">Console workflows preserved</div>
            </div>
          </div>
        </section>

        <section class="placeholder-grid">
          <div class="placeholder-card">
            <h3>What belongs here</h3>
            <p>This section is the future web landing area for the existing {{Html(page.NavigationLabel)}} workflows and related drill-down pages.</p>
          </div>
          <div class="placeholder-card">
            <h3>Current state</h3>
            <p>No business logic has been migrated into this section yet. The page exists to lock in structure, routing, layout, and future composition points.</p>
          </div>
          <div class="placeholder-card">
            <h3>Migration target</h3>
            <p>Next steps can attach focused JSON endpoints, progress reporting, and form-driven actions without reworking the shell again.</p>
          </div>
        </section>

        <section class="panel">
          <h2>Suggested next move for this section</h2>
          <ul class="list-clean">
            <li>Create a minimal section-specific API controller.</li>
            <li>Expose one read-only summary or status call.</li>
            <li>Port one vertical slice end-to-end before adding more pages.</li>
          </ul>
        </section>
      </section>
""";
    }

    private static string BuildTopbarLink(WebPageDefinition page, string currentPath)
    {
        var active = string.Equals(page.Path, currentPath, StringComparison.OrdinalIgnoreCase) ? " active" : string.Empty;
        return $$"""
          <a class="topbar-link{{active}}" href="{{Html(page.Path)}}">{{Html(page.NavigationLabel)}}</a>
""";
    }

    private static string Html(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
