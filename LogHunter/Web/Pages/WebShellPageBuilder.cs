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
        new("/", "Home", "LogHunter 2.0", "Local Web UI", "Start here to navigate the new browser-based shell for LogHunter."),
        new("/alb", "ALB", "ALB", "Section Placeholder", "Future home for ALB downloads, scans, summaries, and drill-down flows."),
        new("/iis", "IIS", "IIS", "Section Placeholder", "Future home for IIS burst analysis, pivots, exports, and request investigation."),
        new("/platform-logs", "Platform Logs", "Platform Logs", "Section Placeholder", "Future home for platform log review, suspicious patterns, and authenticated activity checks."),
        new("/abuseipdb", "AbuseIPDB", "AbuseIPDB", "Section Placeholder", "Future home for IP reputation lookups and export workflows.")
    ];

    public static bool TryBuildPage(WebAppContext context, string path, out string html)
    {
        var page = Pages.FirstOrDefault(static x => string.Equals(x.Path, "/", StringComparison.Ordinal));
        if (!string.IsNullOrWhiteSpace(path))
        {
            page = Pages.FirstOrDefault(x => string.Equals(x.Path, path, StringComparison.OrdinalIgnoreCase));
        }

        if (page is null)
        {
            html = string.Empty;
            return false;
        }

        html = BuildLayout(context, page, string.Equals(page.Path, "/", StringComparison.Ordinal)
            ? BuildHomeContent(context)
            : BuildPlaceholderContent(page));

        return true;
    }

    private static string BuildLayout(WebAppContext context, WebPageDefinition page, string mainContent)
    {
        var nav = string.Join(Environment.NewLine, Pages.Select(x => BuildNavLink(x, page.Path)));
        var pills = string.Join(Environment.NewLine, Pages.Select(x => BuildTopbarLink(x, page.Path)));
        var title = Html(page.Path == "/" ? page.Title : $"{page.Title} | {context.AppName}");

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
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-kicker">Log Analysis Workbench</div>
        <div class="brand-name">{{Html(context.AppName)}} 2.0</div>
        <div class="brand-copy">Local-first web shell hosted by the executable on 127.0.0.1. This keeps the single-app model while moving the interface into the browser.</div>
      </div>

      <section class="nav-section">
        <div class="nav-copy">Primary sections</div>
        <nav class="nav-links">
{{nav}}
        </nav>
      </section>

      <section class="nav-section panel">
        <h2>Runtime</h2>
        <div class="status-badge"><span class="status-dot"></span><span data-app-info="status">Ready</span></div>
        <p class="footer-note">Mode: <strong data-app-info="mode">web</strong></p>
        <p class="footer-note">Started: <strong data-app-info="startedUtc">{{Html(context.StartedUtc.ToString("u"))}}</strong></p>
      </section>
    </aside>

    <main class="content">
      <div class="topbar">
        <div>
          <div class="eyebrow">{{Html(page.Eyebrow)}}</div>
          <h1>{{Html(page.Title)}}</h1>
          <div class="page-copy">{{Html(page.Description)}}</div>
        </div>
        <div class="topbar-actions">
          <button id="themeToggle" class="theme-toggle" type="button" aria-label="Switch to light theme">Switch to light</button>
          <div class="topbar-links">
{{pills}}
          </div>
        </div>
      </div>

{{mainContent}}

      <p class="footer-note">{{Html(context.AppName)}} {{Html(context.Version)}}. Current console workflows remain available during the migration.</p>
    </main>
  </div>
  <script src="/assets/site.js"></script>
</body>
</html>
""";
    }

    private static string BuildHomeContent(WebAppContext context)
    {
        return $$"""
      <section class="hero">
        <div class="hero-grid">
          <div>
            <div class="eyebrow">Foundation Step</div>
            <h1>Browser shell for the next LogHunter phase.</h1>
            <p>This first cut establishes local hosting, navigation, shared assets, and app status wiring without disturbing the current console-first implementation.</p>
            <div class="hero-actions">
              <a class="button-link primary" href="/alb">Open ALB section</a>
              <a class="button-link" href="/api/app/info">View app info API</a>
            </div>
          </div>

          <div class="panel">
            <h2>App status</h2>
            <div class="card-grid">
              <div class="info-card">
                <div class="info-label">App</div>
                <div class="info-value" data-app-info="appName">{{Html(context.AppName)}}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Version</div>
                <div class="info-value" data-app-info="version">{{Html(context.Version)}}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Workspace</div>
                <div class="info-value" data-app-info="rootPath">{{Html(context.RootPath)}}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Saved selections</div>
                <div class="info-value" data-app-info="savedSelectionsCount">{{context.Session.SavedSelections.Count}}</div>
              </div>
            </div>
            <p class="footer-note">The info cards are hydrated from <code>/api/app/info</code>, which will also support future UI workflows.</p>
          </div>
        </div>
      </section>

      <section class="stack">
        <div class="panel">
          <h2>Main sections</h2>
          <div class="section-grid">
            <a class="section-card" href="/alb">
              <h3>ALB</h3>
              <p>AWS Application Load Balancer investigations, downloads, summaries, and future deep-link workflows.</p>
            </a>
            <a class="section-card" href="/iis">
              <h3>IIS</h3>
              <p>W3C log analysis, bursts, pivots, bandwidth views, and request-path inspection.</p>
            </a>
            <a class="section-card" href="/platform-logs">
              <h3>Platform Logs</h3>
              <p>Suspicious activity review and authenticated behavior checks from platform log sources.</p>
            </a>
            <a class="section-card" href="/abuseipdb">
              <h3>AbuseIPDB</h3>
              <p>IP reputation checks and future report/export workflows built on the existing C# services.</p>
            </a>
          </div>
        </div>

        <div class="card-grid">
          <div class="card">
            <div class="card-title">Hosting</div>
            <div class="card-value">127.0.0.1 only</div>
            <div class="card-copy">The shell binds to a local loopback address and auto-opens the browser only in explicit web mode.</div>
          </div>
          <div class="card">
            <div class="card-title">Architecture</div>
            <div class="card-value">Embedded assets</div>
            <div class="card-copy">Shared CSS and JavaScript are organized under the new web layer and embedded into the executable to preserve the local-app model.</div>
          </div>
          <div class="card">
            <div class="card-title">Theme</div>
            <div class="card-value">Dark by default</div>
            <div class="card-copy">Use the header toggle to switch between dark and light. The selected theme is saved locally in the browser.</div>
          </div>
        </div>
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

    private static string BuildNavLink(WebPageDefinition page, string currentPath)
    {
        var active = string.Equals(page.Path, currentPath, StringComparison.OrdinalIgnoreCase) ? " active" : string.Empty;
        return $$"""
          <a class="nav-link{{active}}" href="{{Html(page.Path)}}">
            <div class="nav-label">{{Html(page.NavigationLabel)}}</div>
            <div class="nav-description">{{Html(page.Description)}}</div>
          </a>
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
