using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Menus;

public sealed class AlbMenu : IMenu
{
    private readonly SessionState _session;

    public AlbMenu(SessionState session) => _session = session;

    public async Task<IMenu?> ShowAsync(CancellationToken ct = default)
    {
        ConsoleEx.Header("ALB", $"Workspace: {_session.Root}");

        var items = new[]
        {
            new ConsoleEx.MenuItem(
                "Download logs from S3",
                "Download ALB logs into the workspace (ALB folder).\nUses AWS CLI and your current credentials/session."),

            new ConsoleEx.MenuItem(
                "Top IPs + top full paths for endpoint/path fragment",
                "Match a fragment, rank top IPs, then show top full URI paths (query removed) per IP.\nUseful for quick attacker/source-first triage."),

            new ConsoleEx.MenuItem(
                "IP Summary",
                "Enter one client IP, chart per-minute ALB status activity, and review matching requests in a detailed HTML report."),

            new ConsoleEx.MenuItem(
                "Top 50 IPs overall",
                "Scan logs and show the top 50 client IPs across the selected time range."),

            new ConsoleEx.MenuItem(
                "Top 50 IPs by URI (no query)",
                "Show top IPs per URI with query strings removed.\nHelps group requests by route instead of parameters."),

            new ConsoleEx.MenuItem(
                "Top 50 requests by AVG duration",
                "Find the slowest request paths (query removed), ordered by average duration."),

            new ConsoleEx.MenuItem(
                "ALB requests over time per selected IP (5-minute buckets)",
                "ALB-native timeline analysis: choose IPs from ALB exports (or manual fallback), then scan ALB logs and build chart/CSV."),

            new ConsoleEx.MenuItem(
                "WAF blocked summary + top blocked requests",
                "Summarize WAF-blocked traffic and show the top blocked request patterns."),

            new ConsoleEx.MenuItem(
                "WAF blocks over time (per minute) (chart)",
                "Chart WAF blocks per minute using the same definition as the summary view."),

            new ConsoleEx.MenuItem(
                "Back",
                "Return to the main menu.")
        };

        var selected = ConsoleEx.Menu("ALB menu", items, pageSize: 12);

        // Esc = back
        if (selected is null)
            return new MainMenu(_session);

        switch (selected.Value)
        {
            case 0:
                await AlbDownload.RunAsync().ConfigureAwait(false);
                return this;

            case 1:
                await AlbOptions.TopIpsForEndpointAsync(_session.Root, _session.SavedSelections).ConfigureAwait(false);
                return this;

            case 2:
                await AlbOptions.IpSummaryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 3:
                await AlbOptions.Top50IpsOverallAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 4:
                await AlbOptions.Top50IpUriNoQueryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 5:
                await AlbOptions.Top50RequestsByAvgDurationNoQueryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 6:
                await AlbOptions.TrackRequestsPerIpPer5MinAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 7:
                await AlbOptions.WafBlockedSummaryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 8:
                await AlbOptions.WafBlockedPerMinuteChartAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 9:
                return new MainMenu(_session);

            default:
                return this;
        }
    }
}
