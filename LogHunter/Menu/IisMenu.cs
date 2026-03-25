// Menus/IisMenu.cs
using LogHunter.Services;
using LogHunter.Utils;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Menus;

public sealed class IisMenu : IMenu
{
    private readonly SessionState _session;

    public IisMenu(SessionState session) => _session = session;

    public async Task<IMenu?> ShowAsync(CancellationToken ct = default)
    {
        ConsoleEx.Header("IIS", $"Workspace: {_session.Root}");

        var savedBurstIps = _session.IisBurstIps.Count;

        var items = new[]
        {
            new ConsoleEx.MenuItem(
                "IP Summary",
                "Enter one client IP, chart per-minute IIS response activity, and review matching requests in a detailed HTML report."),

            new ConsoleEx.MenuItem(
                "4xx -> pick suspicious IPs -> pivot to 2xx/3xx",
                "Scan 4xx responses, show top IPs, select suspicious entries,\nthen export and summarize their 2xx/3xx traffic."),

            new ConsoleEx.MenuItem(
                $"Burst patterns (saved IPs: {savedBurstIps})",
                "Detect bursty request patterns per IP using time buckets.\nOptionally save burst IPs to the session for reuse."),

            new ConsoleEx.MenuItem(
                "Top bandwidth IPs and URIs (sc-bytes)",
                "Rank client IPs by total response bytes and list their top URIs by bytes."),

            new ConsoleEx.MenuItem(
                "Uploads and payload attempts (cs-bytes)",
                "Find IPs/endpoints sending large request bodies (POST/PUT) and show max/total request bytes."),

            new ConsoleEx.MenuItem(
                "Back",
                "Return to the main menu.")
        };

        var selected = ConsoleEx.Menu("IIS menu", items, pageSize: 10);

        // Esc = back
        if (selected is null)
            return new MainMenu(_session);

        switch (selected.Value)
        {
            case 0:
                await IisOption_IpSummary.RunAsync(_session.Root, ct).ConfigureAwait(false);
                return this;

            case 1:
                await IisOption_4xxPivot2xx3xx.RunAsync(_session.Root, ct).ConfigureAwait(false);
                return this;

            case 2:
                await IisOption_FindBurstPatterns.RunAsync(_session, ct).ConfigureAwait(false);
                return this;

            case 3:
                await IisOption_BytesIntel.RunTopBandwidthAsync(_session.Root, ct).ConfigureAwait(false);
                return this;

            case 4:
                await IisOption_BytesIntel.RunUploadsPayloadsAsync(_session.Root, ct).ConfigureAwait(false);
                return this;

            case 5:
                return new MainMenu(_session);

            default:
                return this;
        }
    }
}
