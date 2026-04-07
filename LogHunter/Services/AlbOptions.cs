using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static partial class AlbOptions
{
    private static long SumFileSizesSafe(List<string> files)
    {
        long total = 0;
        foreach (var f in files)
        {
            try { total += new FileInfo(f).Length; }
            catch { /* ignore */ }
        }
        return total;
    }

    // ---------- Shared UX helpers (Spectre) ----------

    private static void InfoPanel(string title, params (string Key, string Value)[] rows)
    {
        var t = new Table().RoundedBorder().AddColumn("Field").AddColumn("Value");
        foreach (var (k, v) in rows)
            t.AddRow(Markup.Escape(k), Markup.Escape(v));

        AnsiConsole.Write(new Panel(t)
        {
            Header = new PanelHeader(Markup.Escape(title)),
            Border = BoxBorder.Rounded
        });

        AnsiConsole.WriteLine();
    }

    private static Table TopTable(params string[] columns)
    {
        var t = new Table().RoundedBorder();
        foreach (var c in columns)
            t.AddColumn(new TableColumn(Markup.Escape(c)));
        return t;
    }

    private static async Task RunScanWithProgressAsync(
        string title,
        List<string> files,
        Func<string, Action<long>, Task> scanFileAsync)
    {
        var totalBytes = SumFileSizesSafe(files);

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
            })
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask(title, maxValue: Math.Max(1, totalBytes));

                foreach (var file in files)
                {
                    await scanFileAsync(file, delta =>
                    {
                        if (delta <= 0) return;
                        task.Increment(delta);
                    }).ConfigureAwait(false);
                }

                // Ensure 100% even if deltas don't perfectly match file sizes.
                if (task.Value < task.MaxValue)
                    task.Value = task.MaxValue;

                task.StopTask();
            });

        AnsiConsole.WriteLine();
    }
}
