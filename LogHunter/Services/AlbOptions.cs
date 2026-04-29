using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
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

    // Parallel variant: each file is scanned into a per-file local accumulator (TLocal),
    // then locals are merged sequentially in input file order so behaviour is identical
    // to the sequential RunScanWithProgressAsync for commutative merges, and deterministic
    // for order-sensitive merges (e.g. row lists).
    //
    // Concurrency is capped at Math.Min(Environment.ProcessorCount, files.Count).
    // Spectre.Console's ProgressTask.Increment is thread-safe, so byte-delta progress
    // from worker threads is safe.
    private static async Task RunScanWithProgressParallelAsync<TLocal>(
        string title,
        List<string> files,
        Func<TLocal> createLocal,
        Func<string, TLocal, Action<long>, CancellationToken, Task> scanFileAsync,
        Action<TLocal> mergeLocal,
        CancellationToken cancellationToken = default)
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

                var locals = new TLocal[files.Count];
                var degree = Math.Max(1, Math.Min(Environment.ProcessorCount, files.Count));

                var indexed = new (int Index, string File)[files.Count];
                for (int i = 0; i < files.Count; i++)
                    indexed[i] = (i, files[i]);

                await Parallel.ForEachAsync(
                    indexed,
                    new ParallelOptions
                    {
                        MaxDegreeOfParallelism = degree,
                        CancellationToken = cancellationToken
                    },
                    async (item, ct) =>
                    {
                        var local = createLocal();
                        await scanFileAsync(item.File, local, delta =>
                        {
                            if (delta <= 0) return;
                            task.Increment(delta);
                        }, ct).ConfigureAwait(false);
                        locals[item.Index] = local;
                    }).ConfigureAwait(false);

                // Merge in input file order (deterministic).
                for (int i = 0; i < locals.Length; i++)
                {
                    if (locals[i] is not null)
                        mergeLocal(locals[i]);
                }

                if (task.Value < task.MaxValue)
                    task.Value = task.MaxValue;

                task.StopTask();
            });

        AnsiConsole.WriteLine();
    }
}
