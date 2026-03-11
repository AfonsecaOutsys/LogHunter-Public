using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using Spectre.Console;

namespace LogHunter.Services;

public static class Charts
{
    public sealed record TimeSeriesSeries(
        string SeriesName,
        DateTime[] TimesUtc,
        double[] Values,
        long? SourceHits = null,
        double? TotalRequests = null,
        double? PeakBucket = null);

    /// <summary>
    /// Creates a self-contained offline interactive HTML time-series chart and opens it.
    /// Returns the HTML path.
    /// </summary>
    public static string SaveTimeSeriesHtmlAndOpen(
        string outputFolder,
        string title,
        string yLabel,
        List<(string SeriesName, DateTime[] TimesUtc, double[] Values)> series,
        string filePrefix)
        => SaveTimeSeriesHtmlAndOpen(
            outputFolder,
            title,
            yLabel,
            series.ConvertAll(s => new TimeSeriesSeries(s.SeriesName, s.TimesUtc, s.Values)),
            filePrefix);

    public static string SaveTimeSeriesHtmlAndOpen(
        string outputFolder,
        string title,
        string yLabel,
        List<TimeSeriesSeries> series,
        string filePrefix)
    {
        var htmlPath = SaveTimeSeriesHtml(
            outputFolder: outputFolder,
            title: title,
            yLabel: yLabel,
            series: series,
            filePrefix: filePrefix);

        var opened = TryOpen(htmlPath);

        if (opened)
            AnsiConsole.MarkupLine($"Chart opened: [green]{Markup.Escape(htmlPath)}[/]");
        else
            AnsiConsole.MarkupLine($"Chart saved (open manually): [yellow]{Markup.Escape(htmlPath)}[/]");

        return htmlPath;
    }

    /// <summary>
    /// Creates the HTML and returns the path. Does not try to open.
    /// </summary>
    public static string SaveTimeSeriesHtml(
        string outputFolder,
        string title,
        string yLabel,
        List<(string SeriesName, DateTime[] TimesUtc, double[] Values)> series,
        string filePrefix)
        => SaveTimeSeriesHtml(
            outputFolder,
            title,
            yLabel,
            series.ConvertAll(s => new TimeSeriesSeries(s.SeriesName, s.TimesUtc, s.Values)),
            filePrefix);

    public static string SaveTimeSeriesHtml(
        string outputFolder,
        string title,
        string yLabel,
        List<TimeSeriesSeries> series,
        string filePrefix)
    {
        if (series is null || series.Count == 0)
            throw new ArgumentException("Series is empty.", nameof(series));

        // Validate shared timeline (we chart against the first series times)
        var times = series[0].TimesUtc;
        if (times.Length == 0)
            throw new ArgumentException("Timeline is empty.", nameof(series));

        foreach (var s in series)
        {
            if (s.TimesUtc.Length != times.Length || s.Values.Length != times.Length)
                throw new ArgumentException("All series must share the same TimesUtc length and Values length.");
        }

        Directory.CreateDirectory(outputFolder);

        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var htmlPath = Path.Combine(outputFolder, $"{filePrefix}_{stamp}.html");

        // Convert times to epoch milliseconds (UTC)
        long[] tms = new long[times.Length];
        for (int i = 0; i < times.Length; i++)
        {
            var dt = times[i].Kind == DateTimeKind.Utc ? times[i] : times[i].ToUniversalTime();
            tms[i] = new DateTimeOffset(dt).ToUnixTimeMilliseconds();
        }

        var safeTitle = title ?? "";
        var safeY = yLabel ?? "";

        // Build HTML
        var sb = new StringBuilder(256 * 1024);
        sb.AppendLine("<!doctype html>");
        sb.AppendLine("<html lang=\"en\"><head>");
        sb.AppendLine("<meta charset=\"utf-8\"/>");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>");
        sb.AppendLine($"<title>{Html(safeTitle)}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine(@"
:root { color-scheme: dark; }
body { margin:0; background:#0b0f14; color:#e6edf3; font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, Arial; }
.wrap { padding:16px; }
.hdr { display:flex; gap:12px; align-items:baseline; flex-wrap:wrap; }
.hdr h1 { font-size:18px; margin:0; font-weight:600; }
.hdr .sub { opacity:.75; font-size:12px; }
.card { margin-top:12px; background:#0f1620; border:1px solid rgba(255,255,255,.08); border-radius:14px; padding:12px; box-shadow: 0 12px 28px rgba(0,0,0,.35); }
.row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:8px; }
.pill { font-size:12px; padding:6px 10px; border:1px solid rgba(255,255,255,.10); border-radius:999px; background: rgba(255,255,255,.03); }
.btn { border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.03); color:#e6edf3; padding:5px 9px; border-radius:8px; cursor:pointer; font-size:12px; }
.btn:hover { background:rgba(255,255,255,.08); }
.search { background:#0b0f14; color:#e6edf3; border:1px solid rgba(255,255,255,.14); border-radius:8px; padding:6px 8px; min-width:220px; }
.legendWrap { border:1px solid rgba(255,255,255,.08); border-radius:10px; padding:8px; background:rgba(255,255,255,.015); }
.legendWrap.compact .legend { max-height:140px; overflow:auto; }
.legend { display:flex; flex-wrap:wrap; gap:6px; }
.legend .item { display:flex; gap:8px; align-items:center; font-size:12px; opacity:.95; padding:3px 6px; border:1px solid rgba(255,255,255,.08); border-radius:8px; cursor:pointer; user-select:none; }
.legend .item.hidden { opacity:.4; }
.legend .item.isolated { border-color:rgba(125,211,252,.5); box-shadow: inset 0 0 0 1px rgba(125,211,252,.25); }
.legend .sw { width:10px; height:10px; border-radius:3px; background:#6cf; }
.summaryWrap { border:1px solid rgba(255,255,255,.08); border-radius:10px; overflow:auto; max-height:260px; margin-bottom:8px; }
.summary { width:100%; border-collapse: collapse; font-size:12px; }
.summary th, .summary td { padding:6px 8px; border-bottom:1px solid rgba(255,255,255,.07); white-space:nowrap; }
.summary th { position:sticky; top:0; background:#0f1620; text-align:left; }
.summary tr { cursor:pointer; }
.summary tr.hidden { opacity:.45; }
.summary tr.isolated { background:rgba(125,211,252,.10); }
canvas { width:100%; height:520px; display:block; background: #0b0f14; border-radius:12px; }
.small { font-size:12px; opacity:.75; line-height:1.35; }
kbd { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:11px; padding:2px 6px; border-radius:6px; border:1px solid rgba(255,255,255,.15); background: rgba(255,255,255,.04); }
");
        sb.AppendLine("</style></head><body>");
        sb.AppendLine("<div class=\"wrap\">");
        sb.AppendLine("<div class=\"hdr\">");
        sb.AppendLine($"<h1>{Html(safeTitle)}</h1>");
        sb.AppendLine("<div class=\"sub\">offline interactive chart</div>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"card\">");
        sb.AppendLine("<div class=\"row\">");
        sb.AppendLine("<div class=\"pill\">Pan: <kbd>drag</kbd></div>");
        sb.AppendLine("<div class=\"pill\">Zoom X: <kbd>wheel</kbd></div>");
        sb.AppendLine("<div class=\"pill\">Reset: <kbd>double click</kbd></div>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"row\">");
        sb.AppendLine("<button class=\"btn\" id=\"btnShowAll\">Show all</button>");
        sb.AppendLine("<button class=\"btn\" id=\"btnHideAll\">Hide all</button>");
        sb.AppendLine("<button class=\"btn\" id=\"btnTop5\">Top 5</button>");
        sb.AppendLine("<button class=\"btn\" id=\"btnTop10\">Top 10</button>");
        sb.AppendLine("<button class=\"btn\" id=\"btnResetZoom\">Reset zoom</button>");
        sb.AppendLine("<input id=\"search\" class=\"search\" type=\"text\" placeholder=\"Filter IP...\" />");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"summaryWrap\"><table class=\"summary\" id=\"summary\"></table></div>");
        sb.AppendLine("<div class=\"legendWrap\" id=\"legendWrap\"><div class=\"legend\" id=\"legend\"></div></div>");
        sb.AppendLine("<div style=\"height:8px\"></div>");
        sb.AppendLine("<canvas id=\"c\"></canvas>");
        sb.AppendLine("<div style=\"height:10px\"></div>");
        sb.AppendLine($"<div class=\"small\">Y: {Html(safeY)} • X: UTC time buckets</div>");
        sb.AppendLine("</div>"); // card
        sb.AppendLine("</div>"); // wrap

        // Data
        sb.AppendLine("<script>");
        sb.Append("const T = [");
        for (int i = 0; i < tms.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append(tms[i]);
        }
        sb.AppendLine("];");

        sb.AppendLine("const SERIES = [");
        for (int s = 0; s < series.Count; s++)
        {
            var ser = series[s];
            var total = ser.TotalRequests;
            if (total is null)
            {
                double sum = 0;
                foreach (var v in ser.Values) sum += v;
                total = sum;
            }

            var peak = ser.PeakBucket;
            if (peak is null)
            {
                double max = 0;
                foreach (var v in ser.Values) if (v > max) max = v;
                peak = max;
            }

            sb.Append("{");
            sb.Append($"name:{Js(ser.SeriesName)},");
            sb.Append("y:[");
            for (int i = 0; i < ser.Values.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(ser.Values[i].ToString("0.####", CultureInfo.InvariantCulture));
            }
            sb.Append("],");
            sb.Append($"sourceHits:{(ser.SourceHits.HasValue ? ser.SourceHits.Value.ToString(CultureInfo.InvariantCulture) : "null")},");
            sb.Append($"total:{total.Value.ToString("0.####", CultureInfo.InvariantCulture)},");
            sb.Append($"peak:{peak.Value.ToString("0.####", CultureInfo.InvariantCulture)}");
            sb.Append("}");
            if (s < series.Count - 1) sb.Append(",");
            sb.AppendLine();
        }
        sb.AppendLine("];");

        // JS chart
        sb.AppendLine(@"
const canvas = document.getElementById('c');
const ctx = canvas.getContext('2d', { alpha: false });
const legend = document.getElementById('legend');
const legendWrap = document.getElementById('legendWrap');
const summary = document.getElementById('summary');
const search = document.getElementById('search');

const colors = [
  '#7dd3fc','#a7f3d0','#fda4af','#c4b5fd','#fdba74',
  '#fde68a','#93c5fd','#fca5a5','#86efac','#f9a8d4',
  '#67e8f9','#f0abfc','#5eead4','#bfdbfe','#fca5a5',
  '#bef264','#fcd34d','#c7d2fe','#86efac','#f9a8d4'
];

SERIES.forEach((s, i) => {
  s.color = colors[i % colors.length];
  s.visible = true;
  s._prevVisible = true;
});

const sortedByActivity = [...SERIES.keys()].sort((a,b) => (SERIES[b].total - SERIES[a].total) || (SERIES[b].peak - SERIES[a].peak));
const defaultVisible = SERIES.length <= 12 ? SERIES.length : Math.min(10, SERIES.length);
SERIES.forEach((s, i) => { s.visible = sortedByActivity.indexOf(i) < defaultVisible; });

if (SERIES.length > 15) legendWrap.classList.add('compact');

function fmtUtc(ms) {
  const d = new Date(ms);
  const pad = n => String(n).padStart(2,'0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}
function fmtNum(v) {
  if (v == null || Number.isNaN(v)) return '—';
  if (Math.abs(v) >= 1000) return Math.round(v).toLocaleString('en-US');
  return Number(v).toFixed(0);
}

let xMin = T[0], xMax = T[T.length-1];
let mouseX = null;
let mouseY = null;
let isDragging = false;
let dragStartX = 0;
let dragStartMin = 0;
let dragStartMax = 0;
let isolatedIndex = null;

function resetZoom(){ xMin = T[0]; xMax = T[T.length-1]; }

function showTopN(n){
  const set = new Set(sortedByActivity.slice(0, Math.min(n, SERIES.length)));
  SERIES.forEach((s, i) => s.visible = set.has(i));
  isolatedIndex = null;
  syncUi();
}
function showAll(){ SERIES.forEach(s => s.visible = true); isolatedIndex = null; syncUi(); }
function hideAll(){ SERIES.forEach(s => s.visible = false); isolatedIndex = null; syncUi(); }

function isolateSeries(i){
  if (isolatedIndex === i) {
    SERIES.forEach(s => s.visible = s._prevVisible);
    isolatedIndex = null;
  } else {
    SERIES.forEach(s => s._prevVisible = s.visible);
    SERIES.forEach((s, idx) => s.visible = idx === i);
    isolatedIndex = i;
  }
  syncUi();
}

function toggleSeries(i){
  SERIES[i].visible = !SERIES[i].visible;
  if (isolatedIndex !== null) isolatedIndex = null;
  syncUi();
}

function passesFilter(name){
  const q = (search.value || '').trim().toLowerCase();
  return q.length === 0 || name.toLowerCase().includes(q);
}

function buildLegend(){
  legend.innerHTML = '';
  SERIES.forEach((s, i) => {
    if (!passesFilter(s.name)) return;
    const el = document.createElement('div');
    el.className = 'item';
    if (!s.visible) el.classList.add('hidden');
    if (isolatedIndex === i) el.classList.add('isolated');

    const sw = document.createElement('div');
    sw.className = 'sw';
    sw.style.background = s.color;
    el.appendChild(sw);

    const t = document.createElement('div');
    t.textContent = s.name;
    el.appendChild(t);

    el.addEventListener('click', () => toggleSeries(i));
    el.addEventListener('dblclick', (e) => { e.preventDefault(); isolateSeries(i); });
    legend.appendChild(el);
  });
}

function buildSummary(){
  summary.innerHTML = '';
  const head = document.createElement('tr');
  head.innerHTML = '<th>IP</th><th>Source hits</th><th>Total requests</th><th>Peak (5 min)</th><th>Visible</th>';
  summary.appendChild(head);

  sortedByActivity.forEach(i => {
    const s = SERIES[i];
    if (!passesFilter(s.name)) return;
    const tr = document.createElement('tr');
    if (!s.visible) tr.classList.add('hidden');
    if (isolatedIndex === i) tr.classList.add('isolated');

    tr.innerHTML =
      `<td><span style='display:inline-block;width:9px;height:9px;background:${s.color};border-radius:2px;margin-right:6px'></span>${s.name}</td>` +
      `<td>${s.sourceHits == null ? '—' : Number(s.sourceHits).toLocaleString('en-US')}</td>` +
      `<td>${fmtNum(s.total)}</td>` +
      `<td>${fmtNum(s.peak)}</td>` +
      `<td>${s.visible ? 'Shown' : 'Hidden'}</td>`;

    tr.addEventListener('click', () => toggleSeries(i));
    tr.addEventListener('dblclick', (e) => { e.preventDefault(); isolateSeries(i); });
    summary.appendChild(tr);
  });
}

function resizeCanvas() {
  const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.floor(rect.width * dpr);
  canvas.height = Math.floor(rect.height * dpr);
  ctx.setTransform(dpr,0,0,dpr,0,0);
  draw();
}
window.addEventListener('resize', resizeCanvas);

function clampX() {
  const minSpan = 60 * 1000;
  if ((xMax - xMin) < minSpan) {
    const mid = (xMin + xMax) / 2;
    xMin = mid - minSpan/2;
    xMax = mid + minSpan/2;
  }
  const globalMin = T[0];
  const globalMax = T[T.length-1];
  if (xMin < globalMin) { const d = globalMin - xMin; xMin += d; xMax += d; }
  if (xMax > globalMax) { const d = xMax - globalMax; xMin -= d; xMax -= d; }
  if (xMin < globalMin) xMin = globalMin;
  if (xMax > globalMax) xMax = globalMax;
}

function timeToX(ms, w) { return (ms - xMin) / Math.max(1, (xMax - xMin)) * w; }
function xToTime(x, w) { return xMin + (x / Math.max(1, w)) * (xMax - xMin); }
function lowerBound(arr, x) {
  let lo = 0, hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (arr[mid] < x) lo = mid + 1; else hi = mid;
  }
  return lo;
}

canvas.addEventListener('mousemove', (e) => {
  const r = canvas.getBoundingClientRect();
  mouseX = e.clientX - r.left;
  mouseY = e.clientY - r.top;
  if (isDragging) {
    const dx = mouseX - dragStartX;
    const pxW = r.width;
    const span = (dragStartMax - dragStartMin);
    const dt = -dx / Math.max(1, pxW) * span;
    xMin = dragStartMin + dt;
    xMax = dragStartMax + dt;
    clampX();
  }
  draw();
});
canvas.addEventListener('mouseleave', () => { mouseX = null; mouseY = null; if (!isDragging) draw(); });
canvas.addEventListener('mousedown', (e) => {
  isDragging = true;
  const r = canvas.getBoundingClientRect();
  dragStartX = e.clientX - r.left;
  dragStartMin = xMin;
  dragStartMax = xMax;
});
window.addEventListener('mouseup', () => { isDragging = false; });
canvas.addEventListener('wheel', (e) => {
  e.preventDefault();
  const r = canvas.getBoundingClientRect();
  const x = (e.clientX - r.left);
  const t = xToTime(x, r.width);
  const zoom = Math.exp((e.deltaY > 0 ? 1 : -1) * 0.12);
  const span = (xMax - xMin) * zoom;
  const leftRatio = (t - xMin) / Math.max(1, (xMax - xMin));
  xMin = t - span * leftRatio;
  xMax = xMin + span;
  clampX();
  draw();
}, { passive: false });
canvas.addEventListener('dblclick', () => { resetZoom(); draw(); });

document.getElementById('btnShowAll').addEventListener('click', showAll);
document.getElementById('btnHideAll').addEventListener('click', hideAll);
document.getElementById('btnTop5').addEventListener('click', () => showTopN(5));
document.getElementById('btnTop10').addEventListener('click', () => showTopN(10));
document.getElementById('btnResetZoom').addEventListener('click', () => { resetZoom(); draw(); });
search.addEventListener('input', () => { buildLegend(); buildSummary(); draw(); });

function syncUi(){ buildLegend(); buildSummary(); draw(); }

function draw() {
  const r = canvas.getBoundingClientRect();
  const W = r.width;
  const H = r.height;

  const padL = 64, padR = 18, padT = 14, padB = 44;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  ctx.clearRect(0,0,W,H);
  ctx.fillStyle = '#0b0f14';
  ctx.fillRect(0,0,W,H);

  const i0 = Math.max(0, lowerBound(T, xMin) - 1);
  const i1 = Math.min(T.length - 1, lowerBound(T, xMax) + 1);

  const visibleSeries = SERIES.filter(s => s.visible && passesFilter(s.name));

  let yMin = Infinity, yMax = -Infinity;
  for (const s of visibleSeries) {
    for (let i = i0; i <= i1; i++) {
      const v = s.y[i];
      if (v < yMin) yMin = v;
      if (v > yMax) yMax = v;
    }
  }
  if (!isFinite(yMin) || !isFinite(yMax)) { yMin = 0; yMax = 1; }
  if (yMin === yMax) { yMin -= 1; yMax += 1; }

  const yPad = (yMax - yMin) * 0.08;
  yMin -= yPad; yMax += yPad;

  function valToY(v) {
    return padT + (1 - (v - yMin) / Math.max(1e-9, (yMax - yMin))) * plotH;
  }

  ctx.strokeStyle = 'rgba(255,255,255,.08)';
  ctx.lineWidth = 1;
  const yTicks = 5;
  ctx.font = '12px ui-sans-serif, system-ui';
  ctx.fillStyle = 'rgba(230,237,243,.75)';

  for (let t = 0; t <= yTicks; t++) {
    const vv = yMin + (t / yTicks) * (yMax - yMin);
    const y = valToY(vv);
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(padL + plotW, y);
    ctx.stroke();
    ctx.fillText(vv.toFixed(0), 8, y + 4);
  }

  const xTicks = 5;
  for (let k = 0; k <= xTicks; k++) {
    const ms = xMin + (k / xTicks) * (xMax - xMin);
    const x = padL + timeToX(ms, plotW);
    ctx.beginPath();
    ctx.moveTo(x, padT);
    ctx.lineTo(x, padT + plotH);
    ctx.stroke();

    const lbl = fmtUtc(ms);
    const tw = ctx.measureText(lbl).width;
    ctx.fillText(lbl, x - tw/2, padT + plotH + 28);
  }

  visibleSeries.forEach((s) => {
    ctx.strokeStyle = s.color;
    ctx.lineWidth = isolatedIndex !== null && SERIES[isolatedIndex] === s ? 2.6 : 2;
    ctx.beginPath();

    let started = false;
    for (let i = i0; i <= i1; i++) {
      const ms = T[i];
      if (ms < xMin || ms > xMax) continue;
      const x = padL + timeToX(ms, plotW);
      const y = valToY(s.y[i]);
      if (!started) { ctx.moveTo(x, y); started = true; }
      else ctx.lineTo(x, y);
    }
    ctx.globalAlpha = isolatedIndex !== null && SERIES[isolatedIndex] !== s ? 0.2 : 1;
    ctx.stroke();
    ctx.globalAlpha = 1;
  });

  ctx.strokeStyle = 'rgba(255,255,255,.22)';
  ctx.lineWidth = 1;
  ctx.strokeRect(padL, padT, plotW, plotH);

  if (mouseX != null && mouseY != null && mouseX >= padL && mouseX <= padL + plotW && mouseY >= padT && mouseY <= padT + plotH) {
    const tx = xToTime(mouseX - padL, plotW);
    let idx = lowerBound(T, tx);
    if (idx <= 0) idx = 0;
    else if (idx >= T.length) idx = T.length - 1;
    else {
      const a = T[idx - 1], b = T[idx];
      idx = (Math.abs(tx - a) <= Math.abs(tx - b)) ? (idx - 1) : idx;
    }

    const ms = T[idx];
    const cx = padL + timeToX(ms, plotW);

    ctx.strokeStyle = 'rgba(230,237,243,.35)';
    ctx.beginPath();
    ctx.moveTo(cx, padT);
    ctx.lineTo(cx, padT + plotH);
    ctx.stroke();

    const tooltipSeries = visibleSeries
      .map(s => ({ s, v: s.y[idx] }))
      .sort((a,b) => b.v - a.v)
      .slice(0, 10);

    const lines = [fmtUtc(ms), ...tooltipSeries.map(x => `${x.s.name}: ${fmtNum(x.v)}`)];

    ctx.font = '12px ui-sans-serif, system-ui';
    const padding = 10;
    let w = 0;
    lines.forEach(L => { w = Math.max(w, ctx.measureText(L).width); });
    w = w + padding * 2;
    const h = lines.length * 16 + padding * 2;

    let bx = cx + 14;
    let by = padT + 10;
    if (bx + w > padL + plotW) bx = cx - 14 - w;

    ctx.fillStyle = 'rgba(15,22,32,.94)';
    ctx.strokeStyle = 'rgba(255,255,255,.18)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    roundRect(ctx, bx, by, w, h, 10);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = '#e6edf3';
    let ty = by + padding + 12;
    ctx.fillText(lines[0], bx + padding, ty);
    ty += 18;

    tooltipSeries.forEach((entry) => {
      ctx.fillStyle = entry.s.color;
      ctx.fillText('■', bx + padding, ty);
      ctx.fillStyle = '#e6edf3';
      ctx.fillText(`${entry.s.name}: ${fmtNum(entry.v)}`, bx + padding + 14, ty);
      ty += 16;
    });
  }
}

function roundRect(ctx, x, y, w, h, r) {
  const rr = Math.min(r, w/2, h/2);
  ctx.moveTo(x + rr, y);
  ctx.arcTo(x + w, y, x + w, y + h, rr);
  ctx.arcTo(x + w, y + h, x, y + h, rr);
  ctx.arcTo(x, y + h, x, y, rr);
  ctx.arcTo(x, y, x + w, y, rr);
  ctx.closePath();
}

buildLegend();
buildSummary();
resizeCanvas();
draw();
");
        sb.AppendLine("</script></body></html>");

        File.WriteAllText(htmlPath, sb.ToString(), Encoding.UTF8);
        return htmlPath;
    }

    private static bool TryOpen(string filePath)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = filePath,
                UseShellExecute = true
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string Html(string s)
        => (s ?? "")
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;");

    private static string Js(string s)
        => "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
}
