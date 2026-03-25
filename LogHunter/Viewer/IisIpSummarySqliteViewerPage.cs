namespace LogHunter.Viewer;

internal static class IisIpSummarySqliteViewerPage
{
    public static string BuildHtml() => """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IIS IP Summary SQLite Viewer</title>
  <style>
    :root { color-scheme: light dark; --bg:#0f172a; --text:#e5e7eb; --muted:#94a3b8; --accent:#38bdf8; --border:rgba(148,163,184,0.25); --ok:#34d399; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: Inter, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background:linear-gradient(180deg, #020617 0%, var(--bg) 100%); color:var(--text); }
    .page { max-width:1800px; margin:0 auto; padding:24px; }
    h1 { margin:0 0 8px; font-size:28px; }
    p, label, button, input, select { font:inherit; }
    .muted { color:var(--muted); }
    .grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:12px; }
    .card { background:rgba(17,24,39,0.92); border:1px solid var(--border); border-radius:14px; padding:16px; box-shadow:0 16px 60px rgba(15,23,42,0.25); }
    .meta-label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:0.08em; }
    .meta-value { margin-top:8px; font-size:16px; word-break:break-word; }
    .toolbar,.filters { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-top:16px; }
    .field { display:flex; flex-direction:column; gap:6px; }
    .field label { font-size:13px; color:var(--muted); }
    input,select { width:100%; background:rgba(15,23,42,0.95); color:var(--text); border:1px solid var(--border); border-radius:10px; padding:10px 12px; }
    .button-row { display:flex; flex-wrap:wrap; gap:8px; margin-top:16px; }
    button { border:1px solid rgba(56,189,248,0.35); border-radius:999px; padding:10px 14px; background:rgba(14,165,233,0.12); color:var(--text); cursor:pointer; }
    button:hover { border-color:var(--accent); }
    button.primary { background:linear-gradient(90deg, rgba(14,165,233,0.24), rgba(59,130,246,0.3)); }
    button.active { border-color:var(--ok); box-shadow:0 0 0 1px rgba(52,211,153,0.45) inset; }
    .status { margin-top:16px; display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; color:var(--muted); }
    .table-wrap { margin-top:16px; overflow:auto; border:1px solid var(--border); border-radius:14px; background:rgba(2,6,23,0.55); }
    table { width:100%; border-collapse:collapse; min-width:1500px; }
    th,td { padding:10px 12px; border-bottom:1px solid rgba(148,163,184,0.15); vertical-align:top; text-align:left; }
    th { position:sticky; top:0; background:rgba(15,23,42,0.98); cursor:pointer; user-select:none; white-space:nowrap; }
    td code { white-space:pre-wrap; word-break:break-word; color:#bfdbfe; }
    .pagination { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-top:16px; }
    .pagination .controls { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
    .error { color:#fca5a5; white-space:pre-wrap; }
  </style>
</head>
<body>
  <div class="page">
    <h1>IIS IP Summary SQLite Viewer</h1>
    <p class="muted">This local viewer keeps filtering, sorting, and paging on the server side so very large SQLite exports remain usable.</p>
    <div id="meta" class="grid"></div>
    <div class="card" style="margin-top:16px;">
      <div class="meta-label">Preset queries</div>
      <div id="presetButtons" class="button-row"></div>
      <div class="toolbar">
        <div class="field"><label for="pageSize">Page size</label><select id="pageSize"><option value="50">50</option><option value="100" selected>100</option><option value="250">250</option><option value="500">500</option></select></div>
        <div class="field"><label for="method">Method</label><select id="method"><option value="">Any</option></select></div>
        <div class="field"><label for="startUtc">Start time (UTC)</label><input id="startUtc" type="datetime-local"></div>
        <div class="field"><label for="endUtc">End time (UTC)</label><input id="endUtc" type="datetime-local"></div>
      </div>
      <div class="filters">
        <div class="field"><label for="statusClass">HTTP status class</label><select id="statusClass"><option value="">Any</option><option value="2xx3xx">2xx/3xx</option><option value="4xx">4xx</option><option value="5xx">5xx</option></select></div>
        <div class="field"><label for="statusCode">HTTP status code</label><input id="statusCode" placeholder="e.g. 404"></div>
        <div class="field"><label for="uriContains">URI stem contains</label><input id="uriContains" placeholder="/ServiceCenter"></div>
        <div class="field"><label for="queryContains">URI query contains</label><input id="queryContains" placeholder="id="></div>
        <div class="field"><label for="hostContains">Host contains</label><input id="hostContains" placeholder="portal.example.com"></div>
        <div class="field"><label for="userAgentContains">UserAgent contains</label><input id="userAgentContains" placeholder="Mozilla"></div>
        <div class="field"><label for="refererContains">Referer contains</label><input id="refererContains" placeholder="/home"></div>
      </div>
      <div class="button-row">
        <button id="applyFilters" class="primary">Apply filters</button>
        <button id="resetFilters">Reset</button>
        <button id="exportCsv">Export filtered CSV</button>
      </div>
      <div class="status">
        <div id="summaryLine">Loading metadata...</div>
        <div id="errorLine" class="error"></div>
      </div>
    </div>
    <div class="table-wrap"><table><thead><tr id="headerRow"></tr></thead><tbody id="rowsBody"></tbody></table></div>
    <div class="pagination">
      <div id="pageInfo" class="muted"></div>
      <div class="controls"><button id="firstPage">First</button><button id="prevPage">Previous</button><button id="nextPage">Next</button></div>
    </div>
  </div>
  <script>
    const columns = [['timestampUtc','Timestamp UTC'],['clientIp','Client IP'],['method','Method'],['scStatusCode','Status'],['scSubStatusCode','Substatus'],['scWin32StatusCode','Win32'],['uriStem','URI stem'],['uriQuery','URI query'],['host','Host'],['timeTakenMs','TimeTakenMs'],['csBytes','CsBytes'],['scBytes','ScBytes'],['userAgent','UserAgent'],['referer','Referer']];
    const state = { metadata:null, presets:[], preset:'all', page:1, pageSize:100, sortField:'timestampUtc', sortDirection:'desc', totalFiltered:0, totalRows:0 };
    const q = id => document.getElementById(id);
    const escapeHtml = value => String(value ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
    function encodeUtcLocalInput(utcText){ if(!utcText) return ''; const iso = utcText.replace(' UTC','Z').replace(' ','T'); const date = new Date(iso); if(Number.isNaN(date.getTime())) return ''; return `${date.getUTCFullYear()}-${String(date.getUTCMonth()+1).padStart(2,'0')}-${String(date.getUTCDate()).padStart(2,'0')}T${String(date.getUTCHours()).padStart(2,'0')}:${String(date.getUTCMinutes()).padStart(2,'0')}`; }
    const parseLocalInputToUtc = (value, endOfMinute) => !value ? '' : new Date(`${value}${endOfMinute ? ':59Z' : ':00Z'}`).toISOString();
    function filtersFromUi(){ return { method:q('method').value, startUtc:parseLocalInputToUtc(q('startUtc').value,false), endUtc:parseLocalInputToUtc(q('endUtc').value,true), statusClass:q('statusClass').value, statusCode:q('statusCode').value.trim(), uriContains:q('uriContains').value.trim(), queryContains:q('queryContains').value.trim(), hostContains:q('hostContains').value.trim(), userAgentContains:q('userAgentContains').value.trim(), refererContains:q('refererContains').value.trim() }; }
    function buildQuery(extra = {}){ return new URLSearchParams({ page:String(state.page), pageSize:String(state.pageSize), sortField:state.sortField, sortDirection:state.sortDirection, preset:state.preset, ...filtersFromUi(), ...extra }).toString(); }
    function renderMetadata(){ const metadata = state.metadata; q('meta').innerHTML = [['Selected IP', metadata.selectedIp || '-'],['Database', metadata.databaseName],['Database path', metadata.databasePath],['Total rows', Number(metadata.totalRows).toLocaleString('en-US')],['Time range (UTC)', metadata.timeRangeUtc || '-'],['Local viewer', metadata.viewerUrl]].map(([label, value]) => `<div class="card"><div class="meta-label">${escapeHtml(label)}</div><div class="meta-value">${escapeHtml(value)}</div></div>`).join(''); q('summaryLine').textContent = `Loaded ${Number(metadata.totalRows).toLocaleString('en-US')} total rows from ${metadata.databaseName}.`; state.totalRows = metadata.totalRows; q('method').innerHTML = '<option value="">Any</option>' + metadata.methods.map(method => `<option value="${escapeHtml(method)}">${escapeHtml(method)}</option>`).join(''); if(metadata.startUtc) q('startUtc').value = encodeUtcLocalInput(metadata.startUtc); if(metadata.endUtc) q('endUtc').value = encodeUtcLocalInput(metadata.endUtc); }
    function renderPresets(){ const container = q('presetButtons'); container.innerHTML = state.presets.map(preset => `<button data-preset="${preset.id}" class="${state.preset === preset.id ? 'active' : ''}">${escapeHtml(preset.label)}</button>`).join(''); container.querySelectorAll('button').forEach(button => button.addEventListener('click', () => { state.preset = button.dataset.preset; if(state.preset === 'latest'){ state.sortField = 'timestampUtc'; state.sortDirection = 'desc'; renderHeaders(); } state.page = 1; renderPresets(); loadRows(); })); }
    function renderHeaders(){ q('headerRow').innerHTML = columns.map(([key, label]) => { const arrow = state.sortField === key ? (state.sortDirection === 'asc' ? ' ▲' : ' ▼') : ''; return `<th data-key="${key}">${escapeHtml(label)}${arrow}</th>`; }).join(''); document.querySelectorAll('#headerRow th').forEach(th => th.addEventListener('click', () => { const key = th.dataset.key; if(state.sortField === key) state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc'; else { state.sortField = key; state.sortDirection = key === 'timestampUtc' ? 'desc' : 'asc'; } state.page = 1; renderHeaders(); loadRows(); })); }
    function renderRows(rows){ const body = q('rowsBody'); if(!rows.length){ body.innerHTML = '<tr><td colspan="14" class="muted">No rows matched the current filters.</td></tr>'; return; } body.innerHTML = rows.map(row => `<tr><td>${escapeHtml(row.timestampUtc)}</td><td>${escapeHtml(row.clientIp)}</td><td>${escapeHtml(row.method)}</td><td>${escapeHtml(row.scStatusCode ?? '')}</td><td>${escapeHtml(row.scSubStatusCode ?? '')}</td><td>${escapeHtml(row.scWin32StatusCode ?? '')}</td><td><code>${escapeHtml(row.uriStem)}</code></td><td><code>${escapeHtml(row.uriQuery)}</code></td><td>${escapeHtml(row.host)}</td><td>${escapeHtml(row.timeTakenMs ?? '')}</td><td>${escapeHtml(row.csBytes ?? '')}</td><td>${escapeHtml(row.scBytes ?? '')}</td><td>${escapeHtml(row.userAgent)}</td><td>${escapeHtml(row.referer)}</td></tr>`).join(''); }
    async function loadRows(){ q('errorLine').textContent = ''; q('summaryLine').textContent = 'Loading rows...'; try { const response = await fetch(`/api/rows?${buildQuery()}`); if(!response.ok) throw new Error(await response.text()); const payload = await response.json(); state.totalFiltered = payload.totalFiltered; renderRows(payload.rows); const start = payload.totalFiltered === 0 ? 0 : ((state.page - 1) * state.pageSize) + 1; const end = Math.min(state.page * state.pageSize, payload.totalFiltered); q('summaryLine').textContent = `Showing ${start.toLocaleString('en-US')}-${end.toLocaleString('en-US')} of ${payload.totalFiltered.toLocaleString('en-US')} filtered rows (${state.totalRows.toLocaleString('en-US')} total).`; q('pageInfo').textContent = `Page ${state.page} • ${state.pageSize} rows per page`; } catch(error) { q('errorLine').textContent = String(error); } }
    async function initialize(){ renderHeaders(); const [metadataResponse, presetsResponse] = await Promise.all([fetch('/api/metadata'), fetch('/api/presets')]); state.metadata = await metadataResponse.json(); state.presets = await presetsResponse.json(); renderMetadata(); renderPresets(); await loadRows(); }
    q('applyFilters').addEventListener('click', () => { state.page = 1; state.pageSize = Number(q('pageSize').value); loadRows(); });
    q('resetFilters').addEventListener('click', () => { q('method').value = ''; q('statusClass').value = ''; q('statusCode').value = ''; q('uriContains').value = ''; q('queryContains').value = ''; q('hostContains').value = ''; q('userAgentContains').value = ''; q('refererContains').value = ''; if(state.metadata?.startUtc) q('startUtc').value = encodeUtcLocalInput(state.metadata.startUtc); if(state.metadata?.endUtc) q('endUtc').value = encodeUtcLocalInput(state.metadata.endUtc); state.preset = 'all'; state.page = 1; renderPresets(); loadRows(); });
    q('pageSize').addEventListener('change', () => { state.page = 1; state.pageSize = Number(q('pageSize').value); loadRows(); });
    q('firstPage').addEventListener('click', () => { state.page = 1; loadRows(); });
    q('prevPage').addEventListener('click', () => { state.page = Math.max(1, state.page - 1); loadRows(); });
    q('nextPage').addEventListener('click', () => { const maxPage = Math.max(1, Math.ceil(state.totalFiltered / state.pageSize)); state.page = Math.min(maxPage, state.page + 1); loadRows(); });
    q('exportCsv').addEventListener('click', () => { window.location.href = `/api/export.csv?${buildQuery({ page:'', pageSize:'' })}`; });
    initialize().catch(error => { q('errorLine').textContent = String(error); });
  </script>
</body>
</html>
""";
}
