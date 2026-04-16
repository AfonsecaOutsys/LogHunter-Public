(function () {
  // ── Shared helpers ──────────────────────────────────────────────

  function byId(id) { return document.getElementById(id); }

  function setText(id, value) {
    const node = byId(id);
    if (node) node.textContent = value;
  }

  function setHidden(el, hidden) {
    if (el) el.hidden = hidden;
  }

  function escHtml(s) {
    return String(s || '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');
  }

  function fmt(v) { return Number(v || 0).toLocaleString('en-US'); }

  function formatBytes(bytes) {
    const value = Number(bytes || 0);
    if (!Number.isFinite(value) || value <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = value;
    let index = 0;
    while (size >= 1024 && index < units.length - 1) { size /= 1024; index++; }
    return `${size.toFixed(size >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
  }

  function formatEta(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value < 0) return 'n/a';
    if (value < 60) return `${Math.round(value)}s`;
    const minutes = Math.floor(value / 60);
    const rem = Math.round(value % 60);
    if (minutes < 60) return `${minutes}m ${rem}s`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m`;
  }

  async function fetchJson(url, options) {
    const response = await fetch(url, {
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      ...options
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    return payload;
  }

  function setBar(id, current, total) {
    const node = byId(id);
    if (!node) return;
    const safeTotal = Number(total || 0);
    const safeValue = Number(current || 0);
    const pct = safeTotal > 0 ? Math.max(0, Math.min(100, (safeValue / safeTotal) * 100)) : 0;
    node.style.width = `${pct}%`;
  }

  function computeEta(snap) {
    const createdUtc = snap.createdUtc ? new Date(snap.createdUtc) : null;
    const currentStep = Number(snap.currentStep || 0);
    const totalSteps = Number(snap.totalSteps || 0);
    if (!createdUtc || Number.isNaN(createdUtc.getTime()) || currentStep <= 0 || totalSteps <= currentStep) return 'n/a';
    const elapsed = Math.max(1, (Date.now() - createdUtc.getTime()) / 1000);
    return formatEta((elapsed / currentStep) * (totalSteps - currentStep));
  }

  // ── IIS IP Summary ──────────────────────────────────────────────

  let iisIpSummaryPolling = null;
  let iisIpSummaryExportMode = 'export';

  function setIisIpSummaryError(msg) {
    const node = byId('iisIpSummaryError');
    if (!node) return;
    node.textContent = msg || '';
    node.hidden = !msg;
  }

  function setIisIpSummaryExportMode(mode) {
    iisIpSummaryExportMode = mode;
    const btnChart = byId('iisIpSummaryModeChart');
    const btnExport = byId('iisIpSummaryModeExport');
    if (btnChart) btnChart.classList.toggle('active', mode === 'chart');
    if (btnExport) btnExport.classList.toggle('active', mode === 'export');
    const openExport = byId('iisIpSummaryOpenExport');
    if (openExport && mode === 'chart') {
      openExport.disabled = true;
      openExport.classList.remove('primary');
    }
  }

  async function loadIisIpSummaryMeta() {
    const payload = await fetchJson('/api/iis/ip-summary/meta');
    if (payload.currentJob) {
      renderIisIpSummarySnapshot(payload.currentJob);
      if (payload.currentJob.state === 'running') startIisIpSummaryPolling();
    }
  }

  async function runIisIpSummary() {
    setIisIpSummaryError('');
    const text = byId('iisIpSummaryIpText')?.value || '';
    const ips = text.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
    if (ips.length === 0) { setIisIpSummaryError('Enter at least one IP address.'); return; }
    if (ips.length > 10) { setIisIpSummaryError('Maximum 10 IPs per scan.'); return; }

    const isChartOnly = iisIpSummaryExportMode === 'chart';
    try {
      const payload = await fetchJson('/api/iis/ip-summary/run', {
        method: 'POST',
        body: JSON.stringify({ ips, exportXlsx: !isChartOnly, chartOnly: isChartOnly })
      });
      if (!payload.ok) { setIisIpSummaryError(payload.error || 'Failed to start scan.'); return; }
      renderIisIpSummarySnapshot(payload.snapshot);
      startIisIpSummaryPolling();
    } catch (err) { setIisIpSummaryError(String(err)); }
  }

  function startIisIpSummaryPolling() {
    stopIisIpSummaryPolling();
    iisIpSummaryPolling = setInterval(pollIisIpSummary, 1500);
  }

  function stopIisIpSummaryPolling() {
    if (iisIpSummaryPolling) { clearInterval(iisIpSummaryPolling); iisIpSummaryPolling = null; }
  }

  async function pollIisIpSummary() {
    try {
      const snap = await fetchJson('/api/iis/ip-summary/job');
      renderIisIpSummarySnapshot(snap);
      if (snap.state !== 'running') stopIisIpSummaryPolling();
    } catch { stopIisIpSummaryPolling(); }
  }

  function renderIisIpSummarySnapshot(snap) {
    if (!snap) return;
    const state = snap.state || 'idle';
    const phase = snap.phase || 'idle';
    const currentStep = Number(snap.currentStep || 0);
    const totalSteps = Number(snap.totalSteps || 0);
    const pct = totalSteps > 0 ? Math.round((currentStep / totalSteps) * 100) : 0;
    const eta = computeEta(snap);

    setText('iisIpSummaryState', state);
    setText('iisIpSummaryPhase', phase);
    setText('iisIpSummaryIpCount', String((snap.requestedIps || []).length));
    setText('iisIpSummaryMessage', snap.error ? `${snap.message} ${snap.error}` : (snap.message || ''));
    setText('iisIpSummaryStageBadge', phase);

    const bar = byId('iisIpSummaryBar');

    const isExporting = phase === 'building-excel' || phase === 'building-sqlite' || phase === 'building-report';

    // Lock inputs while running
    setIisIpSummaryInputsLocked(state === 'running' || isExporting);

    if (state === 'completed') {
      setText('iisIpSummarySummary', 'Scan complete.');
      setText('iisIpSummaryBarMeta', `100% | ${snap.filesTotal || 0} files scanned`);
      if (bar) bar.style.width = '100%';
    } else if (state === 'failed') {
      setText('iisIpSummarySummary', 'Scan failed.');
      setText('iisIpSummaryBarMeta', snap.error || '');
    } else if (isExporting) {
      const label = phase === 'building-excel' ? 'Building Excel workbook...'
        : phase === 'building-sqlite' ? 'Finalizing SQLite database...'
        : 'Building chart report...';
      setText('iisIpSummarySummary', label);
      setText('iisIpSummaryBarMeta', `100% | ${label}`);
      if (bar) bar.style.width = '100%';
    } else if (state === 'running') {
      setText('iisIpSummarySummary', `${pct}% — ${snap.filesProcessed || 0} / ${snap.filesTotal || 0} files`);
      setText('iisIpSummaryBarMeta', `${pct}% | ETA ${eta} | ${snap.filesProcessed || 0} / ${snap.filesTotal || 0} files`);
      if (bar) bar.style.width = pct + '%';
    } else {
      setText('iisIpSummarySummary', 'Waiting for a scan to start.');
      setText('iisIpSummaryBarMeta', 'No scan running.');
    }

    // Per-IP row counts
    const ipCounts = snap.ipRowCounts || {};
    const ipProgressSection = byId('iisIpSummaryIpProgress');
    const ipRowsContainer = byId('iisIpSummaryIpRows');
    const hasIps = Object.keys(ipCounts).length > 0;
    setHidden(ipProgressSection, !hasIps);
    if (ipRowsContainer && hasIps) {
      ipRowsContainer.innerHTML = Object.entries(ipCounts)
        .sort((a, b) => b[1] - a[1])
        .map(([ip, count]) => `<div class="status-pill"><span>${escHtml(ip)}</span><strong>${fmt(count)}</strong></div>`)
        .join('');
    }

    // Export buttons
    const openReport = byId('iisIpSummaryOpenReport');
    const openExport = byId('iisIpSummaryOpenExport');
    const hasReport = Boolean(snap.htmlReportPath);
    const hasExport = Boolean(snap.excelPath || snap.sqlitePath);
    const resultsOpenReport = byId('iisIpSummaryResultsOpenReport');
    const resultsOpenExport = byId('iisIpSummaryResultsOpenExport');
    [openReport, resultsOpenReport].forEach(btn => {
      if (btn) { btn.disabled = !hasReport; btn.classList.toggle('primary', hasReport); }
    });
    const chartOnly = iisIpSummaryExportMode === 'chart';
    [openExport, resultsOpenExport].forEach(btn => {
      if (btn) {
        btn.disabled = chartOnly || !hasExport;
        btn.classList.toggle('primary', !chartOnly && hasExport);
        btn.textContent = snap.sqlitePath && !snap.excelPath ? 'Open SQLite' : 'Open Excel';
      }
    });

    const exportInfo = byId('iisIpSummaryExportInfo');
    if (exportInfo) {
      if (snap.detailMode === 'sqlite') exportInfo.textContent = 'Detail mode: SQLite (exceeded 1M rows)';
      else if (snap.excelPath) exportInfo.textContent = 'Excel workbook exported.';
      else if (state === 'completed' && hasReport && !hasExport) exportInfo.textContent = 'Chart summary only (no data export).';
      else exportInfo.textContent = '';
    }

    renderIisIpSummaryResults(snap);

    // Auto-scroll to results on completion
    if (state === 'completed') {
      const resultsEl = byId('iisIpSummaryResults');
      if (resultsEl && !resultsEl.hidden) {
        setTimeout(() => resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200);
      }
    }
  }

  function setIisIpSummaryInputsLocked(locked) {
    ['iisIpSummaryRun', 'iisIpSummaryModeChart', 'iisIpSummaryModeExport'].forEach(id => {
      const el = byId(id);
      if (el) el.disabled = locked;
    });
    const ipText = byId('iisIpSummaryIpText');
    if (ipText) ipText.disabled = locked;
  }

  function renderIisIpSummaryResults(snap) {
    const container = byId('iisIpSummaryPerIp');
    const section = byId('iisIpSummaryResults');
    if (!container || !section) return;

    if (snap.state !== 'completed' || !snap.perIpSummaries || snap.perIpSummaries.length === 0) {
      setHidden(section, true);
      return;
    }

    setHidden(section, false);
    container.innerHTML = snap.perIpSummaries.map(ip => {
      if (ip.totalRows <= 0) {
        return `<div class="result-card"><div class="status-pill"><span>${escHtml(ip.ip)}</span><strong>0 hits</strong></div><p class="page-copy">No IIS hits found for this IP.</p></div>`;
      }

      const topUriRows = (ip.topUris || []).map(u =>
        `<tr><td class="uri-cell" title="${escHtml(u.label)}">${escHtml(u.label)}</td><td style="text-align:right">${fmt(u.hits)}</td></tr>`
      ).join('') || '<tr><td colspan="2">(none)</td></tr>';

      const topMethodRows = (ip.topMethods || []).map(m =>
        `<tr><td>${escHtml(m.label)}</td><td style="text-align:right">${fmt(m.hits)}</td></tr>`
      ).join('') || '<tr><td colspan="2">(none)</td></tr>';

      const topStatusRows = (ip.topStatuses || []).map(s =>
        `<tr><td>${escHtml(s.label)}</td><td style="text-align:right">${fmt(s.hits)}</td></tr>`
      ).join('') || '<tr><td colspan="2">(none)</td></tr>';

      return `
        <details class="expandable-panel" open>
          <summary>${escHtml(ip.ip)} — ${fmt(ip.totalRows)} hits</summary>
          <div class="expandable-body">
            <div class="status-block">
              <div class="status-pill"><span>Total</span><strong>${fmt(ip.totalRows)}</strong></div>
              <div class="status-pill"><span>Files</span><strong>${ip.filesWithHits}</strong></div>
              <div class="status-pill"><span>First hit</span><strong>${ip.firstHitUtc || '-'} UTC</strong></div>
              <div class="status-pill"><span>Last hit</span><strong>${ip.lastHitUtc || '-'} UTC</strong></div>
            </div>
            <div class="ip-summary-grid">
              <div class="result-card">
                <h4>Status totals</h4>
                <table class="mini-table">
                  <tr><td>2xx</td><td>${fmt(ip.s2xx)}</td></tr>
                  <tr><td>3xx</td><td>${fmt(ip.s3xx)}</td></tr>
                  <tr><td>4xx</td><td>${fmt(ip.s4xx)}</td></tr>
                  <tr><td>5xx</td><td>${fmt(ip.s5xx)}</td></tr>
                </table>
              </div>
              <div class="result-card">
                <h4>Latency and bytes</h4>
                <table class="mini-table">
                  <tr><td>Avg time-taken</td><td>${fmt(ip.avgTimeTakenMs)} ms</td></tr>
                  <tr><td>Max time-taken</td><td>${fmt(ip.maxTimeTakenMs)} ms</td></tr>
                  <tr><td>Total cs-bytes</td><td>${formatBytes(ip.totalCsBytes)}</td></tr>
                  <tr><td>Total sc-bytes</td><td>${formatBytes(ip.totalScBytes)}</td></tr>
                </table>
              </div>
              <div class="result-card">
                <h4>Top URIs</h4>
                <table class="mini-table">${topUriRows}</table>
              </div>
              <div class="result-card">
                <h4>Methods</h4>
                <table class="mini-table">${topMethodRows}</table>
              </div>
              <div class="result-card">
                <h4>Top status codes</h4>
                <table class="mini-table">${topStatusRows}</table>
              </div>
            </div>
          </div>
        </details>`;
    }).join('');
  }

  function initializeIisIpSummaryPage() {
    if (!document.querySelector('[data-iis-ip-summary-page]')) return;

    byId('iisIpSummaryModeChart')?.addEventListener('click', () => setIisIpSummaryExportMode('chart'));
    byId('iisIpSummaryModeExport')?.addEventListener('click', () => setIisIpSummaryExportMode('export'));
    byId('iisIpSummaryRun')?.addEventListener('click', runIisIpSummary);

    const openIisReport = async () => {
      try { await fetchJson('/api/iis/ip-summary/open-report', { method: 'POST' }); }
      catch (err) { setIisIpSummaryError(String(err)); }
    };
    const openIisExport = async () => {
      try { await fetchJson('/api/iis/ip-summary/open-export', { method: 'POST' }); }
      catch (err) { setIisIpSummaryError(String(err)); }
    };
    byId('iisIpSummaryOpenReport')?.addEventListener('click', openIisReport);
    byId('iisIpSummaryResultsOpenReport')?.addEventListener('click', openIisReport);
    byId('iisIpSummaryOpenExport')?.addEventListener('click', openIisExport);
    byId('iisIpSummaryResultsOpenExport')?.addEventListener('click', openIisExport);

    loadIisIpSummaryMeta().catch(err => setIisIpSummaryError(String(err)));
  }

  // ── IIS Status Pivot ────────────────────────────────────────────

  let iisStatusPivotPolling = null;
  let iisStatusPivotFilter = '4xx';

  function setIisStatusPivotError(msg) {
    const node = byId('iisStatusPivotError');
    if (!node) return;
    node.textContent = msg || '';
    node.hidden = !msg;
  }

  function setIisStatusPivotFilter(filter) {
    iisStatusPivotFilter = filter;
    document.querySelectorAll('.iis-pivot-filter-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-filter') === filter);
    });
    setHidden(byId('iisStatusPivotCustomCodes'), filter !== 'custom');
  }

  async function loadIisStatusPivotMeta() {
    const payload = await fetchJson('/api/iis/status-pivot/meta');
    if (payload.currentJob) {
      renderIisStatusPivotSnapshot(payload.currentJob);
      if (payload.currentJob.state === 'running') startIisStatusPivotPolling();
    }
  }

  async function runIisStatusPivot() {
    setIisStatusPivotError('');
    let statusFilter = iisStatusPivotFilter;
    if (statusFilter === 'custom') {
      statusFilter = (byId('iisStatusPivotCodesInput')?.value || '').trim();
      if (!statusFilter) { setIisStatusPivotError('Enter at least one status code.'); return; }
    }

    const appScope = (byId('iisStatusPivotAppScope')?.value || '').trim() || null;

    try {
      const payload = await fetchJson('/api/iis/status-pivot/run', {
        method: 'POST',
        body: JSON.stringify({ statusFilter, appScopeFragment: appScope, selectedIps: [] })
      });
      if (!payload.ok) { setIisStatusPivotError(payload.error || 'Failed to start scan.'); return; }
      renderIisStatusPivotSnapshot(payload.snapshot);
      startIisStatusPivotPolling();
    } catch (err) { setIisStatusPivotError(String(err)); }
  }

  function startIisStatusPivotPolling() {
    stopIisStatusPivotPolling();
    iisStatusPivotPolling = setInterval(pollIisStatusPivot, 1500);
  }

  function stopIisStatusPivotPolling() {
    if (iisStatusPivotPolling) { clearInterval(iisStatusPivotPolling); iisStatusPivotPolling = null; }
  }

  async function pollIisStatusPivot() {
    try {
      const snap = await fetchJson('/api/iis/status-pivot/job');
      renderIisStatusPivotSnapshot(snap);
      if (snap.state !== 'running') stopIisStatusPivotPolling();
    } catch { stopIisStatusPivotPolling(); }
  }

  function renderIisStatusPivotSnapshot(snap) {
    if (!snap) return;
    const state = snap.state || 'idle';
    const phase = snap.phase || 'idle';
    const currentStep = Number(snap.currentStep || 0);
    const totalSteps = Number(snap.totalSteps || 0);
    const pct = totalSteps > 0 ? Math.round((currentStep / totalSteps) * 100) : 0;
    const eta = computeEta(snap);

    setText('iisStatusPivotState', state);
    setText('iisStatusPivotPhase', phase);
    setText('iisStatusPivotIpCount', String(snap.uniqueErrorIps || 0));
    setText('iisStatusPivotMessage', snap.error ? `${snap.message} ${snap.error}` : (snap.message || ''));
    setText('iisStatusPivotStageBadge', phase);

    // Lock inputs while running
    setIisStatusPivotInputsLocked(state === 'running');

    if (state === 'completed') {
      setText('iisStatusPivotSummary', `${snap.uniqueErrorIps || 0} error IPs found. ${fmt(snap.exportedLines || 0)} lines exported.`);
      setText('iisStatusPivotBarMeta', `100% | ${snap.filesTotal || 0} files`);
      setBar('iisStatusPivotBar', 1, 1);
    } else if (state === 'failed') {
      setText('iisStatusPivotSummary', 'Scan failed.');
      setText('iisStatusPivotBarMeta', snap.error || '');
    } else if (state === 'running') {
      setText('iisStatusPivotSummary', `${pct}% — ${snap.filesProcessed || 0} / ${snap.filesTotal || 0} files`);
      setText('iisStatusPivotBarMeta', `${pct}% | ETA ${eta} | ${snap.filesProcessed || 0} / ${snap.filesTotal || 0} files`);
      setBar('iisStatusPivotBar', currentStep, totalSteps);
    } else {
      setText('iisStatusPivotSummary', 'Waiting for a scan to start.');
      setText('iisStatusPivotBarMeta', 'No scan running.');
    }

    // Export button
    const hasExport = Boolean(snap.exportPath);
    ['iisStatusPivotOpenExport', 'iisStatusPivotResultsOpenExport'].forEach(id => {
      const btn = byId(id);
      if (btn) { btn.disabled = !hasExport; btn.classList.toggle('primary', hasExport); }
    });
    const exportInfo = byId('iisStatusPivotExportInfo');
    if (exportInfo) {
      exportInfo.textContent = hasExport ? `Exported: ${snap.exportPath}` : '';
    }

    renderIisStatusPivotResults(snap);

    // Auto-scroll to results on completion
    if (state === 'completed') {
      const resultsEl = byId('iisStatusPivotResults');
      if (resultsEl && !resultsEl.hidden) {
        setTimeout(() => resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200);
      }
    }
  }

  function setIisStatusPivotInputsLocked(locked) {
    ['iisStatusPivotRun'].forEach(id => {
      const el = byId(id);
      if (el) el.disabled = locked;
    });
    document.querySelectorAll('.iis-pivot-filter-btn').forEach(btn => { btn.disabled = locked; });
    const codesInput = byId('iisStatusPivotCodesInput');
    if (codesInput) codesInput.disabled = locked;
    const appScope = byId('iisStatusPivotAppScope');
    if (appScope) appScope.disabled = locked;
  }

  function renderIisStatusPivotResults(snap) {
    const resultsSection = byId('iisStatusPivotResults');
    const topIpsContainer = byId('iisStatusPivotTopIps');
    const pivotContainer = byId('iisStatusPivotPivotResults');
    if (!resultsSection || !topIpsContainer || !pivotContainer) return;

    if (snap.state !== 'completed' || !snap.topErrorIps || snap.topErrorIps.length === 0) {
      setHidden(resultsSection, true);
      return;
    }

    setHidden(resultsSection, false);

    // Top error IPs
    topIpsContainer.innerHTML = snap.topErrorIps.map(ip => {
      const statusEntries = ip.statusCounts ? Object.entries(ip.statusCounts)
        .sort((a, b) => b[1] - a[1])
        .map(([code, count]) => `<span class="status-pill"><span>${escHtml(code)}</span><strong>${fmt(count)}</strong></span>`)
        .join('') : '';

      const uriRows = (ip.topUris || []).map(u =>
        `<li style="font-family:monospace;word-break:break-all">${escHtml(u.uri)} <strong>${fmt(u.count)}</strong></li>`
      ).join('');

      return `
        <details class="expandable-panel">
          <summary>${escHtml(ip.ip)} — ${fmt(ip.totalHits)} error hits</summary>
          <div class="expandable-body">
            <div class="status-block">${statusEntries}</div>
            ${uriRows ? `<ul class="list-clean">${uriRows}</ul>` : ''}
          </div>
        </details>`;
    }).join('');

    // Pivot results (2xx/3xx traffic for error IPs)
    if (!snap.pivotResults || snap.pivotResults.length === 0) {
      pivotContainer.innerHTML = '<div class="footer-note">No 2xx/3xx pivot data available.</div>';
      return;
    }

    pivotContainer.innerHTML = snap.pivotResults.map(ip => {
      const uriRows = (ip.topUris || []).map(u =>
        `<li style="font-family:monospace;word-break:break-all">${escHtml(u.uri)} <strong>${fmt(u.count)}</strong></li>`
      ).join('');

      return `
        <details class="expandable-panel">
          <summary>${escHtml(ip.ip)} — 2xx: ${fmt(ip.total2xx)}, 3xx: ${fmt(ip.total3xx)}</summary>
          <div class="expandable-body">
            ${uriRows ? `<ul class="list-clean">${uriRows}</ul>` : '<div class="footer-note">No 2xx/3xx hits.</div>'}
          </div>
        </details>`;
    }).join('');
  }

  function initializeIisStatusPivotPage() {
    if (!document.querySelector('[data-iis-status-pivot-page]')) return;

    document.querySelectorAll('.iis-pivot-filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        setIisStatusPivotFilter(btn.getAttribute('data-filter') || '4xx');
      });
    });

    byId('iisStatusPivotRun')?.addEventListener('click', runIisStatusPivot);

    const openPivotExport = async () => {
      try { await fetchJson('/api/iis/status-pivot/open-export', { method: 'POST' }); }
      catch (err) { setIisStatusPivotError(String(err)); }
    };
    byId('iisStatusPivotOpenExport')?.addEventListener('click', openPivotExport);
    byId('iisStatusPivotResultsOpenExport')?.addEventListener('click', openPivotExport);

    loadIisStatusPivotMeta().catch(err => setIisStatusPivotError(String(err)));
  }

  // ── IIS Burst Patterns ─────────────────────────────────────────

  let iisBurstPolling = null;

  function setIisBurstError(msg) {
    const node = byId('iisBurstError');
    if (!node) return;
    node.textContent = msg || '';
    node.hidden = !msg;
  }

  async function loadIisBurstMeta() {
    const payload = await fetchJson('/api/iis/burst-patterns/meta');
    if (payload.currentJob) {
      renderIisBurstSnapshot(payload.currentJob);
      if (payload.currentJob.state === 'running') startIisBurstPolling();
    }
  }

  async function runIisBurst() {
    setIisBurstError('');
    const bucketSeconds = parseInt(byId('iisBurstBucket')?.value || '60', 10);

    try {
      const payload = await fetchJson('/api/iis/burst-patterns/run', {
        method: 'POST',
        body: JSON.stringify({ bucketSeconds })
      });
      if (!payload.ok) { setIisBurstError(payload.error || 'Failed to start scan.'); return; }
      renderIisBurstSnapshot(payload.snapshot);
      startIisBurstPolling();
    } catch (err) { setIisBurstError(String(err)); }
  }

  function startIisBurstPolling() {
    stopIisBurstPolling();
    iisBurstPolling = setInterval(pollIisBurst, 2000);
  }

  function stopIisBurstPolling() {
    if (iisBurstPolling) { clearInterval(iisBurstPolling); iisBurstPolling = null; }
  }

  async function pollIisBurst() {
    try {
      const snap = await fetchJson('/api/iis/burst-patterns/job');
      renderIisBurstSnapshot(snap);
      if (snap.state !== 'running') stopIisBurstPolling();
    } catch { stopIisBurstPolling(); }
  }

  function renderIisBurstSnapshot(snap) {
    if (!snap) return;
    const state = snap.state || 'idle';
    const phase = snap.phase || 'idle';
    const currentStep = Number(snap.currentStep || 0);
    const totalSteps = Number(snap.totalSteps || 0);
    const pct = totalSteps > 0 ? Math.round((currentStep / totalSteps) * 100) : 0;
    const eta = computeEta(snap);

    setText('iisBurstState', state);
    setText('iisBurstPhase', phase);
    setText('iisBurstCandidates', String(snap.candidateCount || 0));
    setText('iisBurstMessage', snap.error ? `${snap.message} ${snap.error}` : (snap.message || ''));
    setText('iisBurstStageBadge', phase);

    // Lock inputs while running
    setIisBurstInputsLocked(state === 'running');

    if (state === 'completed') {
      setText('iisBurstSummary', `${snap.candidateCount || 0} burst candidates found.`);
      setText('iisBurstBarMeta', `100% | ${snap.filesTotal || 0} files`);
      setBar('iisBurstBar', 1, 1);
    } else if (state === 'failed') {
      setText('iisBurstSummary', 'Scan failed.');
      setText('iisBurstBarMeta', snap.error || '');
    } else if (state === 'running') {
      setText('iisBurstSummary', `${pct}% — ${snap.filesProcessed || 0} / ${snap.filesTotal || 0} files`);
      setText('iisBurstBarMeta', `${pct}% | ETA ${eta} | ${snap.filesProcessed || 0} / ${snap.filesTotal || 0} files`);
      setBar('iisBurstBar', currentStep, totalSteps);
    } else {
      setText('iisBurstSummary', 'Waiting for a scan to start.');
      setText('iisBurstBarMeta', 'No scan running.');
    }

    renderIisBurstResults(snap);

    // Auto-scroll to results on completion
    if (state === 'completed') {
      const resultsEl = byId('iisBurstResults');
      if (resultsEl && !resultsEl.hidden) {
        setTimeout(() => resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200);
      }
    }
  }

  function setIisBurstInputsLocked(locked) {
    const el = byId('iisBurstRun');
    if (el) el.disabled = locked;
    const bucket = byId('iisBurstBucket');
    if (bucket) bucket.disabled = locked;
  }

  function renderIisBurstResults(snap) {
    const section = byId('iisBurstResults');
    const container = byId('iisBurstTable');
    if (!section || !container) return;

    if (snap.state !== 'completed' || !snap.bursts || snap.bursts.length === 0) {
      setHidden(section, true);
      return;
    }

    setHidden(section, false);

    const severityColor = (label) => {
      if (!label) return '';
      const lower = label.toLowerCase();
      if (lower.includes('critical')) return 'color:#f87171';
      if (lower.includes('high')) return 'color:#fb923c';
      if (lower.includes('medium') || lower.includes('elevated')) return 'color:#fbbf24';
      return '';
    };

    container.innerHTML = `
      <table class="mini-table" style="font-size:12px">
        <thead>
          <tr>
            <th>#</th><th>Start (UTC)</th><th>IP</th><th>Score</th><th>Severity</th>
            <th>Flags</th><th>Dyn</th><th>Uniq</th><th>4xx%</th>
            <th>POST</th><th>HEAD</th><th>Avg ms</th><th>Max ms</th>
            <th>2xx</th><th>3xx</th><th>4xx</th><th>5xx</th>
          </tr>
        </thead>
        <tbody>
          ${snap.bursts.map(b => `
            <tr>
              <td>${b.rank}</td>
              <td style="white-space:nowrap">${escHtml(b.startUtc)}</td>
              <td style="white-space:nowrap">${escHtml(b.ip)}</td>
              <td><strong>${b.severityScore}</strong></td>
              <td style="${severityColor(b.severityLabel)}">${escHtml(b.severityLabel)}</td>
              <td style="font-family:monospace;font-size:11px">${escHtml(b.flags)}</td>
              <td>${fmt(b.totalDynamic)}</td>
              <td>${b.uniqueDynamicUris}</td>
              <td>${Number(b.fourxxPct || 0).toFixed(0)}%</td>
              <td>${b.post}</td>
              <td>${b.head}</td>
              <td>${fmt(b.avgMs)}</td>
              <td>${fmt(b.maxMs)}</td>
              <td>${fmt(b.c2xx)}</td>
              <td>${fmt(b.c3xx)}</td>
              <td>${fmt(b.c4xx)}</td>
              <td>${fmt(b.c5xx)}</td>
            </tr>`).join('')}
        </tbody>
      </table>`;
  }

  function initializeIisBurstPatternsPage() {
    if (!document.querySelector('[data-iis-burst-patterns-page]')) return;

    byId('iisBurstRun')?.addEventListener('click', runIisBurst);
    loadIisBurstMeta().catch(err => setIisBurstError(String(err)));
  }

  // ── IIS Bytes Intel (bandwidth + uploads) ──────────────────────

  let iisBytesIntelPolling = null;
  let iisBytesIntelMode = '';

  function getBytesIntelPrefix() {
    return iisBytesIntelMode === 'uploads' ? 'iisUploads' : 'iisBandwidth';
  }

  function setIisBytesIntelError(msg) {
    const prefix = getBytesIntelPrefix();
    const node = byId(`${prefix}Error`);
    if (!node) return;
    node.textContent = msg || '';
    node.hidden = !msg;
  }

  async function loadIisBytesIntelMeta() {
    const payload = await fetchJson('/api/iis/bytes-intel/meta');
    if (payload.currentJob) {
      renderIisBytesIntelSnapshot(payload.currentJob);
      if (payload.currentJob.state === 'running') startIisBytesIntelPolling();
    }
  }

  async function runIisBytesIntel() {
    setIisBytesIntelError('');
    try {
      const payload = await fetchJson('/api/iis/bytes-intel/run', {
        method: 'POST',
        body: JSON.stringify({ mode: iisBytesIntelMode })
      });
      if (!payload.ok) { setIisBytesIntelError(payload.error || 'Failed to start scan.'); return; }
      renderIisBytesIntelSnapshot(payload.snapshot);
      startIisBytesIntelPolling();
    } catch (err) { setIisBytesIntelError(String(err)); }
  }

  function startIisBytesIntelPolling() {
    stopIisBytesIntelPolling();
    iisBytesIntelPolling = setInterval(pollIisBytesIntel, 1500);
  }

  function stopIisBytesIntelPolling() {
    if (iisBytesIntelPolling) { clearInterval(iisBytesIntelPolling); iisBytesIntelPolling = null; }
  }

  async function pollIisBytesIntel() {
    try {
      const snap = await fetchJson('/api/iis/bytes-intel/job');
      renderIisBytesIntelSnapshot(snap);
      if (snap.state !== 'running') stopIisBytesIntelPolling();
    } catch { stopIisBytesIntelPolling(); }
  }

  function renderIisBytesIntelSnapshot(snap) {
    if (!snap) return;
    const prefix = getBytesIntelPrefix();
    const state = snap.state || 'idle';
    const phase = snap.phase || 'idle';
    const currentStep = Number(snap.currentStep || 0);
    const totalSteps = Number(snap.totalSteps || 0);
    const pct = totalSteps > 0 ? Math.round((currentStep / totalSteps) * 100) : 0;
    const eta = computeEta(snap);

    setText(`${prefix}State`, state);
    setText(`${prefix}Phase`, phase);
    setText(`${prefix}Message`, snap.error ? `${snap.message} ${snap.error}` : (snap.message || ''));
    setText(`${prefix}StageBadge`, phase);

    // Lock inputs while running
    setIisBytesIntelInputsLocked(state === 'running');

    if (state === 'completed') {
      const ipCount = snap.topIps ? snap.topIps.length : 0;
      setText(`${prefix}Summary`, `${ipCount} IPs found.`);
      setText(`${prefix}BarMeta`, `100% | ${snap.filesTotal || 0} files`);
      setBar(`${prefix}Bar`, 1, 1);
    } else if (state === 'failed') {
      setText(`${prefix}Summary`, 'Scan failed.');
      setText(`${prefix}BarMeta`, snap.error || '');
    } else if (state === 'running') {
      setText(`${prefix}Summary`, `${pct}% — ${snap.filesProcessed || 0} / ${snap.filesTotal || 0} files`);
      setText(`${prefix}BarMeta`, `${pct}% | ETA ${eta} | ${snap.filesProcessed || 0} / ${snap.filesTotal || 0} files`);
      setBar(`${prefix}Bar`, currentStep, totalSteps);
    } else {
      setText(`${prefix}Summary`, 'Waiting for a scan to start.');
      setText(`${prefix}BarMeta`, 'No scan running.');
    }

    // Export button
    const hasExport2 = Boolean(snap.exportPath);
    [`${prefix}OpenExport`, `${prefix}ResultsOpenExport`].forEach(id => {
      const btn = byId(id);
      if (btn) { btn.disabled = !hasExport2; btn.classList.toggle('primary', hasExport2); }
    });
    const exportInfo = byId(`${prefix}ExportInfo`);
    if (exportInfo) exportInfo.textContent = hasExport2 ? `Exported: ${snap.exportPath}` : '';

    renderIisBytesIntelResults(snap, prefix);

    // Auto-scroll to results on completion
    if (state === 'completed') {
      const resultsEl = byId(`${prefix}Results`);
      if (resultsEl && !resultsEl.hidden) {
        setTimeout(() => resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200);
      }
    }
  }

  function setIisBytesIntelInputsLocked(locked) {
    const prefix = getBytesIntelPrefix();
    const el = byId(`${prefix}Run`);
    if (el) el.disabled = locked;
  }

  function renderIisBytesIntelResults(snap, prefix) {
    const section = byId(`${prefix}Results`);
    const container = byId(`${prefix}TopIps`);
    if (!section || !container) return;

    if (snap.state !== 'completed' || !snap.topIps || snap.topIps.length === 0) {
      setHidden(section, true);
      return;
    }

    setHidden(section, false);
    const isBandwidth = iisBytesIntelMode === 'bandwidth';
    const bytesLabel = isBandwidth ? 'sc-bytes' : 'cs-bytes';

    container.innerHTML = snap.topIps.map(ip => {
      const primaryBytes = isBandwidth ? ip.totalScBytes : ip.totalCsBytes;
      const uriRows = (ip.topUris || []).map(u =>
        `<li style="font-family:monospace;word-break:break-all">${escHtml(u.uri)} — ${formatBytes(u.bytes)} (${fmt(u.hits)} hits)</li>`
      ).join('');

      return `
        <details class="expandable-panel">
          <summary>#${ip.rank} ${escHtml(ip.ip)} — ${formatBytes(primaryBytes)} (${fmt(ip.hits)} hits)</summary>
          <div class="expandable-body">
            <div class="status-block">
              <div class="status-pill"><span>${bytesLabel}</span><strong>${formatBytes(primaryBytes)}</strong></div>
              <div class="status-pill"><span>Hits</span><strong>${fmt(ip.hits)}</strong></div>
              <div class="status-pill"><span>2xx</span><strong>${fmt(ip.c2xx)}</strong></div>
              <div class="status-pill"><span>3xx</span><strong>${fmt(ip.c3xx)}</strong></div>
              <div class="status-pill"><span>4xx</span><strong>${fmt(ip.c4xx)}</strong></div>
              <div class="status-pill"><span>5xx</span><strong>${fmt(ip.c5xx)}</strong></div>
            </div>
            ${uriRows ? `<ul class="list-clean">${uriRows}</ul>` : '<div class="footer-note">No URI breakdown available.</div>'}
          </div>
        </details>`;
    }).join('');
  }

  function initializeIisBytesIntelPage() {
    const section = document.querySelector('[data-iis-bytes-intel-page]');
    if (!section) return;

    iisBytesIntelMode = section.getAttribute('data-iis-bytes-mode') || 'bandwidth';
    const prefix = getBytesIntelPrefix();

    byId(`${prefix}Run`)?.addEventListener('click', runIisBytesIntel);

    const openBytesExport = async () => {
      try { await fetchJson('/api/iis/bytes-intel/open-export', { method: 'POST' }); }
      catch (err) { setIisBytesIntelError(String(err)); }
    };
    byId(`${prefix}OpenExport`)?.addEventListener('click', openBytesExport);
    byId(`${prefix}ResultsOpenExport`)?.addEventListener('click', openBytesExport);

    loadIisBytesIntelMeta().catch(err => setIisBytesIntelError(String(err)));
  }

  // ── Bootstrap ───────────────────────────────────────────────────

  function initializeAll() {
    initializeIisIpSummaryPage();
    initializeIisStatusPivotPage();
    initializeIisBurstPatternsPage();
    initializeIisBytesIntelPage();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAll);
  } else {
    initializeAll();
  }
})();
