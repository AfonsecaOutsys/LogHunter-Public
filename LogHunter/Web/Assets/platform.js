(function () {
  function byId(id) {
    return document.getElementById(id);
  }

  function setHidden(element, hidden) {
    if (element) {
      element.hidden = hidden;
    }
  }

  function setText(id, value) {
    var node = byId(id);
    if (node) {
      node.textContent = value;
    }
  }

  function escHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function fmt(v) {
    return Number(v || 0).toLocaleString('en-US');
  }

  function formatEta(seconds) {
    var value = Number(seconds);
    if (!Number.isFinite(value) || value < 0) {
      return 'n/a';
    }
    if (value < 60) {
      return Math.round(value) + 's';
    }
    var minutes = Math.floor(value / 60);
    var remainingSeconds = Math.round(value % 60);
    if (minutes < 60) {
      return minutes + 'm ' + remainingSeconds + 's';
    }
    var hours = Math.floor(minutes / 60);
    return hours + 'h ' + (minutes % 60) + 'm';
  }

  async function fetchJson(url, options) {
    var response = await fetch(url, {
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      ...options
    });
    var payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || 'HTTP ' + response.status);
    }
    return payload;
  }

  // ── Suspicious requests: extract IPs ──────────────────────────

  var suspiciousPolling = null;

  function setSuspiciousError(msg) {
    var node = byId('platformSuspiciousError');
    if (!node) return;
    node.textContent = msg || '';
    node.hidden = !msg;
  }

  function renderSuspiciousSnapshot(snap) {
    if (!snap) return;

    var state = snap.state || 'idle';
    var phase = snap.phase || 'idle';
    var currentStep = Number(snap.currentStep || 0);
    var totalSteps = Number(snap.totalSteps || 0);
    var createdUtc = snap.createdUtc ? new Date(snap.createdUtc) : null;
    var now = new Date();

    setText('platformSuspiciousState', state);
    setText('platformSuspiciousPhase', phase);
    setText('platformSuspiciousMatchedRows', fmt(snap.matchedRows));
    setText('platformSuspiciousDistinctIps', fmt(snap.distinctIps));
    setText('platformSuspiciousMessage', snap.error ? (snap.message + ' ' + snap.error) : (snap.message || ''));
    setText('platformSuspiciousStageBadge', phase);

    var pct = totalSteps > 0 ? Math.round((currentStep / totalSteps) * 100) : 0;
    var bar = byId('platformSuspiciousBar');
    if (bar) bar.style.width = pct + '%';

    var etaText = 'n/a';
    if (state === 'running' && createdUtc && !Number.isNaN(createdUtc.getTime()) && currentStep > 0 && totalSteps > currentStep) {
      var elapsedSeconds = Math.max(1, (now.getTime() - createdUtc.getTime()) / 1000);
      var secondsPerStep = elapsedSeconds / currentStep;
      etaText = formatEta(secondsPerStep * (totalSteps - currentStep));
    }

    if (state === 'completed') {
      setText('platformSuspiciousSummary', 'Scan complete.');
      setText('platformSuspiciousBarMeta', '100% | ' + fmt(snap.filesScanned) + ' files scanned');
      if (bar) bar.style.width = '100%';
    } else if (state === 'failed') {
      setText('platformSuspiciousSummary', 'Scan failed.');
      setText('platformSuspiciousBarMeta', snap.error || '');
    } else if (state === 'running') {
      setText('platformSuspiciousSummary', pct + '% complete');
      setText('platformSuspiciousBarMeta', pct + '% | ETA ' + etaText);
    } else {
      setText('platformSuspiciousSummary', 'Waiting for a scan to start.');
      setText('platformSuspiciousBarMeta', 'No scan running.');
    }

    var meta = byId('platformSuspiciousMeta');
    if (meta && state === 'completed') {
      meta.textContent = 'Files scanned: ' + fmt(snap.filesScanned) + ' | Files matched: ' + fmt(snap.filesMatched) +
        ' | XFF: ' + fmt(snap.rowsWithXff) + ' | ClientIp only: ' + fmt(snap.rowsWithoutXff);
    }

    renderSuspiciousResults(snap);
  }

  function renderSuspiciousResults(snap) {
    var section = byId('platformSuspiciousResults');
    if (!section) return;

    if (snap.state !== 'completed' || snap.matchedRows === 0) {
      setHidden(section, snap.state !== 'completed');
      if (snap.state === 'completed') {
        setHidden(section, false);
        var overview = byId('platformSuspiciousOverview');
        if (overview) overview.innerHTML = '<div class="footer-note">No suspicious rows matched.</div>';
      }
      return;
    }

    setHidden(section, false);

    // Overview pills
    var overview = byId('platformSuspiciousOverview');
    if (overview) {
      overview.innerHTML =
        '<div class="status-pill"><span>Matched rows</span><strong>' + fmt(snap.matchedRows) + '</strong></div>' +
        '<div class="status-pill"><span>Distinct IPs</span><strong>' + fmt(snap.distinctIps) + '</strong></div>' +
        '<div class="status-pill"><span>Files matched</span><strong>' + fmt(snap.filesMatched) + '</strong></div>' +
        '<div class="status-pill"><span>Used XFF</span><strong>' + fmt(snap.rowsWithXff) + '</strong></div>' +
        '<div class="status-pill"><span>ClientIp only</span><strong>' + fmt(snap.rowsWithoutXff) + '</strong></div>';
    }

    var cacheMeta = byId('platformSuspiciousCacheMeta');
    if (cacheMeta) {
      cacheMeta.textContent = 'Selections: ' + snap.selectionsAdded + ' added, ' + snap.selectionsUpdated + ' updated. Suspicious IP cache: ' + snap.cachedIpCount + ' IP(s).';
    }

    // Error type breakdown
    var errorTypesContainer = byId('platformSuspiciousErrorTypes');
    if (errorTypesContainer) {
      var types = snap.byErrorType || [];
      if (types.length === 0) {
        errorTypesContainer.innerHTML = '<div class="footer-note">No error types matched.</div>';
      } else {
        errorTypesContainer.innerHTML =
          '<table class="mini-table"><thead><tr><th>Error type</th><th style="text-align:right">Rows</th><th style="text-align:right">Distinct IPs</th></tr></thead><tbody>' +
          types.map(function(t) {
            return '<tr><td>' + escHtml(t.errorType) + '</td><td style="text-align:right">' + fmt(t.rows) + '</td><td style="text-align:right">' + fmt(t.distinctIps) + '</td></tr>';
          }).join('') +
          '</tbody></table>';
      }
    }

    // Top IPs overall
    var topIpsContainer = byId('platformSuspiciousTopIps');
    if (topIpsContainer) {
      var ips = snap.topIpsOverall || [];
      if (ips.length === 0) {
        topIpsContainer.innerHTML = '<div class="footer-note">No IPs found.</div>';
      } else {
        topIpsContainer.innerHTML =
          '<table class="mini-table"><thead><tr><th style="text-align:right">#</th><th>IP</th><th style="text-align:right">Hits</th></tr></thead><tbody>' +
          ips.map(function(ip) {
            return '<tr><td style="text-align:right">' + ip.rank + '</td><td>' + escHtml(ip.ip) + '</td><td style="text-align:right">' + fmt(ip.hits) + '</td></tr>';
          }).join('') +
          '</tbody></table>';
      }
    }

    // Per-error-type sections
    var perTypeSection = byId('platformSuspiciousPerTypeSection');
    if (perTypeSection) {
      var perType = snap.topIpsByErrorType || {};
      var typeNames = Object.keys(perType).sort();
      if (typeNames.length === 0) {
        setHidden(perTypeSection, true);
      } else {
        setHidden(perTypeSection, false);
        perTypeSection.innerHTML = typeNames.map(function(typeName) {
          var items = perType[typeName] || [];
          return '<section class="panel"><div class="section-heading"><div><div class="eyebrow">Per-type breakdown</div><h2>Top IPs: ' + escHtml(typeName) + '</h2></div></div>' +
            '<div class="result-summary-body"><table class="mini-table"><thead><tr><th style="text-align:right">#</th><th>IP</th><th style="text-align:right">Hits</th></tr></thead><tbody>' +
            items.map(function(ip) {
              return '<tr><td style="text-align:right">' + ip.rank + '</td><td>' + escHtml(ip.ip) + '</td><td style="text-align:right">' + fmt(ip.hits) + '</td></tr>';
            }).join('') +
            '</tbody></table></div></section>';
        }).join('');
      }
    }
  }

  function startSuspiciousPolling() {
    stopSuspiciousPolling();
    suspiciousPolling = setInterval(pollSuspiciousJob, 1500);
  }

  function stopSuspiciousPolling() {
    if (suspiciousPolling) {
      clearInterval(suspiciousPolling);
      suspiciousPolling = null;
    }
  }

  async function pollSuspiciousJob() {
    try {
      var snapshot = await fetchJson('/api/platform/suspicious/job', { method: 'GET', headers: { 'Accept': 'application/json' } });
      renderSuspiciousSnapshot(snapshot);
      if (snapshot.state !== 'running') {
        stopSuspiciousPolling();
      }
    } catch (err) {
      stopSuspiciousPolling();
    }
  }

  async function runSuspiciousScan() {
    setSuspiciousError('');
    setText('platformSuspiciousState', 'running');
    setText('platformSuspiciousPhase', 'queued');
    setText('platformSuspiciousMessage', 'Starting suspicious request scan...');
    setHidden(byId('platformSuspiciousResults'), true);

    try {
      var payload = await fetchJson('/api/platform/suspicious/run', {
        method: 'POST'
      });

      if (!payload.ok) {
        setSuspiciousError(payload.error || 'Failed to start scan.');
        setText('platformSuspiciousState', 'idle');
        return;
      }

      renderSuspiciousSnapshot(payload.snapshot);
      startSuspiciousPolling();
    } catch (err) {
      setSuspiciousError(String(err));
      setText('platformSuspiciousState', 'idle');
    }
  }

  async function loadSuspiciousMeta() {
    var payload = await fetchJson('/api/platform/suspicious/meta', { method: 'GET', headers: { 'Accept': 'application/json' } });

    if (payload.currentJob) {
      renderSuspiciousSnapshot(payload.currentJob);
      if (payload.currentJob.state === 'running') {
        startSuspiciousPolling();
      }
    }
  }

  function initializeSuspiciousPage() {
    if (!document.querySelector('[data-platform-suspicious-page]')) return;

    byId('platformSuspiciousRun')?.addEventListener('click', runSuspiciousScan);
    loadSuspiciousMeta().catch(function(err) { setSuspiciousError(String(err)); });
  }

  // ── Authenticated activity check ──────────────────────────────

  var authPolling = null;

  function setAuthError(msg) {
    var node = byId('platformAuthError');
    if (!node) return;
    node.textContent = msg || '';
    node.hidden = !msg;
  }

  function renderAuthSnapshot(snap) {
    if (!snap) return;

    var state = snap.state || 'idle';
    var phase = snap.phase || 'idle';
    var currentStep = Number(snap.currentStep || 0);
    var totalSteps = Number(snap.totalSteps || 0);
    var createdUtc = snap.createdUtc ? new Date(snap.createdUtc) : null;
    var now = new Date();

    setText('platformAuthState', state);
    setText('platformAuthPhase', phase);
    setText('platformAuthTotalHits', fmt(snap.totalMatchedRows));
    setText('platformAuthMatchedIps', fmt(snap.distinctMatchedIps));
    setText('platformAuthMessage', snap.error ? (snap.message + ' ' + snap.error) : (snap.message || ''));
    setText('platformAuthStageBadge', phase);

    var pct = totalSteps > 0 ? Math.round((currentStep / totalSteps) * 100) : 0;
    var bar = byId('platformAuthBar');
    if (bar) bar.style.width = pct + '%';

    var etaText = 'n/a';
    if (state === 'running' && createdUtc && !Number.isNaN(createdUtc.getTime()) && currentStep > 0 && totalSteps > currentStep) {
      var elapsedSeconds = Math.max(1, (now.getTime() - createdUtc.getTime()) / 1000);
      var secondsPerStep = elapsedSeconds / currentStep;
      etaText = formatEta(secondsPerStep * (totalSteps - currentStep));
    }

    if (state === 'completed') {
      setText('platformAuthSummary', 'Check complete.');
      setText('platformAuthBarMeta', '100% | ' + fmt(snap.filesScanned) + ' files scanned');
      if (bar) bar.style.width = '100%';
    } else if (state === 'failed') {
      setText('platformAuthSummary', 'Check failed.');
      setText('platformAuthBarMeta', snap.error || '');
    } else if (state === 'running') {
      setText('platformAuthSummary', pct + '% complete');
      setText('platformAuthBarMeta', pct + '% | ETA ' + etaText);
    } else {
      setText('platformAuthSummary', 'Waiting for a check to start.');
      setText('platformAuthBarMeta', 'No check running.');
    }

    var meta = byId('platformAuthMeta');
    if (meta && state === 'completed') {
      meta.textContent = 'Suspicious IPs input: ' + fmt(snap.suspiciousIpsInput) +
        ' | Files scanned: ' + fmt(snap.filesScanned) + ' | Files matched: ' + fmt(snap.filesMatched);
    }

    renderAuthResults(snap);
  }

  function renderAuthResults(snap) {
    var section = byId('platformAuthResults');
    if (!section) return;

    if (snap.state !== 'completed') {
      setHidden(section, true);
      return;
    }

    setHidden(section, false);

    // Overview pills
    var overview = byId('platformAuthOverview');
    if (overview) {
      overview.innerHTML =
        '<div class="status-pill"><span>Suspicious IPs (input)</span><strong>' + fmt(snap.suspiciousIpsInput) + '</strong></div>' +
        '<div class="status-pill"><span>Auth hits</span><strong>' + fmt(snap.totalMatchedRows) + '</strong></div>' +
        '<div class="status-pill"><span>Matched IPs</span><strong>' + fmt(snap.distinctMatchedIps) + '</strong></div>' +
        '<div class="status-pill"><span>Files matched</span><strong>' + fmt(snap.filesMatched) + '</strong></div>';
    }

    var cacheMeta = byId('platformAuthCacheMeta');
    if (cacheMeta) {
      cacheMeta.textContent = 'Authenticated IP cache updated: ' + snap.cachedIpCount + ' IP(s).';
    }

    // Hits by kind
    var byKindContainer = byId('platformAuthByKind');
    if (byKindContainer) {
      var kinds = snap.rowsByKind || {};
      var kindNames = ['General', 'Traditional', 'Screen', 'Error'];
      byKindContainer.innerHTML =
        '<table class="mini-table"><thead><tr><th>Log type</th><th style="text-align:right">Auth hits</th></tr></thead><tbody>' +
        kindNames.map(function(k) {
          return '<tr><td>' + escHtml(k) + '</td><td style="text-align:right">' + fmt(kinds[k]) + '</td></tr>';
        }).join('') +
        '</tbody></table>';
    }

    // Top IPs
    var topIpsContainer = byId('platformAuthTopIps');
    if (topIpsContainer) {
      var ips = snap.topIps || [];
      if (ips.length === 0) {
        topIpsContainer.innerHTML = '<div class="footer-note">No authenticated IPs found.</div>';
      } else {
        topIpsContainer.innerHTML =
          '<table class="mini-table"><thead><tr><th style="text-align:right">#</th><th>IP</th><th style="text-align:right">Total</th><th style="text-align:right">General</th><th style="text-align:right">Traditional</th><th style="text-align:right">Screen</th><th style="text-align:right">Error</th></tr></thead><tbody>' +
          ips.map(function(ip) {
            return '<tr><td style="text-align:right">' + ip.rank + '</td><td>' + escHtml(ip.ip) + '</td><td style="text-align:right">' + fmt(ip.total) + '</td><td style="text-align:right">' + fmt(ip.general) + '</td><td style="text-align:right">' + fmt(ip.traditional) + '</td><td style="text-align:right">' + fmt(ip.screen) + '</td><td style="text-align:right">' + fmt(ip.error) + '</td></tr>';
          }).join('') +
          '</tbody></table>';
      }
    }
  }

  function startAuthPolling() {
    stopAuthPolling();
    authPolling = setInterval(pollAuthJob, 1500);
  }

  function stopAuthPolling() {
    if (authPolling) {
      clearInterval(authPolling);
      authPolling = null;
    }
  }

  async function pollAuthJob() {
    try {
      var snapshot = await fetchJson('/api/platform/auth/job', { method: 'GET', headers: { 'Accept': 'application/json' } });
      renderAuthSnapshot(snapshot);
      if (snapshot.state !== 'running') {
        stopAuthPolling();
      }
    } catch (err) {
      stopAuthPolling();
    }
  }

  async function runAuthCheck() {
    setAuthError('');
    setText('platformAuthState', 'running');
    setText('platformAuthPhase', 'queued');
    setText('platformAuthMessage', 'Starting authenticated activity check...');
    setHidden(byId('platformAuthResults'), true);

    try {
      var payload = await fetchJson('/api/platform/auth/run', {
        method: 'POST'
      });

      if (!payload.ok) {
        setAuthError(payload.error || 'Failed to start check.');
        setText('platformAuthState', 'idle');
        return;
      }

      renderAuthSnapshot(payload.snapshot);
      startAuthPolling();
    } catch (err) {
      setAuthError(String(err));
      setText('platformAuthState', 'idle');
    }
  }

  async function loadAuthMeta() {
    var payload = await fetchJson('/api/platform/auth/meta', { method: 'GET', headers: { 'Accept': 'application/json' } });

    setText('platformAuthSuspiciousCount', fmt(payload.suspiciousCacheCount));
    setText('platformAuthAuthedCount', fmt(payload.authedCacheCount));

    if (payload.currentJob) {
      renderAuthSnapshot(payload.currentJob);
      if (payload.currentJob.state === 'running') {
        startAuthPolling();
      }
    }
  }

  function initializeAuthPage() {
    if (!document.querySelector('[data-platform-auth-page]')) return;

    byId('platformAuthRun')?.addEventListener('click', runAuthCheck);
    loadAuthMeta().catch(function(err) { setAuthError(String(err)); });
  }

  // ── Authenticated IP cache view ───────────────────────────────

  async function loadCacheData() {
    var payload = await fetchJson('/api/platform/cache', { method: 'GET', headers: { 'Accept': 'application/json' } });

    setText('cacheSuspiciousCount', fmt(payload.suspiciousCount));
    setText('cacheAuthedCount', fmt(payload.authedCount));

    var details = byId('cacheDetails');
    if (!details) return;

    var parts = [];

    if (payload.suspiciousUpdatedUtc) {
      parts.push('<div class="footer-note">Suspicious cache updated: ' + escHtml(payload.suspiciousUpdatedUtc) + '</div>');
    }
    if (payload.authedUpdatedUtc) {
      parts.push('<div class="footer-note">Authenticated cache updated: ' + escHtml(payload.authedUpdatedUtc) + '</div>');
    }

    if (payload.authedIps && payload.authedIps.length > 0) {
      parts.push(
        '<table class="mini-table"><thead><tr><th style="text-align:right">#</th><th>IP</th><th style="text-align:right">Auth hits</th></tr></thead><tbody>' +
        payload.authedIps.map(function(ip) {
          return '<tr><td style="text-align:right">' + ip.rank + '</td><td>' + escHtml(ip.ip) + '</td><td style="text-align:right">' + fmt(ip.hits) + '</td></tr>';
        }).join('') +
        '</tbody></table>'
      );
    } else if (payload.suspiciousIps && payload.suspiciousIps.length > 0) {
      parts.push('<div class="footer-note">No authenticated IPs yet. Showing suspicious IP cache:</div>');
      parts.push(
        '<table class="mini-table"><thead><tr><th style="text-align:right">#</th><th>IP</th><th style="text-align:right">Suspicious hits</th></tr></thead><tbody>' +
        payload.suspiciousIps.map(function(ip) {
          return '<tr><td style="text-align:right">' + ip.rank + '</td><td>' + escHtml(ip.ip) + '</td><td style="text-align:right">' + fmt(ip.hits) + '</td></tr>';
        }).join('') +
        '</tbody></table>'
      );
    } else {
      parts.push('<div class="footer-note">Both caches are empty. Run the suspicious request scan first.</div>');
    }

    details.innerHTML = parts.join('');
  }

  function initializeCachePage() {
    if (!document.querySelector('[data-platform-cache-page]')) return;

    loadCacheData().catch(function(err) {
      var details = byId('cacheDetails');
      if (details) details.innerHTML = '<div class="footer-note">Failed to load cache data.</div>';
    });
  }

  // ── Init ──────────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      initializeSuspiciousPage();
      initializeAuthPage();
      initializeCachePage();
    });
  } else {
    initializeSuspiciousPage();
    initializeAuthPage();
    initializeCachePage();
  }
})();
