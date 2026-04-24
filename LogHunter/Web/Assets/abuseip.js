(function () {
  let abuseipPolling = null;
  let abuseipJobId = '';

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

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');
  }

  function setBar(id, value, total) {
    var node = byId(id);
    if (!node) {
      return;
    }

    var safeTotal = Number(total || 0);
    var safeValue = Number(value || 0);
    var percent = safeTotal > 0 ? Math.max(0, Math.min(100, (safeValue / safeTotal) * 100)) : 0;
    node.style.width = percent + '%';
  }

  function setError(id, message) {
    var node = byId(id);
    if (!node) {
      return;
    }

    if (!message) {
      node.textContent = '';
      node.hidden = true;
      return;
    }

    node.textContent = message;
    node.hidden = false;
  }

  function formatNumber(value) {
    var num = Number(value || 0);
    return num.toLocaleString('en-US');
  }

  function formatBytes(v) {
    var value = Number(v || 0);
    if (!Number.isFinite(value) || value <= 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var size = value, index = 0;
    while (size >= 1024 && index < units.length - 1) { size /= 1024; index++; }
    return (size >= 10 || index === 0 ? Math.round(size) : size.toFixed(1)) + ' ' + units[index];
  }

  var _loadingOverlay = null;
  function showLoading() {
    if (_loadingOverlay) return;
    _loadingOverlay = document.createElement('div');
    _loadingOverlay.className = 'loading-overlay';
    _loadingOverlay.innerHTML = '<div class="loading-spinner"></div>';
    document.body.appendChild(_loadingOverlay);
  }
  function hideLoading() {
    if (_loadingOverlay) { _loadingOverlay.remove(); _loadingOverlay = null; }
  }

  function showIpModal(ips, maxSelect, onConfirm) {
    var selected = new Set(ips.slice(0, maxSelect).map(function (x) { return x.ip; }));
    var overlay = document.createElement('div');
    overlay.className = 'ip-modal-overlay';
    var modal = document.createElement('div');
    modal.className = 'ip-modal';

    var header = document.createElement('div');
    header.className = 'ip-modal-header';
    header.innerHTML = '<h3>Select IPs</h3><div class="ip-modal-info">' +
      ips.length + ' IPs found — select up to ' + maxSelect + '</div>';
    modal.appendChild(header);

    var body = document.createElement('div');
    body.className = 'ip-modal-body';
    modal.appendChild(body);

    var footer = document.createElement('div');
    footer.className = 'ip-modal-footer';
    var countEl = document.createElement('span');
    countEl.className = 'ip-modal-count';
    footer.appendChild(countEl);

    var cancelBtn = document.createElement('button');
    cancelBtn.className = 'button-link button-like compact';
    cancelBtn.type = 'button';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', function () { overlay.remove(); });
    footer.appendChild(cancelBtn);

    var confirmBtn = document.createElement('button');
    confirmBtn.className = 'button-link primary button-like compact';
    confirmBtn.type = 'button';
    confirmBtn.textContent = 'Confirm';
    confirmBtn.addEventListener('click', function () {
      overlay.remove();
      onConfirm(Array.from(selected));
    });
    footer.appendChild(confirmBtn);
    modal.appendChild(footer);
    overlay.appendChild(modal);

    var checkboxes = [];

    function updateState() {
      countEl.textContent = selected.size + ' / ' + maxSelect + ' selected';
      var atMax = selected.size >= maxSelect;
      checkboxes.forEach(function (entry) {
        entry.cb.disabled = !entry.cb.checked && atMax;
      });
    }

    var list = document.createElement('div');
    list.className = 'ip-extract-list';
    ips.forEach(function (item) {
      var label = document.createElement('label');
      label.className = 'ip-extract-item';
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = selected.has(item.ip);
      checkboxes.push({ cb: cb });
      cb.addEventListener('change', function () {
        if (cb.checked) {
          if (selected.size >= maxSelect) { cb.checked = false; return; }
          selected.add(item.ip);
        } else {
          selected.delete(item.ip);
        }
        updateState();
      });
      label.appendChild(cb);
      label.appendChild(document.createTextNode(' ' + item.ip + ' (' + Number(item.hits).toLocaleString('en-US') + ' hits)'));
      list.appendChild(label);
    });
    body.appendChild(list);
    updateState();

    overlay.addEventListener('click', function (e) { if (e.target === overlay) overlay.remove(); });
    document.body.appendChild(overlay);
  }

  // ── Check IPs page ────────────────────────────────────────────────

  var abuseipInputMode = 'manual';
  var abuseipSelectedIpsFromFile = [];
  var abuseipSelectedIpsFromBurst = [];

  function setAbuseipInputMode(mode) {
    abuseipInputMode = mode;
    var btnManual = byId('abuseipModeManual');
    var btnFile = byId('abuseipModeFile');
    var btnBurst = byId('abuseipModeBurst');
    if (btnManual) btnManual.classList.toggle('active', mode === 'manual');
    if (btnFile) btnFile.classList.toggle('active', mode === 'file');
    if (btnBurst) btnBurst.classList.toggle('active', mode === 'burst');
    setHidden(byId('abuseipManualSection'), mode !== 'manual');
    setHidden(byId('abuseipFileSection'), mode !== 'file');
    setHidden(byId('abuseipBurstSection'), mode !== 'burst');
  }

  async function browseAndSelectBurstIps() {
    if (_loadingOverlay) return;
    setError('abuseipError', null);
    showLoading();
    try {
      var payload = await fetch('/api/iis/burst-patterns/ip-cache', {
        headers: { 'Accept': 'application/json' }
      }).then(function (r) { return r.json(); });

      var cache = payload.ips || [];
      if (cache.length === 0) {
        setError('abuseipError', 'No burst results available. Run a Burst Patterns scan first.');
        return;
      }

      var modalIps = cache.map(function (e) { return { ip: e.ip, hits: e.totalHits }; });
      hideLoading();
      showIpModal(modalIps, 100, function (selectedIps) {
        abuseipSelectedIpsFromBurst = selectedIps;
        var chip = byId('abuseipBurstChip');
        if (chip) {
          chip.textContent = selectedIps.length + ' of ' + cache.length + ' IPs selected from burst results';
          chip.hidden = false;
        }
      });
    } catch (err) {
      setError('abuseipError', String(err));
    } finally {
      hideLoading();
    }
  }

  async function browseAndExtractAbuseip() {
    if (_loadingOverlay) return;
    setError('abuseipError', null);
    try {
      var browsePayload = await fetch('/api/abuseip/browse-output-file', {
        method: 'POST',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' }
      }).then(function (r) { return r.json(); });

      if (!browsePayload.ok) {
        if (browsePayload.cancelled) return;
        throw new Error(browsePayload.error || 'Failed to browse file.');
      }

      showLoading();

      var extractPayload = await fetch('/api/abuseip/extract-ips', {
        method: 'POST',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ filePath: browsePayload.file.path })
      }).then(function (r) { return r.json(); });

      if (!extractPayload.ok) {
        setError('abuseipError', extractPayload.error || 'Failed to extract IPs.');
        return;
      }

      var ips = extractPayload.ips || [];
      showIpModal(ips, 100, function (selectedIps) {
        abuseipSelectedIpsFromFile = selectedIps;
        var chip = byId('abuseipFileChip');
        if (chip) {
          chip.textContent = browsePayload.file.name + ' — ' + selectedIps.length + ' of ' + ips.length + ' IPs selected';
          chip.hidden = false;
        }
      });
    } catch (err) {
      setError('abuseipError', String(err));
    } finally {
      hideLoading();
    }
  }

  function getAbuseipIps() {
    if (abuseipInputMode === 'file') return abuseipSelectedIpsFromFile.slice();
    if (abuseipInputMode === 'burst') return abuseipSelectedIpsFromBurst.slice();
    var textarea = byId('abuseipIpText');
    var rawText = textarea ? textarea.value.trim() : '';
    return rawText.split(/[\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
  }

  function initCheckPage() {
    var page = document.querySelector('[data-abuseip-check-page]');
    if (!page) {
      return;
    }

    var keyModeDefault = byId('abuseipKeyDefault');
    var keyModeOverride = byId('abuseipKeyOverride');
    var keyOverrideSection = byId('abuseipKeyOverrideSection');

    if (keyModeDefault && keyModeOverride) {
      keyModeDefault.addEventListener('click', function () {
        keyModeDefault.classList.add('active');
        keyModeOverride.classList.remove('active');
        setHidden(keyOverrideSection, true);
      });

      keyModeOverride.addEventListener('click', function () {
        keyModeOverride.classList.add('active');
        keyModeDefault.classList.remove('active');
        setHidden(keyOverrideSection, false);
      });
    }

    byId('abuseipModeManual')?.addEventListener('click', function () { setAbuseipInputMode('manual'); });
    byId('abuseipModeFile')?.addEventListener('click', function () { setAbuseipInputMode('file'); });
    byId('abuseipModeBurst')?.addEventListener('click', function () { setAbuseipInputMode('burst'); });
    byId('abuseipBrowseFile')?.addEventListener('click', browseAndExtractAbuseip);
    byId('abuseipBrowseBurst')?.addEventListener('click', browseAndSelectBurstIps);

    var runBtn = byId('abuseipRun');
    if (runBtn) {
      runBtn.addEventListener('click', startCheck);
    }

    var openExportBtn = byId('abuseipOpenExport');
    if (openExportBtn) {
      openExportBtn.addEventListener('click', openExport);
    }
    var resultsOpenExportBtn = byId('abuseipResultsOpenExport');
    if (resultsOpenExportBtn) {
      resultsOpenExportBtn.addEventListener('click', openExport);
    }

    loadMeta();
  }

  function loadMeta() {
    fetch('/api/abuseip/meta', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var keySource = data.keySource || 'unknown';
        var keyInfo = byId('abuseipKeyInfo');
        if (keyInfo) {
          keyInfo.textContent = 'Key source: ' + keySource + ' | Max age: ' + (data.maxAgeInDays || 30) + ' days';
        }

        var maxAgeInput = byId('abuseipMaxAge');
        if (maxAgeInput && data.maxAgeInDays) {
          maxAgeInput.value = data.maxAgeInDays;
        }

        if (data.currentJob && data.currentJob.state === 'running') {
          abuseipJobId = data.currentJob.jobId || '';
          applyCheckSnapshot(data.currentJob);
          startPolling();
        } else if (data.currentJob && (data.currentJob.state === 'completed' || data.currentJob.state === 'failed')) {
          applyCheckSnapshot(data.currentJob);
        }
      })
      .catch(function () {});
  }

  function startCheck() {
    setError('abuseipError', null);

    var lines = getAbuseipIps();
    if (lines.length === 0) {
      setError('abuseipError', 'Enter at least one IP address.');
      return;
    }

    if (lines.length > 100) {
      setError('abuseipError', 'Maximum 100 IPs per check. You entered ' + lines.length + '.');
      return;
    }

    var maxAgeInput = byId('abuseipMaxAge');
    var maxAge = maxAgeInput ? parseInt(maxAgeInput.value, 10) : 30;
    if (!maxAge || maxAge < 1 || maxAge > 365) {
      maxAge = 30;
    }

    var apiKeyOverride = null;
    var keyModeOverride = byId('abuseipKeyOverride');
    if (keyModeOverride && keyModeOverride.classList.contains('active')) {
      var keyInput = byId('abuseipApiKey');
      apiKeyOverride = keyInput ? keyInput.value.trim() : null;
    }

    var runBtn = byId('abuseipRun');
    if (runBtn) {
      runBtn.disabled = true;
    }

    var body = { ips: lines, maxAgeInDays: maxAge };
    if (apiKeyOverride) {
      body.apiKeyOverride = apiKeyOverride;
    }

    fetch('/api/abuseip/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(body)
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.ok) {
          setError('abuseipError', data.error || 'Failed to start check.');
          if (runBtn) { runBtn.disabled = false; }
          return;
        }

        abuseipJobId = data.snapshot ? data.snapshot.jobId : '';
        applyCheckSnapshot(data.snapshot);
        startPolling();
      })
      .catch(function (err) {
        setError('abuseipError', 'Request failed: ' + err);
        if (runBtn) { runBtn.disabled = false; }
      });
  }

  function startPolling() {
    stopPolling();
    abuseipPolling = setInterval(pollJob, 1800);
  }

  function stopPolling() {
    if (abuseipPolling) {
      clearInterval(abuseipPolling);
      abuseipPolling = null;
    }
  }

  function pollJob() {
    fetch('/api/abuseip/job', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (snapshot) {
        applyCheckSnapshot(snapshot);
        if (snapshot.state !== 'running') {
          stopPolling();
        }
      })
      .catch(function () {});
  }

  function applyCheckSnapshot(snapshot) {
    if (!snapshot) {
      return;
    }

    var state = snapshot.state || 'idle';
    var phase = snapshot.phase || 'idle';
    var message = snapshot.message || '';
    var current = snapshot.currentStep || 0;
    var total = snapshot.totalSteps || 0;
    var results = snapshot.results || [];
    var failures = snapshot.failures || [];

    setText('abuseipState', state);
    setText('abuseipPhase', phase);
    setText('abuseipIpCount', String(total));
    setText('abuseipMessage', message);
    setText('abuseipStageBadge', phase);

    var summary = state === 'idle' ? 'Waiting for a check to start.'
      : state === 'running' ? 'Checking IP ' + current + ' of ' + total + '...'
      : state === 'completed' ? 'Checked ' + results.length + ' IP(s).'
      : 'Check failed.';
    setText('abuseipSummary', summary);

    setBar('abuseipBar', current, total);

    var barMeta = state === 'idle' ? 'No check running.'
      : state === 'running' ? current + ' / ' + total + ' IPs checked'
      : state === 'completed' ? results.length + ' checked, ' + failures.length + ' failed'
      : snapshot.error || 'Error';
    setText('abuseipBarMeta', barMeta);

    // Lock inputs while running
    var locked = state === 'running';
    ['abuseipRun', 'abuseipIpText', 'abuseipMaxAge', 'abuseipKeyDefault', 'abuseipKeyOverride',
     'abuseipModeManual', 'abuseipModeFile', 'abuseipModeBurst', 'abuseipBrowseFile', 'abuseipBrowseBurst'].forEach(function (id) {
      var el = byId(id);
      if (el) el.disabled = locked;
    });

    // Export button
    var exportBtn = byId('abuseipOpenExport');
    var resultsExportBtn = byId('abuseipResultsOpenExport');
    var exportInfo = byId('abuseipExportInfo');
    var hasExport = state === 'completed' && snapshot.csvExportPath;
    [exportBtn, resultsExportBtn].forEach(function (btn) {
      if (btn) { btn.disabled = !hasExport; btn.classList.toggle('primary', !!hasExport); }
    });
    if (exportInfo && hasExport) {
      exportInfo.textContent = snapshot.csvExportPath;
    }

    // Results
    if (state === 'completed' || (state === 'failed' && results.length > 0)) {
      renderResults(results, failures);

      // Auto-scroll to results
      var abuseResultsEl = byId('abuseipResults');
      if (abuseResultsEl && !abuseResultsEl.hidden) {
        setTimeout(function () { abuseResultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 200);
      }
    }
  }

  function renderResults(results, failures) {
    var resultsSection = byId('abuseipResults');
    if (resultsSection) {
      resultsSection.hidden = false;
    }

    renderSummaryCards(results);
    renderResultTable(results);
    renderFailures(failures);
  }

  function renderSummaryCards(results) {
    var host = byId('abuseipSummaryCards');
    if (!host || !results.length) {
      return;
    }

    var clean = 0;
    var low = 0;
    var medium = 0;
    var high = 0;
    var critical = 0;

    for (var i = 0; i < results.length; i++) {
      var band = (results[i].scoreBand || '').toLowerCase();
      if (band === 'clean') clean++;
      else if (band === 'low') low++;
      else if (band === 'medium') medium++;
      else if (band === 'high') high++;
      else if (band === 'critical') critical++;
    }

    host.innerHTML = '<div class="status-pill"><span>Total</span><strong>' + results.length + '</strong></div>'
      + '<div class="status-pill"><span>Clean</span><strong>' + clean + '</strong></div>'
      + '<div class="status-pill"><span>Low</span><strong>' + low + '</strong></div>'
      + '<div class="status-pill"><span>Medium</span><strong>' + medium + '</strong></div>'
      + '<div class="status-pill"><span>High</span><strong>' + high + '</strong></div>'
      + '<div class="status-pill"><span>Critical</span><strong>' + critical + '</strong></div>';
  }

  function renderResultTable(results) {
    var host = byId('abuseipResultTable');
    if (!host) {
      return;
    }

    if (!results.length) {
      host.innerHTML = '<p class="footer-note">No results.</p>';
      return;
    }

    var sorted = results.slice().sort(function (a, b) {
      var diff = (b.abuseConfidenceScore || 0) - (a.abuseConfidenceScore || 0);
      if (diff !== 0) return diff;
      return (b.totalReports || 0) - (a.totalReports || 0);
    });

    var html = '<table class="mini-table">';
    html += '<thead><tr>'
      + '<th>IP</th>'
      + '<th>Score</th>'
      + '<th>Band</th>'
      + '<th>Reports</th>'
      + '<th>Country</th>'
      + '<th>Usage</th>'
      + '<th>ISP</th>'
      + '<th>Domain</th>'
      + '<th>Last Report</th>'
      + '</tr></thead><tbody>';

    for (var i = 0; i < sorted.length; i++) {
      var r = sorted[i];
      var scoreClass = getScoreClass(r.abuseConfidenceScore || 0);
      html += '<tr>'
        + '<td style="font-family:monospace;white-space:nowrap">' + escapeHtml(r.ipAddress) + '</td>'
        + '<td class="' + scoreClass + '" style="font-weight:600;text-align:right">' + escapeHtml(String(r.abuseConfidenceScore ?? 0)) + '</td>'
        + '<td>' + escapeHtml(r.scoreBand || '') + '</td>'
        + '<td style="text-align:right">' + formatNumber(r.totalReports) + '</td>'
        + '<td>' + escapeHtml(r.countryCode || '') + '</td>'
        + '<td>' + escapeHtml(truncate(r.usageType, 30)) + '</td>'
        + '<td>' + escapeHtml(truncate(r.isp, 30)) + '</td>'
        + '<td>' + escapeHtml(truncate(r.domain, 24)) + '</td>'
        + '<td style="white-space:nowrap">' + escapeHtml(r.lastReportedAt ? r.lastReportedAt.substring(0, 10) : '') + '</td>'
        + '</tr>';
    }

    html += '</tbody></table>';
    host.innerHTML = html;
  }

  function getScoreClass(score) {
    if (score <= 0) return 'abuse-score-clean';
    if (score <= 25) return 'abuse-score-low';
    if (score <= 50) return 'abuse-score-medium';
    if (score <= 75) return 'abuse-score-high';
    return 'abuse-score-critical';
  }

  function truncate(value, max) {
    if (!value) return '';
    if (value.length <= max) return value;
    return value.substring(0, max - 3) + '...';
  }

  function renderFailures(failures) {
    var section = byId('abuseipFailuresSection');
    var list = byId('abuseipFailuresList');
    if (!section || !list) {
      return;
    }

    if (!failures || failures.length === 0) {
      section.hidden = true;
      return;
    }

    section.hidden = false;
    var html = '<table class="mini-table"><thead><tr><th>IP</th><th>Error</th></tr></thead><tbody>';
    for (var i = 0; i < failures.length; i++) {
      html += '<tr><td style="font-family:monospace">' + escapeHtml(failures[i].ip) + '</td><td>' + escapeHtml(failures[i].error) + '</td></tr>';
    }
    html += '</tbody></table>';
    list.innerHTML = html;
  }

  function openExport() {
    fetch('/api/abuseip/open-export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({})
    }).catch(function () {});
  }

  // ── Settings page ─────────────────────────────────────────────────

  function initSettingsPage() {
    var page = document.querySelector('[data-abuseip-settings-page]');
    if (!page) {
      return;
    }

    loadSettings();

    var saveBtn = byId('abuseipSettingsSave');
    if (saveBtn) {
      saveBtn.addEventListener('click', saveSettings);
    }

    loadExportHistory();
  }

  function loadSettings() {
    fetch('/api/abuseip/config', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        setText('abuseipSettingsKeySource', data.hasCustomKey ? 'custom key' : 'built-in default');
        setText('abuseipSettingsCurrentMaxAge', String(data.maxAgeInDays || 30));
        setText('abuseipSettingsCurrentVerbose', data.verbose ? 'yes' : 'no');

        var pathEl = byId('abuseipSettingsConfigPath');
        if (pathEl) {
          pathEl.textContent = 'Config: ' + (data.configPath || 'unknown');
        }

        var maxAgeInput = byId('abuseipSettingsMaxAge');
        if (maxAgeInput) {
          maxAgeInput.value = data.maxAgeInDays || 30;
        }

        var verboseCheck = byId('abuseipSettingsVerbose');
        if (verboseCheck) {
          verboseCheck.checked = !!data.verbose;
        }
      })
      .catch(function () {});
  }

  function saveSettings() {
    setError('abuseipSettingsError', null);
    setError('abuseipSettingsSuccess', null);

    var apiKeyInput = byId('abuseipSettingsApiKey');
    var clearKeyCheck = byId('abuseipSettingsClearKey');
    var maxAgeInput = byId('abuseipSettingsMaxAge');
    var verboseCheck = byId('abuseipSettingsVerbose');

    var body = {
      apiKey: apiKeyInput ? apiKeyInput.value.trim() : null,
      clearApiKey: clearKeyCheck ? clearKeyCheck.checked : false,
      maxAgeInDays: maxAgeInput ? parseInt(maxAgeInput.value, 10) : null,
      verbose: verboseCheck ? verboseCheck.checked : false
    };

    fetch('/api/abuseip/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(body)
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.ok) {
          setError('abuseipSettingsError', data.error || 'Failed to save.');
          return;
        }

        var successEl = byId('abuseipSettingsSuccess');
        if (successEl) {
          successEl.textContent = 'Settings saved.';
          successEl.hidden = false;
          setTimeout(function () { successEl.hidden = true; }, 3000);
        }

        if (apiKeyInput) {
          apiKeyInput.value = '';
        }
        if (clearKeyCheck) {
          clearKeyCheck.checked = false;
        }

        setText('abuseipSettingsKeySource', data.hasCustomKey ? 'custom key' : 'built-in default');
        setText('abuseipSettingsCurrentMaxAge', String(data.maxAgeInDays || 30));
        setText('abuseipSettingsCurrentVerbose', data.verbose ? 'yes' : 'no');
      })
      .catch(function (err) {
        setError('abuseipSettingsError', 'Request failed: ' + err);
      });
  }

  function loadExportHistory() {
    fetch('/api/abuseip/output-files', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var files = data.files || [];
        var section = byId('abuseipExportHistory');
        var list = byId('abuseipExportList');
        if (!section || !list) {
          return;
        }

        if (files.length === 0) {
          section.hidden = true;
          return;
        }

        section.hidden = false;
        var html = '<table class="mini-table"><thead><tr><th>File</th><th>Size</th><th>Created</th></tr></thead><tbody>';
        for (var i = 0; i < files.length; i++) {
          var f = files[i];
          html += '<tr>'
            + '<td>' + escapeHtml(f.name) + '</td>'
            + '<td style="text-align:right;white-space:nowrap">' + formatBytes(f.size) + '</td>'
            + '<td style="white-space:nowrap">' + escapeHtml(f.createdUtc || '') + '</td>'
            + '</tr>';
        }
        html += '</tbody></table>';
        list.innerHTML = html;
      })
      .catch(function () {});
  }

  // ── Initialize ────────────────────────────────────────────────────

  function init() {
    initCheckPage();
    initSettingsPage();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
