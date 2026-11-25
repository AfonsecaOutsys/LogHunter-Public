(function () {
  let polling = null;
  let sources = [];
  let lastSnapshot = null;

  function byId(id) {
    return document.getElementById(id);
  }

  function trace(event, data) {
    if (window.lhTrace) {
      window.lhTrace(event, data);
    }
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString('en-US');
  }

  function setError(message) {
    const node = byId('ipSweepError');
    if (!node) return;
    node.textContent = message || '';
    node.hidden = !message;
  }

  async function fetchJson(url, options) {
    const response = await fetch(url, {
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      ...options
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || payload.message || `HTTP ${response.status}`);
    return payload;
  }

  // Client-side check for the counter only; the server parses authoritatively with the same rules.
  const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

  function isIp(text) {
    if (IPV4.test(text)) return true;
    if (!text.includes(':') || !/^[0-9a-fA-F:.]+$/.test(text)) return false;
    try { new URL(`http://[${text}]/`); return true; } catch { return false; }
  }

  function isTarget(token) {
    const slash = token.indexOf('/');
    if (slash > 0) {
      const ip = token.slice(0, slash);
      const prefix = Number(token.slice(slash + 1));
      const max = ip.includes(':') ? 128 : 32;
      return isIp(ip) && /^\d+$/.test(token.slice(slash + 1)) && prefix >= 0 && prefix <= max;
    }
    const dash = token.indexOf('-');
    if (dash > 0) return isIp(token.slice(0, dash)) && isIp(token.slice(dash + 1));
    return isIp(token);
  }

  function checkTargets(text) {
    const tokens = text.split('\n')
      .map(line => line.split('#')[0])
      .join(' ')
      .replace(/\s+-\s+/g, '-')
      .split(/[\s,;]+/)
      .filter(Boolean);
    const invalid = tokens.filter(t => !isTarget(t));
    return { valid: tokens.length - invalid.length, invalid };
  }

  function renderTargetInfo() {
    const { valid, invalid } = checkTargets(byId('ipSweepTargets').value);
    const info = byId('ipSweepTargetInfo');
    info.textContent = invalid.length
      ? `${formatNumber(valid)} targets · not recognised: ${invalid.slice(0, 5).join(', ')}${invalid.length > 5 ? ` (+${invalid.length - 5})` : ''}`
      : `${formatNumber(valid)} targets`;
  }

  const LAST_SWEEP_KEY = 'lh.ipSweep.last';

  function renderSources() {
    const host = byId('ipSweepSources');
    if (!host) return;
    if (sources.length === 0) {
      host.innerHTML = '<div class="source-chip">No folder yet. Add the ALB or IIS log folder of each environment.</div>';
      return;
    }

    host.innerHTML = sources.map((s, i) => `
      <div class="source-chip ip-sweep-source">
        <input class="ip-sweep-label" data-index="${i}" type="text" value="${escapeHtml(s.label)}" aria-label="Folder label">
        <span class="footer-note">${escapeHtml(s.path)} · ${formatNumber(s.files)} files</span>
        <button class="source-btn source-btn--clear" data-remove="${i}" type="button">Remove</button>
      </div>`).join('');

    host.querySelectorAll('.ip-sweep-label').forEach(input => {
      input.addEventListener('input', e => { sources[Number(e.target.dataset.index)].label = e.target.value; });
    });
    host.querySelectorAll('[data-remove]').forEach(btn => {
      btn.addEventListener('click', e => {
        sources.splice(Number(e.target.dataset.remove), 1);
        renderSources();
      });
    });
  }

  async function addFolder() {
    setError('');
    try {
      const result = await fetchJson('/api/ip-sweep/browse-folder', { method: 'POST' });
      if (!result.ok || !result.source) return;
      if (sources.some(s => s.path.toLowerCase() === result.source.path.toLowerCase())) return;
      sources.push(result.source);
      renderSources();
    } catch (err) {
      setError(err.message);
    }
  }

  async function run() {
    setError('');
    const targets = byId('ipSweepTargets').value;
    localStorage.setItem(LAST_SWEEP_KEY, JSON.stringify({ targets, sources }));
    try {
      const result = await fetchJson('/api/ip-sweep/run', {
        method: 'POST',
        body: JSON.stringify({ targets, sources: sources.map(s => ({ label: s.label, path: s.path })), section: moduleBase().substring(1) })
      });
      render(result.snapshot);
      startPolling();
    } catch (err) {
      setError(err.message);
    }
  }

  function startPolling() {
    if (polling) return;
    polling = setInterval(async () => {
      try {
        const snap = await fetchJson('/api/ip-sweep/job');
        render(snap);
        if (snap.state !== 'running') stopPolling();
      } catch (err) {
        stopPolling();
        setError(err.message);
      }
    }, 1000);
  }

  function stopPolling() {
    if (polling) clearInterval(polling);
    polling = null;
  }

  function render(snap) {
    if (!snap) return;
    lastSnapshot = snap;
    const running = snap.state === 'running';
    byId('ipSweepState').textContent = snap.state;
    byId('ipSweepTargetCount').textContent = formatNumber(snap.targetCount);
    byId('ipSweepLines').textContent = formatNumber(snap.linesRead);
    byId('ipSweepMessage').textContent = snap.error ? `${snap.message} ${snap.error}` : snap.message;
    byId('ipSweepFiles').textContent = `${formatNumber(snap.filesProcessed)} / ${formatNumber(snap.filesTotal)} files`;
    const pct = snap.filesTotal > 0 ? Math.min(100, (snap.filesProcessed / snap.filesTotal) * 100) : 0;
    byId('ipSweepBar').style.width = `${pct}%`;
    byId('ipSweepRun').disabled = running;
    byId('ipSweepOpenReport').disabled = !snap.htmlReportPath;
    byId('ipSweepOpenExport').disabled = !snap.excelPath;
    renderResults(snap);
  }

  function renderResults(snap) {
    const section = byId('ipSweepResults');
    if (!snap.targets) {
      section.hidden = true;
      return;
    }

    section.hidden = false;
    const hits = snap.targets.filter(t => t.hits > 0);
    byId('ipSweepResultsTitle').textContent = `${formatNumber(hits.length)} of ${formatNumber(snap.targets.length)} targets found`;
    byId('ipSweepToIpSummary').disabled = hits.length === 0;
    byId('ipSweepCopyHits').disabled = hits.length === 0;
    byId('ipSweepToAbuseIp').disabled = reputationIps(snap).length === 0;

    // Single IPs (and ranges that matched one IP) get a CDN / proxy badge via data-ip.
    const ipFor = t => t.kind === 'IP' ? t.target : (t.topIps.length === 1 ? t.topIps[0] : '');
    const rows = snap.targets.map(t => `
      <tr class="${t.hits > 0 ? 'ip-sweep-hit' : ''}">
        <td${ipFor(t) ? ` data-ip="${escapeHtml(ipFor(t))}"` : ''}>${escapeHtml(t.target)}</td><td>${escapeHtml(t.kind)}</td>
        <td class="num">${formatNumber(t.hits)}</td>
        <td>${escapeHtml(t.firstSeenUtc)}</td><td>${escapeHtml(t.lastSeenUtc)}</td>
        <td class="num">${t.distinctIps > 1 ? formatNumber(t.distinctIps) : ''}</td>
        <td>${escapeHtml(t.topPaths)}</td><td>${escapeHtml(t.statuses)}</td><td>${escapeHtml(t.sources)}</td>
      </tr>`).join('');
    byId('ipSweepTable').innerHTML = `
      <table class="mini-table">
        <tr><th>Target</th><th>Type</th><th>Hits</th><th>First seen</th><th>Last seen</th><th>IPs</th><th>Top paths</th><th>Status</th><th>Sources</th></tr>
        ${rows}
      </table>`;
    if (window.lhIpRanges) window.lhIpRanges.annotate(byId('ipSweepTable')).catch(() => {});

    const scopeRows = (snap.scopes || []).map(s => `
      <tr><td>${escapeHtml(s.label)}</td>
        <td>${[s.albFiles ? `${formatNumber(s.albFiles)} ALB` : '', s.iisFiles ? `${formatNumber(s.iisFiles)} IIS` : ''].filter(Boolean).join(' + ') || '0'}</td>
        <td class="num">${formatNumber(s.linesRead)}</td><td class="num">${formatNumber(s.parseFailures)}</td>
        <td>${escapeHtml(s.minUtc)} → ${escapeHtml(s.maxUtc)}</td>
        <td class="num">${formatNumber(s.unreadableFiles)}</td></tr>`).join('');
    const ignored = (snap.invalidTokens || []).length
      ? `<p class="footer-note">Ignored input: ${escapeHtml(snap.invalidTokens.join(', '))}</p>` : '';
    byId('ipSweepScope').innerHTML = `
      <table class="mini-table">
        <tr><th>Source</th><th>Files</th><th>Lines</th><th>Unparsed</th><th>Observed range</th><th>Unreadable</th></tr>
        ${scopeRows}
      </table>${ignored}`;
  }

  function hitIps(snap) {
    const counts = new Map();
    snap.targets.filter(t => t.hits > 0).forEach(t => t.topIps.forEach(ip => counts.set(ip, (counts.get(ip) || 0) + 1)));
    return Array.from(counts.keys());
  }

  // Single-IP targets (hit or not) plus IPs matched inside ranges.
  function reputationIps(snap) {
    const set = new Set(snap.targets.filter(t => t.kind === 'IP').map(t => t.target));
    hitIps(snap).forEach(ip => set.add(ip));
    return Array.from(set);
  }

  function handOff(storageKey, ips, url) {
    sessionStorage.setItem(storageKey, ips.join('\n'));
    trace('ipsweep.handoff', { to: url, count: ips.length });
    window.location.href = url;
  }

  function moduleBase() {
    return window.location.pathname.toLowerCase().startsWith('/iis') ? '/iis' : '/alb';
  }

  // IP summary gets the first swept folder that holds logs of its own type (ALB or IIS).
  function toIpSummary() {
    const base = moduleBase();
    const scope = (lastSnapshot.scopes || []).find(s => s.path && (base === '/iis' ? s.iisFiles > 0 : s.albFiles > 0));
    if (scope) {
      sessionStorage.setItem('lh.prefill.ipSummaryFolder', JSON.stringify({
        path: scope.path,
        files: base === '/iis' ? scope.iisFiles : scope.albFiles,
        bytes: scope.bytes || 0
      }));
    }
    handOff('lh.prefill.ipSummary', hitIps(lastSnapshot).slice(0, 10), `${base}/ip-summary`);
  }

  // CDN edges and health checkers are not attackers: don't spend AbuseIPDB quota on them.
  async function toReputation() {
    let ips = reputationIps(lastSnapshot);
    try {
      const response = await fetch('/api/ip-ranges/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips })
      });
      const payload = await response.json();
      const skip = new Set((payload.results || [])
        .filter(r => r.category === 'Cdn' || r.category === 'HealthCheck')
        .map(r => r.ip.toLowerCase()));
      ips = ips.filter(ip => !skip.has(ip.toLowerCase()));
    } catch {
      // Lookup unavailable: hand off the full list.
    }

    if (ips.length === 0) {
      setError('Every IP to check is a CDN edge or health checker. Use IIS IP summary to find the real clients.');
      return;
    }
    handOff('lh.prefill.abuseip', ips, '/abuseipdb/check-ips');
  }

  async function openArtifact(action) {
    try {
      await fetchJson(`/api/ip-sweep/${action}`, { method: 'POST' });
    } catch (err) {
      setError(err.message);
    }
  }

  async function init() {
    if (!document.querySelector('[data-ip-sweep-page]')) return;

    const textarea = byId('ipSweepTargets');
    textarea.addEventListener('input', renderTargetInfo);
    byId('ipSweepAddFolder').addEventListener('click', addFolder);
    byId('ipSweepRun').addEventListener('click', run);
    byId('ipSweepOpenReport').addEventListener('click', () => openArtifact('open-report'));
    byId('ipSweepOpenExport').addEventListener('click', () => openArtifact('open-export'));
    byId('ipSweepToIpSummary').addEventListener('click', toIpSummary);
    byId('ipSweepToAbuseIp').addEventListener('click', toReputation);
    byId('ipSweepCopyHits').addEventListener('click', async () => {
      await navigator.clipboard.writeText(hitIps(lastSnapshot).join('\n'));
      byId('ipSweepCopyHits').textContent = 'Copied';
      setTimeout(() => { byId('ipSweepCopyHits').textContent = 'Copy hit IPs'; }, 1500);
    });

    try {
      const meta = await fetchJson('/api/ip-sweep/meta');
      // Restore the last sweep's targets and folders; first visit falls back to the workspace folders.
      const last = JSON.parse(localStorage.getItem(LAST_SWEEP_KEY) || 'null');
      if (last && Array.isArray(last.sources)) {
        textarea.value = last.targets || '';
        sources = last.sources;
      } else {
        sources = (meta.defaultSources || []).slice();
      }
      renderTargetInfo();
      renderSources();
      render(meta.currentJob);
      if (meta.currentJob && meta.currentJob.state === 'running') startPolling();
    } catch (err) {
      setError(err.message);
      renderSources();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
