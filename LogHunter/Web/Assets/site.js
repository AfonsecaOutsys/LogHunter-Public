const THEME_KEY = 'loghunter.theme';
const APP_INFO_POLL_MS = 4000;
const TRACE_ENDPOINT = '/api/trace';
const TRACE_FLUSH_MS = 1000;

// Records browser-side actions into the diagnosis trace when the server enables it. Typed text is never recorded.
function initializeTrace() {
  if (!document.body || document.body.dataset.trace !== 'on') {
    window.lhTrace = function () {};
    return;
  }

  const queue = [];
  const page = window.location.pathname;
  const originalFetch = window.fetch.bind(window);

  window.lhTrace = function (event, data) {
    queue.push({ event, ts: new Date().toISOString(), page, data: data === undefined ? null : data });
  };

  function flush(useBeacon) {
    if (!queue.length) {
      return;
    }

    const body = JSON.stringify({ events: queue.splice(0, queue.length) });
    if (useBeacon && navigator.sendBeacon) {
      navigator.sendBeacon(TRACE_ENDPOINT, body);
      return;
    }

    originalFetch(TRACE_ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, keepalive: true }).catch(() => {});
  }

  window.fetch = async function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    const method = (init && init.method) || (input && input.method) || 'GET';
    const started = performance.now();
    try {
      const response = await originalFetch(input, init);
      window.lhTrace('fetch', { method, url, status: response.status, ms: Math.round(performance.now() - started) });
      return response;
    } catch (error) {
      window.lhTrace('fetch.error', { method, url, error: String(error), ms: Math.round(performance.now() - started) });
      throw error;
    }
  };

  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element
      ? event.target.closest('button, a, summary, [role="button"], input[type="checkbox"], input[type="radio"]')
      : null;
    if (!target) {
      return;
    }

    window.lhTrace('click', {
      tag: target.tagName.toLowerCase(),
      id: target.id || null,
      text: (target.textContent || '').trim().replace(/\s+/g, ' ').substring(0, 80),
      href: target.getAttribute('href')
    });
  }, true);

  document.addEventListener('change', (event) => {
    const target = event.target;
    if (target instanceof HTMLSelectElement) {
      window.lhTrace('change', { id: target.id || target.name || null, value: target.value });
    } else if (target instanceof HTMLInputElement && (target.type === 'checkbox' || target.type === 'radio')) {
      window.lhTrace('change', { id: target.id || target.name || null, checked: target.checked });
    }
  }, true);

  window.addEventListener('error', (event) => {
    window.lhTrace('js.error', { message: event.message, source: event.filename, line: event.lineno });
  });
  window.addEventListener('unhandledrejection', (event) => {
    window.lhTrace('js.unhandled-rejection', { reason: String(event.reason) });
  });
  document.addEventListener('visibilitychange', () => {
    window.lhTrace('visibility', { state: document.visibilityState });
  });
  window.addEventListener('pagehide', () => flush(true));

  window.lhTrace('page.load', { title: document.title, referrer: document.referrer || null });
  setInterval(() => flush(false), TRACE_FLUSH_MS);
}

initializeTrace();

function getPreferredTheme() {
  const storedTheme = window.localStorage.getItem(THEME_KEY);
  if (storedTheme === 'dark' || storedTheme === 'light') {
    return storedTheme;
  }

  return 'dark';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const toggle = document.getElementById('themeToggle');
  if (toggle) {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    toggle.textContent = theme === 'dark' ? 'Switch to light' : 'Switch to dark';
    toggle.setAttribute('aria-label', `Switch to ${nextTheme} theme`);
    toggle.dataset.theme = theme;
  }
}

function initializeTheme() {
  const theme = getPreferredTheme();
  applyTheme(theme);

  const toggle = document.getElementById('themeToggle');
  if (!toggle) {
    return;
  }

  toggle.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
    window.localStorage.setItem(THEME_KEY, nextTheme);
    applyTheme(nextTheme);
  });
}

function setRuntimeHealth(isOnline, title) {
  const light = document.querySelector('[data-runtime-light="status"]');
  const runtimeButton = document.getElementById('runtimeButton');
  const status = document.querySelector('[data-app-info="status"]');

  if (light) {
    light.classList.toggle('is-online', isOnline);
    light.classList.toggle('is-offline', !isOnline);
  }

  if (status && !isOnline) {
    status.textContent = 'offline';
  }

  if (runtimeButton && title) {
    runtimeButton.title = title;
  }
}

async function loadAppInfo() {
  const targets = Array.from(document.querySelectorAll('[data-app-info]'));
  if (!targets.length) {
    return false;
  }

  try {
    const response = await fetch('/api/app/info', { headers: { 'Accept': 'application/json' } });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    for (const element of targets) {
      const key = element.getAttribute('data-app-info');
      if (!key) {
        continue;
      }

      const value = payload[key];
      element.textContent = value === null || value === undefined || value === '' ? 'n/a' : String(value);
    }

    const runtimeButton = document.getElementById('runtimeButton');
    if (runtimeButton) {
      runtimeButton.title = `Local web host status: ${payload.status || 'n/a'} | mode: ${payload.mode || 'n/a'} | started: ${payload.startedUtc || 'n/a'}`;
    }

    const rangesLight = document.querySelector('[data-ip-ranges-light="status"]');
    if (rangesLight) {
      rangesLight.classList.toggle('is-online', payload.ipRangesLevel === 'ok');
      rangesLight.classList.toggle('is-warn', payload.ipRangesLevel === 'stale');
      rangesLight.classList.toggle('is-offline', payload.ipRangesLevel === 'missing');
    }
    setRuntimeHealth(true, `Local web host status: ${payload.status || 'n/a'} | mode: ${payload.mode || 'n/a'} | started: ${payload.startedUtc || 'n/a'}`);
    return true;
  } catch (error) {
    const status = document.querySelector('[data-app-info="status"]');
    if (status) {
      status.textContent = 'offline';
    }
    setRuntimeHealth(false, `Local web host unreachable: ${error}`);
    return false;
  }
}

function startAppInfoPolling() {
  window.setInterval(() => {
    loadAppInfo().catch(() => {});
  }, APP_INFO_POLL_MS);
}

function initializeSqliteViewerCard() {
  const btn = document.getElementById('openSqliteViewer');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    const original = btn.querySelector('p');
    if (original) original.textContent = 'Opening file picker\u2026';
    try {
      const res = await fetch('/api/viewer/browse-and-launch', { method: 'POST' });
      const data = await res.json();
      if (original) original.textContent = data.ok
        ? 'Viewer launched \u2014 check your browser tabs.'
        : (data.message || 'No file selected.');
    } catch {
      if (original) original.textContent = 'Failed to reach the server.';
    }
    setTimeout(() => {
      btn.disabled = false;
      if (original) original.textContent = 'Open an existing .db file.';
    }, 3000);
  });
}

// ── CDN / proxy range labels ─────────────────────────────────────────
// lhIpRanges.annotate(container): badges every [data-ip] element and every table column headed
// "IP" / "Client IP" inside container, and adds a "Fronted by" banner when most IPs are one CDN.
window.lhIpRanges = (function () {
  function esc(value) {
    return String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
  }

  function collectTargets(container) {
    const targets = [];
    container.querySelectorAll('[data-ip]').forEach(el => targets.push({ el, ip: el.getAttribute('data-ip') }));
    container.querySelectorAll('table').forEach(table => {
      const headers = Array.from(table.querySelectorAll('tr:first-child th, thead th'));
      const col = headers.findIndex(th => /^(client\s*)?ip(\s*address)?$/i.test(th.textContent.trim()));
      if (col < 0) return;
      table.querySelectorAll('tbody tr, tr').forEach(tr => {
        const cell = tr.children[col];
        if (cell && cell.tagName === 'TD') targets.push({ el: cell, ip: cell.textContent.trim() });
      });
    });
    // Elements already looked up carry data-ip-checked, so polling re-renders cost nothing.
    return targets.filter(t => t.ip && !t.el.hasAttribute('data-ip-checked'));
  }

  function bannerText(fronted) {
    const pct = Math.round(fronted.share * 100);
    return fronted.level === 'confirmed'
      ? `Fronted by ${fronted.provider} (${pct}% of these IPs). These are CDN edges, not users: use IIS IP summary for the real client IPs.`
      : `Likely fronted by ${fronted.provider} (${pct}% of these IPs). Check IIS OriginalIP before blocking.`;
  }

  async function annotate(container) {
    if (!container) return null;
    const targets = collectTargets(container);
    if (targets.length === 0) return null;
    targets.forEach(t => t.el.setAttribute('data-ip-checked', ''));
    container.querySelectorAll('.ip-ranges-banner').forEach(b => b.remove());

    const response = await fetch('/api/ip-ranges/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ ips: targets.map(t => t.ip) })
    });
    if (!response.ok) return null;
    const payload = await response.json();
    const byIp = new Map((payload.results || []).map(r => [r.ip.toLowerCase(), r]));

    targets.forEach(t => {
      const hit = byIp.get(t.ip.toLowerCase());
      if (!hit || t.el.querySelector('.ip-badge')) return;
      const badge = document.createElement('span');
      badge.className = `ip-badge ip-badge--${hit.category.toLowerCase()}`;
      badge.textContent = hit.badge;
      t.el.appendChild(badge);
    });

    if (payload.fronted && payload.fronted.level !== 'none') {
      const banner = document.createElement('div');
      banner.className = 'ip-ranges-banner';
      banner.innerHTML = esc(bannerText(payload.fronted));
      container.prepend(banner);
    }
    return payload;
  }

  return { annotate };
})();

function initializeIpRangesPage() {
  if (!document.querySelector('[data-ip-ranges-page]')) return;
  const esc = v => String(v ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
  const fmt = v => v ? new Date(v).toISOString().replace('T', ' ').substring(0, 16) + ' UTC' : 'never';

  function render(status) {
    document.getElementById('ipRangesSummary').textContent = status.refreshing
      ? 'Refreshing…'
      : `${status.providerCount} providers · ${Number(status.rangeCount).toLocaleString('en-US')} ranges · oldest feed ${status.label}`;
    const rows = status.feeds.map(f => `
      <tr><td>${esc(f.provider)}</td><td>${esc(f.id)}</td><td class="num">${Number(f.rangeCount).toLocaleString('en-US')}</td>
        <td>${esc(fmt(f.lastSuccessUtc))}</td><td>${f.lastError ? esc(f.lastError) : 'OK'}</td></tr>`).join('');
    document.getElementById('ipRangesTable').innerHTML = `
      <table class="mini-table"><tr><th>Provider</th><th>Feed</th><th>Ranges</th><th>Last updated</th><th>Last result</th></tr>${rows}</table>`;
  }

  async function load(method) {
    const response = await fetch(method === 'POST' ? '/api/ip-ranges/refresh' : '/api/ip-ranges/status', { method });
    render(await response.json());
  }

  const button = document.getElementById('ipRangesRefresh');
  button.addEventListener('click', async () => {
    button.disabled = true;
    document.getElementById('ipRangesSummary').textContent = 'Refreshing…';
    try { await load('POST'); } finally { button.disabled = false; }
  });
  load('GET').catch(() => {});

  const providerInput = document.getElementById('ipRangesCustomProvider');
  const rangesInput = document.getElementById('ipRangesCustomText');
  const info = document.getElementById('ipRangesCustomInfo');

  async function saveCustom(provider, ranges) {
    const response = await fetch('/api/ip-ranges/custom', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider, ranges })
    });
    const result = await response.json();
    info.textContent = result.saved > 0
      ? `${result.saved} range(s) saved.${result.invalid.length ? ` Ignored: ${result.invalid.join(', ')}` : ''}`
      : (result.invalid.length ? `Nothing saved. Ignored: ${result.invalid.join(', ')}` : 'Customer ranges cleared.');
    await load('GET');
  }

  document.getElementById('ipRangesCustomSave').addEventListener('click', () =>
    saveCustom(providerInput.value, rangesInput.value).catch(err => { info.textContent = String(err); }));
  document.getElementById('ipRangesCustomClear').addEventListener('click', () => {
    rangesInput.value = '';
    saveCustom(providerInput.value, '').catch(err => { info.textContent = String(err); });
  });

  fetch('/api/ip-ranges/custom').then(r => r.json()).then(c => {
    providerInput.value = c.ranges ? c.provider : '';
    rangesInput.value = c.ranges || '';
  }).catch(() => {});
}

function initializeShell() {
  initializeTheme();
  loadAppInfo().catch(() => {});
  startAppInfoPolling();
  initializeSqliteViewerCard();
  initializeIpRangesPage();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeShell);
} else {
  initializeShell();
}
