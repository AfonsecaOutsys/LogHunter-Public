const THEME_KEY = 'loghunter.theme';
const APP_INFO_POLL_MS = 4000;
const TRACE_ENDPOINT = '/api/trace';
const TRACE_FLUSH_MS = 1000;

// Records browser-side actions when the exe was started with --trace. Typed text is never recorded.
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

function initializeShell() {
  initializeTheme();
  loadAppInfo().catch(() => {});
  startAppInfoPolling();
  initializeSqliteViewerCard();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeShell);
} else {
  initializeShell();
}
