const THEME_KEY = 'loghunter.theme';
const APP_INFO_POLL_MS = 4000;

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
