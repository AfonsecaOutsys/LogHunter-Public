async function loadAppInfo() {
  const targets = Array.from(document.querySelectorAll('[data-app-info]'));
  if (!targets.length) {
    return;
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
  } catch (error) {
    const status = document.querySelector('[data-app-info="status"]');
    if (status) {
      status.textContent = `error: ${error}`;
    }
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    loadAppInfo().catch(() => {});
  });
} else {
  loadAppInfo().catch(() => {});
}
