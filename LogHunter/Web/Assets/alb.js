(function () {
  let currentJobId = '';
  let albOption2Polling = null;

  function byId(id) {
    return document.getElementById(id);
  }

  function setHidden(element, hidden) {
    if (element) {
      element.hidden = hidden;
    }
  }

  function setText(id, value) {
    const node = byId(id);
    if (node) {
      node.textContent = value;
    }
  }

  function setError(message) {
    const node = byId('albDownloadError');
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

  function setAlbOption2Error(message) {
    const node = byId('albOption2Error');
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

  function setFieldInvalid(id, invalid) {
    const node = byId(id);
    if (!node) {
      return;
    }

    node.setAttribute('aria-invalid', invalid ? 'true' : 'false');
    const field = node.closest('.field');
    if (field) {
      field.classList.toggle('is-invalid', invalid);
    }
  }

  function clearValidation() {
    [
      'savedConfigName',
      'bucket',
      'albId',
      'accountId',
      'awsEnvironmentText',
      'startDateUtc',
      'startHourUtc',
      'startMinuteUtc',
      'endDateUtc',
      'endHourUtc',
      'endMinuteUtc'
    ].forEach((id) => setFieldInvalid(id, false));
  }

  function setBar(id, value, total) {
    const node = byId(id);
    if (!node) {
      return;
    }

    const safeTotal = Number(total || 0);
    const safeValue = Number(value || 0);
    const percent = safeTotal > 0 ? Math.max(0, Math.min(100, (safeValue / safeTotal) * 100)) : 0;
    node.style.width = `${percent}%`;
  }

  function buildUtcIso(dateValue, hourValue, minuteValue) {
    if (!dateValue || hourValue === '' || minuteValue === '') {
      return '';
    }

    const date = new Date(`${dateValue}T${hourValue}:${minuteValue}:00Z`);
    return Number.isNaN(date.getTime()) ? '' : date.toISOString();
  }

  function formatValue(value) {
    if (value === null || value === undefined || value === '') {
      return 'n/a';
    }

    return String(value);
  }

  function formatBytes(bytes) {
    const value = Number(bytes || 0);
    if (!Number.isFinite(value) || value <= 0) {
      return '0 B';
    }

    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = value;
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }

    return `${size.toFixed(size >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
  }

  function formatEta(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value < 0) {
      return 'n/a';
    }

    if (value < 60) {
      return `${Math.round(value)}s`;
    }

    const minutes = Math.floor(value / 60);
    const remainingSeconds = Math.round(value % 60);
    if (minutes < 60) {
      return `${minutes}m ${remainingSeconds}s`;
    }

    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m`;
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');
  }

  function renderResult(snapshot) {
    const detailsBody = byId('albDetailsBody');
    const sampleSection = byId('albSampleFilesSection');
    const sampleList = byId('albSampleFilesList');
    if (!detailsBody || !sampleSection || !sampleList) {
      return;
    }

    const result = snapshot && snapshot.result;
    if (!result) {
      detailsBody.innerHTML = '<div class="footer-note">Extra run details will appear here.</div>';
      sampleSection.hidden = true;
      sampleList.innerHTML = '';
      return;
    }

    detailsBody.innerHTML = `
      <div class="result-lines">
        <div>Config: ${escapeHtml(formatValue(result.configName))}</div>
        <div>Run folder: ${escapeHtml(formatValue(result.runFolder))}</div>
        <div>Days requested: ${escapeHtml(formatValue(result.daysRequested))}</div>
        <div>Day sync failures: ${escapeHtml(formatValue(result.daySyncFailures))}</div>
        <div>Downloaded .gz: ${escapeHtml(formatValue(result.downloadedGzipFiles))}</div>
        <div>Pruned files: ${escapeHtml(formatValue(result.prunedFiles))}</div>
        <div>Unknown timestamps kept: ${escapeHtml(formatValue(result.unknownTimestampFilesKept))}</div>
        <div>Kept for extraction: ${escapeHtml(formatValue(result.keptForExtraction))}</div>
        <div>Extracted logs: ${escapeHtml(formatValue(result.extractedLogFiles))}</div>
        <div>Extract failures: ${escapeHtml(formatValue(result.extractFailedCount))}</div>
      </div>
    `;

    const sampleFiles = Array.isArray(result.sampleLogFiles) ? result.sampleLogFiles : [];
    sampleSection.hidden = sampleFiles.length === 0;
    sampleList.innerHTML = sampleFiles.map((file) => `<li>${escapeHtml(file)}</li>`).join('');
  }

  function renderOutput(snapshot) {
    const output = byId('albJobOutput');
    if (!output) {
      return;
    }

    const lines = snapshot && Array.isArray(snapshot.outputLines) ? snapshot.outputLines : [];
    if (!lines.length) {
      output.textContent = snapshot && snapshot.state === 'running'
        ? 'Starting process...'
        : 'Waiting for a job to start...';
      return;
    }

    output.textContent = lines
      .map((line) => {
        const stamp = line.timestampUtc ? new Date(line.timestampUtc).toISOString().substring(11, 19) : '';
        const stream = line.stream ? `[${line.stream}]` : '';
        return `${stamp} ${stream} ${line.text}`.trim();
      })
      .join('\n');

    output.scrollTop = output.scrollHeight;
  }

  function renderProgress(snapshot) {
    const plan = snapshot && snapshot.plan;
    const progress = snapshot && snapshot.progress;
    const stage = snapshot && snapshot.stage ? String(snapshot.stage) : 'idle';
    const currentDaySection = byId('albCurrentDaySection');
    const currentDayCard = byId('albCurrentDayCard');
    const allDaysSection = byId('albAllDaysSection');
    const allDaysSummary = byId('albAllDaysSummary');
    const dayProgress = byId('albDayProgress');

    const planningDone = progress ? Number(progress.planningDaysCompleted || 0) : 0;
    const planningTotal = progress ? Number(progress.planningDaysTotal || 0) : 0;
    const downloadedFiles = progress ? Number(progress.downloadedFiles || 0) : 0;
    const downloadedBytes = progress ? Number(progress.downloadedBytes || 0) : 0;
    const extractedFiles = progress ? Number(progress.extractedFiles || 0) : 0;
    const totalFiles = plan ? Number(plan.totalFiles || 0) : 0;
    const totalBytes = plan ? Number(plan.totalBytes || 0) : 0;
    const targetExtractFiles = plan ? Number(plan.inWindowFiles || 0) : 0;
    const speed = progress && progress.bytesPerSecond ? `${formatBytes(progress.bytesPerSecond)}/s` : 'n/a';
    const eta = progress && progress.etaSeconds !== null && progress.etaSeconds !== undefined
      ? formatEta(progress.etaSeconds)
      : 'n/a';

    setText('albPrimaryStageBadge', formatValue(stage));

    if (stage === 'planning') {
      setText('albPrimaryLabel', 'Planning');
      setText('albPrimarySummary', planningTotal > 0 ? `${planningDone} / ${planningTotal} day prefixes planned` : 'Preparing ALB download plan');
      setText('albPrimaryMeta', 'Building the download plan before starting the existing ALB workflow.');
      setBar('albPrimaryBar', planningDone, planningTotal);
    }
    else if (stage === 'extracting') {
      setText('albPrimaryLabel', 'Extracting');
      setText('albPrimarySummary', targetExtractFiles > 0 ? `${extractedFiles} / ${targetExtractFiles} logs extracted` : 'Extracting logs');
      setText('albPrimaryMeta', `${downloadedFiles} / ${totalFiles} files | ${formatBytes(downloadedBytes)} | ${speed}`);
      setBar('albPrimaryBar', extractedFiles, targetExtractFiles);
    }
    else if (stage === 'completed') {
      setText('albPrimaryLabel', 'Completed');
      setText('albPrimarySummary', totalFiles > 0 ? `${downloadedFiles} / ${totalFiles} files downloaded` : 'Download completed');
      setText('albPrimaryMeta', `${formatBytes(downloadedBytes)} | ${extractedFiles} extracted`);
      setBar('albPrimaryBar', totalFiles > 0 ? totalFiles : 1, totalFiles > 0 ? totalFiles : 1);
    }
    else if (stage === 'failed') {
      setText('albPrimaryLabel', 'Failed');
      setText('albPrimarySummary', snapshot && snapshot.message ? String(snapshot.message) : 'The ALB download failed.');
      setText('albPrimaryMeta', `${downloadedFiles} / ${totalFiles} files | ${formatBytes(downloadedBytes)}`);
      setBar('albPrimaryBar', downloadedFiles, totalFiles);
    }
    else {
      setText('albPrimaryLabel', stage === 'pruning' ? 'Pruning' : 'Downloading');
      setText('albPrimarySummary', totalFiles > 0 ? `${downloadedFiles} / ${totalFiles} files downloaded` : 'No downloadable files planned yet.');
      setText('albPrimaryMeta', `${formatBytes(downloadedBytes)} / ${formatBytes(totalBytes)} | ${speed} | ETA ${eta}`);
      setBar('albPrimaryBar', downloadedFiles, totalFiles);
    }

    if (!currentDaySection || !currentDayCard || !allDaysSection || !allDaysSummary || !dayProgress) {
      return;
    }

    const days = progress && Array.isArray(progress.days) ? progress.days : [];
    if (!days.length) {
      currentDaySection.hidden = true;
      allDaysSection.hidden = true;
      dayProgress.innerHTML = '';
      return;
    }

    const currentDay = determineCurrentDay(days, stage);
    currentDaySection.hidden = false;
    currentDayCard.innerHTML = buildDayCard(currentDay, true);

    allDaysSection.hidden = days.length <= 1;
    allDaysSummary.textContent = allDaysSection.open ? 'Hide all days' : 'Show all days';
    if (days.length <= 1) {
      dayProgress.innerHTML = '';
      return;
    }

    dayProgress.innerHTML = days.map((day) => buildDayCard(day, false)).join('');
  }

  function determineCurrentDay(days, stage) {
    if (!Array.isArray(days) || !days.length) {
      return null;
    }

    const isComplete = (day) => {
      const total = Number(day.totalFiles || 0);
      const downloaded = Number(day.downloadedFiles || 0);
      const extractTarget = Number(day.inWindowFiles || 0);
      const extracted = Number(day.extractedFiles || 0);

      if (stage === 'extracting' || stage === 'completed') {
        if (extractTarget > 0) {
          return extracted >= extractTarget;
        }
      }

      return total > 0 ? downloaded >= total : false;
    };

    const firstIncomplete = days.find((day) => !isComplete(day));
    if (firstIncomplete) {
      return firstIncomplete;
    }

    const mostRecentlyProgressed = [...days]
      .reverse()
      .find((day) => Number(day.downloadedFiles || 0) > 0 || Number(day.extractedFiles || 0) > 0);

    return mostRecentlyProgressed || days[0];
  }

  function buildDayCard(day, compact) {
    if (!day) {
      return '<div class="footer-note">No current day available yet.</div>';
    }

    const total = Number(day.totalFiles || 0);
    const downloaded = Number(day.downloadedFiles || 0);
    const extractTotal = Number(day.inWindowFiles || 0);
    const extracted = Number(day.extractedFiles || 0);
    const downloadPercent = total > 0 ? Math.max(0, Math.min(100, (downloaded / total) * 100)) : 0;
    const extractPercent = extractTotal > 0 ? Math.max(0, Math.min(100, (extracted / extractTotal) * 100)) : 0;
    const compactClass = compact ? ' day-progress-card--compact' : '';
    const heading = compact ? 'Current day' : day.dayUtc;

    return `
      <div class="result-card day-progress-card${compactClass}">
        <div class="day-progress-head">
          <div class="info-label">${compact ? 'Current day' : 'Day'}</div>
          <div class="info-value day-progress-date">${escapeHtml(day.dayUtc || heading)}</div>
        </div>
        <div class="day-progress-meta">
          <div>${downloaded} / ${total} downloaded</div>
          <div>${extracted} / ${extractTotal} extracted</div>
        </div>
        <div class="progress-track"><div class="progress-fill" style="width:${downloadPercent}%"></div></div>
        <div class="progress-track progress-track--secondary"><div class="progress-fill progress-fill--secondary" style="width:${extractPercent}%"></div></div>
        <div class="footer-note">${formatBytes(day.downloadedBytes || 0)} / ${formatBytes(day.totalBytes || 0)}</div>
      </div>
    `;
  }

  function renderSnapshot(snapshot) {
    if (!snapshot) {
      return;
    }

    setText('albJobState', formatValue(snapshot.state));
    setText('albJobStage', formatValue(snapshot.stage));
    setText('albJobMessage', snapshot.error ? `${snapshot.message} ${snapshot.error}` : formatValue(snapshot.message));
    setText('albJobStep', snapshot.totalSteps ? `Step ${snapshot.currentStep || 0} of ${snapshot.totalSteps}` : '');

    currentJobId = snapshot.jobId || currentJobId;
    renderProgress(snapshot);
    renderOutput(snapshot);
    renderResult(snapshot);
  }

  function collectRequest() {
    const configMode = document.querySelector('input[name="configMode"]:checked')?.value || 'new';
    return {
      configMode,
      savedConfigName: byId('savedConfigName')?.value || '',
      configName: byId('configName')?.value || '',
      bucket: byId('bucket')?.value || '',
      albId: byId('albId')?.value || '',
      scope: byId('scope')?.value || 'external',
      accountId: byId('accountId')?.value || '',
      isSentry: Boolean(byId('isSentry')?.checked),
      awsEnvironmentText: byId('awsEnvironmentText')?.value || '',
      startUtc: buildUtcIso(
        byId('startDateUtc')?.value || '',
        byId('startHourUtc')?.value || '',
        byId('startMinuteUtc')?.value || ''),
      endUtc: buildUtcIso(
        byId('endDateUtc')?.value || '',
        byId('endHourUtc')?.value || '',
        byId('endMinuteUtc')?.value || '')
    };
  }

  function validateRequest(request) {
    const configMode = request.configMode || 'new';
    const missing = [];

    clearValidation();

    const requireValue = (id, label) => {
      const node = byId(id);
      const value = node && 'value' in node ? String(node.value || '').trim() : '';
      if (value) {
        return;
      }

      setFieldInvalid(id, true);
      missing.push(label);
    };

    if (configMode === 'saved') {
      requireValue('savedConfigName', 'Saved configuration');
    } else {
      requireValue('bucket', 'S3 bucket');
      requireValue('albId', 'ALB identifier');
      requireValue('accountId', 'AWS account ID');
    }

    requireValue('awsEnvironmentText', 'AWS credentials block');
    requireValue('startDateUtc', 'Start date');
    requireValue('startHourUtc', 'Start hour');
    requireValue('startMinuteUtc', 'Start minute');
    requireValue('endDateUtc', 'End date');
    requireValue('endHourUtc', 'End hour');
    requireValue('endMinuteUtc', 'End minute');

    if (!missing.length && (!request.startUtc || !request.endUtc)) {
      missing.push('Valid UTC start/end time');

      [
        'startDateUtc',
        'startHourUtc',
        'startMinuteUtc',
        'endDateUtc',
        'endHourUtc',
        'endMinuteUtc'
      ].forEach((id) => setFieldInvalid(id, true));
    }

    return missing;
  }

  async function fetchJson(url, options) {
    const response = await fetch(url, {
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      ...options
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `HTTP ${response.status}`);
    }

    return payload;
  }

  async function loadMeta() {
    const payload = await fetchJson('/api/alb/download/meta');
    const count = byId('albSavedConfigCount');
    if (count) {
      count.textContent = String((payload.configs || []).length);
    }

    if (payload.currentJob) {
      renderSnapshot(payload.currentJob);
      currentJobId = payload.currentJob.jobId || currentJobId;
      return payload.currentJob;
    }

    return null;
  }

  async function pollStatus() {
    if (!currentJobId) {
      return null;
    }

    try {
      const snapshot = await fetchJson(`/api/jobs/${encodeURIComponent(currentJobId)}`, { method: 'GET', headers: { 'Accept': 'application/json' } });
      renderSnapshot(snapshot);
      return snapshot;
    } catch (error) {
      setError(String(error));
      return null;
    }
  }

  function syncConfigMode() {
    const mode = document.querySelector('input[name="configMode"]:checked')?.value || 'new';
    setHidden(byId('savedConfigFields'), mode !== 'saved');
    setHidden(byId('newConfigFields'), mode !== 'new');
  }

  async function startDownload() {
    setError('');
    const request = collectRequest();
    const missing = validateRequest(request);
    if (missing.length) {
      setError(`Missing required input: ${missing.join(', ')}.`);
      return;
    }

    try {
      const payload = await fetchJson('/api/alb/download/start', {
        method: 'POST',
        body: JSON.stringify(request)
      });

      if (payload.snapshot) {
        currentJobId = payload.snapshot.jobId || '';
        renderSnapshot(payload.snapshot);
      }
    } catch (error) {
      setError(String(error));
    }
  }

  async function openRunFolder() {
    setError('');
    try {
      if (!currentJobId) {
        throw new Error('No ALB download job has been started yet.');
      }

      const snapshot = await fetchJson(`/api/jobs/${encodeURIComponent(currentJobId)}`, { method: 'GET', headers: { 'Accept': 'application/json' } });
      const payload = await fetchJson('/api/alb/download/open-run-folder', {
        method: 'POST',
        body: JSON.stringify({ jobId: snapshot.jobId || '' })
      });

      if (!payload.ok) {
        throw new Error(payload.message || 'Unable to open logs folder.');
      }
    } catch (error) {
      setError(String(error));
    }
  }

  async function openAlbOption2Export() {
    setAlbOption2Error('');
    try {
      const payload = await fetchJson('/api/alb/top-ips-top-paths/open-export', {
        method: 'POST',
        body: JSON.stringify({ jobId: currentJobId || '' })
      });

      if (!payload.ok) {
        throw new Error(payload.message || 'Unable to open workbook.');
      }
    } catch (error) {
      setAlbOption2Error(String(error));
    }
  }

  function renderOption2Result(result, exportPath) {
    const results = byId('albOption2Results');
    const topIps = byId('albOption2TopIps');
    const topUris = byId('albOption2TopUris');
    if (!results || !topIps || !topUris) {
      return;
    }

    const items = Array.isArray(result?.topIps) ? result.topIps : [];
    setText('albOption2State', items.length ? 'completed' : 'no matches');
    setText('albOption2Matches', String(result?.totalMatchingIps || 0));
    setText('albOption2Message', items.length
      ? `Scan completed for fragment "${result.endpointFragment}".`
      : `No ALB hits matched fragment "${result.endpointFragment}".`);
    setText('albOption2Meta', `Files scanned: ${result?.filesScanned || 0}`);
    setText('albOption2ExportPath', exportPath ? `Exported workbook: ${exportPath}` : '');

    if (!items.length) {
      results.hidden = false;
      topIps.innerHTML = '<div class="footer-note">No matching IPs found.</div>';
      topUris.innerHTML = '';
      return;
    }

    results.hidden = false;
    topIps.innerHTML = `
      <div class="result-lines">
        ${items.map((item) => `<div>#${escapeHtml(item.rank)} ${escapeHtml(item.ip)} <strong>${escapeHtml(formatValue(item.hits))}</strong> hits</div>`).join('')}
      </div>
    `;

    topUris.innerHTML = items.map((item) => `
      <div class="result-card">
        <div class="info-label">IP #${escapeHtml(item.rank)}</div>
        <div class="info-value">${escapeHtml(item.ip)} <span class="footer-note">(${escapeHtml(formatValue(item.hits))} hits)</span></div>
        <ul class="list-clean">
          ${(Array.isArray(item.topUris) && item.topUris.length
            ? item.topUris.map((uri) => `<li><span class="footer-note">#${escapeHtml(uri.rank)}</span> <strong>${escapeHtml(formatValue(uri.hits))}</strong> ${escapeHtml(uri.uri)}</li>`).join('')
            : '<li class="footer-note">(no URI matches)</li>')}
        </ul>
      </div>
    `).join('');
  }

  async function runAlbOption2() {
    setAlbOption2Error('');
    setText('albOption2State', 'running');
    setText('albOption2Phase', 'queued');
    setText('albOption2Message', 'Scanning ALB logs...');
    setText('albOption2Meta', '');
    setText('albOption2ExportPath', '');
    setText('albOption2StageBadge', 'queued');
    setText('albOption2Summary', 'Preparing ALB option 2 scan.');
    setText('albOption2BarMeta', 'Waiting for the job to start.');
    setHidden(byId('albOption2OpenExport'), true);
    setBar('albOption2Bar', 0, 1);

    const endpoint = byId('albOption2Endpoint')?.value?.trim() || '';
    if (!endpoint) {
      setText('albOption2State', 'idle');
      setAlbOption2Error('Endpoint/path fragment is required.');
      return;
    }

    try {
      const payload = await fetchJson('/api/alb/top-ips-top-paths/run', {
        method: 'POST',
        body: JSON.stringify({
          endpointFragment: endpoint,
          exportXlsx: Boolean(byId('albOption2Export')?.checked)
        })
      });

      renderOption2Snapshot(payload.snapshot || {});
      startAlbOption2Polling();
    } catch (error) {
      setText('albOption2State', 'failed');
      setAlbOption2Error(String(error));
    }
  }

  function renderOption2Snapshot(snapshot) {
    const result = snapshot && snapshot.result ? snapshot.result : null;
    const currentStep = Number(snapshot?.currentStep || 0);
    const totalSteps = Number(snapshot?.totalSteps || 0);
    const filesTotal = Number(snapshot?.filesTotal || 0);
    const totalBytes = Number(snapshot?.totalBytes || 0);
    const phase = snapshot?.phase || 'idle';
    const state = snapshot?.state || 'idle';
    const exportPath = snapshot?.exportPath || '';
    const createdUtc = snapshot?.createdUtc ? new Date(snapshot.createdUtc) : null;
    const now = new Date();
    let etaText = 'n/a';

    if (state === 'running' && createdUtc && !Number.isNaN(createdUtc.getTime()) && currentStep > 0 && totalSteps > currentStep) {
      const elapsedSeconds = Math.max(1, (now.getTime() - createdUtc.getTime()) / 1000);
      const secondsPerStep = elapsedSeconds / currentStep;
      etaText = formatEta(secondsPerStep * (totalSteps - currentStep));
    }

    currentJobId = snapshot?.jobId || currentJobId;
    setText('albOption2State', formatValue(state));
    setText('albOption2Phase', formatValue(phase));
    setText('albOption2StageBadge', formatValue(phase));
    setText('albOption2Message', snapshot?.error ? `${snapshot.message} ${snapshot.error}` : formatValue(snapshot?.message));
    setText('albOption2Meta', filesTotal > 0 ? `Scope: ${filesTotal} files | ${formatBytes(totalBytes)}` : '');
    setText('albOption2ExportPath', exportPath ? `Exported workbook: ${exportPath}` : '');
    setText('albOption2Matches', String(result?.totalMatchingIps || 0));
    setHidden(byId('albOption2OpenExport'), !exportPath);

    if (state === 'completed') {
      setText('albOption2Summary', result && result.totalMatchingIps > 0
        ? `${result.totalMatchingIps} matching IPs found`
        : 'No matching IPs found');
      setText('albOption2BarMeta', 'ETA 0s');
      setBar('albOption2Bar', totalSteps > 0 ? totalSteps : 1, totalSteps > 0 ? totalSteps : 1);
      if (result) {
        renderOption2Result(result, exportPath);
      }
      return;
    }

    if (state === 'failed') {
      setText('albOption2Summary', 'Scan failed');
      setText('albOption2BarMeta', snapshot?.error ? `ETA n/a | ${snapshot.error}` : 'ETA n/a');
      return;
    }

    if (state === 'running') {
      setText('albOption2Summary', totalSteps > 0 ? `${Math.round((currentStep / totalSteps) * 100)}% complete` : 'Scanning ALB logs');
      setText('albOption2BarMeta', `ETA ${etaText}`);
      setBar('albOption2Bar', currentStep, totalSteps);
    }
  }

  async function pollAlbOption2Status() {
    try {
      const snapshot = await fetchJson('/api/alb/top-ips-top-paths/job', { method: 'GET', headers: { 'Accept': 'application/json' } });
      renderOption2Snapshot(snapshot);

      if (snapshot && snapshot.state && snapshot.state !== 'running' && albOption2Polling) {
        clearInterval(albOption2Polling);
        albOption2Polling = null;
      }
    } catch (error) {
      setAlbOption2Error(String(error));
    }
  }

  function startAlbOption2Polling() {
    if (albOption2Polling) {
      clearInterval(albOption2Polling);
    }

    albOption2Polling = setInterval(async () => {
      await pollAlbOption2Status();
    }, 1000);
  }

  function startPollingLoop() {
    setInterval(async () => {
      await pollStatus();
    }, 2000);
  }

  function initializeAlbPage() {
    if (!document.querySelector('[data-alb-download-page="true"]')) {
      return;
    }

    document.querySelectorAll('input[name="configMode"]').forEach((element) => {
      element.addEventListener('change', () => {
        syncConfigMode();
        clearValidation();
        setError('');
      });
    });

    [
      'savedConfigName',
      'bucket',
      'albId',
      'accountId',
      'awsEnvironmentText',
      'startDateUtc',
      'startHourUtc',
      'startMinuteUtc',
      'endDateUtc',
      'endHourUtc',
      'endMinuteUtc'
    ].forEach((id) => {
      const node = byId(id);
      if (!node) {
        return;
      }

      const eventName = node.tagName === 'SELECT' ? 'change' : 'input';
      node.addEventListener(eventName, () => {
        setFieldInvalid(id, false);
        setError('');
      });
    });

    byId('albDownloadStart')?.addEventListener('click', startDownload);
    byId('albOpenRunFolder')?.addEventListener('click', openRunFolder);
    byId('albAllDaysSection')?.addEventListener('toggle', (event) => {
      const node = event.currentTarget;
      const summary = byId('albAllDaysSummary');
      if (node && summary) {
        summary.textContent = node.open ? 'Hide all days' : 'Show all days';
      }
    });

    syncConfigMode();
    loadMeta().catch((error) => setError(String(error)));
    startPollingLoop();
  }

  function initializeAlbOption2Page() {
    if (!document.querySelector('[data-alb-option2-page="true"]')) {
      return;
    }

    byId('albOption2Run')?.addEventListener('click', runAlbOption2);
    byId('albOption2OpenExport')?.addEventListener('click', openAlbOption2Export);
    byId('albOption2Endpoint')?.addEventListener('input', () => {
      setAlbOption2Error('');
    });
    pollAlbOption2Status().catch((error) => setAlbOption2Error(String(error)));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initializeAlbPage();
      initializeAlbOption2Page();
    });
  } else {
    initializeAlbPage();
    initializeAlbOption2Page();
  }
})();
