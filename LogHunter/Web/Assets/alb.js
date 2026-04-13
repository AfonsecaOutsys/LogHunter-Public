(function () {
  let currentJobId = '';
  let albOption2Polling = null;
  let albOption2JobId = '';
  let albOption2DefaultSelection = null;
  let albOption2Selection = null;
  let albOption2ServerSelection = null;

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
    const hasJob = snapshot.state && snapshot.state !== 'idle';
    setHidden(byId('albOpenRunFolder'), !hasJob);
    renderProgress(snapshot);
    renderOutput(snapshot);
    renderResult(snapshot);
  }

  function collectRequest() {
    return {
      configMode: currentConfigMode,
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

  let currentConfigMode = 'new';

  function setConfigMode(mode) {
    currentConfigMode = mode;
    const btnNew = byId('configModeNew');
    const btnSaved = byId('configModeSaved');
    if (btnNew) btnNew.classList.toggle('active', mode === 'new');
    if (btnSaved) btnSaved.classList.toggle('active', mode === 'saved');
    setHidden(byId('savedConfigFields'), mode !== 'saved');
    setHidden(byId('newConfigFields'), mode !== 'new');
  }

  function syncConfigMode() {
    setConfigMode(currentConfigMode);
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
      if (!albOption2JobId) {
        throw new Error('No ALB option 2 scan has produced a workbook yet.');
      }

      const payload = await fetchJson('/api/alb/top-ips-top-paths/open-export', {
        method: 'POST',
        body: JSON.stringify({ jobId: albOption2JobId })
      });

      if (!payload.ok) {
        throw new Error(payload.message || 'Unable to open Excel.');
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
    setText('albOption2ExportPath', exportPath ? `Exported: ${exportPath}` : '');

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

  function cloneSelection(selection) {
    if (!selection) {
      return null;
    }

    return {
      sourceType: selection.sourceType || 'default',
      rootPath: selection.rootPath || '',
      filePaths: Array.isArray(selection.filePaths) ? [...selection.filePaths] : [],
      fileCount: Number(selection.fileCount || 0),
      totalBytes: Number(selection.totalBytes || 0),
      selectionLabel: selection.selectionLabel || '',
      summary: selection.summary || '',
      previewItems: Array.isArray(selection.previewItems) ? [...selection.previewItems] : [],
      remainingCount: Number(selection.remainingCount || 0)
    };
  }

  function buildAlbOption2BrowserSelection(sourceType, files) {
    const items = Array.from(files || [])
      .filter((file) => file && typeof file.name === 'string' && file.name.toLowerCase().endsWith('.log'));

    const totalBytes = items.reduce((sum, file) => sum + Number(file.size || 0), 0);
    const previewItems = items.slice(0, 3).map((file) => file.name);
    const remainingCount = Math.max(0, items.length - previewItems.length);
    const folderName = sourceType === 'folder' && items.length
      ? getTopFolderName(items[0])
      : '';

    const selectionLabel = sourceType === 'folder'
      ? (folderName || 'Selected folder')
      : `${items.length} selected file(s)`;

    const summary = sourceType === 'folder'
      ? `${selectionLabel} | ${items.length} .log files | ${formatBytes(totalBytes)}`
      : `${items.length} selected file(s) | ${formatBytes(totalBytes)}`;

    return {
      sourceType,
      files: items,
      fileCount: items.length,
      totalBytes,
      selectionLabel,
      summary,
      previewItems,
      remainingCount
    };
  }

  function getTopFolderName(file) {
    const relativePath = typeof file.webkitRelativePath === 'string' ? file.webkitRelativePath : '';
    if (!relativePath || !relativePath.includes('/')) {
      return '';
    }

    return relativePath.split('/')[0] || '';
  }

  let albOption2SourceType = 'default';

  function getAlbOption2SourceType() {
    return albOption2SourceType;
  }

  function setAlbOption2SourceType(type) {
    albOption2SourceType = type;
  }

  function renderAlbOption2Selection() {
    const sourceType = getAlbOption2SourceType();
    const chip = byId('albOption2SourceChip');
    const clearButton = byId('albOption2ClearSelection');
    const selection = albOption2Selection && albOption2Selection.sourceType === sourceType ? albOption2Selection : null;

    // Update active button state
    const btnDefault = byId('albOption2UseDefault');
    const btnFolder = byId('albOption2SelectFolder');
    const btnFiles = byId('albOption2SelectFiles');
    if (btnDefault) btnDefault.classList.toggle('active', sourceType === 'default');
    if (btnFolder) btnFolder.classList.toggle('active', sourceType === 'folder');
    if (btnFiles) btnFiles.classList.toggle('active', sourceType === 'files');

    setHidden(clearButton, sourceType === 'default');

    if (sourceType === 'default') {
      if (chip) {
        const def = albOption2DefaultSelection;
        chip.textContent = def
          ? `${def.selectionLabel || 'Default folder'} | ${def.fileCount || 0} files | ${formatBytes(def.totalBytes || 0)}`
          : 'Default folder';
      }
      return;
    }

    if (!selection) {
      if (chip) {
        chip.textContent = sourceType === 'folder' ? 'No folder selected' : 'No files selected';
      }
      return;
    }

    if (chip) {
      if (sourceType === 'files') {
        chip.textContent = `${selection.fileCount} file${selection.fileCount === 1 ? '' : 's'} | ${formatBytes(selection.totalBytes)}`;
      } else {
        chip.textContent = `${selection.selectionLabel || 'Selected folder'} | ${selection.fileCount} file${selection.fileCount === 1 ? '' : 's'} | ${formatBytes(selection.totalBytes)}`;
      }
    }
  }

  function setAlbOption2Selection(selection, forceSourceType) {
    albOption2Selection = cloneSelection(selection);
    if (forceSourceType) {
      setAlbOption2SourceType(forceSourceType);
    }
    renderAlbOption2Selection();
  }

  async function loadAlbOption2Meta() {
    const payload = await fetchJson('/api/alb/top-ips-top-paths/meta', { method: 'GET', headers: { 'Accept': 'application/json' } });
    albOption2DefaultSelection = cloneSelection(payload.defaultSelection);
    renderAlbOption2Selection();

    if (payload.currentJob) {
      renderOption2Snapshot(payload.currentJob);
      albOption2JobId = payload.currentJob.jobId || albOption2JobId;
      if (payload.currentJob.state === 'running') {
        startAlbOption2Polling();
      }
    }
  }

  function useAlbOption2Default() {
    setAlbOption2Error('');
    setAlbOption2SourceType('default');
    albOption2Selection = null;
    renderAlbOption2Selection();
  }

  async function selectAlbOption2Folder() {
    setAlbOption2Error('');
    setAlbOption2SourceType('folder');
    renderAlbOption2Selection();
    await new Promise(r => setTimeout(r, 0));

    try {
      const payload = await fetchJson('/api/alb/top-ips-top-paths/browse-folder', { method: 'POST' });
      if (!payload.ok) {
        if (payload.cancelled) {
          setAlbOption2SourceType('default');
          renderAlbOption2Selection();
          return;
        }
        throw new Error(payload.error || 'Failed to browse folder.');
      }
      albOption2ServerSelection = payload.selection;
      albOption2Selection = payload.selection;
      renderAlbOption2Selection();
    } catch (error) {
      setAlbOption2SourceType('default');
      renderAlbOption2Selection();
      setAlbOption2Error(String(error));
    }
  }

  async function selectAlbOption2Files() {
    setAlbOption2Error('');
    setAlbOption2SourceType('files');
    renderAlbOption2Selection();
    await new Promise(r => setTimeout(r, 0));

    try {
      const payload = await fetchJson('/api/alb/top-ips-top-paths/browse-files', { method: 'POST' });
      if (!payload.ok) {
        if (payload.cancelled) {
          setAlbOption2SourceType('default');
          renderAlbOption2Selection();
          return;
        }
        throw new Error(payload.error || 'Failed to browse files.');
      }
      albOption2ServerSelection = payload.selection;
      albOption2Selection = payload.selection;
      renderAlbOption2Selection();
    } catch (error) {
      setAlbOption2SourceType('default');
      renderAlbOption2Selection();
      setAlbOption2Error(String(error));
    }
  }

  function handleAlbOption2FolderInput() {
    const input = byId('albOption2FolderInput');
    const files = input?.files ? Array.from(input.files) : [];
    albOption2Selection = buildAlbOption2BrowserSelection('folder', files);
    renderAlbOption2Selection();
    setAlbOption2Error('');
  }

  function handleAlbOption2FilesInput() {
    const input = byId('albOption2FilesInput');
    const files = input?.files ? Array.from(input.files) : [];
    albOption2Selection = buildAlbOption2BrowserSelection('files', files);
    renderAlbOption2Selection();
    setAlbOption2Error('');
  }

  function clearAlbOption2Selection() {
    albOption2Selection = null;
    albOption2ServerSelection = null;
    setAlbOption2SourceType('default');
    const folderInput = byId('albOption2FolderInput');
    const filesInput = byId('albOption2FilesInput');
    if (folderInput) {
      folderInput.value = '';
    }
    if (filesInput) {
      filesInput.value = '';
    }
    renderAlbOption2Selection();
    setAlbOption2Error('');
  }

  async function createAlbOption2StagingSession(sourceType) {
    const payload = await fetchJson('/api/alb/top-ips-top-paths/staging/start', {
      method: 'POST',
      body: JSON.stringify({ sourceType })
    });

    return payload.stagingId || '';
  }

  async function uploadAlbOption2Selection(selection) {
    const stagingId = await createAlbOption2StagingSession(selection.sourceType);
    if (!stagingId) {
      throw new Error('Unable to create an upload session.');
    }

    for (const file of selection.files) {
      const relativePath = selection.sourceType === 'folder' && file.webkitRelativePath
        ? file.webkitRelativePath
        : file.name;

      const response = await fetch(`/api/alb/top-ips-top-paths/staging/upload?stagingId=${encodeURIComponent(stagingId)}&relativePath=${encodeURIComponent(relativePath)}`, {
        method: 'POST',
        headers: {
          'Content-Type': file.type || 'application/octet-stream'
        },
        body: file
      });

      let payload = null;
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }

      if (!response.ok || !payload?.ok) {
        throw new Error(payload?.error || `Upload failed for ${file.name}.`);
      }
    }

    return stagingId;
  }

  async function runAlbOption2() {
    const sourceType = getAlbOption2SourceType();
    const selection = albOption2Selection && albOption2Selection.sourceType === sourceType ? albOption2Selection : null;

    setAlbOption2Error('');
    setText('albOption2State', 'running');
    setText('albOption2Phase', 'queued');
    setText('albOption2Message', 'Scanning ALB logs...');
    setText('albOption2Meta', '');
    setText('albOption2ExportPath', '');
    setText('albOption2StageBadge', 'queued');
    setText('albOption2Summary', 'Preparing scan.');
    setText('albOption2BarMeta', 'Waiting for the job to start.');
    setHidden(byId('albOption2OpenExport'), true);
    setHidden(byId('albOption2Results'), true);
    setBar('albOption2Bar', 0, 1);

    const endpoint = byId('albOption2Endpoint')?.value?.trim() || '';
    if (!endpoint) {
      setText('albOption2State', 'idle');
      setAlbOption2Error('Endpoint/path fragment is required.');
      return;
    }

    if (sourceType !== 'default' && !selection) {
      setText('albOption2State', 'idle');
      setAlbOption2Error(sourceType === 'folder'
        ? 'Select a folder before running the scan.'
        : 'Select one or more files before running the scan.');
      renderAlbOption2Selection();
      return;
    }

    if (selection && selection.fileCount === 0) {
      setText('albOption2State', 'idle');
      setAlbOption2Error(sourceType === 'folder'
        ? 'The selected folder does not contain any .log files.'
        : 'Select one or more .log files before running the scan.');
      renderAlbOption2Selection();
      return;
    }

    albOption2JobId = '';

    try {
      const runBody = {
        endpointFragment: endpoint,
        exportXlsx: Boolean(byId('albOption2Export')?.checked),
        sourceType
      };

      if (albOption2ServerSelection && sourceType !== 'default') {
        // Server-side native dialog selection — pass path directly, no upload needed.
        if (sourceType === 'folder' && albOption2ServerSelection.rootPath) {
          runBody.serverPath = albOption2ServerSelection.rootPath;
        } else if (albOption2ServerSelection.filePaths) {
          runBody.serverFilePaths = albOption2ServerSelection.filePaths;
        }
      } else if (selection && sourceType !== 'default') {
        // Browser file input fallback — upload via staging.
        setText('albOption2Message', sourceType === 'folder'
          ? 'Uploading selected folder files...'
          : 'Uploading selected files...');
        setText('albOption2Summary', `Preparing ${selection.fileCount} file(s) for scanning`);
        setText('albOption2BarMeta', 'Uploading selected logs to the local web session.');
        runBody.stagingId = await uploadAlbOption2Selection(selection);
      }

      const payload = await fetchJson('/api/alb/top-ips-top-paths/run', {
        method: 'POST',
        body: JSON.stringify(runBody)
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
    const inputSummary = snapshot?.inputSourceSummary || '';
    const createdUtc = snapshot?.createdUtc ? new Date(snapshot.createdUtc) : null;
    const now = new Date();
    let etaText = 'n/a';

    if (state === 'running' && createdUtc && !Number.isNaN(createdUtc.getTime()) && currentStep > 0 && totalSteps > currentStep) {
      const elapsedSeconds = Math.max(1, (now.getTime() - createdUtc.getTime()) / 1000);
      const secondsPerStep = elapsedSeconds / currentStep;
      etaText = formatEta(secondsPerStep * (totalSteps - currentStep));
    }

    albOption2JobId = snapshot?.jobId || albOption2JobId;
    setText('albOption2State', formatValue(state));
    setText('albOption2Phase', formatValue(phase));
    setText('albOption2StageBadge', formatValue(phase));
    setText('albOption2Message', snapshot?.error ? `${snapshot.message} ${snapshot.error}` : formatValue(snapshot?.message));
    setText('albOption2Meta', inputSummary || (filesTotal > 0 ? `Scope: ${filesTotal} files | ${formatBytes(totalBytes)}` : ''));
    setText('albOption2ExportPath', exportPath ? `Exported: ${exportPath}` : '');
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

    byId('configModeNew')?.addEventListener('click', () => setConfigMode('new'));
    byId('configModeSaved')?.addEventListener('click', () => setConfigMode('saved'));

    // Legacy radio fallback (unused, kept for safety).
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
    byId('albOption2UseDefault')?.addEventListener('click', useAlbOption2Default);
    byId('albOption2SelectFolder')?.addEventListener('click', selectAlbOption2Folder);
    byId('albOption2SelectFiles')?.addEventListener('click', selectAlbOption2Files);
    byId('albOption2ClearSelection')?.addEventListener('click', clearAlbOption2Selection);
    byId('albOption2FolderInput')?.addEventListener('change', handleAlbOption2FolderInput);
    byId('albOption2FilesInput')?.addEventListener('change', handleAlbOption2FilesInput);
    byId('albOption2Endpoint')?.addEventListener('input', () => {
      setAlbOption2Error('');
    });
    loadAlbOption2Meta().catch((error) => setAlbOption2Error(String(error)));
  }

  // ── IP Summary (option 3) ─────────────────────────────────────

  let ipSummarySourceType = 'default';
  let ipSummaryDefaultSelection = null;
  let ipSummarySelection = null;
  let ipSummaryServerSelection = null;
  let ipSummaryPolling = null;
  let ipSummaryJobId = '';
  let ipSummaryInputMode = 'manual';
  let ipSummaryExtractedIps = [];
  let ipSummarySelectedExtractedIps = new Set();
  let ipSummaryExportMode = 'export'; // 'chart' or 'export'

  function setIpSummaryError(msg) {
    const node = byId('ipSummaryError');
    if (!node) return;
    node.textContent = msg || '';
    node.hidden = !msg;
  }

  function setIpSummarySourceType(type) { ipSummarySourceType = type; }

  function renderIpSummarySource() {
    const chip = byId('ipSummarySourceChip');
    const clearBtn = byId('ipSummaryClearSelection');
    const st = ipSummarySourceType;
    const sel = ipSummarySelection && ipSummarySelection.sourceType === st ? ipSummarySelection : null;

    const btnDef = byId('ipSummaryUseDefault');
    const btnFol = byId('ipSummarySelectFolder');
    const btnFil = byId('ipSummarySelectFiles');
    if (btnDef) btnDef.classList.toggle('active', st === 'default');
    if (btnFol) btnFol.classList.toggle('active', st === 'folder');
    if (btnFil) btnFil.classList.toggle('active', st === 'files');
    setHidden(clearBtn, st === 'default');

    if (st === 'default') {
      if (chip) {
        const d = ipSummaryDefaultSelection;
        chip.textContent = d
          ? `${d.selectionLabel || 'Default folder'} | ${d.fileCount || 0} files | ${formatBytes(d.totalBytes || 0)}`
          : 'Default folder';
      }
      return;
    }

    if (!sel) {
      if (chip) chip.textContent = st === 'folder' ? 'No folder selected' : 'No files selected';
      return;
    }

    if (chip) {
      chip.textContent = st === 'files'
        ? `${sel.fileCount} file${sel.fileCount === 1 ? '' : 's'} | ${formatBytes(sel.totalBytes)}`
        : `${sel.selectionLabel || 'Selected folder'} | ${sel.fileCount} file${sel.fileCount === 1 ? '' : 's'} | ${formatBytes(sel.totalBytes)}`;
    }
  }

  function setIpSummaryInputMode(mode) {
    ipSummaryInputMode = mode;
    const btnManual = byId('ipSummaryModeManual');
    const btnFile = byId('ipSummaryModeFile');
    if (btnManual) btnManual.classList.toggle('active', mode === 'manual');
    if (btnFile) btnFile.classList.toggle('active', mode === 'file');

    setHidden(byId('ipSummaryManualSection'), mode !== 'manual');
    setHidden(byId('ipSummaryFileSection'), mode !== 'file');
  }

  async function loadIpSummaryMeta() {
    const payload = await fetchJson('/api/alb/ip-summary/meta', { method: 'GET', headers: { 'Accept': 'application/json' } });
    ipSummaryDefaultSelection = cloneSelection(payload.defaultSelection);
    renderIpSummarySource();

    if (payload.currentJob) {
      renderIpSummarySnapshot(payload.currentJob);
      ipSummaryJobId = payload.currentJob.jobId || ipSummaryJobId;
      if (payload.currentJob.state === 'running') {
        startIpSummaryPolling();
      }
    }
  }

  async function loadIpSummaryOutputFiles() {
    const sel = byId('ipSummaryFileSelect');
    if (!sel) return;
    try {
      const payload = await fetchJson('/api/alb/ip-summary/output-files', { method: 'GET', headers: { 'Accept': 'application/json' } });
      sel.innerHTML = '<option value="">Select a file...</option>';
      (payload.files || []).forEach(f => {
        const opt = document.createElement('option');
        opt.value = f.path;
        opt.textContent = `${f.createdUtc} - ${f.name} (${formatBytes(f.size)})`;
        sel.appendChild(opt);
      });
    } catch {
      sel.innerHTML = '<option value="">Failed to load files</option>';
    }
  }

  async function extractIpsFromFile() {
    const sel = byId('ipSummaryFileSelect');
    const filePath = sel?.value;
    if (!filePath) {
      setIpSummaryError('Select an output file first.');
      return;
    }

    setIpSummaryError('');
    try {
      const payload = await fetchJson('/api/alb/ip-summary/extract-ips', {
        method: 'POST',
        body: JSON.stringify({ filePath })
      });

      if (!payload.ok) {
        setIpSummaryError(payload.error || 'Failed to extract IPs.');
        return;
      }

      ipSummaryExtractedIps = payload.ips || [];
      ipSummarySelectedExtractedIps = new Set(ipSummaryExtractedIps.slice(0, 10).map(x => x.ip));

      const info = byId('ipSummaryExtractInfo');
      if (info) info.textContent = `Column: ${payload.ipColumn} | ${ipSummaryExtractedIps.length} IPs found`;

      renderExtractedIpList();
      setHidden(byId('ipSummaryExtractResult'), false);
    } catch (err) {
      setIpSummaryError(String(err));
    }
  }

  function renderExtractedIpList() {
    const container = byId('ipSummaryExtractedList');
    if (!container) return;
    container.innerHTML = '';

    ipSummaryExtractedIps.forEach(item => {
      const label = document.createElement('label');
      label.className = 'ip-extract-item';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = ipSummarySelectedExtractedIps.has(item.ip);
      cb.disabled = !cb.checked && ipSummarySelectedExtractedIps.size >= 10;
      cb.addEventListener('change', () => {
        if (cb.checked) {
          if (ipSummarySelectedExtractedIps.size >= 10) {
            cb.checked = false;
            return;
          }
          ipSummarySelectedExtractedIps.add(item.ip);
        } else {
          ipSummarySelectedExtractedIps.delete(item.ip);
        }
        renderExtractedIpList();
      });
      label.appendChild(cb);
      label.appendChild(document.createTextNode(` ${item.ip} (${Number(item.hits).toLocaleString('en-US')})`));
      container.appendChild(label);
    });
  }

  function getIpSummaryIps() {
    if (ipSummaryInputMode === 'file') {
      return Array.from(ipSummarySelectedExtractedIps);
    }
    const text = byId('ipSummaryIpText')?.value || '';
    return text.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
  }

  async function selectIpSummaryFolder() {
    setIpSummaryError('');
    setIpSummarySourceType('folder');
    renderIpSummarySource();
    await new Promise(r => setTimeout(r, 0));

    try {
      const payload = await fetchJson('/api/alb/ip-summary/browse-folder', { method: 'POST' });
      if (!payload.ok) {
        if (payload.cancelled) {
          setIpSummarySourceType('default');
          renderIpSummarySource();
          return;
        }
        throw new Error(payload.error || 'Failed to browse folder.');
      }
      ipSummaryServerSelection = payload.selection;
      ipSummarySelection = payload.selection;
      renderIpSummarySource();
    } catch (error) {
      setIpSummarySourceType('default');
      renderIpSummarySource();
      setIpSummaryError(String(error));
    }
  }

  async function selectIpSummaryFiles() {
    setIpSummaryError('');
    setIpSummarySourceType('files');
    renderIpSummarySource();
    await new Promise(r => setTimeout(r, 0));

    try {
      const payload = await fetchJson('/api/alb/ip-summary/browse-files', { method: 'POST' });
      if (!payload.ok) {
        if (payload.cancelled) {
          setIpSummarySourceType('default');
          renderIpSummarySource();
          return;
        }
        throw new Error(payload.error || 'Failed to browse files.');
      }
      ipSummaryServerSelection = payload.selection;
      ipSummarySelection = payload.selection;
      renderIpSummarySource();
    } catch (error) {
      setIpSummarySourceType('default');
      renderIpSummarySource();
      setIpSummaryError(String(error));
    }
  }

  function clearIpSummarySelection() {
    setIpSummaryError('');
    setIpSummarySourceType('default');
    ipSummarySelection = null;
    ipSummaryServerSelection = null;
    renderIpSummarySource();
  }

  async function runIpSummary() {
    setIpSummaryError('');

    const ips = getIpSummaryIps();
    if (ips.length === 0) {
      setIpSummaryError('Enter at least one IP address.');
      return;
    }
    if (ips.length > 10) {
      setIpSummaryError('Maximum 10 IPs per scan.');
      return;
    }

    const isChartOnly = ipSummaryExportMode === 'chart';
    const exportXlsx = !isChartOnly;
    const body = { ips, exportXlsx, chartOnly: isChartOnly, sourceType: ipSummarySourceType };

    if (ipSummarySourceType === 'folder' && ipSummaryServerSelection?.rootPath) {
      body.serverPath = ipSummaryServerSelection.rootPath;
    } else if (ipSummarySourceType === 'files' && ipSummaryServerSelection?.filePaths?.length) {
      body.serverFilePaths = ipSummaryServerSelection.filePaths;
    }

    try {
      const payload = await fetchJson('/api/alb/ip-summary/run', {
        method: 'POST',
        body: JSON.stringify(body)
      });

      if (!payload.ok) {
        setIpSummaryError(payload.error || 'Failed to start scan.');
        return;
      }

      ipSummaryJobId = payload.snapshot?.jobId || '';
      renderIpSummarySnapshot(payload.snapshot);
      startIpSummaryPolling();
    } catch (err) {
      setIpSummaryError(String(err));
    }
  }

  function startIpSummaryPolling() {
    stopIpSummaryPolling();
    ipSummaryPolling = setInterval(pollIpSummaryJob, 1500);
  }

  function stopIpSummaryPolling() {
    if (ipSummaryPolling) {
      clearInterval(ipSummaryPolling);
      ipSummaryPolling = null;
    }
  }

  async function pollIpSummaryJob() {
    try {
      const snapshot = await fetchJson('/api/alb/ip-summary/job', { method: 'GET', headers: { 'Accept': 'application/json' } });
      renderIpSummarySnapshot(snapshot);
      if (snapshot.state !== 'running') {
        stopIpSummaryPolling();
      }
    } catch {
      stopIpSummaryPolling();
    }
  }

  function renderIpSummarySnapshot(snap) {
    if (!snap) return;

    const state = snap.state || 'idle';
    const phase = snap.phase || 'idle';
    const currentStep = Number(snap.currentStep || 0);
    const totalSteps = Number(snap.totalSteps || 0);
    const createdUtc = snap.createdUtc ? new Date(snap.createdUtc) : null;
    const now = new Date();

    setText('ipSummaryState', state);
    setText('ipSummaryPhase', phase);
    setText('ipSummaryIpCount', String((snap.requestedIps || []).length));
    setText('ipSummaryMessage', snap.error ? `${snap.message} ${snap.error}` : (snap.message || ''));
    setText('ipSummaryStageBadge', phase);

    ipSummaryJobId = snap.jobId || ipSummaryJobId;

    // Progress bar + ETA
    const pct = totalSteps > 0 ? Math.round((currentStep / totalSteps) * 100) : 0;
    const bar = byId('ipSummaryBar');
    if (bar) bar.style.width = pct + '%';

    let etaText = 'n/a';
    if (state === 'running' && createdUtc && !Number.isNaN(createdUtc.getTime()) && currentStep > 0 && totalSteps > currentStep) {
      const elapsedSeconds = Math.max(1, (now.getTime() - createdUtc.getTime()) / 1000);
      const secondsPerStep = elapsedSeconds / currentStep;
      etaText = formatEta(secondsPerStep * (totalSteps - currentStep));
    }

    const isExporting = phase === 'building-excel' || phase === 'building-sqlite' || phase === 'building-report';

    if (state === 'completed') {
      setText('ipSummarySummary', 'Scan complete.');
      setText('ipSummaryBarMeta', `100% | ${snap.filesTotal || 0} files scanned`);
      if (bar) bar.style.width = '100%';
    } else if (state === 'failed') {
      setText('ipSummarySummary', 'Scan failed.');
      setText('ipSummaryBarMeta', snap.error || '');
    } else if (isExporting) {
      const exportLabel = phase === 'building-excel' ? 'Building Excel workbook...'
        : phase === 'building-sqlite' ? 'Finalizing SQLite database...'
        : 'Building chart report...';
      setText('ipSummarySummary', exportLabel);
      setText('ipSummaryBarMeta', `100% | ${exportLabel}`);
      if (bar) bar.style.width = '100%';
    } else if (state === 'running') {
      setText('ipSummarySummary', `${pct}% — ${snap.filesProcessed || 0} / ${snap.filesTotal || 0} files`);
      setText('ipSummaryBarMeta', `${pct}% | ETA ${etaText} | ${snap.filesProcessed || 0} / ${snap.filesTotal || 0} files`);
    } else {
      setText('ipSummarySummary', 'Waiting for a scan to start.');
      setText('ipSummaryBarMeta', 'No scan running.');
    }

    // Per-IP row counts
    const ipCounts = snap.ipRowCounts || {};
    const ipProgressSection = byId('ipSummaryIpProgress');
    const ipRowsContainer = byId('ipSummaryIpRows');
    const hasIps = Object.keys(ipCounts).length > 0;
    setHidden(ipProgressSection, !hasIps);

    if (ipRowsContainer && hasIps) {
      ipRowsContainer.innerHTML = Object.entries(ipCounts)
        .sort((a, b) => b[1] - a[1])
        .map(([ip, count]) => `<div class="status-pill"><span>${escHtml(ip)}</span><strong>${Number(count).toLocaleString('en-US')}</strong></div>`)
        .join('');
    }

    // Export buttons — always visible, disabled until artifacts ready
    const openReport = byId('ipSummaryOpenReport');
    const openExport = byId('ipSummaryOpenExport');
    const hasReport = Boolean(snap.htmlReportPath);
    const hasExport = Boolean(snap.excelPath || snap.sqlitePath);

    if (openReport) {
      openReport.disabled = !hasReport;
      openReport.classList.toggle('primary', hasReport);
    }
    if (openExport) {
      const chartOnly = ipSummaryExportMode === 'chart';
      openExport.disabled = chartOnly || !hasExport;
      openExport.classList.toggle('primary', !chartOnly && hasExport);
      openExport.textContent = snap.sqlitePath && !snap.excelPath ? 'Open SQLite' : 'Open Excel';
    }

    const exportInfo = byId('ipSummaryExportInfo');
    if (exportInfo) {
      if (snap.detailMode === 'sqlite') {
        exportInfo.textContent = 'Detail mode: SQLite (exceeded 1M rows)';
      } else if (snap.excelPath) {
        exportInfo.textContent = 'Excel workbook exported.';
      } else if (state === 'completed' && hasReport && !hasExport) {
        exportInfo.textContent = 'Chart summary only (no data export).';
      } else {
        exportInfo.textContent = '';
      }
    }

    // Error
    if (snap.error) {
      const meta = byId('ipSummaryMeta');
      if (meta) meta.textContent = snap.error;
    }

    // Results
    renderIpSummaryResults(snap);
  }

  function renderIpSummaryResults(snap) {
    const container = byId('ipSummaryPerIp');
    const section = byId('ipSummaryResults');
    if (!container || !section) return;

    if (snap.state !== 'completed' || !snap.perIpSummaries || snap.perIpSummaries.length === 0) {
      setHidden(section, true);
      return;
    }

    setHidden(section, false);
    container.innerHTML = snap.perIpSummaries.map(ip => {
      const hasHits = ip.totalRows > 0;
      const mismatchRows = [
        { label: 'FE 5xx while ELB 2xx/3xx', value: ip.fe5xxWhileElb2xx3xx },
        { label: 'FE 4xx while ELB 2xx/3xx', value: ip.fe4xxWhileElb2xx3xx },
        { label: 'ELB 5xx while FE 2xx/3xx', value: ip.elb5xxWhileFe2xx3xx },
        { label: 'ELB 4xx while FE 2xx/3xx', value: ip.elb4xxWhileFe2xx3xx }
      ];
      const endpointRows = (ip.topEndpoints || []).map(e =>
        `<tr><td style="font-family:monospace;word-break:break-all">${escHtml(e.endpoint)}</td><td style="text-align:right">${Number(e.hits).toLocaleString('en-US')}</td></tr>`
      ).join('') || '<tr><td colspan="2">(none)</td></tr>';

      if (!hasHits) {
        return `<div class="result-card"><div class="status-pill"><span>${escHtml(ip.ip)}</span><strong>0 hits</strong></div><p class="page-copy">No ALB hits found for this IP.</p></div>`;
      }

      return `
        <details class="expandable-panel" open>
          <summary>${escHtml(ip.ip)} — ${Number(ip.totalRows).toLocaleString('en-US')} hits</summary>
          <div class="expandable-body">
            <div class="status-block">
              <div class="status-pill"><span>Total</span><strong>${Number(ip.totalRows).toLocaleString('en-US')}</strong></div>
              <div class="status-pill"><span>Files</span><strong>${ip.filesWithHits}</strong></div>
              <div class="status-pill"><span>First hit</span><strong>${ip.firstHitUtc || '-'} UTC</strong></div>
              <div class="status-pill"><span>Last hit</span><strong>${ip.lastHitUtc || '-'} UTC</strong></div>
            </div>
            <div class="ip-summary-grid">
              <div class="result-card">
                <h4>ELB Response totals</h4>
                <table class="mini-table"><tr><td>2xx/3xx</td><td>${fmt(ip.elb2xx3xx)}</td></tr><tr><td>4xx</td><td>${fmt(ip.elb4xx)}</td></tr><tr><td>5xx</td><td>${fmt(ip.elb5xx)}</td></tr></table>
              </div>
              <div class="result-card">
                <h4>FE Response totals</h4>
                <table class="mini-table"><tr><td>2xx/3xx</td><td>${fmt(ip.fe2xx3xx)}</td></tr><tr><td>4xx</td><td>${fmt(ip.fe4xx)}</td></tr><tr><td>5xx</td><td>${fmt(ip.fe5xx)}</td></tr></table>
              </div>
              <div class="result-card">
                <h4>Interesting mismatches</h4>
                <table class="mini-table">${mismatchRows.map(m => `<tr><td>${escHtml(m.label)}</td><td>${fmt(m.value)}</td></tr>`).join('')}</table>
              </div>
              <div class="result-card">
                <h4>Top 10 FE endpoints</h4>
                <table class="mini-table">${endpointRows}</table>
              </div>
            </div>
          </div>
        </details>`;
    }).join('');
  }

  function fmt(v) { return Number(v || 0).toLocaleString('en-US'); }
  function escHtml(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  function setIpSummaryExportMode(mode) {
    ipSummaryExportMode = mode;
    const btnChart = byId('ipSummaryModeChart');
    const btnExport = byId('ipSummaryModeExport');
    if (btnChart) btnChart.classList.toggle('active', mode === 'chart');
    if (btnExport) btnExport.classList.toggle('active', mode === 'export');

    const openExport = byId('ipSummaryOpenExport');
    if (openExport) {
      if (mode === 'chart') {
        openExport.disabled = true;
        openExport.classList.remove('primary');
      }
    }
  }

  function initializeIpSummaryPage() {
    if (!document.querySelector('[data-alb-ip-summary-page]')) return;

    byId('ipSummaryModeManual')?.addEventListener('click', () => setIpSummaryInputMode('manual'));
    byId('ipSummaryModeFile')?.addEventListener('click', () => {
      setIpSummaryInputMode('file');
      loadIpSummaryOutputFiles();
    });

    byId('ipSummaryModeChart')?.addEventListener('click', () => setIpSummaryExportMode('chart'));
    byId('ipSummaryModeExport')?.addEventListener('click', () => setIpSummaryExportMode('export'));

    byId('ipSummaryExtractBtn')?.addEventListener('click', extractIpsFromFile);

    byId('ipSummaryUseDefault')?.addEventListener('click', clearIpSummarySelection);
    byId('ipSummarySelectFolder')?.addEventListener('click', selectIpSummaryFolder);
    byId('ipSummarySelectFiles')?.addEventListener('click', selectIpSummaryFiles);
    byId('ipSummaryClearSelection')?.addEventListener('click', clearIpSummarySelection);

    byId('ipSummaryRun')?.addEventListener('click', runIpSummary);

    byId('ipSummaryOpenReport')?.addEventListener('click', async () => {
      const btn = byId('ipSummaryOpenReport');
      if (btn?.disabled) return;
      try { await fetchJson('/api/alb/ip-summary/open-report', { method: 'POST' }); } catch (err) { setIpSummaryError(String(err)); }
    });

    byId('ipSummaryOpenExport')?.addEventListener('click', async () => {
      const btn = byId('ipSummaryOpenExport');
      if (btn?.disabled) return;
      try { await fetchJson('/api/alb/ip-summary/open-export', { method: 'POST' }); } catch (err) { setIpSummaryError(String(err)); }
    });

    loadIpSummaryMeta().catch(err => setIpSummaryError(String(err)));
  }

  // ── Generic scan pages (options 4-10) ────────────────────────

  function initializeGenericScanPage(prefix, apiBase) {
    var scanEl = document.querySelector('[data-alb-generic-scan="' + prefix + '"]');
    if (!scanEl) return;

    var sourceType = 'default';
    var defaultSelection = null;
    var selection = null;
    var serverSelection = null;
    var polling = null;
    var jobId = '';
    var chartAutoOpened = false;

    function setErr(msg) {
      var node = byId(prefix + 'Error');
      if (!node) return;
      node.textContent = msg || '';
      node.hidden = !msg;
    }

    function renderSource() {
      var chip = byId(prefix + 'SourceChip');
      var clearBtn = byId(prefix + 'ClearSelection');
      var sel = selection && selection.sourceType === sourceType ? selection : null;

      var btnDef = byId(prefix + 'UseDefault');
      var btnFol = byId(prefix + 'SelectFolder');
      var btnFil = byId(prefix + 'SelectFiles');
      if (btnDef) btnDef.classList.toggle('active', sourceType === 'default');
      if (btnFol) btnFol.classList.toggle('active', sourceType === 'folder');
      if (btnFil) btnFil.classList.toggle('active', sourceType === 'files');
      setHidden(clearBtn, sourceType === 'default');

      if (sourceType === 'default') {
        if (chip) {
          var d = defaultSelection;
          chip.textContent = d
            ? (d.selectionLabel || 'Default folder') + ' | ' + (d.fileCount || 0) + ' files | ' + formatBytes(d.totalBytes || 0)
            : 'Default folder';
        }
        return;
      }

      if (!sel) {
        if (chip) chip.textContent = sourceType === 'folder' ? 'No folder selected' : 'No files selected';
        return;
      }

      if (chip) {
        chip.textContent = sourceType === 'files'
          ? sel.fileCount + ' file' + (sel.fileCount === 1 ? '' : 's') + ' | ' + formatBytes(sel.totalBytes)
          : (sel.selectionLabel || 'Selected folder') + ' | ' + sel.fileCount + ' file' + (sel.fileCount === 1 ? '' : 's') + ' | ' + formatBytes(sel.totalBytes);
      }
    }

    function renderSnapshot(snap) {
      if (!snap) return;

      var state = snap.state || 'idle';
      var phase = snap.phase || 'idle';
      var currentStep = Number(snap.currentStep || 0);
      var totalSteps = Number(snap.totalSteps || 0);
      var createdUtc = snap.createdUtc ? new Date(snap.createdUtc) : null;
      var now = new Date();
      var result = snap.result;
      var exportPath = snap.exportPath || '';
      var chartPath = result && result.chartHtmlPath ? result.chartHtmlPath : '';

      jobId = snap.jobId || jobId;
      setText(prefix + 'State', state);
      setText(prefix + 'Phase', phase);
      setText(prefix + 'StageBadge', phase);
      setText(prefix + 'Message', snap.error ? (snap.message + ' ' + snap.error) : (snap.message || ''));
      setText(prefix + 'Meta', snap.inputSourceSummary || '');
      setText(prefix + 'ExportPath', exportPath ? 'Exported: ' + exportPath : '');
      setText(prefix + 'Count', String(result ? result.totalMatches || 0 : 0));
      setHidden(byId(prefix + 'OpenExport'), !exportPath);
      setHidden(byId(prefix + 'OpenChart'), !chartPath);

      var pct = totalSteps > 0 ? Math.round((currentStep / totalSteps) * 100) : 0;
      var bar = byId(prefix + 'Bar');
      if (bar) bar.style.width = pct + '%';

      var etaText = 'n/a';
      if (state === 'running' && createdUtc && !Number.isNaN(createdUtc.getTime()) && currentStep > 0 && totalSteps > currentStep) {
        var elapsedSeconds = Math.max(1, (now.getTime() - createdUtc.getTime()) / 1000);
        var secondsPerStep = elapsedSeconds / currentStep;
        etaText = formatEta(secondsPerStep * (totalSteps - currentStep));
      }

      if (state === 'completed') {
        setText(prefix + 'Summary', result ? result.completionMessage || 'Scan complete.' : 'Scan complete.');
        setText(prefix + 'BarMeta', '100% | ' + (snap.filesTotal || 0) + ' files scanned');
        if (bar) bar.style.width = '100%';
        renderResults(result);

        // Auto-open chart on completion for scans that produce a chart as their primary output
        if (chartPath && !chartAutoOpened && prefix === 'albWafBlockedChart') {
          chartAutoOpened = true;
          openChart();
        }
      } else if (state === 'failed') {
        setText(prefix + 'Summary', 'Scan failed.');
        setText(prefix + 'BarMeta', snap.error || '');
      } else if (state === 'running') {
        chartAutoOpened = false;
        setText(prefix + 'Summary', pct + '% — ' + (snap.filesProcessed || 0) + ' / ' + (snap.filesTotal || 0) + ' files');
        setText(prefix + 'BarMeta', pct + '% | ETA ' + etaText);
      } else {
        setText(prefix + 'Summary', 'Waiting for a scan to start.');
        setText(prefix + 'BarMeta', 'No scan running.');
      }
    }

    function renderResults(result) {
      var section = byId(prefix + 'Results');
      var body = byId(prefix + 'ResultsBody');
      if (!section || !body) return;

      if (!result || !result.rows || result.rows.length === 0) {
        setHidden(section, true);
        return;
      }

      setHidden(section, false);
      var cols = result.columns || [];
      var rows = result.rows || [];

      // Check if rows have a "Section" column (status mismatch multi-table)
      var sectionIdx = cols.indexOf('Section');
      if (sectionIdx >= 0) {
        body.innerHTML = renderSectionedTable(cols, rows, sectionIdx);
        return;
      }

      var html = '<table class="mini-table"><thead><tr>';
      cols.forEach(function (c) { html += '<th>' + escapeHtml(c) + '</th>'; });
      html += '</tr></thead><tbody>';
      rows.forEach(function (row) {
        html += '<tr>';
        var vals = row.values || row;
        vals.forEach(function (v) { html += '<td>' + escapeHtml(v) + '</td>'; });
        html += '</tr>';
      });
      html += '</tbody></table>';
      body.innerHTML = html;
    }

    function renderSectionedTable(cols, rows, sectionIdx) {
      var sections = {};
      var sectionOrder = [];
      var displayCols = cols.filter(function (_, i) { return i !== sectionIdx; });

      rows.forEach(function (row) {
        var vals = row.values || row;
        var sectionName = vals[sectionIdx] || 'Other';
        if (!sections[sectionName]) {
          sections[sectionName] = [];
          sectionOrder.push(sectionName);
        }
        sections[sectionName].push(vals.filter(function (_, i) { return i !== sectionIdx; }));
      });

      var sectionLabels = {
        'status-pair': 'Top status pairs',
        'uri': 'Top URIs',
        'client-ip': 'Top client IPs'
      };

      var html = '';
      sectionOrder.forEach(function (sn) {
        var label = sectionLabels[sn] || sn;
        html += '<div class="result-card"><h4>' + escapeHtml(label) + '</h4>';
        html += '<table class="mini-table"><thead><tr>';
        displayCols.forEach(function (c) { html += '<th>' + escapeHtml(c) + '</th>'; });
        html += '</tr></thead><tbody>';
        sections[sn].forEach(function (vals) {
          html += '<tr>';
          vals.forEach(function (v) { html += '<td>' + escapeHtml(v) + '</td>'; });
          html += '</tr>';
        });
        html += '</tbody></table></div>';
      });

      return html;
    }

    async function loadMeta() {
      var payload = await fetchJson('/api/' + apiBase + '/meta', { method: 'GET', headers: { 'Accept': 'application/json' } });
      defaultSelection = cloneSelection(payload.defaultSelection);
      renderSource();

      if (payload.currentJob) {
        renderSnapshot(payload.currentJob);
        jobId = payload.currentJob.jobId || jobId;
        if (payload.currentJob.state === 'running') {
          startPolling();
        }
      }
    }

    function startPolling() {
      stopPolling();
      polling = setInterval(async function () {
        try {
          var snap = await fetchJson('/api/' + apiBase + '/job', { method: 'GET', headers: { 'Accept': 'application/json' } });
          renderSnapshot(snap);
          if (snap.state !== 'running') stopPolling();
        } catch (e) {
          stopPolling();
        }
      }, 1500);
    }

    function stopPolling() {
      if (polling) { clearInterval(polling); polling = null; }
    }

    async function browseFolder() {
      setErr('');
      sourceType = 'folder';
      renderSource();
      await new Promise(function (r) { setTimeout(r, 0); });
      try {
        var payload = await fetchJson('/api/' + apiBase + '/browse-folder', { method: 'POST' });
        if (!payload.ok) {
          if (payload.cancelled) { sourceType = 'default'; renderSource(); return; }
          throw new Error(payload.error || 'Failed to browse folder.');
        }
        serverSelection = payload.selection;
        selection = payload.selection;
        renderSource();
      } catch (e) {
        sourceType = 'default';
        renderSource();
        setErr(String(e));
      }
    }

    async function browseFiles() {
      setErr('');
      sourceType = 'files';
      renderSource();
      await new Promise(function (r) { setTimeout(r, 0); });
      try {
        var payload = await fetchJson('/api/' + apiBase + '/browse-files', { method: 'POST' });
        if (!payload.ok) {
          if (payload.cancelled) { sourceType = 'default'; renderSource(); return; }
          throw new Error(payload.error || 'Failed to browse files.');
        }
        serverSelection = payload.selection;
        selection = payload.selection;
        renderSource();
      } catch (e) {
        sourceType = 'default';
        renderSource();
        setErr(String(e));
      }
    }

    function clearSelection() {
      setErr('');
      sourceType = 'default';
      selection = null;
      serverSelection = null;
      renderSource();
    }

    async function runScan() {
      setErr('');
      var body = { sourceType: sourceType };

      if (serverSelection && sourceType !== 'default') {
        if (sourceType === 'folder' && serverSelection.rootPath) {
          body.serverPath = serverSelection.rootPath;
        } else if (serverSelection.filePaths) {
          body.serverFilePaths = serverSelection.filePaths;
        }
      }

      try {
        var payload = await fetchJson('/api/' + apiBase + '/run', {
          method: 'POST',
          body: JSON.stringify(body)
        });

        if (!payload.ok) {
          setErr(payload.error || 'Failed to start scan.');
          return;
        }

        renderSnapshot(payload.snapshot);
        startPolling();
      } catch (e) {
        setErr(String(e));
      }
    }

    async function openExport() {
      setErr('');
      try {
        await fetchJson('/api/' + apiBase + '/open-export', { method: 'POST' });
      } catch (e) {
        setErr(String(e));
      }
    }

    async function openChart() {
      setErr('');
      try {
        await fetchJson('/api/' + apiBase + '/open-chart', { method: 'POST' });
      } catch (e) {
        setErr(String(e));
      }
    }

    byId(prefix + 'UseDefault')?.addEventListener('click', clearSelection);
    byId(prefix + 'SelectFolder')?.addEventListener('click', browseFolder);
    byId(prefix + 'SelectFiles')?.addEventListener('click', browseFiles);
    byId(prefix + 'ClearSelection')?.addEventListener('click', clearSelection);
    byId(prefix + 'Run')?.addEventListener('click', runScan);
    byId(prefix + 'OpenExport')?.addEventListener('click', openExport);
    byId(prefix + 'OpenChart')?.addEventListener('click', openChart);

    loadMeta().catch(function (e) { setErr(String(e)); });
  }

  // ── Requests over time per IP (option 8) ────────────────────

  function initializeReqOverTimePage() {
    var scanEl = document.querySelector('[data-alb-generic-scan="albReqOverTime"]');
    if (!scanEl) return;

    var prefix = 'albReqOverTime';
    var apiBase = 'alb/requests-over-time';

    var sourceType = 'default';
    var defaultSelection = null;
    var selection = null;
    var serverSelection = null;
    var polling = null;
    var jobId = '';
    var inputMode = 'manual';
    var extractedIps = [];
    var selectedExtractedIps = new Set();

    function setErr(msg) {
      var node = byId(prefix + 'Error');
      if (!node) return;
      node.textContent = msg || '';
      node.hidden = !msg;
    }

    function setInputMode(mode) {
      inputMode = mode;
      var btnManual = byId(prefix + 'ModeManual');
      var btnFile = byId(prefix + 'ModeFile');
      if (btnManual) btnManual.classList.toggle('active', mode === 'manual');
      if (btnFile) btnFile.classList.toggle('active', mode === 'file');

      setHidden(byId(prefix + 'ManualSection'), mode !== 'manual');
      setHidden(byId(prefix + 'FileSection'), mode !== 'file');
    }

    function renderSource() {
      var chip = byId(prefix + 'SourceChip');
      var clearBtn = byId(prefix + 'ClearSelection');
      var sel = selection && selection.sourceType === sourceType ? selection : null;

      var btnDef = byId(prefix + 'UseDefault');
      var btnFol = byId(prefix + 'SelectFolder');
      var btnFil = byId(prefix + 'SelectFiles');
      if (btnDef) btnDef.classList.toggle('active', sourceType === 'default');
      if (btnFol) btnFol.classList.toggle('active', sourceType === 'folder');
      if (btnFil) btnFil.classList.toggle('active', sourceType === 'files');
      setHidden(clearBtn, sourceType === 'default');

      if (sourceType === 'default') {
        if (chip) {
          var d = defaultSelection;
          chip.textContent = d
            ? (d.selectionLabel || 'Default folder') + ' | ' + (d.fileCount || 0) + ' files | ' + formatBytes(d.totalBytes || 0)
            : 'Default folder';
        }
        return;
      }

      if (!sel) {
        if (chip) chip.textContent = sourceType === 'folder' ? 'No folder selected' : 'No files selected';
        return;
      }

      if (chip) {
        chip.textContent = sourceType === 'files'
          ? sel.fileCount + ' file' + (sel.fileCount === 1 ? '' : 's') + ' | ' + formatBytes(sel.totalBytes)
          : (sel.selectionLabel || 'Selected folder') + ' | ' + sel.fileCount + ' file' + (sel.fileCount === 1 ? '' : 's') + ' | ' + formatBytes(sel.totalBytes);
      }
    }

    function getIps() {
      if (inputMode === 'file') {
        return Array.from(selectedExtractedIps);
      }
      var text = byId(prefix + 'IpText')?.value || '';
      return text.split(/[\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
    }

    function renderSnapshot(snap) {
      if (!snap) return;

      var state = snap.state || 'idle';
      var phase = snap.phase || 'idle';
      var currentStep = Number(snap.currentStep || 0);
      var totalSteps = Number(snap.totalSteps || 0);
      var createdUtc = snap.createdUtc ? new Date(snap.createdUtc) : null;
      var now = new Date();
      var result = snap.result;
      var chartPath = result && result.chartHtmlPath ? result.chartHtmlPath : '';

      jobId = snap.jobId || jobId;
      setText(prefix + 'State', state);
      setText(prefix + 'Phase', phase);
      setText(prefix + 'StageBadge', phase);
      setText(prefix + 'Message', snap.error ? (snap.message + ' ' + snap.error) : (snap.message || ''));
      setText(prefix + 'Meta', snap.inputSourceSummary || '');
      setText(prefix + 'Count', String(result ? result.totalMatches || 0 : 0));
      setHidden(byId(prefix + 'OpenChart'), !chartPath);

      var pct = totalSteps > 0 ? Math.round((currentStep / totalSteps) * 100) : 0;
      var bar = byId(prefix + 'Bar');
      if (bar) bar.style.width = pct + '%';

      var etaText = 'n/a';
      if (state === 'running' && createdUtc && !Number.isNaN(createdUtc.getTime()) && currentStep > 0 && totalSteps > currentStep) {
        var elapsedSeconds = Math.max(1, (now.getTime() - createdUtc.getTime()) / 1000);
        var secondsPerStep = elapsedSeconds / currentStep;
        etaText = formatEta(secondsPerStep * (totalSteps - currentStep));
      }

      if (state === 'completed') {
        setText(prefix + 'Summary', result ? result.completionMessage || 'Scan complete.' : 'Scan complete.');
        setText(prefix + 'BarMeta', '100% | ' + (snap.filesTotal || 0) + ' files scanned');
        if (bar) bar.style.width = '100%';
        renderResults(result);
      } else if (state === 'failed') {
        setText(prefix + 'Summary', 'Scan failed.');
        setText(prefix + 'BarMeta', snap.error || '');
      } else if (state === 'running') {
        setText(prefix + 'Summary', pct + '% — ' + (snap.filesProcessed || 0) + ' / ' + (snap.filesTotal || 0) + ' files');
        setText(prefix + 'BarMeta', pct + '% | ETA ' + etaText);
      } else {
        setText(prefix + 'Summary', 'Waiting for a scan to start.');
        setText(prefix + 'BarMeta', 'No scan running.');
      }
    }

    function renderResults(result) {
      var section = byId(prefix + 'Results');
      var body = byId(prefix + 'ResultsBody');
      if (!section || !body) return;

      if (!result || !result.rows || result.rows.length === 0) {
        setHidden(section, true);
        return;
      }

      setHidden(section, false);
      var cols = result.columns || [];
      var rows = result.rows || [];

      var html = '<table class="mini-table"><thead><tr>';
      cols.forEach(function (c) { html += '<th>' + escapeHtml(c) + '</th>'; });
      html += '</tr></thead><tbody>';
      rows.forEach(function (row) {
        html += '<tr>';
        var vals = row.values || row;
        vals.forEach(function (v) { html += '<td>' + escapeHtml(v) + '</td>'; });
        html += '</tr>';
      });
      html += '</tbody></table>';
      body.innerHTML = html;
    }

    async function loadMetaData() {
      var payload = await fetchJson('/api/' + apiBase + '/meta', { method: 'GET', headers: { 'Accept': 'application/json' } });
      defaultSelection = cloneSelection(payload.defaultSelection);
      renderSource();

      if (payload.currentJob) {
        renderSnapshot(payload.currentJob);
        jobId = payload.currentJob.jobId || jobId;
        if (payload.currentJob.state === 'running') {
          startPolling();
        }
      }
    }

    async function loadOutputFiles() {
      var sel = byId(prefix + 'FileSelect');
      if (!sel) return;
      try {
        var payload = await fetchJson('/api/' + apiBase + '/output-files', { method: 'GET', headers: { 'Accept': 'application/json' } });
        sel.innerHTML = '<option value="">Select a file...</option>';
        (payload.files || []).forEach(function (f) {
          var opt = document.createElement('option');
          opt.value = f.path;
          opt.textContent = f.createdUtc + ' - ' + f.name + ' (' + formatBytes(f.size) + ')';
          sel.appendChild(opt);
        });
      } catch (e) {
        sel.innerHTML = '<option value="">Failed to load files</option>';
      }
    }

    async function extractIps() {
      var sel = byId(prefix + 'FileSelect');
      var filePath = sel?.value;
      if (!filePath) {
        setErr('Select an output file first.');
        return;
      }

      setErr('');
      try {
        var payload = await fetchJson('/api/' + apiBase + '/extract-ips', {
          method: 'POST',
          body: JSON.stringify({ filePath: filePath })
        });

        if (!payload.ok) {
          setErr(payload.error || 'Failed to extract IPs.');
          return;
        }

        extractedIps = payload.ips || [];
        selectedExtractedIps = new Set(extractedIps.slice(0, 20).map(function (x) { return x.ip; }));

        var info = byId(prefix + 'ExtractInfo');
        if (info) info.textContent = 'Column: ' + payload.ipColumn + ' | ' + extractedIps.length + ' IPs found';

        renderExtractedList();
        setHidden(byId(prefix + 'ExtractResult'), false);
      } catch (e) {
        setErr(String(e));
      }
    }

    function renderExtractedList() {
      var container = byId(prefix + 'ExtractedList');
      if (!container) return;
      container.innerHTML = '';

      extractedIps.forEach(function (item) {
        var label = document.createElement('label');
        label.className = 'ip-extract-item';
        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = selectedExtractedIps.has(item.ip);
        cb.disabled = !cb.checked && selectedExtractedIps.size >= 20;
        cb.addEventListener('change', function () {
          if (cb.checked) {
            if (selectedExtractedIps.size >= 20) { cb.checked = false; return; }
            selectedExtractedIps.add(item.ip);
          } else {
            selectedExtractedIps.delete(item.ip);
          }
          renderExtractedList();
        });
        label.appendChild(cb);
        label.appendChild(document.createTextNode(' ' + item.ip + ' (' + Number(item.hits).toLocaleString('en-US') + ')'));
        container.appendChild(label);
      });
    }

    function startPolling() {
      stopPolling();
      polling = setInterval(async function () {
        try {
          var snap = await fetchJson('/api/' + apiBase + '/job', { method: 'GET', headers: { 'Accept': 'application/json' } });
          renderSnapshot(snap);
          if (snap.state !== 'running') stopPolling();
        } catch (e) {
          stopPolling();
        }
      }, 1500);
    }

    function stopPolling() {
      if (polling) { clearInterval(polling); polling = null; }
    }

    async function browseFolder() {
      setErr('');
      sourceType = 'folder';
      renderSource();
      await new Promise(function (r) { setTimeout(r, 0); });
      try {
        var payload = await fetchJson('/api/' + apiBase + '/browse-folder', { method: 'POST' });
        if (!payload.ok) {
          if (payload.cancelled) { sourceType = 'default'; renderSource(); return; }
          throw new Error(payload.error || 'Failed to browse folder.');
        }
        serverSelection = payload.selection;
        selection = payload.selection;
        renderSource();
      } catch (e) {
        sourceType = 'default';
        renderSource();
        setErr(String(e));
      }
    }

    async function browseFiles() {
      setErr('');
      sourceType = 'files';
      renderSource();
      await new Promise(function (r) { setTimeout(r, 0); });
      try {
        var payload = await fetchJson('/api/' + apiBase + '/browse-files', { method: 'POST' });
        if (!payload.ok) {
          if (payload.cancelled) { sourceType = 'default'; renderSource(); return; }
          throw new Error(payload.error || 'Failed to browse files.');
        }
        serverSelection = payload.selection;
        selection = payload.selection;
        renderSource();
      } catch (e) {
        sourceType = 'default';
        renderSource();
        setErr(String(e));
      }
    }

    function clearSel() {
      setErr('');
      sourceType = 'default';
      selection = null;
      serverSelection = null;
      renderSource();
    }

    async function runScan() {
      setErr('');
      var ips = getIps();
      if (ips.length === 0) {
        setErr('Enter at least one IP address.');
        return;
      }
      if (ips.length > 20) {
        setErr('Maximum 20 IPs per scan.');
        return;
      }

      var body = { ips: ips, sourceType: sourceType };

      if (serverSelection && sourceType !== 'default') {
        if (sourceType === 'folder' && serverSelection.rootPath) {
          body.serverPath = serverSelection.rootPath;
        } else if (serverSelection.filePaths) {
          body.serverFilePaths = serverSelection.filePaths;
        }
      }

      try {
        var payload = await fetchJson('/api/' + apiBase + '/run', {
          method: 'POST',
          body: JSON.stringify(body)
        });

        if (!payload.ok) {
          setErr(payload.error || 'Failed to start scan.');
          return;
        }

        renderSnapshot(payload.snapshot);
        startPolling();
      } catch (e) {
        setErr(String(e));
      }
    }

    async function openChart() {
      setErr('');
      try { await fetchJson('/api/' + apiBase + '/open-chart', { method: 'POST' }); } catch (e) { setErr(String(e)); }
    }

    byId(prefix + 'ModeManual')?.addEventListener('click', function () { setInputMode('manual'); });
    byId(prefix + 'ModeFile')?.addEventListener('click', function () {
      setInputMode('file');
      loadOutputFiles();
    });
    byId(prefix + 'ExtractBtn')?.addEventListener('click', extractIps);
    byId(prefix + 'UseDefault')?.addEventListener('click', clearSel);
    byId(prefix + 'SelectFolder')?.addEventListener('click', browseFolder);
    byId(prefix + 'SelectFiles')?.addEventListener('click', browseFiles);
    byId(prefix + 'ClearSelection')?.addEventListener('click', clearSel);
    byId(prefix + 'Run')?.addEventListener('click', runScan);
    byId(prefix + 'OpenChart')?.addEventListener('click', openChart);

    loadMetaData().catch(function (e) { setErr(String(e)); });
  }

  function initializeAllGenericScanPages() {
    var genericPageDefs = [
      { prefix: 'alb5xxMismatch', apiBase: 'alb/5xx-mismatch' },
      { prefix: 'albTop50Ips', apiBase: 'alb/top-50-ips' },
      { prefix: 'albTop50IpUri', apiBase: 'alb/top-50-ips-by-uri' },
      { prefix: 'albTop50AvgDuration', apiBase: 'alb/top-50-avg-duration' },
      { prefix: 'albWafBlockedSummary', apiBase: 'alb/waf-blocked-summary' },
      { prefix: 'albWafBlockedChart', apiBase: 'alb/waf-blocks-over-time' }
    ];

    genericPageDefs.forEach(function (def) {
      initializeGenericScanPage(def.prefix, def.apiBase);
    });

    initializeReqOverTimePage();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initializeAlbPage();
      initializeAlbOption2Page();
      initializeIpSummaryPage();
      initializeAllGenericScanPages();
    });
  } else {
    initializeAlbPage();
    initializeAlbOption2Page();
    initializeIpSummaryPage();
    initializeAllGenericScanPages();
  }
})();
