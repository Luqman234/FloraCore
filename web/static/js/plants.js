(() => {
  'use strict';

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';

  const deviceSelect = document.getElementById('plantDeviceSelect');
  const refreshButton = document.getElementById('refreshCareButton');
  const editProfileButton = document.getElementById('editProfileButton');
  const createProfileButton = document.getElementById('createProfileButton');

  const profileSpeciesLabel = document.getElementById('profileSpeciesLabel');
  const profilePlantName = document.getElementById('profilePlantName');
  const profileStageLabel = document.getElementById('profileStageLabel');

  const profileSetup = document.getElementById('profileSetup');
  const profileSetupTitle = document.getElementById('profileSetupTitle');
  const closeProfileButton = document.getElementById('closeProfileButton');
  const deleteProfileButton = document.getElementById('deleteProfileButton');
  const saveProfileButton = document.getElementById('saveProfileButton');
  const profileEditorMessage = document.getElementById('profileEditorMessage');

  const plantNameInput = document.getElementById('plantNameInput');
  const speciesSelect = document.getElementById('speciesSelect');
  const growthStageSelect = document.getElementById('growthStageSelect');
  const presetName = document.getElementById('presetName');
  const presetDescription = document.getElementById('presetDescription');
  const applyPresetButton = document.getElementById('applyPresetButton');

  const soilMinInput = document.getElementById('soilMinInput');
  const soilMaxInput = document.getElementById('soilMaxInput');
  const lightMinInput = document.getElementById('lightMinInput');
  const lightMaxInput = document.getElementById('lightMaxInput');
  const temperatureMinInput = document.getElementById('temperatureMinInput');
  const temperatureMaxInput = document.getElementById('temperatureMaxInput');
  const humidityMinInput = document.getElementById('humidityMinInput');
  const humidityMaxInput = document.getElementById('humidityMaxInput');
  const reservoirLowInput = document.getElementById('reservoirLowInput');
  const fertilizerLowInput = document.getElementById('fertilizerLowInput');

  const careEmptyProfile = document.getElementById('careEmptyProfile');
  const careDashboard = document.getElementById('careDashboard');
  const careScoreRing = document.getElementById('careScoreRing');
  const careScoreValue = document.getElementById('careScoreValue');
  const careHeadline = document.getElementById('careHeadline');
  const careDisclaimer = document.getElementById('careDisclaimer');
  const careConfidence = document.getElementById('careConfidence');
  const careDeviceStatus = document.getElementById('careDeviceStatus');
  const telemetryAgeValue = document.getElementById('telemetryAgeValue');
  const heartbeatAgeValue = document.getElementById('heartbeatAgeValue');
  const careEvaluatedValue = document.getElementById('careEvaluatedValue');

  const conditionGrid = document.getElementById('conditionGrid');
  const supplyGrid = document.getElementById('supplyGrid');
  const insightList = document.getElementById('insightList');
  const insightCount = document.getElementById('insightCount');
  const targetProfileName = document.getElementById('targetProfileName');
  const targetSummaryGrid = document.getElementById('targetSummaryGrid');
  const catalogNotice = document.getElementById('catalogNotice');
  const editTargetsButton = document.getElementById('editTargetsButton');

  let catalog = [];
  let catalogMap = new Map();
  let growthStages = [];
  let devices = [];
  let currentDevice = null;
  let currentProfile = null;
  let currentCare = null;
  let refreshTimer = null;

  const escapeHtml = (value) =>
    String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');

  const api = async (url, options = {}) => {
    const response = await fetch(url, {
      credentials: 'same-origin',
      ...options,
      headers: {
        'Accept': 'application/json',
        ...(options.body ? {'Content-Type': 'application/json'} : {}),
        ...(options.method && options.method !== 'GET' ? {'X-CSRF-Token': csrf} : {}),
        ...(options.headers || {}),
      },
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload?.error || `Request failed (${response.status}).`);
    }
    return payload;
  };

  const setEditorMessage = (message = '', type = '') => {
    if (!profileEditorMessage) return;
    profileEditorMessage.textContent = message;
    profileEditorMessage.className = '';
    if (type) profileEditorMessage.classList.add(type);
  };

  const selectedDevice = () => {
    if (!deviceSelect) return null;
    return devices.find((device) => device.device_id === deviceSelect.value) || null;
  };

  const formatNumber = (value, maximumFractionDigits = 0) => {
    const number = Number(value);
    if (!Number.isFinite(number)) return '—';
    return new Intl.NumberFormat(undefined, {
      maximumFractionDigits,
    }).format(number);
  };

  const formatAge = (seconds) => {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value < 0) return '—';
    if (value < 60) return `${Math.round(value)}s`;
    if (value < 3600) return `${Math.floor(value / 60)}m ${Math.round(value % 60)}s`;
    if (value < 86400) {
      const hours = Math.floor(value / 3600);
      const minutes = Math.floor((value % 3600) / 60);
      return `${hours}h ${minutes}m`;
    }
    return `${Math.floor(value / 86400)}d`;
  };

  const titleCase = (value) =>
    String(value || '')
      .replaceAll('_', ' ')
      .replace(/\b\w/g, (letter) => letter.toUpperCase());

  const unitWithSpace = (unit) => (unit === '%' || unit === '°C' ? unit : ` ${unit}`);

  const updateUrlDevice = (deviceId) => {
    try {
      const url = new URL(window.location.href);
      if (deviceId) url.searchParams.set('device', deviceId);
      else url.searchParams.delete('device');
      window.history.replaceState({}, '', url);
    } catch (_) {}
  };

  const currentPreset = () => catalogMap.get(speciesSelect?.value || '') || null;

  const updatePresetDescription = () => {
    const preset = currentPreset();
    if (presetName) presetName.textContent = preset?.name || 'Preset';
    if (presetDescription) {
      presetDescription.textContent =
        preset?.description || 'Choose a species preset.';
    }
  };

  const setInputValue = (element, value) => {
    if (!element) return;
    element.value = Number.isFinite(Number(value)) ? String(value) : '';
  };

  const applyPresetToInputs = (preset, {preserveName = true} = {}) => {
    if (!preset) return;

    if (!preserveName && plantNameInput) {
      plantNameInput.value = preset.name === 'Custom' ? 'My plant' : preset.name;
    }

    setInputValue(soilMinInput, preset.soil_min);
    setInputValue(soilMaxInput, preset.soil_max);
    setInputValue(lightMinInput, preset.light_min_lux);
    setInputValue(lightMaxInput, preset.light_max_lux);
    setInputValue(temperatureMinInput, preset.temperature_min_c);
    setInputValue(temperatureMaxInput, preset.temperature_max_c);
    setInputValue(humidityMinInput, preset.humidity_min);
    setInputValue(humidityMaxInput, preset.humidity_max);
    setInputValue(reservoirLowInput, preset.reservoir_low_percent);
    setInputValue(fertilizerLowInput, preset.fertilizer_low_percent);
  };

  const fillEditorFromProfile = (profile) => {
    if (!profile) return;
    if (plantNameInput) plantNameInput.value = profile.plant_name || '';
    if (speciesSelect) speciesSelect.value = profile.species_key || 'custom';
    if (growthStageSelect) growthStageSelect.value = profile.growth_stage || 'mature';

    const targets = profile.targets || {};
    setInputValue(soilMinInput, targets.soil?.min);
    setInputValue(soilMaxInput, targets.soil?.max);
    setInputValue(lightMinInput, targets.light?.min);
    setInputValue(lightMaxInput, targets.light?.max);
    setInputValue(temperatureMinInput, targets.temperature?.min);
    setInputValue(temperatureMaxInput, targets.temperature?.max);
    setInputValue(humidityMinInput, targets.humidity?.min);
    setInputValue(humidityMaxInput, targets.humidity?.max);
    setInputValue(reservoirLowInput, targets.reservoir_low_percent);
    setInputValue(fertilizerLowInput, targets.fertilizer_low_percent);
    updatePresetDescription();
  };

  const fillEditorForNewProfile = () => {
    const device = selectedDevice();
    const defaultKey = catalogMap.has('generic_houseplant')
      ? 'generic_houseplant'
      : catalog[0]?.key || 'custom';

    if (speciesSelect) speciesSelect.value = defaultKey;
    if (growthStageSelect) growthStageSelect.value = 'mature';
    if (plantNameInput) {
      plantNameInput.value = device?.nickname?.trim() || 'My plant';
    }

    updatePresetDescription();
    applyPresetToInputs(currentPreset(), {preserveName: true});
  };

  const openEditor = () => {
    if (!profileSetup) return;
    profileSetup.hidden = false;
    if (profileSetupTitle) {
      profileSetupTitle.textContent = currentProfile
        ? 'Edit plant profile'
        : 'Create plant profile';
    }
    if (deleteProfileButton) deleteProfileButton.hidden = !currentProfile;

    if (currentProfile) fillEditorFromProfile(currentProfile);
    else fillEditorForNewProfile();

    setEditorMessage('');
    profileSetup.scrollIntoView({behavior: 'smooth', block: 'start'});
  };

  const closeEditor = () => {
    if (profileSetup) profileSetup.hidden = true;
    setEditorMessage('');
  };

  const profilePayload = () => ({
    plant_name: plantNameInput?.value.trim() || '',
    species_key: speciesSelect?.value || '',
    growth_stage: growthStageSelect?.value || '',
    soil_min: Number(soilMinInput?.value),
    soil_max: Number(soilMaxInput?.value),
    light_min_lux: Number(lightMinInput?.value),
    light_max_lux: Number(lightMaxInput?.value),
    temperature_min_c: Number(temperatureMinInput?.value),
    temperature_max_c: Number(temperatureMaxInput?.value),
    humidity_min: Number(humidityMinInput?.value),
    humidity_max: Number(humidityMaxInput?.value),
    reservoir_low_percent: Number(reservoirLowInput?.value),
    fertilizer_low_percent: Number(fertilizerLowInput?.value),
  });

  const renderProfileSummary = () => {
    if (!currentProfile) {
      if (profileSpeciesLabel) profileSpeciesLabel.textContent = 'NO PROFILE';
      if (profilePlantName) profilePlantName.textContent = 'Configure this FloraCore';
      if (profileStageLabel) profileStageLabel.textContent = '—';
      return;
    }

    if (profileSpeciesLabel) {
      profileSpeciesLabel.textContent = String(currentProfile.species_name || '').toUpperCase();
    }
    if (profilePlantName) profilePlantName.textContent = currentProfile.plant_name || 'Plant';
    if (profileStageLabel) {
      profileStageLabel.textContent =
        `${titleCase(currentProfile.growth_stage)} · updated ${new Date(currentProfile.updated_at * 1000).toLocaleString()}`;
    }
  };

  const renderConditionCards = (metrics = []) => {
    if (!conditionGrid) return;

    if (!metrics.length) {
      conditionGrid.innerHTML =
        '<div class="condition-card"><span>TELEMETRY</span><div class="condition-value-row"><strong>—</strong></div><small class="condition-target">No current metrics</small></div>';
      return;
    }

    conditionGrid.innerHTML = metrics.map((metric) => {
      const value = Number(metric.value);
      const hasValue = Number.isFinite(value);
      const unit = metric.unit || '';
      const precision = metric.key === 'temperature' ? 1 : 0;
      const valueText = hasValue ? formatNumber(value, precision) : '—';
      const targetMin = formatNumber(metric.min, precision);
      const targetMax = formatNumber(metric.max, precision);
      const status = metric.status || 'unknown';

      return `
        <article class="condition-card">
          <span>${escapeHtml(String(metric.label || metric.key).toUpperCase())}</span>
          <div class="condition-value-row">
            <strong>${escapeHtml(valueText)}</strong>
            <em>${escapeHtml(unit)}</em>
          </div>
          <small class="condition-target">
            TARGET ${escapeHtml(targetMin)}–${escapeHtml(targetMax)}${escapeHtml(unitWithSpace(unit))}
          </small>
          <b class="condition-status ${escapeHtml(status)}">${escapeHtml(titleCase(status))}</b>
        </article>
      `;
    }).join('');
  };

  const renderSupplyCards = (supplies = []) => {
    if (!supplyGrid) return;

    if (!supplies.length) {
      supplyGrid.innerHTML = '<div class="supply-card"><span>RESERVOIRS</span><strong>—</strong><p>No reservoir telemetry reported.</p></div>';
      return;
    }

    supplyGrid.innerHTML = supplies.map((item) => {
      const value = Number(item.value);
      const hasValue = Number.isFinite(value);
      const status = item.status || 'unknown';

      return `
        <article class="supply-card">
          <span>${escapeHtml(String(item.label || item.key).toUpperCase())}</span>
          <strong>${hasValue ? `${escapeHtml(formatNumber(value))}%` : '—'}</strong>
          <p>Warn below ${escapeHtml(formatNumber(item.low_threshold))}%</p>
          <b class="condition-status ${escapeHtml(status)}">${escapeHtml(titleCase(status))}</b>
        </article>
      `;
    }).join('');
  };

  const renderInsights = (insights = []) => {
    if (!insightList || !insightCount) return;

    insightCount.textContent = `${insights.length} insight${insights.length === 1 ? '' : 's'}`;

    if (!insights.length) {
      insightList.innerHTML =
        '<div class="insight-row good"><i class="insight-severity"></i><div class="insight-copy"><b>No care warnings</b><p>There is nothing to surface right now.</p></div></div>';
      return;
    }

    insightList.innerHTML = insights.map((item) => `
      <article class="insight-row ${escapeHtml(item.severity || '')}">
        <i class="insight-severity" aria-hidden="true"></i>
        <div class="insight-copy">
          <b>${escapeHtml(item.title || 'Care insight')}</b>
          <p>${escapeHtml(item.detail || '')}</p>
        </div>
        <p class="insight-action">${escapeHtml(item.action || '')}</p>
      </article>
    `).join('');
  };

  const renderTargets = (profile) => {
    if (!targetSummaryGrid || !profile) return;

    const targets = profile.targets || {};
    const items = [
      ['Soil moisture', targets.soil, '%'],
      ['Light', targets.light, 'lux'],
      ['Temperature', targets.temperature, '°C'],
      ['Humidity', targets.humidity, '%'],
    ];

    targetSummaryGrid.innerHTML = items.map(([label, range, unit]) => `
      <article class="target-summary-card">
        <span>${escapeHtml(label)}</span>
        <b>${escapeHtml(formatNumber(range?.min, unit === '°C' ? 1 : 0))}–${escapeHtml(formatNumber(range?.max, unit === '°C' ? 1 : 0))}${escapeHtml(unitWithSpace(unit))}</b>
      </article>
    `).join('');

    if (targetProfileName) {
      targetProfileName.textContent = `${profile.plant_name} · ${profile.species_name}`;
    }
  };

  const renderCare = () => {
    renderProfileSummary();

    if (!currentProfile) {
      if (careEmptyProfile) careEmptyProfile.hidden = false;
      if (careDashboard) careDashboard.hidden = true;
      return;
    }

    if (careEmptyProfile) careEmptyProfile.hidden = true;
    if (careDashboard) careDashboard.hidden = false;

    const care = currentCare || {};
    const score = Number(care.score);
    const scoreValue = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;

    if (careScoreRing) careScoreRing.style.setProperty('--score', String(scoreValue));
    if (careScoreValue) careScoreValue.textContent = Number.isFinite(score) ? String(Math.round(score)) : '—';
    if (careHeadline) careHeadline.textContent = care.headline || 'Waiting for telemetry';
    if (careDisclaimer) careDisclaimer.textContent = care.disclaimer || '';
    if (careConfidence) careConfidence.textContent = `${Number(care.confidence_percent || 0)}%`;

    if (careDeviceStatus) {
      careDeviceStatus.classList.toggle('online', Boolean(care.online));
      careDeviceStatus.innerHTML = `<i></i>${care.online ? 'ONLINE' : 'OFFLINE'}`;
    }

    if (telemetryAgeValue) telemetryAgeValue.textContent = formatAge(care.telemetry_age_seconds);
    if (heartbeatAgeValue) heartbeatAgeValue.textContent = formatAge(care.heartbeat_age_seconds);
    if (careEvaluatedValue) careEvaluatedValue.textContent = new Date().toLocaleTimeString();

    renderConditionCards(Array.isArray(care.metrics) ? care.metrics : []);
    renderSupplyCards(Array.isArray(care.supplies) ? care.supplies : []);
    renderInsights(Array.isArray(care.insights) ? care.insights : []);
    renderTargets(currentProfile);
  };

  const loadCatalog = async () => {
    if (!speciesSelect || !growthStageSelect) return;

    const payload = await api('/api/plants/catalog');
    catalog = Array.isArray(payload.data) ? payload.data : [];
    growthStages = Array.isArray(payload.growth_stages) ? payload.growth_stages : [];
    catalogMap = new Map(catalog.map((item) => [item.key, item]));

    speciesSelect.innerHTML = '';
    catalog.forEach((item) => {
      const option = document.createElement('option');
      option.value = item.key;
      option.textContent = item.name;
      speciesSelect.append(option);
    });

    growthStageSelect.innerHTML = '';
    growthStages.forEach((stage) => {
      const option = document.createElement('option');
      option.value = stage;
      option.textContent = titleCase(stage);
      growthStageSelect.append(option);
    });

    if (catalogNotice) catalogNotice.textContent = payload.notice || '';
    updatePresetDescription();
  };

  const loadDevices = async () => {
    if (!deviceSelect) return;

    const payload = await api('/api/plants');
    devices = Array.isArray(payload.data) ? payload.data : [];

    const requested = new URL(window.location.href).searchParams.get('device');
    const previous = deviceSelect.value;
    const desired =
      devices.find((item) => item.device_id === requested)?.device_id ||
      devices.find((item) => item.device_id === previous)?.device_id ||
      devices[0]?.device_id ||
      '';

    deviceSelect.innerHTML = '';
    devices.forEach((device) => {
      const option = document.createElement('option');
      option.value = device.device_id;
      option.textContent =
        `${device.nickname || device.device_id} · ${device.device_id}`;
      deviceSelect.append(option);
    });

    if (desired) deviceSelect.value = desired;
    currentDevice = selectedDevice();
    currentProfile = currentDevice?.profile || null;
    updateUrlDevice(desired);
  };

  const loadCare = async ({quiet = false} = {}) => {
    const device = selectedDevice();
    if (!device) return;

    currentDevice = device;
    if (!quiet && refreshButton) {
      refreshButton.disabled = true;
      refreshButton.textContent = 'Refreshing…';
    }

    try {
      const payload = await api(`/api/plants/${encodeURIComponent(device.device_id)}/care`);
      currentProfile = payload.data?.profile || null;
      currentCare = payload.data?.care || null;

      const listDevice = devices.find((item) => item.device_id === device.device_id);
      if (listDevice) listDevice.profile = currentProfile;

      renderCare();
    } catch (error) {
      if (careHeadline) careHeadline.textContent = error.message;
    } finally {
      if (!quiet && refreshButton) {
        refreshButton.disabled = false;
        refreshButton.textContent = 'Refresh care';
      }
    }
  };

  const saveProfile = async () => {
    const device = selectedDevice();
    if (!device) return;

    setEditorMessage('Saving profile…');
    if (saveProfileButton) saveProfileButton.disabled = true;

    try {
      const payload = await api(`/api/plants/${encodeURIComponent(device.device_id)}`, {
        method: 'PUT',
        body: JSON.stringify(profilePayload()),
      });

      currentProfile = payload.data || null;
      const listDevice = devices.find((item) => item.device_id === device.device_id);
      if (listDevice) listDevice.profile = currentProfile;

      setEditorMessage('Plant profile saved.', 'success');
      await loadCare({quiet: true});

      window.setTimeout(() => {
        closeEditor();
      }, 450);
    } catch (error) {
      setEditorMessage(error.message, 'error');
    } finally {
      if (saveProfileButton) saveProfileButton.disabled = false;
    }
  };

  const deleteProfile = async () => {
    const device = selectedDevice();
    if (!device || !currentProfile) return;
    if (!window.confirm(`Remove the plant profile "${currentProfile.plant_name}" from this FloraCore?`)) {
      return;
    }

    if (deleteProfileButton) deleteProfileButton.disabled = true;
    setEditorMessage('Removing profile…');

    try {
      await api(`/api/plants/${encodeURIComponent(device.device_id)}`, {
        method: 'DELETE',
      });

      currentProfile = null;
      currentCare = null;
      const listDevice = devices.find((item) => item.device_id === device.device_id);
      if (listDevice) listDevice.profile = null;

      closeEditor();
      renderCare();
    } catch (error) {
      setEditorMessage(error.message, 'error');
    } finally {
      if (deleteProfileButton) deleteProfileButton.disabled = false;
    }
  };

  const startRefreshTimer = () => {
    if (refreshTimer) window.clearInterval(refreshTimer);
    refreshTimer = window.setInterval(() => {
      if (!document.hidden && selectedDevice()) {
        loadCare({quiet: true});
      }
    }, 30000);
  };

  const init = async () => {
    if (!deviceSelect) return;

    try {
      await loadCatalog();
      await loadDevices();

      if (!devices.length) return;

      await loadCare();
      startRefreshTimer();
    } catch (error) {
      if (careHeadline) careHeadline.textContent = error.message;
    }
  };

  deviceSelect?.addEventListener('change', async () => {
    currentDevice = selectedDevice();
    currentProfile = currentDevice?.profile || null;
    currentCare = null;
    updateUrlDevice(currentDevice?.device_id || '');
    closeEditor();
    renderCare();
    await loadCare();
  });

  refreshButton?.addEventListener('click', () => loadCare());

  editProfileButton?.addEventListener('click', openEditor);
  createProfileButton?.addEventListener('click', openEditor);
  editTargetsButton?.addEventListener('click', openEditor);
  closeProfileButton?.addEventListener('click', closeEditor);

  speciesSelect?.addEventListener('change', updatePresetDescription);
  applyPresetButton?.addEventListener('click', () => {
    applyPresetToInputs(currentPreset(), {preserveName: true});
    setEditorMessage('Preset targets loaded. Review them before saving.');
  });

  saveProfileButton?.addEventListener('click', saveProfile);
  deleteProfileButton?.addEventListener('click', deleteProfile);

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && selectedDevice()) {
      loadCare({quiet: true});
    }
  });

  init();
})();
