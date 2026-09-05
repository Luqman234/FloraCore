(() => {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const logoutButton = document.getElementById('logoutButton');
  const promptModal = document.getElementById('connectPromptModal');
  const yesButton = document.getElementById('connectYesButton');
  const laterButton = document.getElementById('connectLaterButton');
  const promptError = document.getElementById('connectPromptError');
  const connectOnly = document.body.dataset.connectOnly === 'true';

  const formatRelative = (unixSeconds) => {
    if (!Number.isFinite(Number(unixSeconds))) return '—';
    const delta = Math.max(0, Math.floor(Date.now() / 1000 - Number(unixSeconds)));
    if (delta < 5) return 'just now';
    if (delta < 60) return `${delta}s ago`;
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
    return `${Math.floor(delta / 86400)}d ago`;
  };

  const formatAbsolute = (unixSeconds) => {
    if (!Number.isFinite(Number(unixSeconds))) return '—';
    return new Date(Number(unixSeconds) * 1000).toLocaleString();
  };

  const safeText = (value, fallback = '—') => {
    if (value === null || value === undefined || value === '') return fallback;
    return String(value);
  };

  const closePrompt = () => {
    promptModal?.classList.remove('is-open');
    promptModal?.setAttribute('aria-hidden', 'true');
  };

  const saveConnectionChoice = async (choice) => {
    const response = await fetch('/api/onboarding/connection-choice', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      credentials: 'same-origin',
      body: JSON.stringify({ choice })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Could not save onboarding choice.');
    return data;
  };

  yesButton?.addEventListener('click', async () => {
    yesButton.disabled = true;
    if (laterButton) laterButton.disabled = true;
    if (promptError) promptError.textContent = '';
    try {
      const data = await saveConnectionChoice('yes');
      window.location.assign(data.redirect || '/connect');
    } catch (error) {
      if (promptError) promptError.textContent = error.message || 'Could not start setup.';
      yesButton.disabled = false;
      if (laterButton) laterButton.disabled = false;
    }
  });

  laterButton?.addEventListener('click', async () => {
    laterButton.disabled = true;
    if (yesButton) yesButton.disabled = true;
    if (promptError) promptError.textContent = '';
    try {
      await saveConnectionChoice('later');
      closePrompt();
      document.querySelector('.connect-link')?.focus();
    } catch (error) {
      if (promptError) promptError.textContent = error.message || 'Could not save your choice.';
    } finally {
      laterButton.disabled = false;
      if (yesButton) yesButton.disabled = false;
    }
  });

  logoutButton?.addEventListener('click', async () => {
    logoutButton.disabled = true;
    try {
      const response = await fetch('/api/logout', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrfToken },
        credentials: 'same-origin'
      });
      if (!response.ok) throw new Error('Logout failed.');
      window.location.assign('/');
    } catch (_) {
      logoutButton.disabled = false;
    }
  });

  if (connectOnly) return;

  // -----------------------------------------------------------------------
  // Sidebar scroll-spy
  // -----------------------------------------------------------------------
  // Section links become active both when clicked and as the user scrolls.
  // External sidebar links (/docs, /connect, Developer API) are untouched.
  const dashboardSidebar = document.getElementById('dashboardSidebar');
  const sectionLinks = dashboardSidebar
    ? Array.from(dashboardSidebar.querySelectorAll('a[href^="#"]'))
    : [];

  const sectionEntries = sectionLinks
    .map((link) => {
      const id = link.getAttribute('href')?.slice(1);
      const section = id ? document.getElementById(id) : null;
      return section ? { id, link, section } : null;
    })
    .filter(Boolean);

  let clickedSectionId = null;
  let clickReleaseTimer = 0;
  let scrollSpyFrame = 0;

  const setActiveSidebarSection = (id) => {
    sectionEntries.forEach(({ id: sectionId, link }) => {
      const active = sectionId === id;
      link.classList.toggle('active', active);

      if (active) {
        link.setAttribute('aria-current', 'location');
      } else {
        link.removeAttribute('aria-current');
      }
    });
  };

  const releaseClickedSection = () => {
    clickedSectionId = null;
    window.clearTimeout(clickReleaseTimer);
  };

  const getCurrentSection = () => {
    if (!sectionEntries.length) return null;

    // The top bar is 64px high. Looking ~100px below the viewport top makes
    // the highlighted item change when a section actually enters the reading
    // area instead of the instant its first border touches the screen.
    const marker = window.scrollY + 104;

    const ordered = [...sectionEntries].sort(
      (a, b) =>
        (a.section.getBoundingClientRect().top + window.scrollY) -
        (b.section.getBoundingClientRect().top + window.scrollY)
    );

    let current = ordered[0];

    for (const entry of ordered) {
      const top = entry.section.getBoundingClientRect().top + window.scrollY;
      if (top <= marker) current = entry;
      else break;
    }

    // At the very bottom, make sure the final reachable section wins even
    // when its top cannot physically scroll all the way to the marker.
    const atBottom =
      window.innerHeight + window.scrollY >=
      document.documentElement.scrollHeight - 4;

    if (atBottom) current = ordered[ordered.length - 1];

    return current;
  };

  const updateSidebarFromScroll = () => {
    scrollSpyFrame = 0;

    // While a smooth click-scroll is in progress, keep the clicked item lit
    // instead of briefly lighting every section the browser passes through.
    if (clickedSectionId) {
      setActiveSidebarSection(clickedSectionId);
      return;
    }

    const current = getCurrentSection();
    if (current) setActiveSidebarSection(current.id);
  };

  const scheduleSidebarScrollSpy = () => {
    if (scrollSpyFrame) return;
    scrollSpyFrame = window.requestAnimationFrame(updateSidebarFromScroll);
  };

  sectionEntries.forEach(({ id, link, section }) => {
    link.addEventListener('click', (event) => {
      event.preventDefault();

      clickedSectionId = id;
      setActiveSidebarSection(id);

      // Keep the URL useful/bookmarkable without causing the browser's
      // default instant hash jump.
      if (window.location.hash !== `#${id}`) {
        window.history.pushState(null, '', `#${id}`);
      }

      section.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
      });

      window.clearTimeout(clickReleaseTimer);
      clickReleaseTimer = window.setTimeout(() => {
        releaseClickedSection();
        updateSidebarFromScroll();
      }, 900);
    });
  });

  window.addEventListener('scroll', scheduleSidebarScrollSpy, { passive: true });
  window.addEventListener('resize', scheduleSidebarScrollSpy, { passive: true });

  // Modern browsers fire scrollend after smooth scrolling. The timeout above
  // remains as a fallback for browsers that do not.
  window.addEventListener?.('scrollend', () => {
    if (!clickedSectionId) return;
    releaseClickedSection();
    updateSidebarFromScroll();
  });

  window.addEventListener('popstate', () => {
    const id = window.location.hash.slice(1);
    if (id && sectionEntries.some((entry) => entry.id === id)) {
      setActiveSidebarSection(id);
    } else {
      updateSidebarFromScroll();
    }
  });

  // Respect a directly opened URL such as /dashboard#firmware, otherwise
  // highlight whichever section is currently visible.
  const initialHash = window.location.hash.slice(1);
  if (initialHash && sectionEntries.some((entry) => entry.id === initialHash)) {
    setActiveSidebarSection(initialHash);
  } else {
    updateSidebarFromScroll();
  }


  const ownedDeviceList = document.getElementById('ownedDeviceList');
  const ownedCount = document.getElementById('ownedCount');
  const onlineCount = document.getElementById('onlineCount');
  const lastSyncValue = document.getElementById('lastSyncValue');
  const latestMessageType = document.getElementById('latestMessageType');
  const telemetryState = document.getElementById('telemetryState');
  const selectedDeviceId = document.getElementById('selectedDeviceId');
  const selectedDeviceName = document.getElementById('selectedDeviceName');
  const deviceOnlineState = document.getElementById('deviceOnlineState');
  const coreConnectionState = document.querySelector('.topbar-meta .live');
  const soilPercent = document.getElementById('soilPercent');
  const soilAdc = document.getElementById('soilAdc');
  const lightLux = document.getElementById('lightLux');
  const lightValidity = document.getElementById('lightValidity');
  const pumpState = document.getElementById('pumpState');
  const rtcValue = document.getElementById('rtcValue');
  const rtcValidity = document.getElementById('rtcValidity');
  const telemetryReceived = document.getElementById('telemetryReceived');
  const telemetryMessageId = document.getElementById('telemetryMessageId');
  const stateLastSeen = document.getElementById('stateLastSeen');
  const stateMessageType = document.getElementById('stateMessageType');
  const stateMessageId = document.getElementById('stateMessageId');
  const stateClaimedAt = document.getElementById('stateClaimedAt');
  const firmwareStatus = document.getElementById('firmwareStatus');
  const firmwareInstalled = document.getElementById('firmwareInstalled');
  const firmwareAvailable = document.getElementById('firmwareAvailable');
  const firmwareChannel = document.getElementById('firmwareChannel');
  const firmwareLastUpdate = document.getElementById('firmwareLastUpdate');
  const firmwareReleaseMeta = document.getElementById('firmwareReleaseMeta');
  const firmwareReleaseVersion = document.getElementById('firmwareReleaseVersion');
  const firmwareReleaseHash = document.getElementById('firmwareReleaseHash');
  const firmwareHistory = document.getElementById('firmwareHistory');

  let currentDeviceId = ownedDeviceList?.querySelector('[data-device-id]')?.dataset.deviceId || null;
  let refreshTimer = null;

  // FloraOS heartbeat cadence: one heartbeat every 60 seconds.
  // Two missed heartbeats => offline.
  const HEARTBEAT_INTERVAL_SECONDS = 60;
  const MISSED_HEARTBEATS_OFFLINE = 2;
  const HEARTBEAT_OFFLINE_AFTER_SECONDS =
    HEARTBEAT_INTERVAL_SECONDS * MISSED_HEARTBEATS_OFFLINE;

  const isHeartbeatOnline = (lastHeartbeatAt) => {
    const timestamp = Number(lastHeartbeatAt);
    if (!Number.isFinite(timestamp)) return false;

    const age = Date.now() / 1000 - timestamp;
    return age >= 0 && age <= HEARTBEAT_OFFLINE_AFTER_SECONDS;
  };

  const setCoreConnectionState = (online) => {
    if (!coreConnectionState) return;

    coreConnectionState.classList.toggle('is-offline', !online);
    coreConnectionState.innerHTML =
      `<i></i>${online ? 'CORE ONLINE' : 'CORE OFFLINE'}`;

    // Force the top-bar status to use a neutral gray when offline.
    // This avoids older CSS keeping the status green.
    const dot = coreConnectionState.querySelector('i');

    if (online) {
      coreConnectionState.style.color = '#8DE5B0';
      if (dot) {
        dot.style.background = '#8DE5B0';
        dot.style.boxShadow = '0 0 0 3px rgba(141, 229, 176, 0.10)';
      }
    } else {
      coreConnectionState.style.color = '#97A7B8';
      if (dot) {
        dot.style.background = '#97A7B8';
        dot.style.boxShadow = '0 0 0 3px rgba(151, 167, 184, 0.08)';
      }
    }
  };

  const setOnlineBadge = (lastHeartbeatAt) => {
    const online = isHeartbeatOnline(lastHeartbeatAt);

    if (deviceOnlineState) {
      deviceOnlineState.classList.toggle('is-offline', !online);
      deviceOnlineState.innerHTML = `<i></i>${online ? 'ONLINE' : 'OFFLINE'}`;
    }

    setCoreConnectionState(online);
    return online;
  };

  const renderTelemetry = (data) => {
    const payload = data?.telemetry?.payload || {};
    const hasTelemetry = Boolean(data?.telemetry && data.telemetry.payload && typeof payload === 'object');

    if (selectedDeviceId) selectedDeviceId.textContent = safeText(data?.device_id, 'DEVICE');
    if (selectedDeviceName) selectedDeviceName.textContent = safeText(data?.nickname, 'Live telemetry');
    // Online state is updated from the authenticated heartbeat timestamp in /api/devices.

    if (soilPercent) soilPercent.textContent = Number.isFinite(Number(payload.soil_percent)) && Number(payload.soil_percent) >= 0
      ? `${Number(payload.soil_percent)}%`
      : '—';
    if (soilAdc) soilAdc.textContent = Number.isFinite(Number(payload.soil_adc)) ? `ADC ${Number(payload.soil_adc)}` : 'ADC —';
    if (lightLux) lightLux.textContent = Number.isFinite(Number(payload.light_lux)) ? `${Number(payload.light_lux).toLocaleString(undefined, { maximumFractionDigits: 2 })} lux` : '—';
    if (lightValidity) lightValidity.textContent = payload.light_valid === true ? 'sensor valid' : payload.light_valid === false ? 'sensor invalid' : 'sensor —';
    if (pumpState) pumpState.textContent = payload.pump_on === true ? 'ON' : payload.pump_on === false ? 'OFF' : '—';
    if (rtcValue) rtcValue.textContent = safeText(payload.rtc);
    if (rtcValidity) rtcValidity.textContent = payload.rtc_valid === true ? 'clock valid' : payload.rtc_valid === false ? 'clock invalid' : 'clock —';
    if (telemetryReceived) telemetryReceived.textContent = data?.telemetry?.received_at ? formatAbsolute(data.telemetry.received_at) : 'No telemetry yet';
    if (telemetryMessageId) telemetryMessageId.textContent = safeText(data?.telemetry?.message_id);

    if (stateLastSeen) stateLastSeen.textContent = data?.last_seen ? `${formatRelative(data.last_seen)} · ${formatAbsolute(data.last_seen)}` : 'Never';
    if (stateMessageType) stateMessageType.textContent = safeText(data?.last_message_type);
    if (stateMessageId) stateMessageId.textContent = safeText(data?.last_message_id);
    if (stateClaimedAt) stateClaimedAt.textContent = formatAbsolute(data?.claimed_at);

    if (lastSyncValue) lastSyncValue.textContent = data?.last_seen ? formatRelative(data.last_seen) : '—';
    if (latestMessageType) latestMessageType.textContent = safeText(data?.last_message_type);
    if (telemetryState) telemetryState.textContent = hasTelemetry ? 'available' : 'waiting';
  };

  const renderFirmware = (data) => {
    if (firmwareInstalled) firmwareInstalled.textContent = safeText(data?.installed);
    if (firmwareAvailable) firmwareAvailable.textContent = safeText(data?.available, 'None');
    if (firmwareChannel) {
      const channel = safeText(data?.channel);
      firmwareChannel.textContent = channel === '—'
        ? channel
        : channel.charAt(0).toUpperCase() + channel.slice(1);
    }

    const history = Array.isArray(data?.history) ? data.history : [];
    const latest = history[0];

    if (firmwareStatus) {
      firmwareStatus.textContent = safeText(data?.status, 'UNKNOWN').toUpperCase();
      const status = String(data?.status || '').toLowerCase();
      firmwareStatus.classList.toggle(
        'is-error',
        status.includes('failed') || status.includes('rolled back')
      );
      firmwareStatus.classList.toggle(
        'is-update',
        status.includes('available')
      );
    }

    if (firmwareLastUpdate) {
      const lastTimestamp = latest?.completed_at || latest?.updated_at;
      firmwareLastUpdate.textContent = lastTimestamp
        ? formatAbsolute(lastTimestamp)
        : 'Never';
    }

    if (data?.latest_release) {
      if (firmwareReleaseMeta) firmwareReleaseMeta.hidden = false;
      if (firmwareReleaseVersion) {
        firmwareReleaseVersion.textContent = `FloraCore ${safeText(data.latest_release.version)}`;
      }
      if (firmwareReleaseHash) {
        const hash = String(data.latest_release.sha256 || '');
        firmwareReleaseHash.textContent = hash
          ? `SHA-256 ${hash.slice(0, 16)}…`
          : 'SHA-256 —';
      }
    } else if (firmwareReleaseMeta) {
      firmwareReleaseMeta.hidden = true;
    }

    if (firmwareHistory) {
      if (!history.length) {
        firmwareHistory.innerHTML = '<p class="firmware-empty">No OTA history yet.</p>';
      } else {
        firmwareHistory.innerHTML = history.map((item) => {
          const status = safeText(item?.status, 'unknown').toUpperCase();
          const target = safeText(item?.target_version);
          const from = safeText(item?.from_version);
          const when = item?.updated_at ? formatRelative(item.updated_at) : '—';
          const error = item?.error
            ? `<small>${safeText(item.error)}</small>`
            : '';
          return `
            <div class="firmware-history-row">
              <span><b>${status}</b><small>${from} → ${target}</small></span>
              <em>${when}</em>
              ${error}
            </div>
          `;
        }).join('');
      }
    }
  };

  const loadFirmware = async (deviceId) => {
    if (!deviceId) return;
    try {
      const response = await fetch(
        `/api/firmware/devices/${encodeURIComponent(deviceId)}`,
        {
          credentials: 'same-origin',
          headers: { 'Accept': 'application/json' }
        }
      );
      if (!response.ok) throw new Error('Firmware state is unavailable.');
      renderFirmware(await response.json());
    } catch (_) {
      renderFirmware({
        installed: null,
        available: null,
        channel: null,
        status: 'Unavailable',
        history: []
      });
    }
  };

  const loadDevice = async (deviceId) => {
    if (!deviceId) return;
    currentDeviceId = deviceId;
    ownedDeviceList?.querySelectorAll('[data-device-id]').forEach((button) => {
      button.classList.toggle('active', button.dataset.deviceId === deviceId);
    });

    try {
      const response = await fetch(`/api/device/latest/${encodeURIComponent(deviceId)}`, {
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json' }
      });
      if (!response.ok) throw new Error('Device telemetry is unavailable.');
      renderTelemetry(await response.json());
    } catch (_) {
      renderTelemetry({ device_id: deviceId });
    }

    await loadFirmware(deviceId);
  };

  const refreshSummary = async () => {
    try {
      const response = await fetch('/api/devices', { credentials: 'same-origin' });
      if (!response.ok) throw new Error('Could not load devices.');
      const data = await response.json();
      const devices = Array.isArray(data.devices) ? data.devices : [];
      if (ownedCount) ownedCount.textContent = String(devices.length);

      if (onlineCount) {
        onlineCount.textContent = String(
          devices.filter((device) => isHeartbeatOnline(device.last_heartbeat_at)).length
        );
      }

      if (!currentDeviceId && devices[0]?.device_id) {
        currentDeviceId = devices[0].device_id;
      }

      const currentDevice = devices.find(
        (device) => device.device_id === currentDeviceId
      );

      if (currentDevice) {
        setOnlineBadge(currentDevice.last_heartbeat_at);
      } else {
        setCoreConnectionState(false);
      }

      if (currentDeviceId) await loadDevice(currentDeviceId);
    } catch (_) {
      if (onlineCount) onlineCount.textContent = '—';
    }
  };

  ownedDeviceList?.addEventListener('click', (event) => {
    const button = event.target.closest('[data-device-id]');
    if (button) loadDevice(button.dataset.deviceId);
  });

  refreshSummary();
  refreshTimer = window.setInterval(refreshSummary, 5000);
  window.addEventListener('beforeunload', () => window.clearInterval(refreshTimer), { once: true });
})();
