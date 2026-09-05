(() => {
  'use strict';

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';

  const mfaStatusPill = document.getElementById('mfaStatusPill');
  const mfaCurrentMethod = document.getElementById('mfaCurrentMethod');
  const mfaCurrentDescription = document.getElementById('mfaCurrentDescription');

  const securityGate = document.getElementById('securityGate');
  const securityGateTitle = document.getElementById('securityGateTitle');
  const securityGateText = document.getElementById('securityGateText');
  const sendSecurityCodeButton = document.getElementById('sendSecurityCodeButton');
  const securityCodeForm = document.getElementById('securityCodeForm');
  const securityCodeInput = document.getElementById('securityCodeInput');
  const verifySecurityCodeButton = document.getElementById('verifySecurityCodeButton');

  const enableEmailMfaButton = document.getElementById('enableEmailMfaButton');
  const startAuthenticatorButton = document.getElementById('startAuthenticatorButton');
  const authenticatorSetup = document.getElementById('authenticatorSetup');
  const authenticatorSetupKey = document.getElementById('authenticatorSetupKey');
  const authenticatorUri = document.getElementById('authenticatorUri');
  const copySetupKeyButton = document.getElementById('copySetupKeyButton');
  const authenticatorCodeInput = document.getElementById('authenticatorCodeInput');
  const confirmAuthenticatorButton = document.getElementById('confirmAuthenticatorButton');

  const recoverySummary = document.getElementById('recoverySummary');
  const recoveryRemaining = document.getElementById('recoveryRemaining');
  const regenerateRecoveryButton = document.getElementById('regenerateRecoveryButton');
  const disableMfaButton = document.getElementById('disableMfaButton');

  const settingsMessage = document.getElementById('settingsMessage');

  const recoveryModal = document.getElementById('recoveryModal');
  const recoveryCodes = document.getElementById('recoveryCodes');
  const copyRecoveryCodesButton = document.getElementById('copyRecoveryCodesButton');
  const closeRecoveryModalButton = document.getElementById('closeRecoveryModalButton');
  const currentPasswordInput = document.getElementById('currentPasswordInput');
  const newPasswordInput = document.getElementById('newPasswordInput');
  const confirmNewPasswordInput = document.getElementById('confirmNewPasswordInput');
  const changePasswordButton = document.getElementById('changePasswordButton');
  const passwordMessage = document.getElementById('passwordMessage');

  const sessionList = document.getElementById('sessionList');
  const sessionsMessage = document.getElementById('sessionsMessage');
  const revokeOtherSessionsButton = document.getElementById('revokeOtherSessionsButton');

  const activityList = document.getElementById('activityList');
  const refreshActivityButton = document.getElementById('refreshActivityButton');

  const controlDeviceSelect = document.getElementById('controlDeviceSelect');
  const controlReadiness = document.getElementById('controlReadiness');
  const waterDurationInput = document.getElementById('waterDurationInput');
  const growLightDurationInput = document.getElementById('growLightDurationInput');
  const waterNowButton = document.getElementById('waterNowButton');
  const growLightOnButton = document.getElementById('growLightOnButton');
  const growLightOffButton = document.getElementById('growLightOffButton');
  const deviceControlMessage = document.getElementById('deviceControlMessage');


  let securityVerified = securityGate?.classList.contains('verified') || false;
  let currentRecoveryCodes = [];

  const setMessage = (message = '', type = '') => {
    if (!settingsMessage) return;
    settingsMessage.textContent = message;
    settingsMessage.className = 'settings-message';
    if (type) settingsMessage.classList.add(type);
  };

  const api = async (url, options = {}) => {
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (options.body) headers.set('Content-Type', 'application/json');
    if (options.method && options.method !== 'GET') {
      headers.set('X-CSRF-Token', csrf);
    }

    const response = await fetch(url, {
      credentials: 'same-origin',
      ...options,
      headers,
    });

    let payload = null;
    try {
      payload = await response.json();
    } catch (_) {
      payload = null;
    }

    if (!response.ok) {
      const error = new Error(
        payload?.error?.message || payload?.error || `Request failed (${response.status}).`
      );
      error.code = payload?.error?.code || 'request_failed';
      throw error;
    }

    return payload;
  };

  const setSecurityVerified = (verified) => {
    securityVerified = Boolean(verified);
    securityGate?.classList.toggle('verified', securityVerified);

    if (securityGateTitle) {
      securityGateTitle.textContent = securityVerified
        ? 'Security changes unlocked'
        : 'Verify sensitive account changes';
    }
    if (securityGateText) {
      securityGateText.textContent = securityVerified
        ? 'Password, MFA, and session controls are unlocked for a few minutes.'
        : 'FloraCore will send a confirmation code to your account email.';
    }

    if (sendSecurityCodeButton) sendSecurityCodeButton.hidden = securityVerified;
    if (securityCodeForm) securityCodeForm.hidden = true;

    document.querySelectorAll('.mfa-change-control, .security-sensitive-control').forEach((button) => {
      button.disabled = !securityVerified;
    });
  };

  const renderStatus = (mfa) => {
    const enabled = Boolean(mfa?.enabled);
    const method = mfa?.method || null;

    if (mfaStatusPill) {
      mfaStatusPill.textContent = enabled ? 'ENABLED' : 'OFF';
      mfaStatusPill.classList.toggle('enabled', enabled);
    }

    if (mfaCurrentMethod) {
      mfaCurrentMethod.textContent =
        method === 'email'
          ? 'Email code'
          : method === 'totp'
            ? 'Authenticator app'
            : 'None';
    }

    if (mfaCurrentDescription) {
      mfaCurrentDescription.textContent =
        method === 'email'
          ? 'FloraCore emails a one-time code after your password or OAuth sign-in.'
          : method === 'totp'
            ? 'Enter a rotating code from your authenticator app after primary sign-in.'
            : 'Add a second factor to protect your FloraCore account.';
    }

    if (enableEmailMfaButton) {
      enableEmailMfaButton.textContent =
        enabled && method === 'email' ? 'Enabled' : 'Use email';
    }

    if (startAuthenticatorButton) {
      startAuthenticatorButton.textContent =
        enabled && method === 'totp' ? 'Reconfigure' : 'Set up';
    }

    if (disableMfaButton) disableMfaButton.hidden = !enabled;

    const recoveryVisible = enabled && method === 'totp';
    if (recoverySummary) recoverySummary.hidden = !recoveryVisible;
    if (regenerateRecoveryButton) regenerateRecoveryButton.hidden = !recoveryVisible;
    if (recoveryRemaining) {
      recoveryRemaining.textContent = `${Number(mfa?.recovery_codes_remaining || 0)} remaining`;
    }

    document.querySelectorAll('.mfa-change-control, .security-sensitive-control').forEach((button) => {
      button.disabled = !securityVerified;
    });
  };

  const refreshStatus = async () => {
    const payload = await api('/api/settings/security');
    setSecurityVerified(Boolean(payload.data.security_verified));
    renderStatus(payload.data.mfa);
  };

  const showRecoveryCodes = (codes) => {
    currentRecoveryCodes = Array.isArray(codes) ? codes : [];
    if (recoveryCodes) {
      recoveryCodes.innerHTML = currentRecoveryCodes
        .map((code) => `<code>${String(code)}</code>`)
        .join('');
    }
    if (recoveryModal) recoveryModal.hidden = false;
  };

  const escapeHtml = (value) =>
    String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');

  const setSectionMessage = (element, message = '', type = '') => {
    if (!element) return;
    element.textContent = message;
    element.className = 'section-message';
    if (type) element.classList.add(type);
  };

  const formatTime = (unixSeconds) => {
    const value = Number(unixSeconds);
    if (!Number.isFinite(value)) return 'Unknown time';
    return new Date(value * 1000).toLocaleString();
  };

  const eventLabel = (type) => {
    const labels = {
      new_session: 'New session created',
      login_failed: 'Failed password sign-in',
      mfa_verified: 'MFA verification passed',
      recovery_code_used: 'Recovery code used',
      mfa_enabled: 'MFA enabled',
      mfa_disabled: 'MFA disabled',
      recovery_codes_regenerated: 'Recovery codes regenerated',
      password_reset_requested: 'Password reset requested',
      password_reset_completed: 'Password reset completed',
      password_changed: 'Password changed',
      password_change_failed: 'Password change failed',
      session_revoked: 'Session revoked',
      other_sessions_revoked: 'Other sessions revoked',
      device_command_queued: 'Manual device command queued',
    };
    return labels[type] || String(type || 'Security event').replaceAll('_', ' ');
  };

  const loadSessions = async () => {
    if (!sessionList) return;

    try {
      const payload = await api('/api/settings/sessions');
      const sessions = Array.isArray(payload.data) ? payload.data : [];

      if (!sessions.length) {
        sessionList.innerHTML = '<div class="empty-row">No active sessions found.</div>';
        return;
      }

      sessionList.innerHTML = sessions.map((item) => `
        <div class="session-row">
          <div class="session-main">
            <b>${escapeHtml(item.client)}</b>
            <p>${escapeHtml(item.ip)} · last active ${escapeHtml(formatTime(item.last_seen_at))}</p>
            <div class="session-meta">
              ${item.current ? '<span class="session-chip current">CURRENT SESSION</span>' : ''}
              <span class="session-chip">${escapeHtml(item.provider)}</span>
              <span class="session-chip">Created ${escapeHtml(formatTime(item.created_at))}</span>
            </div>
          </div>
          <div class="session-actions">
            ${
              item.current
                ? '<span class="session-chip current">This browser</span>'
                : `<button class="settings-button danger session-revoke-button security-sensitive-control" data-session-id="${escapeHtml(item.session_id)}" type="button" ${securityVerified ? '' : 'disabled'}>Revoke</button>`
            }
          </div>
        </div>
      `).join('');
    } catch (error) {
      sessionList.innerHTML = `<div class="empty-row">${escapeHtml(error.message)}</div>`;
    }
  };

  const loadActivity = async () => {
    if (!activityList) return;

    try {
      const payload = await api('/api/settings/security/activity?limit=50');
      const events = Array.isArray(payload.data) ? payload.data : [];

      if (!events.length) {
        activityList.innerHTML = '<div class="empty-row">No security events yet.</div>';
        return;
      }

      activityList.innerHTML = events.map((item) => `
        <div class="activity-row">
          <div class="activity-main">
            <b><span class="activity-icon">${item.success ? '✓' : '!'}</span>${escapeHtml(eventLabel(item.event_type))}</b>
            <p>${escapeHtml(item.client)} · ${escapeHtml(item.ip)}</p>
            <div class="activity-meta">
              <span class="activity-chip ${item.success ? '' : 'failed'}">${item.success ? 'SUCCESS' : 'FAILED'}</span>
              <span class="activity-chip">${escapeHtml(formatTime(item.created_at))}</span>
            </div>
          </div>
        </div>
      `).join('');
    } catch (error) {
      activityList.innerHTML = `<div class="empty-row">${escapeHtml(error.message)}</div>`;
    }
  };

  let controlDevices = [];

  const selectedControlDevice = () =>
    controlDevices.find((item) => item.device_id === controlDeviceSelect?.value) || null;

  const updateControlReadiness = () => {
    if (!controlReadiness) return;
    const device = selectedControlDevice();
    const controls = [waterNowButton, growLightOnButton, growLightOffButton];

    let ready = false;
    let message = 'Choose a FloraCore.';

    if (device) {
      if (!device.online) {
        message = 'Offline — physical commands are not queued.';
      } else if (Number(device.command_protocol) !== 1) {
        message = 'Online, but command protocol v1 is unavailable.';
      } else {
        ready = true;
        message = 'Online · command protocol v1 ready';
      }
    }

    controlReadiness.classList.toggle('ready', ready);
    const label = controlReadiness.querySelector('b');
    if (label) label.textContent = message;

    controls.forEach((button) => {
      if (button) button.disabled = !ready;
    });
  };

  const loadControlDevices = async () => {
    if (!controlDeviceSelect) return;

    try {
      const payload = await api('/api/settings/device-control/devices');
      controlDevices = Array.isArray(payload.data) ? payload.data : [];
      controlDeviceSelect.innerHTML = '';

      if (!controlDevices.length) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'No linked FloraCore';
        controlDeviceSelect.append(option);
      } else {
        controlDevices.forEach((device) => {
          const option = document.createElement('option');
          option.value = device.device_id;
          option.textContent =
            `${device.device_id} · ${device.online ? 'online' : 'offline'}`;
          controlDeviceSelect.append(option);
        });
      }

      updateControlReadiness();
    } catch (error) {
      setSectionMessage(deviceControlMessage, error.message, 'error');
    }
  };

  const idempotencyKey = () => {
    if (window.crypto?.randomUUID) return window.crypto.randomUUID();
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  };

  const queuePhysicalCommand = async (type, parameters) => {
    const device = selectedControlDevice();
    if (!device) {
      setSectionMessage(deviceControlMessage, 'Choose a FloraCore first.', 'error');
      return;
    }

    setSectionMessage(deviceControlMessage, 'Queueing validated command…');

    try {
      const payload = await api('/api/settings/device-control/commands', {
        method: 'POST',
        body: JSON.stringify({
          device_id: device.device_id,
          type,
          parameters,
          idempotency_key: idempotencyKey(),
          expires_in_seconds: 90,
        }),
      });

      const command = payload.data?.command || {};
      setSectionMessage(
        deviceControlMessage,
        `Command ${command.command_id || command.id || ''} queued securely.`,
        'success'
      );
      window.setTimeout(loadActivity, 250);
    } catch (error) {
      setSectionMessage(deviceControlMessage, error.message, 'error');
      await loadControlDevices();
    }
  };

  const setupSettingsScrollSpy = () => {
    const links = Array.from(document.querySelectorAll('.settings-section-nav a[href^="#"]'));
    const sections = links
      .map((link) => document.querySelector(link.getAttribute('href')))
      .filter(Boolean);

    if (!links.length || !sections.length) return;

    const activate = (id) => {
      links.forEach((link) => {
        link.classList.toggle('active', link.getAttribute('href') === `#${id}`);
      });
    };

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible) activate(visible.target.id);
      },
      {rootMargin: '-90px 0px -60% 0px', threshold: [0.05, 0.2, 0.5]}
    );

    sections.forEach((section) => observer.observe(section));
  };

  sendSecurityCodeButton?.addEventListener('click', async () => {
    sendSecurityCodeButton.disabled = true;
    setMessage('Sending security code…');

    try {
      const payload = await api('/api/settings/security/send-code', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      if (securityCodeForm) securityCodeForm.hidden = false;
      if (securityGateText) {
        securityGateText.textContent =
          `Code sent to ${payload.data.masked_email}. It expires in 10 minutes.`;
      }
      securityCodeInput?.focus();
      setMessage('');
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      sendSecurityCodeButton.disabled = false;
    }
  });

  verifySecurityCodeButton?.addEventListener('click', async () => {
    const code = securityCodeInput?.value.trim() || '';
    if (code.length !== 6) {
      setMessage('Enter the six-digit security code.', 'error');
      return;
    }

    verifySecurityCodeButton.disabled = true;
    try {
      await api('/api/settings/security/verify-code', {
        method: 'POST',
        body: JSON.stringify({ code }),
      });
      setSecurityVerified(true);
      setMessage('Security changes unlocked for 10 minutes.', 'success');
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      verifySecurityCodeButton.disabled = false;
    }
  });

  enableEmailMfaButton?.addEventListener('click', async () => {
    if (!securityVerified) return;
    if (!window.confirm('Use an emailed verification code as your second sign-in factor?')) return;

    enableEmailMfaButton.disabled = true;
    try {
      await api('/api/settings/mfa/email/enable', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      if (authenticatorSetup) authenticatorSetup.hidden = true;
      await refreshStatus();
      setMessage('Email MFA is now enabled.', 'success');
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      enableEmailMfaButton.disabled = !securityVerified;
    }
  });

  startAuthenticatorButton?.addEventListener('click', async () => {
    if (!securityVerified) return;

    startAuthenticatorButton.disabled = true;
    setMessage('Creating authenticator setup…');

    try {
      const payload = await api('/api/settings/mfa/authenticator/start', {
        method: 'POST',
        body: JSON.stringify({}),
      });

      if (authenticatorSetupKey) {
        authenticatorSetupKey.textContent = payload.data.setup_key;
      }
      if (authenticatorUri) {
        authenticatorUri.textContent = payload.data.otpauth_uri;
      }
      if (authenticatorSetup) authenticatorSetup.hidden = false;
      if (authenticatorCodeInput) authenticatorCodeInput.value = '';
      setMessage('Add the setup key to your authenticator, then confirm one current code.');
      authenticatorSetup?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      startAuthenticatorButton.disabled = !securityVerified;
    }
  });

  copySetupKeyButton?.addEventListener('click', async () => {
    const key = authenticatorSetupKey?.textContent || '';
    if (!key || key === '—') return;
    await navigator.clipboard.writeText(key);
    copySetupKeyButton.textContent = 'Copied';
    window.setTimeout(() => {
      copySetupKeyButton.textContent = 'Copy';
    }, 1200);
  });

  confirmAuthenticatorButton?.addEventListener('click', async () => {
    const code = authenticatorCodeInput?.value.trim() || '';
    if (code.length !== 6) {
      setMessage('Enter the current six-digit authenticator code.', 'error');
      return;
    }

    confirmAuthenticatorButton.disabled = true;
    try {
      const payload = await api('/api/settings/mfa/authenticator/confirm', {
        method: 'POST',
        body: JSON.stringify({ code }),
      });
      if (authenticatorSetup) authenticatorSetup.hidden = true;
      showRecoveryCodes(payload.data.recovery_codes);
      await refreshStatus();
      setMessage('Authenticator MFA is now enabled.', 'success');
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      confirmAuthenticatorButton.disabled = false;
    }
  });

  regenerateRecoveryButton?.addEventListener('click', async () => {
    if (!securityVerified) return;
    if (!window.confirm('Replace all existing recovery codes? Old unused codes will stop working.')) return;

    regenerateRecoveryButton.disabled = true;
    try {
      const payload = await api('/api/settings/mfa/recovery/regenerate', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      showRecoveryCodes(payload.data.recovery_codes);
      await refreshStatus();
      setMessage('New recovery codes generated.', 'success');
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      regenerateRecoveryButton.disabled = !securityVerified;
    }
  });

  disableMfaButton?.addEventListener('click', async () => {
    if (!securityVerified) return;
    if (!window.confirm('Disable multi-factor authentication for this account?')) return;

    disableMfaButton.disabled = true;
    try {
      await api('/api/settings/mfa/disable', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      if (authenticatorSetup) authenticatorSetup.hidden = true;
      await refreshStatus();
      setMessage('MFA has been disabled.', 'success');
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      disableMfaButton.disabled = !securityVerified;
    }
  });

  copyRecoveryCodesButton?.addEventListener('click', async () => {
    if (!currentRecoveryCodes.length) return;
    await navigator.clipboard.writeText(currentRecoveryCodes.join('\n'));
    copyRecoveryCodesButton.textContent = 'Copied';
  });

  closeRecoveryModalButton?.addEventListener('click', () => {
    currentRecoveryCodes = [];
    if (recoveryCodes) recoveryCodes.textContent = '';
    if (recoveryModal) recoveryModal.hidden = true;
    if (copyRecoveryCodesButton) copyRecoveryCodesButton.textContent = 'Copy all';
  });

  recoveryModal?.addEventListener('click', (event) => {
    if (event.target !== recoveryModal) return;
    setMessage('Save your recovery codes before closing this window.', 'error');
  });

  changePasswordButton?.addEventListener('click', async () => {
    if (!securityVerified) return;

    const currentPassword = currentPasswordInput?.value || '';
    const next = newPasswordInput?.value || '';
    const confirm = confirmNewPasswordInput?.value || '';

    if (next.length < 8) {
      setSectionMessage(passwordMessage, 'Password must be at least 8 characters.', 'error');
      return;
    }
    if (next !== confirm) {
      setSectionMessage(passwordMessage, 'New passwords do not match.', 'error');
      return;
    }

    changePasswordButton.disabled = true;
    setSectionMessage(passwordMessage, 'Changing password…');

    try {
      const payload = await api('/api/settings/password/change', {
        method: 'POST',
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: next,
          confirm_password: confirm,
        }),
      });

      currentPasswordInput.value = '';
      newPasswordInput.value = '';
      confirmNewPasswordInput.value = '';
      setSectionMessage(passwordMessage, payload.message, 'success');
      await loadSessions();
      await loadActivity();
    } catch (error) {
      setSectionMessage(passwordMessage, error.message, 'error');
    } finally {
      changePasswordButton.disabled = !securityVerified;
    }
  });

  sessionList?.addEventListener('click', async (event) => {
    const button = event.target.closest('.session-revoke-button');
    if (!button || !securityVerified) return;

    const sessionId = button.dataset.sessionId || '';
    if (!sessionId) return;
    if (!window.confirm('Revoke this browser session?')) return;

    button.disabled = true;
    try {
      const payload = await api('/api/settings/sessions/revoke', {
        method: 'POST',
        body: JSON.stringify({session_id: sessionId}),
      });
      setSectionMessage(sessionsMessage, payload.message, 'success');
      await loadSessions();
      await loadActivity();
    } catch (error) {
      setSectionMessage(sessionsMessage, error.message, 'error');
      button.disabled = false;
    }
  });

  revokeOtherSessionsButton?.addEventListener('click', async () => {
    if (!securityVerified) return;
    if (!window.confirm('Sign out every other active FloraCore browser session?')) return;

    revokeOtherSessionsButton.disabled = true;
    try {
      const payload = await api('/api/settings/sessions/revoke-others', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      setSectionMessage(
        sessionsMessage,
        `${payload.revoked || 0} other session(s) revoked.`,
        'success'
      );
      await loadSessions();
      await loadActivity();
    } catch (error) {
      setSectionMessage(sessionsMessage, error.message, 'error');
    } finally {
      revokeOtherSessionsButton.disabled = !securityVerified;
    }
  });

  refreshActivityButton?.addEventListener('click', loadActivity);
  controlDeviceSelect?.addEventListener('change', updateControlReadiness);

  waterNowButton?.addEventListener('click', async () => {
    const seconds = Number(waterDurationInput?.value || 0);
    if (!Number.isFinite(seconds) || seconds < 0.5 || seconds > 30) {
      setSectionMessage(deviceControlMessage, 'Water duration must be 0.5–30 seconds.', 'error');
      return;
    }
    if (seconds > 10 && !window.confirm(`Water for ${seconds} seconds?`)) return;

    await queuePhysicalCommand('water', {
      duration_ms: Math.round(seconds * 1000),
    });
  });

  growLightOnButton?.addEventListener('click', async () => {
    const minutes = Number(growLightDurationInput?.value || 0);
    if (!Number.isFinite(minutes) || minutes < 1 || minutes > 720) {
      setSectionMessage(deviceControlMessage, 'Grow-light duration must be 1–720 minutes.', 'error');
      return;
    }

    await queuePhysicalCommand('grow_light', {
      state: 'on',
      duration_seconds: Math.round(minutes * 60),
    });
  });

  growLightOffButton?.addEventListener('click', async () => {
    await queuePhysicalCommand('grow_light', {state: 'off'});
  });

  setupSettingsScrollSpy();

  refreshStatus()
    .then(() => {
      loadSessions();
      loadActivity();
      loadControlDevices();
    })
    .catch((error) => setMessage(error.message, 'error'));
})();
