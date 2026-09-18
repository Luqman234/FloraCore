(() => {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const generateButton = document.getElementById('generateClaimButton');
  const powerReadyButton = document.getElementById('powerReadyButton');
  const codeReadyButton = document.getElementById('codeReadyButton');
  const joinedWifiButton = document.getElementById('joinedWifiButton');
  const openSetupButton = document.getElementById('openSetupButton');
  const checkNowButton = document.getElementById('checkNowButton');
  const claimConsole = document.getElementById('claimConsole');
  const claimCode = document.getElementById('claimCode');
  const copyClaimButton = document.getElementById('copyClaimButton');
  const copyConfirm = document.getElementById('copyConfirm');
  const claimCountdown = document.getElementById('claimCountdown');
  const claimError = document.getElementById('claimError');
  const claimStatusValue = document.getElementById('claimStatusValue');
  const deviceStatusValue = document.getElementById('deviceStatusValue');
  const statusTitle = document.getElementById('statusTitle');
  const statusDescription = document.getElementById('statusDescription');
  const connectedResult = document.getElementById('connectedResult');
  const connectedDeviceId = document.getElementById('connectedDeviceId');
  const continueButton = document.getElementById('continueButton');
  const connectAnotherButton = document.getElementById('connectAnotherButton');
  const localSetupCard = document.getElementById('localSetupCard');
  const waitingTitle = document.getElementById('waitingTitle');
  const waitingText = document.getElementById('waitingText');
  const logoutButton = document.getElementById('logoutButton');
  const progressBar = document.getElementById('progressBar');
  const progressLabel = document.getElementById('progressLabel');
  const progressTitle = document.getElementById('progressTitle');

  const storageKey = 'floracore.activeClaim';
  const stepTitles = ['Power on', 'Create code', 'Device setup', 'Finish'];

  let currentStep = 1;
  let activeClaimId = null;
  let activeToken = '';
  let expiresAt = 0;
  let pollTimer = null;
  let countdownTimer = null;
  let pollingBusy = false;
  let expiryCheckRequested = false;

  const stepElements = [...document.querySelectorAll('.setup-step[data-step]')];

  const setStep = (step, { scroll = true } = {}) => {
    currentStep = Math.max(1, Math.min(4, Number(step) || 1));
    stepElements.forEach((element) => {
      const value = Number(element.dataset.step);
      element.classList.toggle('active-step', value === currentStep);
      element.classList.toggle('completed-step', value < currentStep);
    });
    if (progressBar) progressBar.style.width = `${currentStep * 25}%`;
    if (progressLabel) progressLabel.textContent = `Step ${currentStep} of 4`;
    if (progressTitle) progressTitle.textContent = stepTitles[currentStep - 1];
    if (scroll) {
      document.querySelector(`.setup-step[data-step="${currentStep}"]`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  const stopTimers = () => {
    if (pollTimer) window.clearInterval(pollTimer);
    if (countdownTimer) window.clearInterval(countdownTimer);
    pollTimer = null;
    countdownTimer = null;
  };

  const saveClaimState = () => {
    if (!activeClaimId || !expiresAt) return;
    try {
      sessionStorage.setItem(storageKey, JSON.stringify({ claimId: activeClaimId, expiresAt }));
    } catch (_) {}
  };

  const clearClaimState = () => {
    try { sessionStorage.removeItem(storageKey); } catch (_) {}
  };

  const restoreClaimState = () => {
    try {
      const raw = sessionStorage.getItem(storageKey);
      if (!raw) return false;
      const state = JSON.parse(raw);
      if (!state?.claimId || !state?.expiresAt) return false;
      activeClaimId = String(state.claimId);
      expiresAt = Number(state.expiresAt) || 0;
      if (expiresAt <= Math.floor(Date.now() / 1000)) {
        clearClaimState();
        return false;
      }
      return true;
    } catch (_) {
      return false;
    }
  };

  const formatCountdown = () => {
    const remaining = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
    const minutes = Math.floor(remaining / 60).toString().padStart(2, '0');
    const seconds = (remaining % 60).toString().padStart(2, '0');
    if (claimCountdown) claimCountdown.textContent = `${minutes}:${seconds}`;

    // The backend is authoritative for expiry. A browser clock can be wrong,
    // and the user may have spent part of setup disconnected from floraos.life.
    // When the local countdown reaches zero, keep the claim and ask the server
    // instead of cancelling or replacing it client-side.
    if (remaining === 0 && activeClaimId && !expiryCheckRequested) {
      expiryCheckRequested = true;
      if (claimStatusValue) claimStatusValue.textContent = 'CHECKING';
      if (waitingTitle) waitingTitle.textContent = 'Checking connection code…';
      if (waitingText) waitingText.textContent = 'We are confirming the code status with FloraCore services.';
      pollClaim();
    }
  };

  const copyText = async (text) => {
    if (!text) return false;
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      const copied = document.execCommand('copy');
      area.remove();
      return copied;
    }
  };

  copyClaimButton?.addEventListener('click', async () => {
    const copied = await copyText(activeToken);
    if (copied) {
      copyClaimButton.textContent = 'Copied';
      if (copyConfirm) copyConfirm.hidden = false;
      window.setTimeout(() => { copyClaimButton.textContent = 'Copy code'; }, 1200);
    }
  });

  const showNetworkPause = () => {
    if (deviceStatusValue) deviceStatusValue.textContent = 'WAITING';
    if (waitingTitle) waitingTitle.textContent = 'Connection check paused';
    if (waitingText) waitingText.textContent = 'We cannot reach floraos.life right now. Your current Connection Code stays active, and checking resumes automatically when the connection returns.';
  };

  const syncCountdownFromServer = (data) => {
    const remaining = Number(data?.seconds_remaining);
    if (!Number.isFinite(remaining) || remaining < 0) return;
    expiresAt = Math.floor(Date.now() / 1000) + Math.floor(remaining);
    if (remaining > 0) expiryCheckRequested = false;
    saveClaimState();
    formatCountdown();
  };

  const showDefinitiveFailure = (data) => {
    stopTimers();
    clearClaimState();
    const status = String(data?.status || 'failed');
    const errorCode = String(data?.error_code || '');

    if (claimStatusValue) claimStatusValue.textContent = status.toUpperCase();
    if (generateButton) generateButton.disabled = false;

    if (status === 'expired' || errorCode === 'claim_expired' || errorCode === 'invalid_claim_token' || errorCode === 'claim_already_used') {
      if (waitingTitle) waitingTitle.textContent = 'Connection code no longer valid';
      if (waitingText) waitingText.textContent = 'Generate a new Connection Code on floraos.life, then paste the new code into your FloraCore setup page.';
    } else if (errorCode === 'device_already_owned') {
      if (waitingTitle) waitingTitle.textContent = 'FloraCore already linked';
      if (waitingText) waitingText.textContent = 'This FloraCore is already linked to another account.';
    } else if (status === 'cancelled') {
      if (waitingTitle) waitingTitle.textContent = 'Connection code cancelled';
      if (waitingText) waitingText.textContent = 'This code is no longer active. Create a new Connection Code when you are ready.';
    } else {
      if (waitingTitle) waitingTitle.textContent = 'Setup could not finish';
      if (waitingText) waitingText.textContent = data?.error || 'Create a new Connection Code and try again.';
    }

    setStep(2, { scroll: false });
  };

  const showConnected = (data) => {
    stopTimers();
    clearClaimState();
    if (claimStatusValue) claimStatusValue.textContent = 'CONNECTED';
    if (deviceStatusValue) deviceStatusValue.textContent = 'ONLINE';
    if (statusTitle) statusTitle.textContent = 'FloraCore connected';
    if (statusDescription) statusDescription.textContent = 'Ownership is securely stored on the backend. Your full workspace is now unlocked.';
    if (connectedDeviceId) connectedDeviceId.textContent = data.device?.device_id || 'FloraCore';
    if (connectedResult) connectedResult.hidden = false;
    if (continueButton) continueButton.hidden = false;
    if (connectAnotherButton) connectAnotherButton.hidden = false;
    if (waitingTitle) waitingTitle.textContent = 'Connected successfully';
    if (waitingText) waitingText.textContent = 'Your FloraCore is now linked to this account.';
    setStep(4, { scroll: false });
  };

  const resetForAnotherDevice = () => {
    stopTimers();
    clearClaimState();

    activeClaimId = null;
    activeToken = '';
    expiresAt = 0;
    pollingBusy = false;
    expiryCheckRequested = false;

    if (claimConsole) claimConsole.hidden = true;
    if (claimCode) claimCode.textContent = '••••••••••••••••';
    if (copyConfirm) copyConfirm.hidden = true;
    if (claimCountdown) claimCountdown.textContent = '10:00';
    if (claimError) claimError.textContent = '';

    if (connectedResult) connectedResult.hidden = true;
    if (continueButton) continueButton.hidden = true;
    if (connectAnotherButton) connectAnotherButton.hidden = true;
    if (localSetupCard) localSetupCard.hidden = true;

    if (generateButton) {
      generateButton.disabled = false;
      generateButton.textContent = 'Create Connection Code →';
    }
    if (copyClaimButton) copyClaimButton.textContent = 'Copy code';

    if (claimStatusValue) claimStatusValue.textContent = 'NOT STARTED';
    if (deviceStatusValue) deviceStatusValue.textContent = 'WAITING';
    if (statusTitle) statusTitle.textContent = 'Add another FloraCore';
    if (statusDescription) {
      statusDescription.textContent =
        'Your existing FloraCore devices stay linked. Start these four steps again to add another one.';
    }
    if (waitingTitle) waitingTitle.textContent = 'Waiting for FloraCore…';
    if (waitingText) {
      waitingText.textContent =
        'Complete setup on your device, then reconnect this computer or phone to the internet.';
    }

    setStep(1, { scroll: true });
  };

  connectAnotherButton?.addEventListener('click', resetForAnotherDevice);

  const pollClaim = async ({ userInitiated = false } = {}) => {
    if (!activeClaimId || pollingBusy) return;
    pollingBusy = true;
    try {
      const response = await fetch(`/api/device/claim/${encodeURIComponent(activeClaimId)}`, {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
        cache: 'no-store'
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Could not read connection status.');

      if (data.status === 'pending') {
        syncCountdownFromServer(data);
        if (claimStatusValue) claimStatusValue.textContent = 'WAITING';
        if (deviceStatusValue) deviceStatusValue.textContent = 'CLAIMING';
        if (waitingTitle) waitingTitle.textContent = 'Waiting for FloraCore…';
        if (waitingText) waitingText.textContent = 'After your FloraCore joins home Wi-Fi, it immediately sends the encrypted ownership claim. If FloraCore services are temporarily unavailable, the device retries automatically — keep this Connection Code and wait.';
        return;
      }

      if (data.status === 'claimed') {
        showConnected(data);
        return;
      }

      showDefinitiveFailure(data);
    } catch (error) {
      if (!navigator.onLine || error instanceof TypeError) {
        showNetworkPause();
      } else if (userInitiated && claimError) {
        claimError.textContent = error.message || 'Could not check connection status.';
      }
    } finally {
      pollingBusy = false;
    }
  };

  const startPolling = () => {
    if (!activeClaimId) return;
    if (pollTimer) window.clearInterval(pollTimer);
    if (countdownTimer) window.clearInterval(countdownTimer);
    formatCountdown();
    countdownTimer = window.setInterval(formatCountdown, 1000);
    pollTimer = window.setInterval(() => pollClaim(), 1800);
    pollClaim();
  };

  powerReadyButton?.addEventListener('click', () => setStep(2));

  generateButton?.addEventListener('click', async () => {
    generateButton.disabled = true;
    if (claimError) claimError.textContent = '';
    if (connectedResult) connectedResult.hidden = true;
    if (continueButton) continueButton.hidden = true;
    if (connectAnotherButton) connectAnotherButton.hidden = true;
    stopTimers();

    try {
      const response = await fetch('/api/device/claim/start', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        credentials: 'same-origin',
        body: '{}'
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Could not create a connection code.');

      activeClaimId = data.claim_id;
      activeToken = data.setup_code || data.token || '';
      expiryCheckRequested = false;
      const ttlSeconds = Number(data.ttl_seconds);
      expiresAt = Math.floor(Date.now() / 1000) + (Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? Math.floor(ttlSeconds) : 600);
      saveClaimState();

      if (claimCode) claimCode.textContent = activeToken;
      if (claimConsole) claimConsole.hidden = false;
      if (claimStatusValue) claimStatusValue.textContent = 'READY';
      if (deviceStatusValue) deviceStatusValue.textContent = 'WAITING';
      startPolling();
    } catch (error) {
      if (claimError) claimError.textContent = error.message || 'Could not create a connection code.';
      generateButton.disabled = false;
    }
  });

  codeReadyButton?.addEventListener('click', () => setStep(3));

  joinedWifiButton?.addEventListener('click', () => {
    if (localSetupCard) localSetupCard.hidden = false;
    if (deviceStatusValue) deviceStatusValue.textContent = 'SETUP MODE';
    localSetupCard?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });

  openSetupButton?.addEventListener('click', () => {
    setStep(4, { scroll: false });
    showNetworkPause();
  });

  checkNowButton?.addEventListener('click', () => pollClaim({ userInitiated: true }));

  window.addEventListener('online', () => {
    if (activeClaimId) {
      if (deviceStatusValue) deviceStatusValue.textContent = 'CHECKING';
      pollClaim();
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

  const restoreFromServer = async () => {
    try {
      const response = await fetch('/api/onboarding', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
        cache: 'no-store'
      });
      if (!response.ok) return false;
      const data = await response.json().catch(() => ({}));

      // An active claim is the only setup session that should be resumed.
      // Merely owning one or more FloraCore devices does NOT mean a new
      // /connect visit is finished; users may add any number of devices.
      if (data.pending_claim?.claim_id && data.pending_claim?.seconds_remaining > 0) {
        activeClaimId = String(data.pending_claim.claim_id);
        expiresAt = Math.floor(Date.now() / 1000) + Number(data.pending_claim.seconds_remaining);
        saveClaimState();
        if (claimStatusValue) claimStatusValue.textContent = 'WAITING';
        if (deviceStatusValue) deviceStatusValue.textContent = 'CHECKING';
        if (statusTitle) statusTitle.textContent = 'Resuming FloraCore setup';
        if (statusDescription) statusDescription.textContent = 'A Connection Code is already active for this account.';
        if (waitingTitle) waitingTitle.textContent = 'Resuming setup…';
        if (waitingText) waitingText.textContent = 'A secure connection code is already active. We will keep watching for your FloraCore.';
        setStep(4, { scroll: false });
        startPolling();
        return true;
      }

      // Existing ownership only changes the wording. Start a fresh four-step
      // setup so this account can claim a second, third, or later FloraCore.
      if (data.connected && Array.isArray(data.devices) && data.devices.length) {
        if (statusTitle) statusTitle.textContent = 'Add another FloraCore';
        if (statusDescription) {
          statusDescription.textContent =
            `You already have ${data.devices.length} FloraCore${data.devices.length === 1 ? '' : 's'} linked. Start below to add another.`;
        }
        if (claimStatusValue) claimStatusValue.textContent = 'NOT STARTED';
        if (deviceStatusValue) deviceStatusValue.textContent = 'WAITING';
        if (connectedResult) connectedResult.hidden = true;
        if (continueButton) continueButton.hidden = true;
        if (connectAnotherButton) connectAnotherButton.hidden = true;
        setStep(1, { scroll: false });
        return true;
      }
    } catch (_) {
      return false;
    }
    return false;
  };

  const initialize = async () => {
    if (restoreClaimState()) {
      if (claimStatusValue) claimStatusValue.textContent = 'WAITING';
      if (deviceStatusValue) deviceStatusValue.textContent = 'CHECKING';
      if (waitingTitle) waitingTitle.textContent = 'Checking your FloraCore…';
      if (waitingText) waitingText.textContent = 'We found an in-progress setup and will continue automatically.';
      setStep(4, { scroll: false });
      startPolling();
      return;
    }

    const restored = await restoreFromServer();
    if (!restored) setStep(1, { scroll: false });
  };

  initialize();
  window.addEventListener('beforeunload', stopTimers, { once: true });
})();
