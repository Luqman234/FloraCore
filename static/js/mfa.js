(() => {
  'use strict';

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const method = window.FLORACORE_MFA_METHOD || null;

  const form = document.getElementById('mfaForm');
  const mfaCode = document.getElementById('mfaCode');
  const verifyMfaButton = document.getElementById('verifyMfaButton');
  const resendMfaButton = document.getElementById('resendMfaButton');
  const useRecoveryButton = document.getElementById('useRecoveryButton');
  const recoveryEntry = document.getElementById('recoveryEntry');
  const recoveryCode = document.getElementById('recoveryCode');
  const verifyRecoveryButton = document.getElementById('verifyRecoveryButton');
  const mfaMessage = document.getElementById('mfaMessage');

  const setMessage = (message = '', type = '') => {
    if (!mfaMessage) return;
    mfaMessage.textContent = message;
    mfaMessage.className = 'mfa-message';
    if (type) mfaMessage.classList.add(type);
  };

  const api = async (url, body) => {
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
      },
      body: JSON.stringify(body || {}),
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

  const verify = async ({ recovery = false } = {}) => {
    const code = recovery
      ? recoveryCode?.value.trim() || ''
      : mfaCode?.value.trim() || '';

    if (!recovery && !/^\d{6}$/.test(code)) {
      setMessage('Enter the six-digit verification code.', 'error');
      return;
    }

    if (recovery && !code) {
      setMessage('Enter one of your recovery codes.', 'error');
      return;
    }

    if (verifyMfaButton) verifyMfaButton.disabled = true;
    if (verifyRecoveryButton) verifyRecoveryButton.disabled = true;
    setMessage('Verifying…');

    try {
      const payload = await api('/api/mfa/login/verify', recovery
        ? { recovery_code: code }
        : { code }
      );

      setMessage('Verified. Continuing…', 'success');
      window.location.assign(payload.data.redirect || '/dashboard');
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      if (verifyMfaButton) verifyMfaButton.disabled = false;
      if (verifyRecoveryButton) verifyRecoveryButton.disabled = false;
    }
  };

  form?.addEventListener('submit', (event) => {
    event.preventDefault();
    verify();
  });

  resendMfaButton?.addEventListener('click', async () => {
    resendMfaButton.disabled = true;
    setMessage('Sending another code…');

    try {
      await api('/api/mfa/login/resend', {});
      setMessage('A new sign-in code was sent.', 'success');
      mfaCode?.focus();
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      resendMfaButton.disabled = false;
    }
  });

  useRecoveryButton?.addEventListener('click', () => {
    if (!recoveryEntry) return;
    recoveryEntry.hidden = !recoveryEntry.hidden;
    useRecoveryButton.textContent = recoveryEntry.hidden
      ? 'Use a recovery code instead'
      : 'Use authenticator code instead';
    if (!recoveryEntry.hidden) recoveryCode?.focus();
  });

  verifyRecoveryButton?.addEventListener('click', () => verify({ recovery: true }));

  if (method === 'totp') {
    mfaCode?.focus();
  }
})();
