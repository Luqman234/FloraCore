(() => {
  'use strict';

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';

  const requestForm = document.getElementById('resetRequestForm');
  const completeForm = document.getElementById('resetCompleteForm');
  const email = document.getElementById('resetEmail');
  const code = document.getElementById('resetCode');
  const newPassword = document.getElementById('newPassword');
  const confirmPassword = document.getElementById('confirmPassword');
  const requestButton = document.getElementById('requestResetButton');
  const completeButton = document.getElementById('completeResetButton');
  const startOverButton = document.getElementById('startOverButton');
  const message = document.getElementById('resetMessage');
  const title = document.getElementById('resetTitle');
  const intro = document.getElementById('resetIntro');

  const turnstileTarget = document.getElementById('resetTurnstile');
  const turnstileStatus = document.getElementById('resetTurnstileStatus');

  let turnstileToken = '';
  let widgetId = null;

  const setMessage = (text = '', type = '') => {
    if (!message) return;
    message.textContent = text;
    message.className = 'reset-message';
    if (type) message.classList.add(type);
  };

  const setTurnstileStatus = (text = '', type = '') => {
    if (!turnstileStatus) return;
    turnstileStatus.textContent = text;
    turnstileStatus.className = 'reset-turnstile-status';
    if (type) turnstileStatus.classList.add(type);
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
      body: JSON.stringify(body),
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload?.error || `Request failed (${response.status}).`);
    }
    return payload;
  };

  const resetTurnstile = () => {
    turnstileToken = '';
    if (window.turnstile && widgetId !== null) {
      try { window.turnstile.reset(widgetId); } catch (_) {}
    }
  };

  const renderTurnstile = () => {
    if (!turnstileTarget) return true;
    if (!window.turnstile) return false;

    const sitekey = turnstileTarget.dataset.siteKey || '';
    if (!sitekey) {
      setTurnstileStatus('Turnstile site key is missing.', 'error');
      return true;
    }

    widgetId = window.turnstile.render(turnstileTarget, {
      sitekey,
      action: 'password_reset',
      theme: 'dark',
      size: 'flexible',
      appearance: 'interaction-only',
      callback(token) {
        turnstileToken = String(token || '');
        setTurnstileStatus('');
      },
      'expired-callback'() {
        turnstileToken = '';
        setTurnstileStatus('Security check expired. Try again.');
      },
      'error-callback'() {
        turnstileToken = '';
        setTurnstileStatus('Security check could not load.', 'error');
      },
    });

    setTurnstileStatus('Bot protection active.');
    return true;
  };

  if (turnstileTarget) {
    let attempts = 0;
    const timer = window.setInterval(() => {
      attempts += 1;
      if (renderTurnstile() || attempts >= 100) {
        window.clearInterval(timer);
        if (attempts >= 100 && !window.turnstile) {
          setTurnstileStatus('Cloudflare security check could not load.', 'error');
        }
      }
    }, 50);
  }

  requestForm?.addEventListener('submit', async (event) => {
    event.preventDefault();

    const value = email?.value.trim() || '';
    if (!value) {
      setMessage('Enter your account email.', 'error');
      return;
    }

    if (turnstileTarget && !turnstileToken) {
      setMessage('Complete the security check first.', 'error');
      return;
    }

    requestButton.disabled = true;
    setMessage('Requesting reset code…');

    try {
      const payload = await api('/api/password-reset/start', {
        email: value,
        turnstile_token: turnstileToken,
      });

      requestForm.hidden = true;
      completeForm.hidden = false;
      if (title) title.textContent = 'Check your email.';
      if (intro) {
        intro.textContent =
          'If that email belongs to a FloraCore account, a six-digit reset code was sent.';
      }
      setMessage(payload.message || 'Reset code requested.', 'success');
      code?.focus();
    } catch (error) {
      setMessage(error.message, 'error');
      resetTurnstile();
    } finally {
      requestButton.disabled = false;
    }
  });

  completeForm?.addEventListener('submit', async (event) => {
    event.preventDefault();

    const otp = code?.value.trim() || '';
    const next = newPassword?.value || '';
    const confirm = confirmPassword?.value || '';

    if (!/^\d{6}$/.test(otp)) {
      setMessage('Enter the six-digit reset code.', 'error');
      return;
    }
    if (next.length < 8) {
      setMessage('Password must be at least 8 characters.', 'error');
      return;
    }
    if (next !== confirm) {
      setMessage('Passwords do not match.', 'error');
      return;
    }

    completeButton.disabled = true;
    setMessage('Resetting password…');

    try {
      const payload = await api('/api/password-reset/complete', {
        code: otp,
        new_password: next,
        confirm_password: confirm,
      });

      setMessage(payload.message || 'Password reset complete.', 'success');
      window.setTimeout(() => {
        window.location.assign(payload.redirect || '/login');
      }, 700);
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      completeButton.disabled = false;
    }
  });

  startOverButton?.addEventListener('click', () => {
    completeForm.hidden = true;
    requestForm.hidden = false;
    code.value = '';
    newPassword.value = '';
    confirmPassword.value = '';
    if (title) title.textContent = 'Reset your password.';
    if (intro) {
      intro.textContent =
        'Enter your account email. If it exists, FloraCore will send a six-digit reset code.';
    }
    resetTurnstile();
    setMessage('');
    email?.focus();
  });
})();
