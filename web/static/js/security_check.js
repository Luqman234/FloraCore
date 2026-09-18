(() => {
  'use strict';

  const target = document.getElementById('siteEntryTurnstile');
  const config = {
    siteKey: target?.dataset.siteKey || '',
    next: target?.dataset.next || '/',
  };
  const status = document.getElementById('securityStatus');

  let widgetId = null;
  let submitting = false;

  const setStatus = (message, type = '') => {
    if (!status) return;
    status.textContent = message;
    status.className = 'security-status';
    if (type) status.classList.add(type);
  };

  const verify = async (token) => {
    if (submitting) return;
    submitting = true;
    setStatus('Verifying with FloraCore…');

    try {
      const response = await fetch('/api/security-check/verify', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          turnstile_token: token,
          next: config.next || '/',
        }),
      });

      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(
          payload?.error || `Security verification failed (${response.status}).`
        );
      }

      setStatus('Verified. Entering FloraCore…', 'success');
      window.location.replace(payload?.data?.redirect || '/');
    } catch (error) {
      submitting = false;
      setStatus(error.message || 'Security verification failed. Try again.', 'error');
      if (window.turnstile && widgetId !== null) {
        try { window.turnstile.reset(widgetId); } catch (_) {}
      }
    }
  };

  const render = () => {
    if (!window.turnstile || !target || !config.siteKey) return false;

    widgetId = window.turnstile.render(target, {
      sitekey: config.siteKey,
      action: 'site_entry',
      theme: 'dark',
      size: 'flexible',
      appearance: 'always',
      callback: verify,
      'expired-callback'() {
        submitting = false;
        setStatus('Security check expired. Try again.');
      },
      'error-callback'() {
        submitting = false;
        setStatus('Cloudflare security check could not load.', 'error');
      },
      'timeout-callback'() {
        submitting = false;
        setStatus('Security check timed out. Try again.', 'error');
      },
    });

    setStatus('Complete the check to continue.');
    return true;
  };

  let attempts = 0;
  let rendered = false;

  if (!config.siteKey) {
    setStatus('Turnstile site key is missing from the rendered page.', 'error');
  } else {
    setStatus('Loading Cloudflare challenge…');
  }

  const timer = window.setInterval(() => {
    attempts += 1;

    if (!rendered) {
      rendered = render();
    }

    if (rendered) {
      window.clearInterval(timer);
      return;
    }

    if (attempts === 20 && !window.turnstile && config.siteKey) {
      setStatus('Waiting for challenges.cloudflare.com…');
    }

    if (attempts >= 100) {
      window.clearInterval(timer);

      if (!config.siteKey) {
        setStatus('Turnstile site key is missing from the rendered page.', 'error');
      } else if (!window.turnstile) {
        setStatus('Cloudflare challenge script was blocked or could not load. Check CSP, VPN, blockers, or network access.', 'error');
      } else {
        setStatus('Turnstile loaded but the widget could not initialize.', 'error');
      }
    }
  }, 50);
})();
