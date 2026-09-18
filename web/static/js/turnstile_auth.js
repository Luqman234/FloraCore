(() => {
  'use strict';

  const protectedPaths = new Map([
    ['/api/login', 'login'],
    ['/api/signup', 'signup'],
  ]);

  const widgets = new Map();

  const pathFor = (input) => {
    try {
      if (typeof input === 'string') {
        return new URL(input, window.location.origin).pathname;
      }
      if (input instanceof Request) {
        return new URL(input.url, window.location.origin).pathname;
      }
    } catch (_) {}
    return '';
  };

  const setStatus = (record, message = '', type = '') => {
    if (!record?.status) return;
    record.status.textContent = message;
    record.status.className = 'flora-turnstile-status';
    if (type) record.status.classList.add(type);
  };

  const renderWidgets = () => {
    if (!window.turnstile) return;

    document.querySelectorAll('.flora-turnstile[data-flora-action]').forEach((element) => {
      if (element.dataset.rendered === '1') return;

      const action = element.dataset.floraAction || '';
      const sitekey = element.dataset.sitekey || '';
      const form = element.closest('form');
      const status = form?.querySelector('.flora-turnstile-status') || null;

      if (!action || !sitekey || !form) return;

      const record = {
        action,
        element,
        form,
        status,
        token: '',
        widgetId: null,
      };
      widgets.set(action, record);

      record.widgetId = window.turnstile.render(element, {
        sitekey,
        action,
        theme: 'dark',
        size: 'flexible',
        appearance: 'interaction-only',
        callback(token) {
          record.token = String(token || '');
          setStatus(record, '');
        },
        'expired-callback'() {
          record.token = '';
          setStatus(record, 'Security check expired. Verifying again…', 'muted');
        },
        'error-callback'() {
          record.token = '';
          setStatus(record, 'Security check could not load. Retry in a moment.', 'error');
        },
        'timeout-callback'() {
          record.token = '';
          setStatus(record, 'Security check timed out. Retry in a moment.', 'error');
        },
      });

      element.dataset.rendered = '1';

      // Enter-key submission can bypass a disabled button. Stop the form in
      // capture phase until Turnstile has issued a token.
      form.addEventListener('submit', (event) => {
        if (record.token) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        setStatus(record, 'Completing security check…', 'muted');
      }, true);
    });
  };

  const resetAction = (action) => {
    const record = widgets.get(action);
    if (!record) return;
    record.token = '';
    if (window.turnstile && record.widgetId !== null) {
      try {
        window.turnstile.reset(record.widgetId);
      } catch (_) {}
    }
  };

  const originalFetch = window.fetch.bind(window);

  window.fetch = async (input, init = {}) => {
    const path = pathFor(input);
    const action = protectedPaths.get(path);

    if (!action) {
      return originalFetch(input, init);
    }

    const record = widgets.get(action);
    if (!record?.token) {
      return new Response(
        JSON.stringify({
          error: 'Complete the security check and try again.',
          error_code: 'captcha_required',
        }),
        {
          status: 403,
          headers: {'Content-Type': 'application/json'},
        }
      );
    }

    const nextInit = {...init};
    let bodyObject = null;

    if (typeof nextInit.body === 'string') {
      try {
        const parsed = JSON.parse(nextInit.body);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          bodyObject = parsed;
        }
      } catch (_) {}
    }

    if (bodyObject) {
      bodyObject.turnstile_token = record.token;
      nextInit.body = JSON.stringify(bodyObject);
    } else if (nextInit.body instanceof FormData) {
      nextInit.body.set('cf-turnstile-response', record.token);
    } else {
      // FloraCore's login/signup endpoints use JSON. If a future frontend
      // changes that contract, fail locally rather than sending an unprotected
      // request that the backend will reject anyway.
      return new Response(
        JSON.stringify({
          error: 'Security verification could not be attached to this request.',
          error_code: 'captcha_client_error',
        }),
        {
          status: 400,
          headers: {'Content-Type': 'application/json'},
        }
      );
    }

    try {
      return await originalFetch(input, nextInit);
    } finally {
      // Turnstile tokens are single-use. Always reset after a protected
      // submission so retries get a fresh token.
      resetAction(action);
    }
  };

  const boot = () => {
    if (window.turnstile) {
      renderWidgets();
      return;
    }

    // The Cloudflare script is defer-loaded immediately after this script.
    // Poll briefly to cover network timing without creating a global callback.
    let tries = 0;
    const timer = window.setInterval(() => {
      tries += 1;
      if (window.turnstile) {
        window.clearInterval(timer);
        renderWidgets();
      } else if (tries >= 100) {
        window.clearInterval(timer);
        document.querySelectorAll('.flora-turnstile-status').forEach((status) => {
          status.textContent = 'Security verification could not load. Refresh the page.';
          status.classList.add('error');
        });
      }
    }, 50);
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, {once: true});
  } else {
    boot();
  }
})();
