(() => {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const tokenList = document.getElementById('tokenList');
  const refreshTokens = document.getElementById('refreshTokens');
  const openCreateToken = document.getElementById('openCreateToken');
  const createModal = document.getElementById('createTokenModal');
  const closeCreateToken = document.getElementById('closeCreateToken');
  const createForm = document.getElementById('createTokenForm');
  const tokenName = document.getElementById('tokenName');
  const tokenExpiration = document.getElementById('tokenExpiration');
  const createFeedback = document.getElementById('createTokenFeedback');
  const createSubmit = document.getElementById('createTokenSubmit');
  const revealModal = document.getElementById('tokenRevealModal');
  const rawTokenValue = document.getElementById('rawTokenValue');
  const copyRawToken = document.getElementById('copyRawToken');
  const closeTokenReveal = document.getElementById('closeTokenReveal');
  const tokenCopyStatus = document.getElementById('tokenCopyStatus');
  const copyExample = document.getElementById('copyExample');
  const quickstartExample = document.getElementById('quickstartExample');

  let rawTokenInMemory = '';

  const scopeLabels = {
    'devices:read': 'Read devices',
    'devices:write': 'Edit device metadata',
    'devices:control': 'Control devices',
    'telemetry:read': 'Read telemetry',
    'plants:read': 'Read plant profiles',
    'plants:write': 'Edit plant profiles',
    'firmware:read': 'Read firmware status'
  };

  const escapeHtml = (value) => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');

  const formatDate = (unix) => {
    if (!Number.isFinite(Number(unix))) return 'Never';
    return new Date(Number(unix) * 1000).toLocaleString();
  };

  const formatRelative = (unix) => {
    if (!Number.isFinite(Number(unix))) return 'Never used';
    const seconds = Math.max(0, Math.floor(Date.now() / 1000 - Number(unix)));
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  const copyText = async (text) => {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    textarea.remove();
  };

  const readJson = async (response) => {
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data?.error?.message || data?.error || 'Request failed.');
    }
    return data;
  };

  const renderTokens = (tokens) => {
    if (!Array.isArray(tokens) || tokens.length === 0) {
      tokenList.innerHTML = '<div class="token-empty">No API tokens yet. Create one when an integration needs access.</div>';
      return;
    }

    tokenList.innerHTML = tokens.map((token) => {
      const active = token.status === 'active';
      const scopes = Array.isArray(token.scopes) ? token.scopes : [];
      return `
        <article class="token-item" data-token-id="${escapeHtml(token.token_id)}">
          <div class="token-main">
            <div class="token-name-row">
              <span class="token-name">${escapeHtml(token.name)}</span>
              <span class="token-status ${escapeHtml(token.status)}">${escapeHtml(token.status)}</span>
            </div>
            <code class="token-prefix">${escapeHtml(token.token_prefix)}…</code>
            <div class="scope-chips">
              ${scopes.map((scope) => `<span class="scope-chip">${escapeHtml(scopeLabels[scope] || scope)}</span>`).join('')}
            </div>
            <div class="token-meta">
              <span>Expires ${escapeHtml(formatDate(token.expires_at))}</span>
              <span>Last used ${escapeHtml(formatRelative(token.last_used_at))}</span>
              <span>Created ${escapeHtml(formatDate(token.created_at))}</span>
            </div>
          </div>
          <button class="revoke-token" type="button" ${active ? '' : 'disabled'}>${active ? 'Revoke' : 'Unavailable'}</button>
        </article>`;
    }).join('');
  };

  const loadTokens = async () => {
    tokenList.innerHTML = '<div class="token-loading">Loading API tokens…</div>';
    try {
      const response = await fetch('/api/developer/tokens', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
        cache: 'no-store'
      });
      const payload = await readJson(response);
      renderTokens(payload.data);
    } catch (error) {
      tokenList.innerHTML = `<div class="token-empty">${escapeHtml(error.message || 'Could not load API tokens.')}</div>`;
    }
  };

  const openCreate = () => {
    createFeedback.textContent = '';
    createModal.hidden = false;
    window.setTimeout(() => tokenName.focus(), 0);
  };

  const closeCreate = () => {
    createModal.hidden = true;
    createFeedback.textContent = '';
  };

  const closeReveal = () => {
    revealModal.hidden = true;
    rawTokenInMemory = '';
    rawTokenValue.textContent = '';
    tokenCopyStatus.textContent = '';
  };

  openCreateToken?.addEventListener('click', openCreate);
  closeCreateToken?.addEventListener('click', closeCreate);
  refreshTokens?.addEventListener('click', loadTokens);

  createModal?.addEventListener('click', (event) => {
    if (event.target === createModal) closeCreate();
  });
  revealModal?.addEventListener('click', (event) => {
    if (event.target === revealModal) closeReveal();
  });

  createForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    createFeedback.textContent = '';

    const name = tokenName.value.trim();
    const scopes = [...createForm.querySelectorAll('input[name="scope"]:checked')]
      .map((input) => input.value);
    const expiresInDays = Number(tokenExpiration.value);

    if (!name) {
      createFeedback.textContent = 'Give this token a name.';
      return;
    }
    if (!scopes.length) {
      createFeedback.textContent = 'Choose at least one permission.';
      return;
    }

    createSubmit.disabled = true;
    createSubmit.textContent = 'Creating…';

    try {
      const response = await fetch('/api/developer/tokens', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({
          name,
          scopes,
          expires_in_days: expiresInDays
        })
      });
      const payload = await readJson(response);

      rawTokenInMemory = String(payload.data.token || '');
      rawTokenValue.textContent = rawTokenInMemory;
      closeCreate();
      createForm.reset();
      createForm.querySelector('input[value="devices:read"]').checked = true;
      createForm.querySelector('input[value="telemetry:read"]').checked = true;
      tokenExpiration.value = '90';
      revealModal.hidden = false;
      await loadTokens();
    } catch (error) {
      createFeedback.textContent = error.message || 'Could not create token.';
    } finally {
      createSubmit.disabled = false;
      createSubmit.textContent = 'Create token';
    }
  });

  copyRawToken?.addEventListener('click', async () => {
    if (!rawTokenInMemory) return;
    try {
      await copyText(rawTokenInMemory);
      tokenCopyStatus.textContent = 'Copied. Store it somewhere safe.';
    } catch (_) {
      tokenCopyStatus.textContent = 'Could not copy automatically. Select the token manually.';
    }
  });

  closeTokenReveal?.addEventListener('click', closeReveal);

  tokenList?.addEventListener('click', async (event) => {
    const button = event.target.closest('.revoke-token');
    if (!button || button.disabled) return;

    const item = button.closest('[data-token-id]');
    const tokenId = item?.dataset.tokenId;
    if (!tokenId) return;

    if (!window.confirm('Revoke this API token? Applications using it will immediately lose access.')) return;

    button.disabled = true;
    button.textContent = 'Revoking…';
    try {
      const response = await fetch(`/api/developer/tokens/${encodeURIComponent(tokenId)}`, {
        method: 'DELETE',
        credentials: 'same-origin',
        headers: { 'X-CSRF-Token': csrfToken }
      });
      await readJson(response);
      await loadTokens();
    } catch (error) {
      button.disabled = false;
      button.textContent = 'Revoke';
      window.alert(error.message || 'Could not revoke token.');
    }
  });

  copyExample?.addEventListener('click', async () => {
    try {
      await copyText(quickstartExample.textContent.trim());
      const old = copyExample.textContent;
      copyExample.textContent = 'Copied';
      window.setTimeout(() => { copyExample.textContent = old; }, 1200);
    } catch (_) {}
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    if (!revealModal.hidden) closeReveal();
    else if (!createModal.hidden) closeCreate();
  });

  loadTokens();
})();
