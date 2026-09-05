(() => {
  const form = document.getElementById('signupForm');
  const otpForm = document.getElementById('otpForm');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const confirmInput = document.getElementById('confirmPassword');
  const togglePassword = document.getElementById('togglePassword');
  const message = document.getElementById('message');
  const otpMessage = document.getElementById('otpMessage');
  const otpInput = document.getElementById('otp');
  const submitButton = form?.querySelector('.submit-btn');
  const verifyButton = document.getElementById('verifyButton');
  const resendButton = document.getElementById('resendOtp');
  const changeEmailButton = document.getElementById('changeEmail');
  const resendStatus = document.getElementById('resendStatus');
  const signupStage = document.getElementById('signupStage');
  const verificationStage = document.getElementById('verificationStage');
  const providerStage = document.getElementById('providerStage');
  const authSwitch = document.getElementById('authSwitch');
  const securityNote = document.getElementById('securityNote');
  const verificationEmail = document.getElementById('verificationEmail');
  const title = document.getElementById('signup-title');
  const intro = document.querySelector('.auth-intro');
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const lengthRule = document.getElementById('lengthRule');
  const commonRule = document.getElementById('commonRule');

  /*
   * FloraCore password meter — Microsoft Entra-inspired
   *
   * Microsoft publicly documents an approach based on:
   *   1) normalizing common character substitutions,
   *   2) comparing against banned/common terms,
   *   3) fuzzy matching close variants,
   *   4) scoring the remaining password rather than requiring arbitrary
   *      uppercase/number/symbol composition rules.
   *
   * FloraCore adapts that approach into three advisory labels:
   *   Common   -> score <= 4, or clearly predictable
   *   Uncommon -> score 5..9
   *   Strong   -> score >= 10
   *
   * IMPORTANT:
   * - This meter is advisory only.
   * - Signup still requires only 8+ characters.
   * - Common passwords are NOT blocked.
   * - The password is evaluated locally in the browser.
   */

  const bannedTerms = [
    'password', 'passw0rd', 'qwerty', 'asdfgh', 'zxcvbn',
    'letmein', 'welcome', 'admin', 'administrator', 'login',
    'secret', 'changeme', 'default', 'iloveyou',
    'football', 'baseball', 'princess', 'dragon', 'monkey',
    'sunshine', 'summer', 'winter', 'spring', 'autumn',
    'floracore', 'floraos'
  ];

  const exactCommonPasswords = new Set([
    '12345678', '123456789', '1234567890', '00000000', '11111111',
    '12121212', '12341234', '87654321',
    'password', 'password1', 'password12', 'password123', 'password1234',
    'passw0rd', 'p@ssword', 'p@ssw0rd', 'p@ssw0rd123',
    'qwertyui', 'qwertyuiop', 'qwerty123', 'qwerty1234',
    'asdfghjk', 'asdf1234', 'zxcvbnm1',
    'letmein1', 'letmein123', 'welcome1', 'welcome123',
    'admin123', 'admin1234', 'administrator',
    'iloveyou', 'iloveyou1', 'monkey123', 'dragon123',
    'abc12345', 'abcdefg1', 'abcdef123',
    'floracore', 'floracore1', 'floracore123',
    'floraos', 'floraos1', 'floraos123'
  ]);

  const keyboardRows = [
    '1234567890',
    '0987654321',
    'qwertyuiop',
    'poiuytrewq',
    'asdfghjkl',
    'lkjhgfdsa',
    'zxcvbnm',
    'mnbvcxz'
  ];

  let pendingSignupId = '';
  let pendingEmail = '';
  let resendTimer = null;

  const setMessage = (element, text, kind = '') => {
    if (!element) return;
    element.textContent = text;
    element.className = 'message';
    if (kind) element.classList.add(kind);
  };

  /*
   * Keep the normalization deliberately close to the substitutions Microsoft
   * publicly documents for password-ban evaluation.
   */
  const normalizeForPasswordCheck = (value) => value
    .toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/\$/g, 's')
    .replace(/@/g, 'a');

  const compactForComparison = (value) =>
    normalizeForPasswordCheck(value).replace(/[^a-z0-9]/g, '');

  const levenshteinDistanceAtMostOne = (a, b) => {
    if (a === b) return true;

    const lengthDiff = Math.abs(a.length - b.length);
    if (lengthDiff > 1) return false;

    // Same length: allow one substitution.
    if (a.length === b.length) {
      let differences = 0;
      for (let i = 0; i < a.length; i += 1) {
        if (a[i] !== b[i]) {
          differences += 1;
          if (differences > 1) return false;
        }
      }
      return true;
    }

    // Different lengths: allow one insertion/deletion.
    const shorter = a.length < b.length ? a : b;
    const longer = a.length < b.length ? b : a;
    let i = 0;
    let j = 0;
    let differences = 0;

    while (i < shorter.length && j < longer.length) {
      if (shorter[i] === longer[j]) {
        i += 1;
        j += 1;
      } else {
        differences += 1;
        if (differences > 1) return false;
        j += 1;
      }
    }

    return true;
  };

  const dynamicBannedTerms = () => {
    const terms = [...bannedTerms];

    const localPart = (emailInput?.value || '')
      .trim()
      .toLowerCase()
      .split('@')[0]
      .replace(/[^a-z0-9]/g, '');

    if (localPart.length >= 4) terms.push(localPart);

    // Include service/domain-specific words, similar to an organization's
    // custom banned-password dictionary.
    terms.push('floraoslife');

    return [...new Set(
      terms
        .map(compactForComparison)
        .filter((term) => term.length >= 4)
    )];
  };

  const hasRepeatedPattern = (value) => {
    const normalized = compactForComparison(value);
    if (!normalized) return false;

    if (/^(.)\1{3,}$/.test(normalized)) return true;

    for (let size = 1; size <= Math.min(5, Math.floor(normalized.length / 2)); size += 1) {
      const chunk = normalized.slice(0, size);
      const repeated = chunk
        .repeat(Math.ceil(normalized.length / size))
        .slice(0, normalized.length);

      if (repeated === normalized) return true;
    }

    return /(.)\1{4,}/.test(normalized);
  };

  const hasKeyboardPattern = (value) => {
    const normalized = compactForComparison(value);

    for (const row of keyboardRows) {
      for (let size = 4; size <= Math.min(8, row.length); size += 1) {
        for (let i = 0; i <= row.length - size; i += 1) {
          if (normalized.includes(row.slice(i, i + size))) return true;
        }
      }
    }

    return false;
  };

  const hasSequentialPattern = (value) => {
    const normalized = compactForComparison(value);
    if (normalized.length < 4) return false;

    for (let i = 0; i <= normalized.length - 4; i += 1) {
      const run = normalized.slice(i, i + 4);
      const codes = [...run].map((char) => char.charCodeAt(0));

      const ascending = codes.every(
        (code, index) => index === 0 || code === codes[index - 1] + 1
      );
      const descending = codes.every(
        (code, index) => index === 0 || code === codes[index - 1] - 1
      );

      if (ascending || descending) return true;
    }

    return false;
  };

  /*
   * Return all direct or edit-distance-1 matches against a candidate substring.
   * This catches simple mutations like:
   *   password -> passw0rd (after normalization)
   *   password -> passwore
   *   welcome  -> welcom
   */
  const fuzzyBannedMatch = (candidate, term) => {
    if (!candidate || !term) return false;
    if (candidate === term) return true;

    // Avoid very short fuzzy matches because they create too many false positives.
    if (term.length < 4 || candidate.length < 3) return false;

    return levenshteinDistanceAtMostOne(candidate, term);
  };

  /*
   * Entra-inspired scoring:
   *
   * Each banned term that consumes part of the normalized password contributes
   * one point. Each unmatched character contributes one point.
   *
   * Example:
   *   "floracoreblank12"
   *   [floracore] [blank] [1] [2]
   *       1          1     1   1  = 4
   *
   * We greedily choose the longest banned/fuzzy match at each position.
   */
  const entraStyleScore = (password) => {
    const normalized = compactForComparison(password);
    const terms = dynamicBannedTerms();

    if (!normalized) return 0;

    let score = 0;
    let index = 0;

    while (index < normalized.length) {
      let bestMatchLength = 0;

      for (const term of terms) {
        // Check candidates with term length, one shorter, and one longer
        // to support edit-distance-1 matching.
        const candidateLengths = [
          term.length,
          term.length - 1,
          term.length + 1
        ].filter((length) => length >= 3);

        for (const length of candidateLengths) {
          if (index + length > normalized.length) continue;

          const candidate = normalized.slice(index, index + length);
          if (fuzzyBannedMatch(candidate, term) && length > bestMatchLength) {
            bestMatchLength = length;
          }
        }
      }

      if (bestMatchLength > 0) {
        score += 1;
        index += bestMatchLength;
      } else {
        score += 1;
        index += 1;
      }
    }

    return score;
  };

  const isClearlyCommon = (password) => {
    const raw = password.toLowerCase();
    const normalized = compactForComparison(password);

    if (password.length < 8) return true;
    if (exactCommonPasswords.has(raw) || exactCommonPasswords.has(normalized)) return true;
    if (hasRepeatedPattern(password)) return true;
    if (hasKeyboardPattern(password)) return true;
    if (hasSequentialPattern(password)) return true;

    // Exact/fuzzy whole-password comparison against banned terms.
    for (const term of dynamicBannedTerms()) {
      if (fuzzyBannedMatch(normalized, term)) return true;
    }

    return false;
  };

  const estimateStrength = (password) => {
    if (!password) return 'neutral';
    if (isClearlyCommon(password)) return 'common';

    const score = entraStyleScore(password);

    /*
     * Microsoft documents a score of 5 as the minimum acceptable result for
     * its banned-password evaluation. FloraCore keeps that same boundary for
     * Common -> Uncommon, then adds a higher advisory tier for Strong.
     *
     * These labels do not block signup.
     */
    if (score <= 4) return 'common';
    if (score <= 9) return 'uncommon';
    return 'strong';
  };

  const setStrengthIndicator = (state) => {
    if (!commonRule) return;

    let dot = commonRule.querySelector('i');
    if (!dot) dot = document.createElement('i');

    commonRule.classList.remove('valid');

    const states = {
      neutral: {
        label: '',
        text: '#708294',
        dot: '#526575',
        glow: '0 0 0 3px rgba(255,255,255,.025)'
      },
      common: {
        label: 'Common',
        text: '#FF7B7B',
        dot: '#FF7B7B',
        glow: '0 0 0 3px rgba(255,123,123,.10)'
      },
      uncommon: {
        label: 'Uncommon',
        text: '#E7C56A',
        dot: '#E7C56A',
        glow: '0 0 0 3px rgba(231,197,106,.10)'
      },
      strong: {
        label: 'Strong',
        text: '#8DE5B0',
        dot: '#8DE5B0',
        glow: '0 0 0 3px rgba(141,229,176,.10)'
      }
    };

    const selected = states[state] || states.neutral;

    commonRule.replaceChildren(dot, document.createTextNode(selected.label));
    commonRule.style.color = selected.text;
    dot.style.background = selected.dot;
    dot.style.boxShadow = selected.glow;
  };

  const updateRules = () => {
    const password = passwordInput?.value || '';

    lengthRule?.classList.toggle('valid', password.length >= 8);
    setStrengthIndicator(estimateStrength(password));
  };

  const beginResendCooldown = (seconds = 60) => {
    if (!resendButton || !resendStatus) return;
    window.clearInterval(resendTimer);
    let remaining = Math.max(0, Number(seconds) || 0);
    resendButton.disabled = remaining > 0;

    const render = () => {
      if (remaining <= 0) {
        window.clearInterval(resendTimer);
        resendButton.disabled = false;
        resendStatus.textContent = 'You can request another code.';
        return;
      }
      resendStatus.textContent = `Available again in ${remaining}s`;
      remaining -= 1;
    };

    render();
    resendTimer = window.setInterval(render, 1000);
  };

  const showVerification = (maskedEmail, signupId) => {
    pendingEmail = emailInput.value.trim().toLowerCase();
    pendingSignupId = signupId || pendingSignupId;
    signupStage.hidden = true;
    providerStage.hidden = true;
    authSwitch.hidden = true;
    securityNote.hidden = true;
    verificationStage.hidden = false;
    verificationEmail.textContent = maskedEmail || pendingEmail;
    title.textContent = 'Verify your email.';
    intro.textContent = 'Enter the one-time code we sent before we create your FloraCore ID.';
    otpInput.value = '';
    otpInput.focus();
    beginResendCooldown(60);
    try {
      sessionStorage.setItem('floracore_pending_signup', JSON.stringify({
        signup_id: pendingSignupId,
        masked_email: maskedEmail || pendingEmail
      }));
    } catch (_) {}
  };

  const showSignup = () => {
    window.clearInterval(resendTimer);
    pendingSignupId = '';
    pendingEmail = '';
    verificationStage.hidden = true;
    signupStage.hidden = false;
    providerStage.hidden = false;
    authSwitch.hidden = false;
    securityNote.hidden = false;
    title.textContent = 'Create your FloraCore ID.';
    intro.textContent = 'One account for dashboards, devices, telemetry, automations, and future system services.';
    setMessage(otpMessage, '');
    setMessage(message, '');
    try { sessionStorage.removeItem('floracore_pending_signup'); } catch (_) {}
    emailInput.focus();
    updateRules();
  };

  passwordInput?.addEventListener('input', updateRules);

  togglePassword?.addEventListener('click', () => {
    const revealing = passwordInput.type === 'password';
    passwordInput.type = revealing ? 'text' : 'password';
    confirmInput.type = revealing ? 'text' : 'password';
    togglePassword.textContent = revealing ? 'Hide' : 'Show';
    togglePassword.setAttribute('aria-label', revealing ? 'Hide passwords' : 'Show passwords');
  });

  form?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmInput.value;

    setMessage(message, '');

    if (!email || !password || !confirmPassword) {
      setMessage(message, 'Complete all fields.', 'error');
      return;
    }
    if (password.length < 8) {
      setMessage(message, 'Password must be at least 8 characters.', 'error');
      return;
    }
    if (password !== confirmPassword) {
      setMessage(message, 'Passwords do not match.', 'error');
      return;
    }

    // Common passwords are deliberately NOT blocked here.
    submitButton.disabled = true;
    submitButton.firstChild.textContent = 'Sending verification code ';

    try {
      const response = await fetch('/api/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        credentials: 'same-origin',
        body: JSON.stringify({ email, password, confirm_password: confirmPassword })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not start sign-up.');

      pendingSignupId = data.signup_id || '';
      if (!pendingSignupId) throw new Error('FloraCore did not return a verification session.');
      showVerification(data.email || email, pendingSignupId);
      setMessage(otpMessage, 'Verification code sent.', 'success');
    } catch (error) {
      setMessage(message, error.message || 'Could not connect to FloraCore.', 'error');
    } finally {
      submitButton.disabled = false;
      submitButton.firstChild.textContent = 'Create account ';
    }
  });

  otpInput?.addEventListener('input', () => {
    otpInput.value = otpInput.value.replace(/\D/g, '').slice(0, 6);
  });

  otpForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const otp = otpInput.value.replace(/\D/g, '');

    if (otp.length !== 6) {
      setMessage(otpMessage, 'Enter the 6-digit verification code.', 'error');
      return;
    }

    verifyButton.disabled = true;
    verifyButton.firstChild.textContent = 'Verifying ';
    setMessage(otpMessage, '');

    try {
      const response = await fetch('/api/signup/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        credentials: 'same-origin',
        body: JSON.stringify({ signup_id: pendingSignupId, otp })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not verify this code.');

      try { sessionStorage.removeItem('floracore_pending_signup'); } catch (_) {}
      setMessage(otpMessage, 'Email verified. Opening FloraCore…', 'success');
      window.setTimeout(() => window.location.assign(data.redirect || '/dashboard'), 350);
    } catch (error) {
      setMessage(otpMessage, error.message || 'Could not verify this code.', 'error');
      otpInput.select();
    } finally {
      verifyButton.disabled = false;
      verifyButton.firstChild.textContent = 'Verify email ';
    }
  });

  resendButton?.addEventListener('click', async () => {
    if (!pendingSignupId || resendButton.disabled) return;

    resendButton.disabled = true;
    resendStatus.textContent = 'Sending…';
    setMessage(otpMessage, '');

    try {
      const response = await fetch('/api/signup/resend', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        credentials: 'same-origin',
        body: JSON.stringify({ signup_id: pendingSignupId })
      });

      const data = await response.json();
      if (!response.ok) {
        if (response.status === 429 && data.retry_after) {
          beginResendCooldown(data.retry_after);
        }
        throw new Error(data.error || 'Could not resend the code.');
      }

      setMessage(otpMessage, 'A new verification code was sent.', 'success');
      beginResendCooldown(60);
      otpInput.focus();
    } catch (error) {
      setMessage(otpMessage, error.message || 'Could not resend the code.', 'error');
      if (!resendStatus.textContent.startsWith('Available again')) {
        resendButton.disabled = false;
      }
    }
  });

  changeEmailButton?.addEventListener('click', showSignup);

  try {
    const saved = JSON.parse(sessionStorage.getItem('floracore_pending_signup') || 'null');
    if (saved?.signup_id) {
      pendingSignupId = String(saved.signup_id);
      signupStage.hidden = true;
      providerStage.hidden = true;
      authSwitch.hidden = true;
      securityNote.hidden = true;
      verificationStage.hidden = false;
      verificationEmail.textContent = saved.masked_email || 'your email';
      title.textContent = 'Verify your email.';
      intro.textContent = 'Enter the one-time code we sent before we create your FloraCore ID.';
      otpInput.focus();
    }
  } catch (_) {}

  updateRules();
})();
