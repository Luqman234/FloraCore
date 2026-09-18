(() => {
  const form = document.getElementById('loginForm');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const togglePassword = document.getElementById('togglePassword');
  const message = document.getElementById('message');
  const submitButton = form?.querySelector('.submit-btn');
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const nextUrl = document.getElementById('nextUrl')?.value || '/dashboard';

  togglePassword?.addEventListener('click', () => {
    const revealing = passwordInput.type === 'password';
    passwordInput.type = revealing ? 'text' : 'password';
    togglePassword.textContent = revealing ? 'Hide' : 'Show';
    togglePassword.setAttribute('aria-label', revealing ? 'Hide password' : 'Show password');
  });

  form?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const remember = form.elements.remember.checked;

    message.className = 'message';
    if (!email || !password) {
      message.textContent = 'Email and password are required.';
      message.classList.add('error');
      return;
    }

    submitButton.disabled = true;
    submitButton.firstChild.textContent = 'Authenticating ';

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        credentials: 'same-origin',
        body: JSON.stringify({ email, password, remember, next: nextUrl })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Login failed.');

      message.textContent = 'Session established. Opening dashboard…';
      message.classList.add('success');
      window.setTimeout(() => window.location.assign(data.redirect || '/dashboard'), 350);
    } catch (error) {
      message.textContent = error.message || 'Could not connect to FloraCore.';
      message.classList.add('error');
      submitButton.disabled = false;
      submitButton.firstChild.textContent = 'Sign in ';
    }
  });
})();
