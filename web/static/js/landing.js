(() => {
  const header = document.getElementById('siteHeader');
  const menuToggle = document.getElementById('menuToggle');
  const mobileMenu = document.getElementById('mobileMenu');
  const heroConsole = document.getElementById('heroConsole');
  const graphLine = document.getElementById('graphLine');
  const graphArea = document.getElementById('graphArea');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const setHeaderState = () => header?.classList.toggle('scrolled', window.scrollY > 18);
  setHeaderState();
  window.addEventListener('scroll', setHeaderState, { passive: true });

  if (menuToggle && mobileMenu) {
    const closeMenu = () => {
      menuToggle.setAttribute('aria-expanded', 'false');
      menuToggle.setAttribute('aria-label', 'Open navigation');
      mobileMenu.hidden = true;
    };

    menuToggle.addEventListener('click', () => {
      const opening = menuToggle.getAttribute('aria-expanded') !== 'true';
      menuToggle.setAttribute('aria-expanded', String(opening));
      menuToggle.setAttribute('aria-label', opening ? 'Close navigation' : 'Open navigation');
      mobileMenu.hidden = !opening;
    });

    mobileMenu.querySelectorAll('a').forEach((link) => link.addEventListener('click', closeMenu));
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeMenu();
    });
  }

  const values = {
    soil: 42,
    reservoir: 73,
    temperature: 27.4,
    lux: 12840,
    latency: 23,
  };

  const setText = (selector, text) => {
    const el = document.querySelector(selector);
    if (el) el.textContent = text;
  };

  const history = [46, 45, 44, 44, 43, 43, 42, 42, 43, 42, 42, 41, 42, 42, 42, 43, 42, 42];

  function renderGraph() {
    if (!graphLine || !graphArea) return;
    const width = 480;
    const height = 210;
    const min = 30;
    const max = 55;
    const points = history.map((value, index) => {
      const x = (index / (history.length - 1)) * width;
      const y = height - ((value - min) / (max - min)) * (height - 24) - 12;
      return [x, y];
    });
    const pointString = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
    graphLine.setAttribute('points', pointString);
    graphArea.setAttribute('d', `M ${points[0][0]} ${height} L ${pointString.replaceAll(',', ' ')} L ${points.at(-1)[0]} ${height} Z`);
  }

  renderGraph();

  const updateClock = () => {
    const now = new Date();
    const time = now.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    document.querySelectorAll('[data-clock]').forEach((el) => { el.textContent = time; });
    document.querySelectorAll('[data-event-time]').forEach((el) => { el.textContent = time; });
  };
  updateClock();
  window.setInterval(updateClock, 1000);

  if (!reduceMotion) {
    window.setInterval(() => {
      values.soil = Math.max(39, Math.min(45, values.soil + (Math.random() > 0.55 ? 1 : Math.random() < 0.25 ? -1 : 0)));
      values.temperature = Math.max(26.8, Math.min(28.2, values.temperature + (Math.random() - 0.5) * 0.12));
      values.lux = Math.max(12600, Math.min(13100, values.lux + Math.round((Math.random() - 0.5) * 80)));
      values.latency = Math.max(19, Math.min(29, values.latency + Math.round((Math.random() - 0.5) * 3)));

      setText('[data-metric="soil"]', String(values.soil));
      setText('[data-metric="temperature"]', values.temperature.toFixed(1));
      setText('[data-metric="lux"]', values.lux.toLocaleString());
      setText('[data-latency]', String(values.latency));

      history.push(values.soil + (Math.random() - 0.5) * 1.4);
      history.shift();
      renderGraph();
    }, 2600);
  }

  let syncAge = 3;
  window.setInterval(() => {
    syncAge = syncAge >= 5 ? 1 : syncAge + 1;
    document.querySelectorAll('[data-sync-age]').forEach((el) => { el.textContent = `${syncAge}s`; });
  }, 1000);

  if (heroConsole && !reduceMotion && window.matchMedia('(pointer: fine)').matches) {
    const glow = heroConsole.querySelector('.console-glow');
    heroConsole.addEventListener('pointermove', (event) => {
      const rect = heroConsole.getBoundingClientRect();
      glow.style.left = `${event.clientX - rect.left}px`;
      glow.style.top = `${event.clientY - rect.top}px`;
    });
  }
})();
