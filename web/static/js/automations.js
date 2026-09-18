(() => {
  'use strict';

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

  const automationName = document.getElementById('automationName');
  const deviceSelect = document.getElementById('deviceSelect');
  const timezoneInput = document.getElementById('timezoneInput');
  const newAutomationButton = document.getElementById('newAutomationButton');
  const saveAutomationButton = document.getElementById('saveAutomationButton');
  const simulateAutomationButton = document.getElementById('simulateAutomationButton');
  const deleteAutomationButton = document.getElementById('deleteAutomationButton');
  const enableAutomationButton = document.getElementById('enableAutomationButton');
  const automationList = document.getElementById('automationList');
  const automationCount = document.getElementById('automationCount');
  const saveState = document.getElementById('saveState');
  const editorMessage = document.getElementById('editorMessage');

  const automationCanvas = document.getElementById('automationCanvas');
  const edgeLayer = document.getElementById('edgeLayer');
  const canvasEmpty = document.getElementById('canvasEmpty');
  const fitCanvasButton = document.getElementById('fitCanvasButton');
  const clearCanvasButton = document.getElementById('clearCanvasButton');

  const selectedNodeType = document.getElementById('selectedNodeType');
  const inspectorEmpty = document.getElementById('inspectorEmpty');
  const nodeInspector = document.getElementById('nodeInspector');
  const inspectorFields = document.getElementById('inspectorFields');
  const deleteNodeButton = document.getElementById('deleteNodeButton');

  const runHistory = document.getElementById('runHistory');
  const runHistoryLabel = document.getElementById('runHistoryLabel');

  const simulationModal = document.getElementById('simulationModal');
  const simulationSource = document.getElementById('simulationSource');
  const simulationSourceNote = document.getElementById('simulationSourceNote');
  const simulationSoil = document.getElementById('simulationSoil');
  const simulationLight = document.getElementById('simulationLight');
  const simulationTime = document.getElementById('simulationTime');
  const simulationResult = document.getElementById('simulationResult');
  const simulationOutcomeBadge = document.getElementById('simulationOutcomeBadge');
  const simulationOutcomeTitle = document.getElementById('simulationOutcomeTitle');
  const simulationOutcomeText = document.getElementById('simulationOutcomeText');
  const simulationSoilResult = document.getElementById('simulationSoilResult');
  const simulationLightResult = document.getElementById('simulationLightResult');
  const simulationTimeResult = document.getElementById('simulationTimeResult');
  const simulationActionPreview = document.getElementById('simulationActionPreview');
  const simulationActionText = document.getElementById('simulationActionText');
  const simulationDeliveryText = document.getElementById('simulationDeliveryText');
  const simulationSteps = document.getElementById('simulationSteps');
  const closeSimulationButton = document.getElementById('closeSimulationButton');
  const runSimulationButton = document.getElementById('runSimulationButton');

  const advancedModal = document.getElementById('advancedModal');
  const advancedConfirmCheckbox = document.getElementById('advancedConfirmCheckbox');
  const confirmEnableButton = document.getElementById('confirmEnableButton');
  const cancelEnableButton = document.getElementById('cancelEnableButton');

  const state = {
    automations: [],
    devices: [],
    currentId: null,
    currentEnabled: false,
    dirty: false,
    nodes: [],
    edges: [],
    selectedNodeId: null,
    connectingFrom: null,
    nodeCounter: 0,
    runPollTimer: 0,
  };

  const NODE_META = {
    trigger_soil_below: { title: 'Soil below', kicker: 'TRIGGER', kind: 'trigger' },
    trigger_soil_above: { title: 'Soil above', kicker: 'TRIGGER', kind: 'trigger' },
    trigger_light_below: { title: 'Light below', kicker: 'TRIGGER', kind: 'trigger' },
    trigger_light_above: { title: 'Light above', kicker: 'TRIGGER', kind: 'trigger' },
    trigger_schedule: { title: 'Schedule', kicker: 'TRIGGER', kind: 'trigger' },
    trigger_telemetry: { title: 'Telemetry received', kicker: 'TRIGGER', kind: 'trigger' },

    condition_soil_below: { title: 'Soil below', kicker: 'CONDITION', kind: 'condition' },
    condition_soil_above: { title: 'Soil above', kicker: 'CONDITION', kind: 'condition' },
    condition_light_below: { title: 'Light below', kicker: 'CONDITION', kind: 'condition' },
    condition_light_above: { title: 'Light above', kicker: 'CONDITION', kind: 'condition' },
    condition_time_between: { title: 'Time window', kicker: 'CONDITION', kind: 'condition' },

    cooldown: { title: 'Cooldown', kicker: 'FLOW', kind: 'flow' },

    action_water: { title: 'Water', kicker: 'ACTION', kind: 'action' },
    action_grow_light: { title: 'Grow light', kicker: 'ACTION', kind: 'action' },
  };

  const setMessage = (message = '', type = '') => {
    if (!editorMessage) return;
    editorMessage.textContent = message;
    editorMessage.classList.remove('is-error', 'is-success');
    if (type === 'error') editorMessage.classList.add('is-error');
    if (type === 'success') editorMessage.classList.add('is-success');
  };

  const api = async (url, options = {}) => {
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');

    if (options.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    if (options.method && options.method !== 'GET') {
      headers.set('X-CSRF-Token', csrfToken);
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
      const message =
        payload?.error?.message ||
        payload?.error ||
        `Request failed (${response.status}).`;
      const error = new Error(message);
      error.code = payload?.error?.code || 'request_failed';
      error.status = response.status;
      throw error;
    }

    return payload;
  };

  const getLocalTimezone = () => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    } catch (_) {
      return 'UTC';
    }
  };

  const defaultConfig = (type) => {
    switch (type) {
      case 'trigger_soil_below':
      case 'trigger_soil_above':
      case 'condition_soil_below':
      case 'condition_soil_above':
        return { percent: 35 };

      case 'trigger_light_below':
      case 'trigger_light_above':
      case 'condition_light_below':
      case 'condition_light_above':
        return { lux: 500 };

      case 'trigger_schedule':
        return { time: '18:00', grace_minutes: 10 };

      case 'trigger_telemetry':
        return {};

      case 'condition_time_between':
        return { start: '08:00', end: '20:00' };

      case 'cooldown':
        return { seconds: 21600 };

      case 'action_water':
        return { duration_ms: 5000 };

      case 'action_grow_light':
        return { state: 'on', duration_seconds: 14400 };

      default:
        return {};
    }
  };

  const inlineEditorForNode = (node) => {
    const c = node.config || {};

    if (
      node.type === 'trigger_soil_below' ||
      node.type === 'trigger_soil_above' ||
      node.type === 'condition_soil_below' ||
      node.type === 'condition_soil_above'
    ) {
      return `
        <label class="node-inline-editor" aria-label="Soil threshold">
          <input
            class="node-inline-input"
            data-inline-config="percent"
            type="number"
            min="0"
            max="100"
            step="1"
            value="${Number(c.percent ?? 35)}"
          >
          <span>%</span>
        </label>
      `;
    }

    if (
      node.type === 'trigger_light_below' ||
      node.type === 'trigger_light_above' ||
      node.type === 'condition_light_below' ||
      node.type === 'condition_light_above'
    ) {
      return `
        <label class="node-inline-editor" aria-label="Light threshold">
          <input
            class="node-inline-input"
            data-inline-config="lux"
            type="number"
            min="0"
            max="250000"
            step="1"
            value="${Number(c.lux ?? 500)}"
          >
          <span>lux</span>
        </label>
      `;
    }

    return `<small class="node-summary">${summaryForNode(node)}</small>`;
  };

  const summaryForNode = (node) => {
    const c = node.config || {};

    if (node.type.includes('soil_')) {
      return `${Number(c.percent ?? 0)}%`;
    }
    if (node.type.includes('light_')) {
      return `${Number(c.lux ?? 0).toLocaleString()} lux`;
    }
    if (node.type === 'trigger_schedule') {
      return `${c.time || '—'} · ${c.grace_minutes || 10}m grace`;
    }
    if (node.type === 'trigger_telemetry') {
      return 'Every authenticated sample';
    }
    if (node.type === 'condition_time_between') {
      return `${c.start || '—'} → ${c.end || '—'}`;
    }
    if (node.type === 'cooldown') {
      const seconds = Number(c.seconds || 0);
      if (seconds % 3600 === 0) return `${seconds / 3600}h`;
      if (seconds % 60 === 0) return `${seconds / 60}m`;
      return `${seconds}s`;
    }
    if (node.type === 'action_water') {
      return `${(Number(c.duration_ms || 0) / 1000).toFixed(1)} sec`;
    }
    if (node.type === 'action_grow_light') {
      if (c.state === 'off') return 'Turn off';
      const minutes = Number(c.duration_seconds || 0) / 60;
      return `On · ${minutes >= 60 ? `${(minutes / 60).toFixed(1)}h` : `${minutes}m`}`;
    }
    return '';
  };

  const nodeById = (id) => state.nodes.find((node) => node.id === id) || null;

  const markDirty = () => {
    if (!state.dirty) {
      state.dirty = true;
      if (saveState) saveState.textContent = 'UNSAVED CHANGES';
    }
    setMessage('');
  };

  const markSaved = (label = 'SAVED') => {
    state.dirty = false;
    if (saveState) saveState.textContent = label;
  };

  const nextNodeId = () => {
    state.nodeCounter += 1;
    return `node_${Date.now().toString(36)}_${state.nodeCounter}`;
  };

  const createNode = (type, x, y) => {
    if (!NODE_META[type]) return null;
    if (state.nodes.length >= 12) {
      setMessage('Automation v1 supports up to 12 blocks.', 'error');
      return null;
    }

    const node = {
      id: nextNodeId(),
      type,
      x: Math.max(10, Math.min(1980, Math.round(x))),
      y: Math.max(10, Math.min(1280, Math.round(y))),
      config: defaultConfig(type),
    };

    state.nodes.push(node);
    state.selectedNodeId = node.id;
    markDirty();
    renderCanvas();
    renderInspector();
    return node;
  };

  const removeNode = (id) => {
    state.nodes = state.nodes.filter((node) => node.id !== id);
    state.edges = state.edges.filter((edge) => edge.from !== id && edge.to !== id);
    if (state.selectedNodeId === id) state.selectedNodeId = null;
    if (state.connectingFrom === id) state.connectingFrom = null;
    markDirty();
    renderCanvas();
    renderInspector();
  };

  const connectNodes = (from, to) => {
    if (!from || !to || from === to) return;

    const source = nodeById(from);
    const target = nodeById(to);
    if (!source || !target) return;

    // v1 is intentionally a single path. Replacing an existing source output
    // or target input keeps the editor aligned with the backend invariant.
    state.edges = state.edges.filter(
      (edge) => edge.from !== from && edge.to !== to
    );
    state.edges.push({ from, to });
    state.connectingFrom = null;
    markDirty();
    renderCanvas();
  };

  const renderEdges = () => {
    if (!edgeLayer) return;
    edgeLayer.innerHTML = '';

    state.edges.forEach((edge) => {
      const source = nodeById(edge.from);
      const target = nodeById(edge.to);
      if (!source || !target) return;

      const x1 = source.x + 180;
      const y1 = source.y + 46;
      const x2 = target.x;
      const y2 = target.y + 46;
      const bend = Math.max(55, Math.abs(x2 - x1) * 0.42);

      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('class', 'edge-path');
      path.setAttribute(
        'd',
        `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`
      );
      edgeLayer.appendChild(path);
    });
  };

  const makeNodeElement = (node) => {
    const meta = NODE_META[node.type];

    const element = document.createElement('article');
    element.className = `automation-node ${meta.kind}${state.selectedNodeId === node.id ? ' selected' : ''}`;
    element.dataset.nodeId = node.id;
    element.style.left = `${node.x}px`;
    element.style.top = `${node.y}px`;

    element.innerHTML = `
      <button class="node-port in" type="button" aria-label="Connect into ${meta.title}"></button>
      <div class="node-drag-handle">
        <span class="node-kicker">${meta.kicker}</span>
        <b class="node-title">${meta.title}</b>
      </div>
      ${inlineEditorForNode(node)}
      <button class="node-port out${state.connectingFrom === node.id ? ' armed' : ''}" type="button" aria-label="Connect from ${meta.title}"></button>
    `;

    element.addEventListener('click', (event) => {
      if (event.target.closest('.node-port, .node-inline-editor')) return;
      state.selectedNodeId = node.id;
      renderCanvas();
      renderInspector();
    });

    const inputPort = element.querySelector('.node-port.in');
    const outputPort = element.querySelector('.node-port.out');
    const inlineInput = element.querySelector('.node-inline-input');

    if (inlineInput) {
      // Editing a threshold should never start dragging/selecting a wire.
      for (const eventName of ['pointerdown', 'mousedown', 'click', 'dblclick']) {
        inlineInput.addEventListener(eventName, (event) => {
          event.stopPropagation();
        });
      }

      const applyInlineValue = () => {
        const key = inlineInput.dataset.inlineConfig;
        if (!key) return;

        const numeric = Number(inlineInput.value);
        if (!Number.isFinite(numeric)) return;

        if (key === 'percent') {
          node.config.percent = Math.max(0, Math.min(100, numeric));
          inlineInput.value = String(node.config.percent);
        } else if (key === 'lux') {
          node.config.lux = Math.max(0, Math.min(250000, numeric));
          inlineInput.value = String(node.config.lux);
        }

        state.selectedNodeId = node.id;
        markDirty();

        // Keep the inspector synchronized without rebuilding the node that
        // currently owns keyboard focus.
        renderInspector();
      };

      inlineInput.addEventListener('input', applyInlineValue);
      inlineInput.addEventListener('change', applyInlineValue);
      inlineInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          applyInlineValue();
          inlineInput.blur();
        }
      });
    }

    inputPort?.addEventListener('click', (event) => {
      event.stopPropagation();
      if (state.connectingFrom) {
        connectNodes(state.connectingFrom, node.id);
      } else {
        state.selectedNodeId = node.id;
        renderCanvas();
        renderInspector();
      }
    });

    outputPort?.addEventListener('click', (event) => {
      event.stopPropagation();
      state.connectingFrom =
        state.connectingFrom === node.id ? null : node.id;
      state.selectedNodeId = node.id;
      renderCanvas();
      renderInspector();
    });

    const handle = element.querySelector('.node-drag-handle');
    handle?.addEventListener('pointerdown', (event) => {
      if (event.button !== 0) return;
      event.preventDefault();

      const startX = event.clientX;
      const startY = event.clientY;
      const originalX = node.x;
      const originalY = node.y;

      let deleteArmed = false;
      let moved = false;

      const pointerOutsideCanvas = (clientX, clientY) => {
        if (!automationCanvas) return false;
        const rect = automationCanvas.getBoundingClientRect();

        // Small buffer prevents an accidental delete when releasing directly
        // on the border while still making "drag it out of the frame" natural.
        const buffer = 8;
        return (
          clientX < rect.left - buffer ||
          clientX > rect.right + buffer ||
          clientY < rect.top - buffer ||
          clientY > rect.bottom + buffer
        );
      };

      handle.setPointerCapture(event.pointerId);

      const move = (moveEvent) => {
        moved = true;

        deleteArmed = pointerOutsideCanvas(
          moveEvent.clientX,
          moveEvent.clientY
        );
        setDeleteDragState(deleteArmed, element);

        // While still inside the canvas, move normally. Once the pointer is
        // outside, leave the block at its last valid position so it does not
        // jump to a content boundary just before being removed.
        if (deleteArmed) return;

        node.x = Math.max(
          10,
          Math.min(
            1980,
            Math.round(originalX + moveEvent.clientX - startX)
          )
        );
        node.y = Math.max(
          10,
          Math.min(
            1280,
            Math.round(originalY + moveEvent.clientY - startY)
          )
        );
        element.style.left = `${node.x}px`;
        element.style.top = `${node.y}px`;
        renderEdges();
      };

      const finish = (finishEvent, cancelled = false) => {
        handle.removeEventListener('pointermove', move);
        handle.removeEventListener('pointerup', end);
        handle.removeEventListener('pointercancel', cancel);

        const shouldDelete =
          !cancelled &&
          moved &&
          pointerOutsideCanvas(
            finishEvent.clientX,
            finishEvent.clientY
          );

        setDeleteDragState(false, element);

        if (shouldDelete) {
          removeNode(node.id);
          setMessage('Block removed.', 'success');
          return;
        }

        if (moved) markDirty();
      };

      const end = (endEvent) => finish(endEvent, false);
      const cancel = (cancelEvent) => finish(cancelEvent, true);

      handle.addEventListener('pointermove', move);
      handle.addEventListener('pointerup', end);
      handle.addEventListener('pointercancel', cancel);
    });

    return element;
  };

  const renderCanvas = () => {
    if (!automationCanvas) return;

    automationCanvas
      .querySelectorAll('.automation-node')
      .forEach((node) => node.remove());

    state.nodes.forEach((node) => {
      automationCanvas.appendChild(makeNodeElement(node));
    });

    if (canvasEmpty) canvasEmpty.hidden = state.nodes.length > 0;
    renderEdges();
  };

  const field = (label, html, helper = '') => `
    <label class="inspector-field">
      <span>${label}</span>
      ${html}
      ${helper ? `<small>${helper}</small>` : ''}
    </label>
  `;

  const renderInspector = () => {
    const node = nodeById(state.selectedNodeId);

    if (!node) {
      if (selectedNodeType) selectedNodeType.textContent = 'No block selected';
      if (inspectorEmpty) inspectorEmpty.hidden = false;
      if (nodeInspector) nodeInspector.hidden = true;
      return;
    }

    const meta = NODE_META[node.type];
    if (selectedNodeType) selectedNodeType.textContent = `${meta.kicker} / ${meta.title}`;
    if (inspectorEmpty) inspectorEmpty.hidden = true;
    if (nodeInspector) nodeInspector.hidden = false;

    let html = '';

    if (node.type.includes('soil_')) {
      html += field(
        'SOIL THRESHOLD',
        `<input data-config="percent" type="number" min="0" max="100" step="1" value="${Number(node.config.percent ?? 35)}">`,
        'Uses authenticated soil_percent telemetry.'
      );
    } else if (node.type.includes('light_')) {
      html += field(
        'LIGHT THRESHOLD',
        `<input data-config="lux" type="number" min="0" max="250000" step="1" value="${Number(node.config.lux ?? 500)}">`,
        'Uses authenticated light_lux telemetry.'
      );
    } else if (node.type === 'trigger_schedule') {
      html += field(
        'DAILY TIME',
        `<input data-config="time" type="time" value="${node.config.time || '18:00'}">`
      );
      html += field(
        'GRACE WINDOW (MIN)',
        `<input data-config="grace_minutes" type="number" min="1" max="60" step="1" value="${Number(node.config.grace_minutes ?? 10)}">`,
        'If the device misses the exact minute, FloraOS may trigger inside this short window.'
      );
    } else if (node.type === 'trigger_telemetry') {
      html += field(
        'EVENT',
        `<input value="Authenticated telemetry sample" disabled>`,
        'The automation is evaluated when FloraCore uploads telemetry.'
      );
    } else if (node.type === 'condition_time_between') {
      html += field(
        'START',
        `<input data-config="start" type="time" value="${node.config.start || '08:00'}">`
      );
      html += field(
        'END',
        `<input data-config="end" type="time" value="${node.config.end || '20:00'}">`,
        'Overnight windows such as 20:00 → 06:00 are supported.'
      );
    } else if (node.type === 'cooldown') {
      html += field(
        'COOLDOWN (MINUTES)',
        `<input data-config-minutes="seconds" type="number" min="1" max="10080" step="1" value="${Math.max(1, Math.round(Number(node.config.seconds || 21600) / 60))}">`,
        'Water automations always enforce at least 15 minutes; grow-light automations at least 5 minutes.'
      );
    } else if (node.type === 'action_water') {
      html += field(
        'WATER DURATION (SECONDS)',
        `<input data-config-seconds="duration_ms" type="number" min="0.5" max="30" step="0.5" value="${Number(node.config.duration_ms || 5000) / 1000}">`,
        'The command queue and firmware still apply independent pump safety limits.'
      );
    } else if (node.type === 'action_grow_light') {
      html += field(
        'STATE',
        `<select data-config="state">
          <option value="on"${node.config.state === 'on' ? ' selected' : ''}>On</option>
          <option value="off"${node.config.state === 'off' ? ' selected' : ''}>Off</option>
        </select>`
      );

      if (node.config.state !== 'off') {
        html += field(
          'AUTO-OFF (MINUTES)',
          `<input data-config-minutes="duration_seconds" type="number" min="1" max="720" step="1" value="${Math.max(1, Math.round(Number(node.config.duration_seconds || 3600) / 60))}">`,
          'Grow-light on commands always include a bounded local auto-off duration.'
        );
      }
    }

    if (inspectorFields) {
      inspectorFields.innerHTML = html;

      inspectorFields.querySelectorAll('[data-config]').forEach((input) => {
        input.addEventListener('input', () => {
          const key = input.dataset.config;
          if (!key) return;

          if (input.type === 'number') {
            node.config[key] = Number(input.value);
          } else {
            node.config[key] = input.value;
          }

          if (node.type === 'action_grow_light' && key === 'state') {
            if (input.value === 'off') {
              delete node.config.duration_seconds;
            } else if (!node.config.duration_seconds) {
              node.config.duration_seconds = 3600;
            }
            renderInspector();
          }

          markDirty();
          renderCanvas();
        });
      });

      inspectorFields.querySelectorAll('[data-config-minutes]').forEach((input) => {
        input.addEventListener('input', () => {
          const key = input.dataset.configMinutes;
          node.config[key] = Math.round(Number(input.value) * 60);
          markDirty();
          renderCanvas();
        });
      });

      inspectorFields.querySelectorAll('[data-config-seconds]').forEach((input) => {
        input.addEventListener('input', () => {
          const key = input.dataset.configSeconds;
          node.config[key] = Math.round(Number(input.value) * 1000);
          markDirty();
          renderCanvas();
        });
      });
    }
  };

  const graphPayload = () => ({
    version: 1,
    nodes: state.nodes.map((node) => ({
      id: node.id,
      type: node.type,
      x: Number(node.x),
      y: Number(node.y),
      config: { ...node.config },
    })),
    edges: state.edges.map((edge) => ({ ...edge })),
  });

  const renderDevices = () => {
    if (!deviceSelect) return;

    if (!state.devices.length) {
      deviceSelect.innerHTML = '<option value="">No FloraCore connected</option>';
      deviceSelect.disabled = true;
      return;
    }

    const current = deviceSelect.value;
    deviceSelect.disabled = false;
    deviceSelect.innerHTML = state.devices
      .map((device) => {
        const label = device.nickname || device.device_id;
        const suffix = device.online ? ' · online' : ' · offline';
        return `<option value="${escapeHtml(device.device_id)}">${escapeHtml(label)}${escapeHtml(suffix)}</option>`;
      })
      .join('');

    if (current && state.devices.some((device) => device.device_id === current)) {
      deviceSelect.value = current;
    }
  };

  const renderAutomationList = () => {
    if (automationCount) automationCount.textContent = String(state.automations.length);
    if (!automationList) return;

    if (!state.automations.length) {
      automationList.innerHTML = '<p class="studio-empty">No automations yet.</p>';
      return;
    }

    automationList.innerHTML = state.automations
      .map((automation) => {
        const device =
          state.devices.find((item) => item.device_id === automation.device_id);
        const deviceName = device?.nickname || automation.device_id;
        return `
          <button
            class="automation-list-item${automation.automation_id === state.currentId ? ' active' : ''}"
            data-automation-id="${automation.automation_id}"
            type="button"
          >
            <span>
              <b>${escapeHtml(automation.name)}</b>
              <small>${escapeHtml(deviceName)}</small>
            </span>
            <em class="${automation.enabled ? 'on' : ''}" title="${automation.enabled ? 'Enabled' : 'Disabled'}"></em>
          </button>
        `;
      })
      .join('');

    automationList
      .querySelectorAll('[data-automation-id]')
      .forEach((button) => {
        button.addEventListener('click', () => {
          if (state.dirty && !window.confirm('Discard unsaved automation changes?')) {
            return;
          }
          loadAutomation(button.dataset.automationId);
        });
      });
  };

  const escapeHtml = (value) =>
    String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');

  const formatTime = (timestamp) => {
    if (!timestamp) return '—';
    const date = new Date(Number(timestamp) * 1000);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleString();
  };

  const renderRuns = (runs) => {
    if (!runHistory) return;

    if (!runs?.length) {
      runHistory.innerHTML = '<p class="studio-empty">No run history yet.</p>';
      return;
    }

    runHistory.innerHTML = runs
      .map((run) => {
        const status = String(run.status || 'unknown').toLowerCase();
        const command = run.command_id ? ` · ${escapeHtml(run.command_id)}` : '';
        const error = run.error ? ` · ${escapeHtml(run.error)}` : '';
        return `
          <div class="run-row">
            <span class="run-status ${status}">${escapeHtml(status.toUpperCase())}</span>
            <div class="run-main">
              <b>${escapeHtml(run.trigger?.type || 'Automation trigger')}${command}</b>
              <small>${escapeHtml(run.device_id)}${error}</small>
            </div>
            <time class="run-time">${escapeHtml(formatTime(run.started_at))}</time>
          </div>
        `;
      })
      .join('');
  };

  const loadRuns = async () => {
    window.clearTimeout(state.runPollTimer);
    if (!state.currentId) {
      if (runHistoryLabel) runHistoryLabel.textContent = 'Select a saved automation';
      renderRuns([]);
      return;
    }

    try {
      const payload = await api(
        `/api/automations/${encodeURIComponent(state.currentId)}/runs?limit=20`
      );
      renderRuns(payload.data || []);
      if (runHistoryLabel) {
        const current = state.automations.find(
          (item) => item.automation_id === state.currentId
        );
        runHistoryLabel.textContent = current?.name || 'Recent activity';
      }
    } catch (error) {
      if (runHistory) {
        runHistory.innerHTML = `<p class="studio-empty">${escapeHtml(error.message)}</p>`;
      }
    }

    state.runPollTimer = window.setTimeout(loadRuns, 10000);
  };

  const updateEnableButton = () => {
    if (!enableAutomationButton) return;

    if (!state.currentId) {
      enableAutomationButton.disabled = true;
      enableAutomationButton.textContent = 'Enable';
      return;
    }

    enableAutomationButton.disabled = false;
    enableAutomationButton.textContent = state.currentEnabled ? 'Disable' : 'Enable';
  };

  const newDraft = ({ confirmDiscard = true } = {}) => {
    if (confirmDiscard && state.dirty && !window.confirm('Discard unsaved automation changes?')) {
      return;
    }

    state.currentId = null;
    state.currentEnabled = false;
    state.dirty = false;
    state.nodes = [];
    state.edges = [];
    state.selectedNodeId = null;
    state.connectingFrom = null;

    if (automationName) automationName.value = '';
    if (timezoneInput) timezoneInput.value = getLocalTimezone();

    renderDevices();
    if (deviceSelect && state.devices.length) {
      deviceSelect.value = state.devices[0].device_id;
    }

    if (deleteAutomationButton) deleteAutomationButton.hidden = true;
    markSaved('NEW AUTOMATION');
    setMessage('Drag a trigger and an action onto the canvas.');
    renderAutomationList();
    renderCanvas();
    renderInspector();
    updateEnableButton();
    loadRuns();
  };

  const applyAutomation = (automation) => {
    state.currentId = automation.automation_id;
    state.currentEnabled = Boolean(automation.enabled);
    state.dirty = false;
    state.nodes = Array.isArray(automation.graph?.nodes)
      ? automation.graph.nodes.map((node) => ({
          ...node,
          config: { ...(node.config || {}) },
        }))
      : [];
    state.edges = Array.isArray(automation.graph?.edges)
      ? automation.graph.edges.map((edge) => ({ ...edge }))
      : [];
    state.selectedNodeId = null;
    state.connectingFrom = null;

    if (automationName) automationName.value = automation.name || '';
    if (timezoneInput) timezoneInput.value = automation.timezone || getLocalTimezone();
    renderDevices();
    if (deviceSelect) deviceSelect.value = automation.device_id || '';

    if (deleteAutomationButton) deleteAutomationButton.hidden = false;
    markSaved(state.currentEnabled ? 'ENABLED' : 'DISABLED');
    setMessage('');
    renderAutomationList();
    renderCanvas();
    renderInspector();
    updateEnableButton();
    loadRuns();
  };

  const loadAutomation = async (automationId) => {
    setMessage('Loading…');
    try {
      const payload = await api(`/api/automations/${encodeURIComponent(automationId)}`);
      applyAutomation(payload.data);
    } catch (error) {
      setMessage(error.message, 'error');
    }
  };

  const loadIndex = async () => {
    setMessage('Loading automations…');
    try {
      const payload = await api('/api/automations');
      state.automations = Array.isArray(payload.data) ? payload.data : [];
      state.devices = Array.isArray(payload.devices) ? payload.devices : [];
      renderDevices();
      renderAutomationList();

      if (!state.devices.length) {
        setMessage('Connect a FloraCore before creating an automation.', 'error');
      } else if (state.automations.length) {
        await loadAutomation(state.automations[0].automation_id);
      } else {
        newDraft({ confirmDiscard: false });
      }
    } catch (error) {
      setMessage(error.message, 'error');
    }
  };

  const saveAutomation = async () => {
    if (!deviceSelect?.value) {
      setMessage('Choose a connected FloraCore.', 'error');
      return;
    }

    const body = {
      name: automationName?.value || '',
      device_id: deviceSelect.value,
      timezone: timezoneInput?.value || getLocalTimezone(),
      graph: graphPayload(),
    };

    saveAutomationButton.disabled = true;
    setMessage('Validating and saving…');

    try {
      const payload = state.currentId
        ? await api(`/api/automations/${encodeURIComponent(state.currentId)}`, {
            method: 'PUT',
            body: JSON.stringify(body),
          })
        : await api('/api/automations', {
            method: 'POST',
            body: JSON.stringify(body),
          });

      const saved = payload.data;
      const index = state.automations.findIndex(
        (item) => item.automation_id === saved.automation_id
      );

      const summary = {
        automation_id: saved.automation_id,
        device_id: saved.device_id,
        name: saved.name,
        enabled: saved.enabled,
        timezone: saved.timezone,
        updated_at: saved.updated_at,
      };

      if (index >= 0) state.automations[index] = summary;
      else state.automations.unshift(summary);

      applyAutomation(saved);
      setMessage(
        'Saved. Edited automations are disabled until you review and enable them again.',
        'success'
      );
    } catch (error) {
      setMessage(error.message, 'error');
    } finally {
      saveAutomationButton.disabled = false;
    }
  };

  const deleteAutomation = async () => {
    if (!state.currentId) return;
    const current = state.automations.find(
      (item) => item.automation_id === state.currentId
    );
    if (!window.confirm(`Delete "${current?.name || 'this automation'}"?`)) return;

    try {
      await api(`/api/automations/${encodeURIComponent(state.currentId)}`, {
        method: 'DELETE',
      });
      state.automations = state.automations.filter(
        (item) => item.automation_id !== state.currentId
      );
      newDraft({ confirmDiscard: false });
      renderAutomationList();
      setMessage('Automation deleted.', 'success');
    } catch (error) {
      setMessage(error.message, 'error');
    }
  };

  const currentClock = () => {
    const now = new Date();
    return `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
  };

  const syncSimulationSource = () => {
    const custom = simulationSource?.value === 'custom';

    for (const input of [simulationSoil, simulationLight, simulationTime]) {
      if (input) input.disabled = !custom;
    }

    if (simulationSourceNote) {
      simulationSourceNote.textContent = custom
        ? 'Use hypothetical values. They are evaluated only inside this dry run.'
        : 'Reads the latest authenticated telemetry already stored by FloraOS. Nothing is sent to the device.';
    }
  };

  const openSimulation = () => {
    if (!deviceSelect?.value) {
      setMessage('Choose a connected FloraCore before testing this flow.', 'error');
      return;
    }

    if (simulationSource) simulationSource.value = 'latest';
    if (simulationTime) simulationTime.value = currentClock();
    if (simulationResult) simulationResult.hidden = true;
    syncSimulationSource();

    if (simulationModal) simulationModal.hidden = false;
  };

  const closeSimulation = () => {
    if (simulationModal) simulationModal.hidden = true;
  };

  const simulationStatusLabel = (status) => {
    if (status === 'passed') return 'PASS';
    if (status === 'failed') return 'STOP';
    return 'SKIP';
  };

  const renderSimulation = (data) => {
    if (!simulationResult) return;
    simulationResult.hidden = false;

    const outcome = String(data?.outcome || 'stopped');
    const action = data?.action || null;
    const delivery = data?.delivery || {};

    if (simulationOutcomeBadge) {
      simulationOutcomeBadge.className = '';
      if (outcome === 'would_execute') {
        simulationOutcomeBadge.textContent = 'WOULD RUN';
        simulationOutcomeBadge.classList.add('would-run');
      } else if (outcome === 'would_request_but_blocked') {
        simulationOutcomeBadge.textContent = 'LOGIC MATCHED';
        simulationOutcomeBadge.classList.add('blocked');
      } else {
        simulationOutcomeBadge.textContent = 'FLOW STOPS';
        simulationOutcomeBadge.classList.add('stopped');
      }
    }

    if (simulationOutcomeTitle) {
      if (outcome === 'would_execute') {
        simulationOutcomeTitle.textContent = action
          ? `Flow reaches: ${action.summary}`
          : 'Flow would execute';
      } else if (outcome === 'would_request_but_blocked') {
        simulationOutcomeTitle.textContent = 'Flow matches, but delivery is currently blocked';
      } else {
        simulationOutcomeTitle.textContent = 'The flow does not reach its action';
      }
    }

    if (simulationOutcomeText) {
      simulationOutcomeText.textContent =
        'Simulation only — no device command was queued.';
    }

    const soil = data?.inputs?.soil_percent;
    const light = data?.inputs?.light_lux;

    if (simulationSoilResult) {
      simulationSoilResult.textContent =
        soil === null || soil === undefined ? '—' : `${Number(soil).toFixed(0)}%`;
    }
    if (simulationLightResult) {
      simulationLightResult.textContent =
        light === null || light === undefined
          ? '—'
          : `${Number(light).toLocaleString()} lx`;
    }
    if (simulationTimeResult) {
      const local = String(data?.simulated_local_time || '—');
      const match = local.match(/\b(\d{2}:\d{2}):\d{2}\b/);
      simulationTimeResult.textContent = match?.[1] || local;
    }

    if (simulationActionPreview) {
      simulationActionPreview.hidden = !action;
    }
    if (simulationActionText) {
      simulationActionText.textContent = action?.summary || '—';
    }
    if (simulationDeliveryText) {
      if (!action) {
        simulationDeliveryText.textContent = 'Action was not reached.';
      } else if (delivery?.ready === true) {
        simulationDeliveryText.textContent =
          'Current device state: ready for this validated command.';
      } else if (delivery?.ready === false) {
        simulationDeliveryText.textContent =
          `Current device state: ${delivery.message || delivery.reason || 'blocked'}`;
      } else {
        simulationDeliveryText.textContent = 'Device delivery was not checked.';
      }
    }

    if (simulationSteps) {
      const steps = Array.isArray(data?.steps) ? data.steps : [];
      simulationSteps.innerHTML = steps
        .map((step, index) => `
          <div class="simulation-step ${escapeHtml(step.status)}">
            <span class="simulation-step-index">${String(index + 1).padStart(2, '0')}</span>
            <div>
              <b>${escapeHtml(step.label)}</b>
              <small>${escapeHtml(step.detail)}</small>
            </div>
            <em>${simulationStatusLabel(step.status)}</em>
          </div>
        `)
        .join('');
    }
  };

  const runSimulation = async () => {
    if (!deviceSelect?.value) {
      setMessage('Choose a connected FloraCore before testing this flow.', 'error');
      return;
    }

    const source = simulationSource?.value || 'latest';
    const body = {
      automation_id: state.currentId,
      device_id: deviceSelect.value,
      timezone: timezoneInput?.value || getLocalTimezone(),
      graph: graphPayload(),
      source,
      inputs: {},
    };

    if (source === 'custom') {
      body.inputs = {
        soil_percent:
          simulationSoil?.value === '' ? null : Number(simulationSoil?.value),
        light_lux:
          simulationLight?.value === '' ? null : Number(simulationLight?.value),
        local_time: simulationTime?.value || currentClock(),
      };
    }

    if (runSimulationButton) {
      runSimulationButton.disabled = true;
      runSimulationButton.textContent = 'Simulating…';
    }

    try {
      const payload = await api('/api/automations/simulate', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      renderSimulation(payload.data);
    } catch (error) {
      setMessage(error.message, 'error');
      if (simulationResult) simulationResult.hidden = true;
    } finally {
      if (runSimulationButton) {
        runSimulationButton.disabled = false;
        runSimulationButton.textContent = 'Run simulation';
      }
    }
  };

  const setEnabled = async (enabled, acknowledged = false) => {
    if (!state.currentId) return;

    try {
      const payload = await api(
        `/api/automations/${encodeURIComponent(state.currentId)}/enabled`,
        {
          method: 'POST',
          body: JSON.stringify({
            enabled,
            acknowledge_advanced_control: acknowledged,
          }),
        }
      );

      state.currentEnabled = Boolean(payload.data.enabled);
      const index = state.automations.findIndex(
        (item) => item.automation_id === state.currentId
      );
      if (index >= 0) state.automations[index].enabled = state.currentEnabled;

      markSaved(state.currentEnabled ? 'ENABLED' : 'DISABLED');
      renderAutomationList();
      updateEnableButton();
      setMessage(
        state.currentEnabled
          ? 'Automation enabled. FloraOS may now queue validated hardware actions when this flow matches.'
          : 'Automation disabled.',
        'success'
      );
    } catch (error) {
      setMessage(error.message, 'error');
    }
  };

  const arrangeNodes = () => {
    if (!state.nodes.length) return;

    // Follow existing edges if there is a clear start; otherwise sort by x.
    const incoming = new Set(state.edges.map((edge) => edge.to));
    let start = state.nodes.find((node) => !incoming.has(node.id));
    const next = new Map(state.edges.map((edge) => [edge.from, edge.to]));
    const ordered = [];
    const seen = new Set();

    while (start && !seen.has(start.id)) {
      ordered.push(start);
      seen.add(start.id);
      const nextId = next.get(start.id);
      start = nextId ? nodeById(nextId) : null;
    }

    state.nodes
      .filter((node) => !seen.has(node.id))
      .sort((a, b) => a.x - b.x)
      .forEach((node) => ordered.push(node));

    ordered.forEach((node, index) => {
      node.x = 70 + index * 230;
      node.y = 170 + (index % 2) * 80;
    });

    markDirty();
    renderCanvas();
  };

  const clearCanvas = () => {
    if (!state.nodes.length) return;
    if (!window.confirm('Remove every block from this automation?')) return;
    state.nodes = [];
    state.edges = [];
    state.selectedNodeId = null;
    state.connectingFrom = null;
    markDirty();
    renderCanvas();
    renderInspector();
  };

  // Palette drag/drop and click-to-add fallback.
  document.querySelectorAll('.palette-block[data-node-type]').forEach((button) => {
    button.addEventListener('dragstart', (event) => {
      event.dataTransfer?.setData('text/x-floracore-node', button.dataset.nodeType || '');
      if (event.dataTransfer) event.dataTransfer.effectAllowed = 'copy';
    });

    button.addEventListener('click', () => {
      const offset = state.nodes.length * 35;
      createNode(
        button.dataset.nodeType,
        90 + Math.min(offset, 360),
        100 + Math.min(offset, 260)
      );
    });
  });

  const ensureCanvasDeleteHint = () => {
    if (!automationCanvas) return null;

    let hint = automationCanvas.querySelector('.canvas-delete-hint');
    if (!hint) {
      hint = document.createElement('div');
      hint.className = 'canvas-delete-hint';
      hint.setAttribute('aria-hidden', 'true');
      hint.innerHTML = '<span>×</span><b>Release outside canvas to remove block</b>';
      automationCanvas.appendChild(hint);
    }
    return hint;
  };

  const setDeleteDragState = (armed, element = null) => {
    automationCanvas?.classList.toggle('is-delete-armed', armed);
    element?.classList.toggle('delete-armed', armed);

    const hint = ensureCanvasDeleteHint();
    if (hint) hint.classList.toggle('visible', armed);
  };

  automationCanvas?.addEventListener('dragover', (event) => {
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
  });

  automationCanvas?.addEventListener('drop', (event) => {
    event.preventDefault();
    const type = event.dataTransfer?.getData('text/x-floracore-node');
    if (!type) return;

    const rect = automationCanvas.getBoundingClientRect();
    const x = event.clientX - rect.left + automationCanvas.scrollLeft - 90;
    const y = event.clientY - rect.top + automationCanvas.scrollTop - 46;
    createNode(type, x, y);
  });

  automationCanvas?.addEventListener('click', (event) => {
    if (event.target === automationCanvas || event.target === edgeLayer) {
      state.selectedNodeId = null;
      state.connectingFrom = null;
      renderCanvas();
      renderInspector();
    }
  });

  deleteNodeButton?.addEventListener('click', () => {
    if (state.selectedNodeId) removeNode(state.selectedNodeId);
  });

  automationName?.addEventListener('input', markDirty);
  deviceSelect?.addEventListener('change', markDirty);
  timezoneInput?.addEventListener('input', markDirty);

  newAutomationButton?.addEventListener('click', () => newDraft());
  saveAutomationButton?.addEventListener('click', saveAutomation);
  simulateAutomationButton?.addEventListener('click', openSimulation);
  simulationSource?.addEventListener('change', syncSimulationSource);
  runSimulationButton?.addEventListener('click', runSimulation);
  closeSimulationButton?.addEventListener('click', closeSimulation);
  simulationModal?.addEventListener('click', (event) => {
    if (event.target === simulationModal) closeSimulation();
  });
  deleteAutomationButton?.addEventListener('click', deleteAutomation);
  fitCanvasButton?.addEventListener('click', arrangeNodes);
  clearCanvasButton?.addEventListener('click', clearCanvas);

  enableAutomationButton?.addEventListener('click', () => {
    if (!state.currentId) return;

    if (state.dirty) {
      setMessage('Save your changes before enabling this automation.', 'error');
      return;
    }

    if (state.currentEnabled) {
      setEnabled(false, false);
      return;
    }

    if (advancedConfirmCheckbox) advancedConfirmCheckbox.checked = false;
    if (confirmEnableButton) confirmEnableButton.disabled = true;
    if (advancedModal) advancedModal.hidden = false;
  });

  advancedConfirmCheckbox?.addEventListener('change', () => {
    if (confirmEnableButton) {
      confirmEnableButton.disabled = !advancedConfirmCheckbox.checked;
    }
  });

  cancelEnableButton?.addEventListener('click', () => {
    if (advancedModal) advancedModal.hidden = true;
  });

  confirmEnableButton?.addEventListener('click', async () => {
    if (!advancedConfirmCheckbox?.checked) return;
    confirmEnableButton.disabled = true;
    await setEnabled(true, true);
    if (advancedModal) advancedModal.hidden = true;
  });

  advancedModal?.addEventListener('click', (event) => {
    if (event.target === advancedModal) advancedModal.hidden = true;
  });

  window.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
      event.preventDefault();
      saveAutomation();
    }
    if (event.key === 'Escape') {
      state.connectingFrom = null;
      if (advancedModal) advancedModal.hidden = true;
      if (simulationModal) simulationModal.hidden = true;
      renderCanvas();
    }
    if (
      (event.key === 'Delete' || event.key === 'Backspace') &&
      state.selectedNodeId &&
      !event.target.closest('input, select, textarea')
    ) {
      event.preventDefault();
      removeNode(state.selectedNodeId);
    }
  });

  window.addEventListener('beforeunload', (event) => {
    if (!state.dirty) return;
    event.preventDefault();
  });

  loadIndex();
})();
