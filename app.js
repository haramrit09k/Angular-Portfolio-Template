'use strict';

/* =========================================================================
 * Util
 * ========================================================================= */

function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrs) { out.set(a, offset); offset += a.length; }
  return out;
}

function esc(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function todayKey() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function isoWeekKey(date = new Date()) {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(weekNo).padStart(2, '0')}`;
}

/* =========================================================================
 * Crypto — PIN verification + content decryption.
 * The SHA-256 hash below is a cheap fast-fail check only. The real gate is
 * the AES-GCM auth tag verified during decryptContent(): a wrong PIN derives
 * a wrong key, and GCM decryption throws rather than silently succeeding.
 * ========================================================================= */

const Crypto = (() => {
  async function sha256Hex(bytes) {
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  async function fastCheck(pin) {
    const salt = b64ToBytes(window.APP_CRYPTO.saltB64);
    const pinBytes = new TextEncoder().encode(pin);
    const hash = await sha256Hex(concatBytes(salt, pinBytes));
    return hash === window.APP_CRYPTO.pinHashHex;
  }

  async function deriveKey(pin) {
    const salt = b64ToBytes(window.APP_CRYPTO.saltB64);
    const pinBytes = new TextEncoder().encode(pin);
    const baseKey = await crypto.subtle.importKey('raw', pinBytes, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: window.APP_CRYPTO.iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      true, // extractable — needed so Settings can wrap this key for WebAuthn
      ['decrypt']
    );
  }

  async function decryptContent(key) {
    const iv = b64ToBytes(window.APP_CRYPTO.ivB64);
    const ciphertext = b64ToBytes(window.APP_CRYPTO.ciphertextB64);
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(plainBuf));
  }

  return { fastCheck, deriveKey, decryptContent };
})();

/* =========================================================================
 * Store — plain localStorage for operational/day-to-day state only.
 * Decrypted content and the PIN itself never touch storage (see AppState).
 * ========================================================================= */

const Store = (() => {
  const KEY = 'compass.v1.state';

  function defaultState() {
    return {
      todayAnchorOverride: null,
      dailyChecklist: {},
      weeklyReview: {},
      experiments: {},
      ui: { lastRoute: '/dashboard' }
    };
  }

  function load() {
    try {
      const raw = localStorage.getItem(KEY);
      if (!raw) return defaultState();
      const parsed = JSON.parse(raw);
      const base = defaultState();
      return Object.assign(base, parsed, { ui: Object.assign(base.ui, parsed.ui || {}) });
    } catch {
      return defaultState();
    }
  }

  function save() {
    localStorage.setItem(KEY, JSON.stringify(AppState.local));
  }

  return { load, save };
})();

/* =========================================================================
 * WebAuthn — optional, additive, per-device Face ID / Touch ID quick-unlock.
 * Never a replacement for the PIN: only offered after a real PIN unlock,
 * and only usable again on that same device/credential.
 * ========================================================================= */

const WebAuthn = (() => {
  const STORAGE_KEY = 'compass.v1.webauthn';
  const PRF_SALT = new TextEncoder().encode('compass-prf-v1');

  async function platformAuthenticatorAvailable() {
    if (!window.PublicKeyCredential || !PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) return false;
    try { return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); }
    catch { return false; }
  }

  function loadRecord() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null'); }
    catch { return null; }
  }
  function saveRecord(record) { localStorage.setItem(STORAGE_KEY, JSON.stringify(record)); }
  function clearRecord() { localStorage.removeItem(STORAGE_KEY); }
  function isEnrolled() { return !!loadRecord(); }
  function enrolledMode() { const r = loadRecord(); return r ? r.mode : null; }
  function randomBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }

  async function enroll(contentKey) {
    if (!(await platformAuthenticatorAvailable())) throw new Error('No platform authenticator available.');

    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: randomBytes(32),
        rp: { name: 'Compass' },
        user: { id: randomBytes(16), name: 'compass-user', displayName: 'Compass' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
        timeout: 60000,
        extensions: { prf: { eval: { first: PRF_SALT } } }
      }
    });
    if (!cred) throw new Error('Enrollment cancelled.');

    const credentialId = bytesToB64(new Uint8Array(cred.rawId));
    const rawKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', contentKey));
    const ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};

    if (ext && ext.prf && ext.prf.results && ext.prf.results.first) {
      const prfBytes = new Uint8Array(ext.prf.results.first);
      const wrapKey = await crypto.subtle.importKey('raw', prfBytes, 'AES-GCM', false, ['encrypt']);
      const wrapIv = randomBytes(12);
      const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wrapIv }, wrapKey, rawKeyBytes));
      saveRecord({ mode: 'prf', credentialId, wrapIvB64: bytesToB64(wrapIv), wrappedKeyB64: bytesToB64(wrapped) });
      return 'prf';
    }

    // Fallback: this browser/authenticator doesn't support the PRF extension.
    // Weaker guarantee — a successful assertion gates a locally-stored key,
    // rather than the assertion itself cryptographically unwrapping it.
    saveRecord({ mode: 'assertion-gate', credentialId, rawKeyB64: bytesToB64(rawKeyBytes) });
    return 'assertion-gate';
  }

  async function tryQuickUnlock() {
    const record = loadRecord();
    if (!record) return null;
    if (!(await platformAuthenticatorAvailable())) return null;

    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        allowCredentials: [{ id: b64ToBytes(record.credentialId), type: 'public-key' }],
        userVerification: 'required',
        extensions: record.mode === 'prf' ? { prf: { eval: { first: PRF_SALT } } } : undefined,
        timeout: 60000
      }
    });
    if (!assertion) return null;

    if (record.mode === 'prf') {
      const ext = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
      if (!ext || !ext.prf || !ext.prf.results || !ext.prf.results.first) return null;
      const prfBytes = new Uint8Array(ext.prf.results.first);
      const unwrapKey = await crypto.subtle.importKey('raw', prfBytes, 'AES-GCM', false, ['decrypt']);
      const rawKeyBytes = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBytes(record.wrapIvB64) }, unwrapKey, b64ToBytes(record.wrappedKeyB64)
      ));
      return crypto.subtle.importKey('raw', rawKeyBytes, 'AES-GCM', true, ['decrypt']);
    }

    const rawKeyBytes = b64ToBytes(record.rawKeyB64);
    return crypto.subtle.importKey('raw', rawKeyBytes, 'AES-GCM', true, ['decrypt']);
  }

  return { platformAuthenticatorAvailable, enroll, tryQuickUnlock, isEnrolled, enrolledMode, clearRecord };
})();

/* =========================================================================
 * WeeklyScore
 * ========================================================================= */

const WeeklyScore = {
  compute(metrics, entry) {
    if (!metrics || !metrics.length) return 0;
    let score = 0;
    for (const m of metrics) {
      const actual = (entry && entry[m.id]) || 0;
      const ratio = Math.min(actual / m.target, 1);
      score += m.weight * ratio;
    }
    return Math.round(score * 100);
  }
};

/* =========================================================================
 * AppState — in-memory only. `content` and `key` must never be written to
 * localStorage/sessionStorage: that would defeat the whole point of
 * encrypting the content at rest.
 * ========================================================================= */

const AppState = {
  content: null,
  key: null,
  local: null,
  webauthnAvailable: false
};

/* =========================================================================
 * Views
 * ========================================================================= */

const Views = {
  dashboard() {
    const c = AppState.content;
    const local = AppState.local;
    const today = todayKey();
    const anchorDone = !!(local.dailyChecklist[today] && local.dailyChecklist[today].anchorDone);
    const anchorText = local.todayAnchorOverride || c.dashboard.todaysAnchorDefault;
    const weekKey = isoWeekKey();
    const entry = local.weeklyReview[weekKey] || {};
    const score = WeeklyScore.compute(c.weeklyReview.metrics, entry);

    return `
      <section class="hero">
        <div>
          <p class="eyebrow">Current Mission</p>
          <h2>${esc(c.dashboard.currentMission)}</h2>
          <p>Dashboard for the week of ${esc(weekKey)}.</p>
        </div>
        <div class="emergency-card">
          <strong>Emergency line</strong>
          <p>${esc(c.dashboard.emergencyPrompt)}</p>
        </div>
      </section>

      <section class="grid">
        <article class="card">
          <h3>Today's Anchor</h3>
          <p>${esc(anchorText)}</p>
          <label class="anchor-check">
            <input type="checkbox" data-action="toggle-anchor" ${anchorDone ? 'checked' : ''} />
            <span>${anchorDone ? 'Done' : 'Mark done'}</span>
          </label>
        </article>
        <article class="card">
          <h3>Weekly Score</h3>
          <div class="score-gauge">
            <div class="score-ring" style="--pct:${score}"><span>${score}</span></div>
            <p>Based on this week's <a href="#/weekly-review">review</a>.</p>
          </div>
        </article>
        <article class="card">
          <h3>Quick Actions</h3>
          <p>Situational protocols, one tap away.</p>
          <a class="btn" href="#/quick-actions">Open</a>
        </article>
      </section>

      <section class="panel">
        <h3>Override today's anchor</h3>
        <textarea data-action="save-anchor" rows="2" placeholder="Leave blank to use the default anchor">${esc(local.todayAnchorOverride || '')}</textarea>
      </section>
    `;
  },

  quickActions() {
    const c = AppState.content;
    const tiles = c.quickActions.map((qa) => `
      <button type="button" class="quick-action-tile" data-action="go" data-href="/protocol/${qa.protocolId}">${esc(qa.label)}</button>
    `).join('');
    return `
      <a class="back-link" href="#/dashboard">&larr; Dashboard</a>
      <h2>Quick Actions</h2>
      <div class="quick-grid">${tiles}</div>
    `;
  },

  protocol(params) {
    const id = params[0];
    const c = AppState.content;
    const p = c.protocols.find((x) => x.id === id);
    if (!p) return `<a class="back-link" href="#/quick-actions">&larr; Quick Actions</a><p>Protocol not found.</p>`;
    const fields = [
      ['Situation', p.situation, false],
      ['Symptoms', p.symptoms, false],
      ['What NOT to do', p.whatNotToDo, true],
      ['Immediate response', p.immediateResponse, false],
      ['Next 30 minutes', p.next30Minutes, false],
      ['Tomorrow reset', p.tomorrowReset, false]
    ];
    return `
      <a class="back-link" href="#/quick-actions">&larr; Quick Actions</a>
      <h2>${esc(p.title)}</h2>
      <div class="protocol-fields">
        ${fields.map(([label, val, isDont]) => `
          <div class="protocol-field${isDont ? ' dont' : ''}">
            <h4>${esc(label)}</h4>
            <p>${esc(val)}</p>
          </div>
        `).join('')}
      </div>
    `;
  },

  knownBugs(params) {
    const c = AppState.content;
    const highlightId = params && params[0];
    const items = c.knownBugs.map((b) => `
      <details ${b.id === highlightId ? 'open' : ''}>
        <summary>${esc(b.title)}</summary>
        <p><strong>Symptom:</strong> ${esc(b.description)}</p>
        <p><strong>Patch:</strong> ${esc(b.notes)}</p>
      </details>
    `).join('');
    return `
      <a class="back-link" href="#/dashboard">&larr; Dashboard</a>
      <h2>Known Bugs</h2>
      <div class="bug-list">${items}</div>
    `;
  },

  decisionTrees() {
    const c = AppState.content;
    const cards = c.decisionTrees.map((t) => `
      <button type="button" class="tree-card" data-action="go" data-href="/decision-tree/${t.id}">
        <h3>${esc(t.title)}</h3>
        <p>Answer a few questions for a recommendation.</p>
      </button>
    `).join('');
    return `
      <a class="back-link" href="#/dashboard">&larr; Dashboard</a>
      <h2>Decision Trees</h2>
      <div class="tree-grid">${cards}</div>
    `;
  },

  decisionTree(params) {
    const [treeId, nodeId] = params;
    const c = AppState.content;
    const back = `<a class="back-link" href="#/decision-trees">&larr; Decision Trees</a>`;
    const tree = c.decisionTrees.find((t) => t.id === treeId);
    if (!tree) return `${back}<p>Not found.</p>`;
    const currentId = nodeId || tree.rootNodeId;
    const node = tree.nodes[currentId];
    if (!node) return `${back}<p>Not found.</p>`;

    if (node.recommendation) {
      return `
        ${back}
        <h2>${esc(tree.title)}</h2>
        <div class="panel tree-result">
          <h3>Recommendation</h3>
          <p>${esc(node.recommendation)}</p>
          <button type="button" class="btn tree-restart" data-action="go" data-scroll="false" data-href="/decision-tree/${tree.id}">Start over</button>
        </div>
      `;
    }

    return `
      ${back}
      <h2>${esc(tree.title)}</h2>
      <div class="panel">
        <p class="tree-question">${esc(node.question)}</p>
        <div class="tree-actions">
          <button type="button" data-action="go" data-scroll="false" data-href="/decision-tree/${tree.id}/${node.yes}">Yes</button>
          <button type="button" data-action="go" data-scroll="false" data-href="/decision-tree/${tree.id}/${node.no}">No</button>
        </div>
      </div>
    `;
  },

  weeklyReview() {
    const c = AppState.content;
    const local = AppState.local;
    const weekKey = isoWeekKey();
    const entry = local.weeklyReview[weekKey] || {};
    const score = WeeklyScore.compute(c.weeklyReview.metrics, entry);

    const rows = c.weeklyReview.metrics.map((m) => {
      const val = entry[m.id] || 0;
      return `
        <div class="review-metric">
          <label><span>${esc(m.label)}</span><span>${val} / ${m.target}</span></label>
          <input type="range" min="0" max="${m.target}" step="1" value="${val}"
                 data-action="set-metric" data-metric="${m.id}" />
        </div>
      `;
    }).join('');

    return `
      <a class="back-link" href="#/dashboard">&larr; Dashboard</a>
      <h2>Weekly Review — ${esc(weekKey)}</h2>
      <div class="score-gauge" style="margin-bottom:24px;">
        <div class="score-ring" style="--pct:${score}"><span>${score}</span></div>
        <p>Weekly Score</p>
      </div>
      <div class="review-form panel">${rows}</div>
    `;
  },

  experiments() {
    const c = AppState.content;
    const cards = c.experiments.map((ex) => {
      const local = AppState.local.experiments[ex.id];
      const started = !!local;
      const doneCount = started ? Object.values(local.days || {}).filter((d) => d.done).length : 0;
      return `
        <button type="button" class="tree-card" data-action="go" data-href="/experiment/${ex.id}">
          <h3>${esc(ex.title)}</h3>
          <p>${started ? `${doneCount} / ${ex.durationDays} days` : 'Not started'}</p>
        </button>
      `;
    }).join('');
    return `
      <a class="back-link" href="#/dashboard">&larr; Dashboard</a>
      <h2>Experiments</h2>
      <p>Rules only graduate into the Playbook after surviving real life.</p>
      <div class="tree-grid">${cards}</div>
    `;
  },

  experiment(params) {
    const id = params[0];
    const c = AppState.content;
    const back = `<a class="back-link" href="#/experiments">&larr; Experiments</a>`;
    const ex = c.experiments.find((x) => x.id === id);
    if (!ex) return `${back}<p>Not found.</p>`;
    const local = AppState.local.experiments[id];

    if (!local) {
      return `
        ${back}
        <h2>${esc(ex.title)}</h2>
        <p>${esc(ex.description)}</p>
        <button type="button" class="btn" data-action="start-experiment" data-experiment="${id}">Start ${ex.durationDays}-day run</button>
      `;
    }

    const cells = [];
    for (let i = 1; i <= ex.durationDays; i++) {
      const done = !!(local.days[i] && local.days[i].done);
      cells.push(`<button type="button" class="day-cell${done ? ' done' : ''}" data-action="toggle-day" data-experiment="${id}" data-day="${i}">${i}</button>`);
    }

    return `
      ${back}
      <h2>${esc(ex.title)}</h2>
      <p>${esc(ex.description)}</p>
      <p class="eyebrow">Started ${esc(local.startedAt)}</p>
      <div class="experiment-day-grid">${cells.join('')}</div>
      <div class="experiment panel">
        <h3>Notes</h3>
        <textarea data-action="save-experiment-note" data-experiment="${id}" placeholder="What did you notice?">${esc(local.note || '')}</textarea>
      </div>
    `;
  },

  settings() {
    const enrolled = WebAuthn.isEnrolled();
    const mode = WebAuthn.enrolledMode();
    const showBiometric = enrolled || AppState.webauthnAvailable;

    return `
      <a class="back-link" href="#/dashboard">&larr; Dashboard</a>
      <h2>Settings</h2>

      ${showBiometric ? `
        <div class="settings-block">
          <h3>Face ID / Touch ID</h3>
          <p>Status: <span class="pill ${enrolled ? 'on' : 'off'}">${enrolled ? 'Enabled — ' + esc(mode) : 'Not enabled'}</span></p>
          <p>Per-device convenience only. A device that has never unlocked with your real PIN can never use this to get in.</p>
          ${enrolled
            ? `<button type="button" class="btn danger" data-action="disable-biometric">Disable on this device</button>`
            : `<button type="button" class="btn" data-action="enable-biometric">Enable on this device</button>`}
          ${mode === 'assertion-gate' ? `<p style="color:var(--warn); margin-top:10px; font-size:13px;">This device doesn't support the WebAuthn PRF extension, so this mode gates a locally-stored key rather than truly wrapping it — a weaker guarantee than the PIN.</p>` : ''}
        </div>
      ` : ''}

      <div class="settings-block">
        <h3>PIN &amp; content</h3>
        <p>The PIN is fixed at build time and shared across every device — there's no in-app way to change it. To rotate the PIN or edit the playbook content, edit <code>scripts/content.json</code> locally and re-run <code>node scripts/build-content.js</code>, then redeploy. See README.md.</p>
      </div>

      <div class="settings-block">
        <h3>Principles</h3>
        <ul class="principles">
          ${AppState.content.principles.map((p) => `<li>${esc(p)}</li>`).join('')}
        </ul>
      </div>

      <div class="settings-block">
        <button type="button" class="btn" data-action="lock-now">Lock now</button>
      </div>
    `;
  }
};

/* =========================================================================
 * Router — hash-based SPA router with a single delegated event listener
 * for all in-app interactions.
 * ========================================================================= */

const Router = (() => {
  const outlet = document.getElementById('view-outlet');
  let started = false;

  const routes = [
    { pattern: /^\/dashboard$/, view: Views.dashboard },
    { pattern: /^\/quick-actions$/, view: Views.quickActions },
    { pattern: /^\/protocol\/([\w-]+)$/, view: Views.protocol },
    { pattern: /^\/known-bugs$/, view: Views.knownBugs },
    { pattern: /^\/known-bugs\/([\w-]+)$/, view: Views.knownBugs },
    { pattern: /^\/decision-trees$/, view: Views.decisionTrees },
    { pattern: /^\/decision-tree\/([\w-]+)$/, view: Views.decisionTree },
    { pattern: /^\/decision-tree\/([\w-]+)\/([\w-]+)$/, view: Views.decisionTree },
    { pattern: /^\/weekly-review$/, view: Views.weeklyReview },
    { pattern: /^\/experiments$/, view: Views.experiments },
    { pattern: /^\/experiment\/([\w-]+)$/, view: Views.experiment },
    { pattern: /^\/settings$/, view: Views.settings }
  ];

  function currentPath() {
    const hash = location.hash || '#/dashboard';
    return hash.slice(1) || '/dashboard';
  }

  // Re-renders the current route's view in place — used both for real
  // navigation and for in-place updates (a checkbox toggle, a slider
  // change) that redraw the same view without actually navigating.
  function renderView() {
    const path = currentPath();
    AppState.local.ui.lastRoute = path;
    Store.save();
    updateActiveNav(path);

    for (const route of routes) {
      const match = path.match(route.pattern);
      if (match) {
        outlet.innerHTML = route.view(match.slice(1));
        return;
      }
    }
    outlet.innerHTML = Views.dashboard();
  }

  // Only real navigation (hashchange, initial load) should reset scroll
  // position — in-place updates must not, or every interaction yanks the
  // page back to the top.
  function render() {
    renderView();
    window.scrollTo(0, 0);
  }

  function updateActiveNav(path) {
    const top = '/' + path.split('/')[1];
    document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === top));
  }

  function initOutletEvents() {
    outlet.addEventListener('click', async (e) => {
      const el = e.target.closest('[data-action]');
      if (!el) return;
      const action = el.dataset.action;

      if (action === 'go') {
        const href = '#' + el.dataset.href;
        if (el.dataset.scroll === 'false') {
          // Steps within the same continuous interaction (a decision tree's
          // Yes/No/Start over) — update the URL without the scroll-to-top
          // that a real hashchange-driven navigation gets. pushState alone
          // doesn't fire 'hashchange', so we re-render manually.
          history.pushState(null, '', href);
          renderView();
        } else {
          location.hash = href;
        }
        return;
      }
      if (action === 'toggle-day') {
        const rec = AppState.local.experiments[el.dataset.experiment];
        if (!rec) return;
        const day = el.dataset.day;
        rec.days[day] = rec.days[day] || {};
        rec.days[day].done = !rec.days[day].done;
        Store.save();
        renderView();
        return;
      }
      if (action === 'start-experiment') {
        AppState.local.experiments[el.dataset.experiment] = { startedAt: todayKey(), days: {}, note: '' };
        Store.save();
        renderView();
        return;
      }
      if (action === 'enable-biometric') {
        try {
          await WebAuthn.enroll(AppState.key);
        } catch (err) {
          alert('Could not enable Face ID / Touch ID: ' + err.message);
        }
        renderView();
        return;
      }
      if (action === 'disable-biometric') {
        WebAuthn.clearRecord();
        renderView();
        return;
      }
      if (action === 'lock-now') {
        App.lockNow();
      }
    });

    outlet.addEventListener('change', (e) => {
      const el = e.target.closest('[data-action]');
      if (!el) return;
      if (el.dataset.action === 'toggle-anchor') {
        const today = todayKey();
        AppState.local.dailyChecklist[today] = AppState.local.dailyChecklist[today] || {};
        AppState.local.dailyChecklist[today].anchorDone = el.checked;
        Store.save();
        renderView();
      }
      if (el.dataset.action === 'set-metric') {
        const weekKey = isoWeekKey();
        AppState.local.weeklyReview[weekKey] = AppState.local.weeklyReview[weekKey] || {};
        AppState.local.weeklyReview[weekKey][el.dataset.metric] = Number(el.value);
        Store.save();
        renderView();
      }
    });

    outlet.addEventListener('input', (e) => {
      const el = e.target.closest('[data-action]');
      if (!el) return;
      if (el.dataset.action === 'save-anchor') {
        const val = el.value.trim();
        AppState.local.todayAnchorOverride = val || null;
        Store.save();
      }
      if (el.dataset.action === 'save-experiment-note') {
        const rec = AppState.local.experiments[el.dataset.experiment];
        if (rec) { rec.note = el.value; Store.save(); }
      }
    });

    outlet.addEventListener('focusout', (e) => {
      const el = e.target.closest('[data-action="save-anchor"]');
      if (el) renderView();
    });
  }

  function start() {
    if (!started) {
      window.addEventListener('hashchange', render);
      initOutletEvents();
      started = true;
    }
    if (!location.hash) location.hash = '#' + (AppState.local.ui.lastRoute || '/dashboard');
    render();
  }

  return { start, render };
})();

/* =========================================================================
 * App — lock screen controller + unlock orchestration.
 * ========================================================================= */

const App = (() => {
  const lockScreen = document.getElementById('lock-screen');
  const lockCard = lockScreen.querySelector('.lock-card');
  const appRoot = document.getElementById('app-root');
  const pinDotsEl = document.getElementById('pin-dots');
  const lockErrorEl = document.getElementById('lock-error');
  const keypadEl = document.getElementById('keypad');
  const biometricKeyEl = document.getElementById('biometric-key');
  const lockTriggerEl = document.getElementById('lock-trigger');
  const sidebarEl = document.querySelector('.sidebar');
  const navEl = document.getElementById('nav');
  const navBackdropEl = document.getElementById('nav-backdrop');
  const navToggleEl = document.getElementById('nav-toggle');
  const quickLockEl = document.getElementById('quick-lock');

  let enteredPin = '';
  let busy = false;

  function renderDots() {
    const len = window.APP_CRYPTO.pinLength;
    pinDotsEl.innerHTML = '';
    for (let i = 0; i < len; i++) {
      const d = document.createElement('span');
      d.className = 'dot' + (i < enteredPin.length ? ' filled' : '');
      pinDotsEl.appendChild(d);
    }
  }

  function resetPin(message) {
    enteredPin = '';
    renderDots();
    if (message) showError(message); else clearError();
  }

  function showError(msg) {
    lockErrorEl.textContent = msg;
    lockCard.classList.remove('shake');
    void lockCard.offsetWidth;
    lockCard.classList.add('shake');
  }
  function clearError() { lockErrorEl.textContent = ''; }

  async function attemptPinUnlock(pin) {
    if (busy) return;
    busy = true;
    clearError();
    try {
      const fastOk = await Crypto.fastCheck(pin);
      if (!fastOk) { resetPin('Wrong PIN.'); return; }
      const key = await Crypto.deriveKey(pin);
      const content = await Crypto.decryptContent(key);
      await completeUnlock(content, key);
    } catch (e) {
      resetPin('Wrong PIN.');
    } finally {
      busy = false;
    }
  }

  async function tryBiometricUnlock() {
    if (busy) return;
    busy = true;
    clearError();
    try {
      const key = await WebAuthn.tryQuickUnlock();
      if (!key) { showError('Face ID / Touch ID unavailable.'); return; }
      const content = await Crypto.decryptContent(key);
      await completeUnlock(content, key);
    } catch (e) {
      showError('Face ID / Touch ID failed. Use your PIN.');
    } finally {
      busy = false;
    }
  }

  async function completeUnlock(content, key) {
    AppState.content = content;
    AppState.key = key;
    AppState.local = Store.load();
    AppState.webauthnAvailable = await WebAuthn.platformAuthenticatorAvailable();
    lockScreen.hidden = true;
    appRoot.hidden = false;
    Router.start();
  }

  function lockNow() {
    AppState.content = null;
    AppState.key = null;
    enteredPin = '';
    appRoot.hidden = true;
    lockScreen.hidden = false;
    renderDots();
    clearError();
    refreshBiometricKeyVisibility();
  }

  async function refreshBiometricKeyVisibility() {
    const avail = WebAuthn.isEnrolled() && await WebAuthn.platformAuthenticatorAvailable();
    biometricKeyEl.hidden = !avail;
  }

  // Mobile nav drawer — the sidebar becomes a slide-in overlay under 900px
  // (see styles.css), toggled by the fixed hamburger button so switching
  // tabs never requires scrolling back up to reach the nav.
  function openDrawer() {
    sidebarEl.classList.add('mobile-open');
    navBackdropEl.classList.add('visible');
    navToggleEl.setAttribute('aria-expanded', 'true');
  }
  function closeDrawer() {
    sidebarEl.classList.remove('mobile-open');
    navBackdropEl.classList.remove('visible');
    navToggleEl.setAttribute('aria-expanded', 'false');
  }
  navToggleEl.addEventListener('click', () => {
    sidebarEl.classList.contains('mobile-open') ? closeDrawer() : openDrawer();
  });
  navBackdropEl.addEventListener('click', closeDrawer);
  navEl.addEventListener('click', (e) => { if (e.target.closest('a')) closeDrawer(); });
  quickLockEl.addEventListener('click', lockNow);

  keypadEl.addEventListener('click', (e) => {
    const btn = e.target.closest('.key');
    if (!btn) return;
    if (btn.dataset.action === 'backspace') {
      enteredPin = enteredPin.slice(0, -1);
      renderDots();
      return;
    }
    if (btn.dataset.action === 'biometric') {
      tryBiometricUnlock();
      return;
    }
    if (busy) return;
    const digit = btn.dataset.digit;
    if (digit === undefined) return;
    if (enteredPin.length >= window.APP_CRYPTO.pinLength) return;
    enteredPin += digit;
    renderDots();
    if (enteredPin.length === window.APP_CRYPTO.pinLength) {
      attemptPinUnlock(enteredPin);
    }
  });

  document.addEventListener('keydown', (e) => {
    if (lockScreen.hidden) return;
    if (/^[0-9]$/.test(e.key)) {
      const btn = keypadEl.querySelector(`[data-digit="${e.key}"]`);
      if (btn) btn.click();
    }
    if (e.key === 'Backspace') keypadEl.querySelector('[data-action="backspace"]').click();
  });

  lockTriggerEl.addEventListener('click', lockNow);

  function init() {
    renderDots();
    refreshBiometricKeyVisibility();
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('sw.js').catch(() => {});
    }
  }

  return { init, lockNow };
})();

document.addEventListener('DOMContentLoaded', () => App.init());
