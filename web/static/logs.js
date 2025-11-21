const logState = {
  authToken: null,
  events: [],
  users: [],
};

function fmtDate(value) {
  if (!value) return '—';
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return '—';
  return dt.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function ensureAuth() {
  const token = sessionStorage.getItem('taAuth');
  if (token) {
    logState.authToken = token;
    return true;
  }
  document.getElementById('authOverlay').classList.remove('hidden');
  document.getElementById('authLogin').focus();
  return false;
}

async function apiFetch(path, options = {}) {
  if (!logState.authToken) throw new Error('no auth');
  const headers = Object.assign({}, options.headers || {}, {
    Authorization: 'Basic ' + logState.authToken,
  });
  if (options.body && !(options.body instanceof FormData)) {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  }
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    document.getElementById('authOverlay').classList.remove('hidden');
    throw new Error('unauthorized');
  }
  if (response.headers.get('content-type')?.includes('application/json')) {
    const json = await response.json();
    if (!response.ok) throw new Error(json.detail || response.statusText);
    return json;
  }
  if (!response.ok) throw new Error(response.statusText || 'Request failed');
  return response;
}

function badgeClass(type) {
  switch (type) {
    case 'capture_started':
      return 'event-blue';
    case 'capture_stopped':
      return 'event-red';
    case 'sniffer_started':
    case 'nfstream_started':
    case 'scapy_started':
      return 'event-green';
    case 'flow_emitted':
      return 'event-purple';
    case 'data_load':
      return 'event-yellow';
    case 'analysis':
      return 'event-orange';
    default:
      return 'event-blue';
  }
}

function translateKey(key) {
  const mapping = {
    bytes: 'Байты',
    packets: 'Пакеты',
    src: 'Источник',
    dst: 'Назначение',
    proto: 'Протокол',
    score: 'Оценка',
    label: 'Метка',
  };
  return mapping[key] || key;
}

function shorten(value) {
  if (value === undefined || value === null) return '';
  const str = String(value);
  if (str.length > 10) return `${str.slice(0, 10)}…`;
  return str;
}

function payloadSummary(payload) {
  if (!payload || typeof payload !== 'object') return '—';
  const keys = ['src', 'dst', 'proto', 'bytes', 'packets', 'label', 'score'];
  const parts = [];
  keys.forEach((k) => {
    if (payload[k] !== undefined && payload[k] !== null) {
      parts.push(`${translateKey(k)}: ${payload[k]}`);
    }
  });
  if (parts.length) return parts.join(' · ');
  const asString = JSON.stringify(payload);
  return asString.length > 120 ? `${asString.slice(0, 120)}…` : asString;
}

function renderDetails(payload) {
  const wrapper = document.createElement('div');
  wrapper.className = 'details-card';
  const grid = document.createElement('div');
  grid.className = 'details-kv';
  if (payload && typeof payload === 'object') {
    Object.entries(payload).forEach(([k, v]) => {
      const item = document.createElement('div');
      item.innerHTML = `<span>${translateKey(k)}:</span> ${shorten(v)}`;
      grid.appendChild(item);
    });
  } else {
    const item = document.createElement('div');
    item.textContent = '—';
    grid.appendChild(item);
  }
  wrapper.appendChild(grid);
  return wrapper;
}

async function loadUsers() {
  try {
    const data = await apiFetch('/api/logs/users');
    logState.users = data.items || [];
    const select = document.getElementById('userFilter');
    logState.users.forEach((u) => {
      const opt = document.createElement('option');
      opt.value = u;
      opt.textContent = u;
      select.appendChild(opt);
    });
  } catch (err) {
    console.warn('Failed to load users', err);
  }
}

function buildQuery() {
  const params = new URLSearchParams();
  const dateFrom = document.getElementById('dateFrom').value;
  const dateTo = document.getElementById('dateTo').value;
  const user = document.getElementById('userFilter').value;
  const type = document.getElementById('typeFilter').value;
  const search = document.getElementById('searchField').value;
  if (dateFrom) params.append('date_from', dateFrom);
  if (dateTo) params.append('date_to', dateTo);
  if (user) params.append('user', user);
  if (type) params.append('event_type', type);
  if (search) params.append('search', search);
  params.append('limit', '400');
  return params.toString();
}

async function loadEvents() {
  try {
    const query = buildQuery();
    const data = await apiFetch(`/api/logs/full?${query}`);
    logState.events = data.items || [];
    renderEvents();
  } catch (err) {
    console.error('Failed to load events', err);
  }
}

function renderEvents() {
  const body = document.getElementById('logsTableBody');
  if (!body) return;
  body.innerHTML = '';

  logState.events.forEach((event) => {
    const row = document.createElement('tr');
    row.className = 'logs-row';

    const timeTd = document.createElement('td');
    timeTd.textContent = fmtDate(event.time);
    row.appendChild(timeTd);

    const userTd = document.createElement('td');
    userTd.textContent = event.user || '—';
    row.appendChild(userTd);

    const typeTd = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `event-badge ${badgeClass(event.type)}`;
    badge.textContent = event.type || '—';
    typeTd.appendChild(badge);
    row.appendChild(typeTd);

    const descTd = document.createElement('td');
    descTd.textContent = payloadSummary(event.payload);
    row.appendChild(descTd);

    const actionTd = document.createElement('td');
    const btn = document.createElement('button');
    btn.className = 'details-btn';
    btn.type = 'button';
    btn.textContent = 'Подробнее';
    btn.addEventListener('click', () => {
      detailsRow.classList.toggle('hidden');
    });
    actionTd.appendChild(btn);
    row.appendChild(actionTd);

    const detailsRow = document.createElement('tr');
    detailsRow.className = 'hidden';
    const detailsTd = document.createElement('td');
    detailsTd.colSpan = 5;
    detailsTd.appendChild(renderDetails(event.payload));
    detailsRow.appendChild(detailsTd);

    body.appendChild(row);
    body.appendChild(detailsRow);
  });
}

async function loadSessionDetails(sessionId) {
  try {
    const data = await apiFetch(`/api/logs/session/${sessionId}`);
    renderSessionInfo(data.session);
    renderSessionActions(data.actions);
    renderSessionFlows(data.flows);
  } catch (err) {
    console.error('Failed to load session', err);
  }
}

function renderSessionInfo(session) {
  const container = document.getElementById('sessionInfo');
  if (!container || !session) return;
  const durationMs = session.finished_at && session.started_at
    ? new Date(session.finished_at).getTime() - new Date(session.started_at).getTime()
    : null;
  const durationSec = durationMs ? Math.max(0, durationMs / 1000).toFixed(1) : '—';
  const details = session.details || {};
  container.innerHTML = `
    <div class="session-grid">
      <div class="session-card"><h4>Начало</h4><div class="value">${fmtDate(session.started_at)}</div></div>
      <div class="session-card"><h4>Окончание</h4><div class="value">${fmtDate(session.finished_at)}</div></div>
      <div class="session-card"><h4>Длительность</h4><div class="value">${durationSec} с</div></div>
      <div class="session-card"><h4>Результат</h4><div class="value">${session.result || '—'}</div></div>
      <div class="session-card"><h4>Потоков обработано</h4><div class="value">${details.flows_processed ?? '—'}</div></div>
      <div class="session-card"><h4>Обнаружено атак</h4><div class="value">${details.attacks_detected ?? '—'}</div></div>
      <div class="session-card"><h4>Байты</h4><div class="value">${details.total_bytes ?? '—'}</div></div>
      <div class="session-card"><h4>Пакеты</h4><div class="value">${details.total_packets ?? '—'}</div></div>
    </div>
  `;
}

function renderSessionActions(actions) {
  const body = document.getElementById('sessionActions');
  if (!body) return;
  body.innerHTML = '';
  actions.forEach((a) => {
    const row = document.createElement('tr');
    row.className = 'logs-row';
    const time = document.createElement('td');
    time.textContent = fmtDate(a.created_at);
    const type = document.createElement('td');
    type.innerHTML = `<span class="event-badge ${badgeClass(a.name)}">${a.name}</span>`;
    const desc = document.createElement('td');
    desc.textContent = payloadSummary(a.payload);
    row.appendChild(time);
    row.appendChild(type);
    row.appendChild(desc);
    body.appendChild(row);
  });
}

function renderSessionFlows(flows) {
  const body = document.getElementById('sessionFlows');
  if (!body) return;
  body.innerHTML = '';
  flows.forEach((f) => {
    const row = document.createElement('tr');
    const time = document.createElement('td');
    time.textContent = fmtDate(f.ts);
    const route = document.createElement('td');
    route.textContent = `${f.src} → ${f.dst}`;
    const bytes = document.createElement('td');
    bytes.textContent = f.bytes ?? '—';
    const packets = document.createElement('td');
    packets.textContent = f.packets ?? '—';
    const proto = document.createElement('td');
    proto.textContent = f.proto ?? '—';
    const label = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge-label';
    badge.textContent = f.label || '—';
    label.appendChild(badge);
    row.appendChild(time);
    row.appendChild(route);
    row.appendChild(bytes);
    row.appendChild(packets);
    row.appendChild(proto);
    row.appendChild(label);
    body.appendChild(row);
  });
}

function bindAuthForm() {
  const form = document.getElementById('authForm');
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const login = document.getElementById('authLogin').value;
    const pass = document.getElementById('authPassword').value;
    const token = btoa(`${login}:${pass}`);
    logState.authToken = token;
    sessionStorage.setItem('taAuth', token);
    try {
      await apiFetch('/health');
      document.getElementById('authOverlay').classList.add('hidden');
      initPage();
    } catch (err) {
      console.error('Auth failed', err);
    }
  });
}

function bindFilters() {
  const apply = document.getElementById('applyFilters');
  const reset = document.getElementById('resetFilters');
  if (apply) apply.addEventListener('click', loadEvents);
  if (reset)
    reset.addEventListener('click', () => {
      const dateFrom = document.getElementById('dateFrom');
      const dateTo = document.getElementById('dateTo');
      const user = document.getElementById('userFilter');
      const type = document.getElementById('typeFilter');
      const search = document.getElementById('searchField');
      if (dateFrom) dateFrom.value = '';
      if (dateTo) dateTo.value = '';
      if (user) user.value = '';
      if (type) type.value = '';
      if (search) search.value = '';
      loadEvents();
    });
}

async function initPage() {
  const page = document.body.dataset.page;
  if (!logState.authToken && !ensureAuth()) return;

  if (page === 'logs') {
    await loadUsers();
    await loadEvents();
    bindFilters();
  } else if (page === 'session') {
    const id = document.body.dataset.sessionId;
    bindFilters();
    await loadSessionDetails(id);
  }
}

window.addEventListener('DOMContentLoaded', () => {
  bindAuthForm();
  if (sessionStorage.getItem('taAuth')) {
    logState.authToken = sessionStorage.getItem('taAuth');
    initPage();
  } else {
    ensureAuth();
  }
});
