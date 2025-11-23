const logState = {
  authToken: null,
  events: [],
  users: [],
};

const featureTranslations = {
  model: 'Модель',
  task: 'Задача',
  attack: 'Атака',
  vpn: 'VPN',
  anomaly: 'Аномалия',
  confidence: 'Уверенность',
  score: 'Счёт',
  summary: 'Сводка',
  jsd: 'JSD (расхождение распределений)',
  z_score: 'Z-оценка дрейфа',
  drift: 'Дрейф',
  fwd_packet_length_max: 'макс. длина прямых пакетов',
  fwd_packet_length_min: 'мин. длина прямых пакетов',
  fwd_packet_length_mean: 'средняя длина прямых пакетов',
  fwd_packet_length_std: 'СКО длины прямых пакетов',
  bwd_packet_length_max: 'макс. длина обратных пакетов',
  bwd_packet_length_min: 'мин. длина обратных пакетов',
  bwd_packet_length_mean: 'средняя длина обратных пакетов',
  bwd_packet_length_std: 'СКО длины обратных пакетов',
  flow_duration: 'длительность потока (мс)',

  flow_iat_mean: 'средний интервал между пакетами',
  flow_iat_std: 'СКО интервалов между пакетами',
  fwd_iat_total: 'сумма интервалов прямых пакетов',
  bwd_iat_total: 'сумма интервалов обратных пакетов',
  packet_length_mean: 'средняя длина пакетов',
  packet_length_std: 'СКО длины пакетов',
  flow_packets_per_second: 'пакетов в секунду',
  flow_bytes_per_second: 'байтов в секунду',
  fwd_packets_s: 'прямых пакетов в секунду',
  bwd_packets_s: 'обратных пакетов в секунду',
  fwd_bytes_b_avg: 'средний объём прямых байт',
  bwd_bytes_b_avg: 'средний объём обратных байт',
  init_win_bytes_forward: 'начальный размер окна (вперёд)',
  init_win_bytes_backward: 'начальный размер окна (назад)',
  active_mean: 'средняя активность',
  idle_mean: 'средний простой',
  min_seg_size_forward: 'минимальный размер сегмента (вперёд)',
  avg_pkt_size: 'средний размер пакета',
  avg_fwd_segment_size: 'средний размер сегмента вперёд',
  avg_bwd_segment_size: 'средний размер сегмента назад',
  max_active: 'макс. активность',
  min_active: 'мин. активность',
  max_idle: 'макс. простой',
  min_idle: 'мин. простой',
  urgent_pkts_total: 'число срочных пакетов',
  flow_fin_flags_cnt: 'количество FIN флагов',
  flow_syn_flags_cnt: 'количество SYN флагов',
  flow_rst_flags_cnt: 'количество RST флагов',
  flow_psh_flags_cnt: 'количество PSH флагов',
  flow_ack_flags_cnt: 'количество ACK флагов',
  flow_urg_flags_cnt: 'количество URG флагов',
  flow_cwe_flags_cnt: 'количество CWE флагов',
  flow_ece_flags_cnt: 'количество ECE флагов',
  destination_port_entropy: 'энтропия порта назначения',
  tls_sni: 'TLS SNI',
  http_host: 'HTTP хост',
  dns_query: 'DNS запрос',
  app: 'Приложение',
  model_task: 'Задача модели',
  model_version: 'Версия модели',
  label: 'Метка',
  label_name: 'Имя метки',
  confidence: 'Уверенность',
  summary: 'Сводка',

};

function translateFeatureKey(key) {
  if (!key) return '';
  if (featureTranslations[key] !== undefined) return featureTranslations[key];
  return key.replace(/_/g, ' ').replace(/\b([a-zа-яё])/gi, (m) => m.toUpperCase());
}

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

function roundDisplayNumber(value) {
  if (value === null || value === undefined) return value;
  const num = Number(value);
  if (!Number.isFinite(num)) return 0;
  const abs = Math.abs(num);
  const digits = abs >= 100 ? 0 : abs >= 1 ? 2 : 3;
  return Number(num.toFixed(digits));
}

function truncateString(value, maxLen = 60) {
  if (typeof value !== 'string') return value;
  return value.length > maxLen ? `${value.slice(0, maxLen - 1)}…` : value;
}

function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sanitizeJsonValue(value, { truncateStrings = false } = {}) {
  if (value === undefined) return '—';
  if (value === null) return null;
  if (typeof value === 'number') return roundDisplayNumber(value);
  if (typeof value === 'string') return truncateStrings ? truncateString(value) : value;
  if (typeof value === 'boolean') return value;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map((item) => sanitizeJsonValue(item, { truncateStrings }));
  if (typeof value === 'object') {
    const normalized = {};
    Object.entries(value).forEach(([k, v]) => {
      normalized[k] = sanitizeJsonValue(v, { truncateStrings });
    });
    return normalized;
  }
  return String(value);
}

function localizeKeys(obj) {
  if (Array.isArray(obj)) return obj.map((item) => localizeKeys(item));
  if (obj && typeof obj === 'object') {
    const normalized = {};
    Object.entries(obj).forEach(([k, v]) => {
      normalized[translateFeatureKey(k)] = localizeKeys(v);
    });
    return normalized;
  }
  return obj;
}

function formatInlineValue(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return value.toString();
  if (typeof value === 'string') return truncateString(value);
  const json = JSON.stringify(value);
  return truncateString(json);
}

function formatJsonInline(obj) {
  if (!obj || typeof obj !== 'object') {
    return escapeHtml(formatInlineValue(sanitizeJsonValue(obj, { truncateStrings: true })) || '—');
  }
  const sanitized = sanitizeJsonValue(obj, { truncateStrings: true });
  const lines = Object.entries(sanitized).map(
    ([key, val]) => `${escapeHtml(translateFeatureKey(key))}: ${escapeHtml(formatInlineValue(val))}`
  );
  return lines.length ? lines.join('<br>') : '—';
}

function formatJsonPretty(obj) {
  const sanitized = sanitizeJsonValue(obj, { truncateStrings: false });
  const localized = localizeKeys(sanitized);
  const pretty = JSON.stringify(localized, (k, v) => (typeof v === 'number' ? roundDisplayNumber(v) : v), 2);
  return `<pre class="json-pretty">${escapeHtml(pretty || '—')}</pre>`;
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
    descTd.innerHTML = formatJsonInline(event.payload);
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
    const detailsWrapper = document.createElement('div');
    detailsWrapper.className = 'details-card';
    detailsWrapper.innerHTML = formatJsonPretty(event.payload);
    detailsTd.appendChild(detailsWrapper);
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
    desc.innerHTML = formatJsonInline(a.payload);
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
    const detailsCell = document.createElement('td');
    const btn = document.createElement('button');
    btn.className = 'details-btn';
    btn.type = 'button';
    btn.textContent = 'Подробнее';
    detailsCell.appendChild(btn);
    const detailsRow = document.createElement('tr');
    detailsRow.className = 'hidden';
    const detailsTd = document.createElement('td');
    detailsTd.colSpan = 7;
    const detailsWrapper = document.createElement('div');
    detailsWrapper.className = 'details-card';
    const detailsPayload = {
      summary: f.summary || {},
      attack: {
        task: f.task_attack,
        confidence: f.attack_confidence,
        version: f.attack_version,
        explanation: f.attack_explanation,
      },
      vpn: {
        task: f.task_vpn,
        confidence: f.vpn_confidence,
        version: f.vpn_version,
        explanation: f.vpn_explanation,
      },
      anomaly: {
        task: f.task_anomaly,
        confidence: f.anomaly_confidence,
        version: f.anomaly_version,
        explanation: f.anomaly_explanation,
      },
    };
    detailsWrapper.innerHTML = formatJsonPretty(detailsPayload);
    detailsTd.appendChild(detailsWrapper);
    detailsRow.appendChild(detailsTd);
    btn.addEventListener('click', () => {
      detailsRow.classList.toggle('hidden');
    });

    row.appendChild(time);
    row.appendChild(route);
    row.appendChild(bytes);
    row.appendChild(packets);
    row.appendChild(proto);
    row.appendChild(label);
    row.appendChild(detailsCell);
    body.appendChild(row);
    body.appendChild(detailsRow);
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
