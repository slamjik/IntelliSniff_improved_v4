const state = {
  authToken: null,
  flows: [],
  labelCounts: new Map(),
  destBytes: new Map(),
  trafficHistory: [],
  lastStatus: null,
  websocket: null,
  ml: {
    tasks: ['attack', 'vpn', 'anomaly'],
    versions: {},
    active: {},
    metrics: {},
    drift: {},
    autoUpdate: true,
    predictions: [],
    predictionLimit: 20,
  },
  flowLimit: 50,
  uiCollapsed: {
    mlPredictions: false,
    flows: false,
  },
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
  model_version: 'Версия модели',
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
  label: 'Метка',
  label_name: 'Имя метки',
};

function translateFeatureKey(key) {
  if (!key) return '';
  if (featureTranslations[key] !== undefined) return featureTranslations[key];
  return key.replace(/_/g, ' ').replace(/\b([a-zа-яё])/gi, (m) => m.toUpperCase());
}

function translateTaskName(task) {
  const map = { attack: 'Детектор атак', vpn: 'Определение VPN', anomaly: 'Поиск аномалий' };
  return map[task] || translateFeatureKey(task);
}

function translateDriftFlag(flag) {
  if (flag === true) return 'Дрейф обнаружен: Да';
  if (flag === false) return 'Дрейф обнаружен: Нет';
  return 'Дрейф: данные недоступны';
}

function buildDriftSummary(driftInfo = {}) {
  const jsd = driftInfo.jsd !== undefined ? Number(driftInfo.jsd) : null;
  const z = driftInfo.z_score !== undefined ? Number(driftInfo.z_score) : null;
  const detected = driftInfo.drift === true;
  const jsdText = jsd !== null && Number.isFinite(jsd) ? jsd.toFixed(3) : '—';
  const zText = z !== null && Number.isFinite(z) ? z.toFixed(2) : '—';
  return `
    <div class="drift-line"><strong>JSD (расхождение распределений):</strong> ${jsdText}</div>
    <div class="drift-desc">JSD — мера различия между обучающим распределением признаков и текущим трафиком.</div>
    <div class="drift-line"><strong>Z-оценка дрейфа:</strong> ${zText}</div>
    <div class="drift-desc">Z-оценка показывает, насколько сильно текущие признаки отклоняются от обучающей выборки.</div>
    <div class="drift-line ${detected ? 'drift-flag-warning' : ''}">${translateDriftFlag(driftInfo.drift === true)}</div>
    <div class="drift-desc">Если JSD превышает порог, модель считает, что входящие данные изменились.</div>
  `;
}

const ui = {};

function formatDate(ts) {
  if (!ts) return '—';
  const date = new Date(Number(ts));
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('ru-RU', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    day: '2-digit',
    month: '2-digit',
  });
}

function formatNumber(value, digits = 0) {
  if (value === undefined || value === null) return '—';
  return Number(value).toLocaleString('ru-RU', {
    maximumFractionDigits: digits,
    minimumFractionDigits: digits,
  });
}

function truncateString(value, maxLen = 80) {
  if (value === null || value === undefined) return '';
  const str = String(value);
  return str.length > maxLen ? `${str.slice(0, maxLen - 1)}…` : str;
}

function roundDisplayNumber(value) {
  if (value === null || value === undefined) return value;
  const num = Number(value);
  if (!Number.isFinite(num)) return 0;
  const abs = Math.abs(num);
  const digits = abs >= 100 ? 0 : abs >= 1 ? 2 : 3;
  return Number(num.toFixed(digits));
}

function detectAddressType(value) {
  if (!value) return null;
  const normalized = String(value).trim();
  const macRegex = /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/;
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$/;
  const looksLikeIpv6 = normalized.includes(':') && normalized.replace(/:/g, '').length >= 3;
  if (macRegex.test(normalized)) return 'mac';
  if (ipv4Regex.test(normalized) || looksLikeIpv6) return 'ip';
  return null;
}

function formatSourceDestination(value, role = 'Адрес') {
  if (!value) return '—';
  const type = detectAddressType(value);
  const label = type === 'mac' ? 'MAC' : type === 'ip' ? 'IP' : role;
  return `${label}: ${value}`;
}

function mapProtocolToName(proto) {
  if (proto === null || proto === undefined || proto === '') return 'Unknown';
  const protoMap = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    132: 'SCTP',
  };
  const numeric = Number(proto);
  if (!Number.isNaN(numeric) && protoMap[numeric]) return protoMap[numeric];
  const normalized = String(proto).trim().toUpperCase();
  return protoMap[normalized] || normalized;
}

function handleNegativeValues(flow) {
  const clampFields = ['packets', 'bytes', 'packets_per_sec', 'bytes_per_sec', 'avg_pkt_size'];
  clampFields.forEach((field) => {
    if (flow[field] === undefined || flow[field] === null) return;
    const value = Number(flow[field]);
    flow[field] = Number.isFinite(value) ? Math.max(0, value) : 0;
  });
  if (flow.summary && typeof flow.summary === 'object') {
    ['пакетов_в_сек', 'байт_в_сек', 'средний_размер_пакета'].forEach((key) => {
      if (key in flow.summary) {
        const value = Number(flow.summary[key]);
        flow.summary[key] = Number.isFinite(value) ? Math.max(0, value) : 0;
      }
    });
  }
  return flow;
}

function mergeModelResults(flow) {
  const models = { ...(flow.models || flow.summary?.models || {}) };

  const upsert = (task, labelKey, confKey, versionKey, explanationKey) => {
    const label = flow[labelKey];
    const conf = flow[confKey];
    const version = flow[versionKey];
    const explanation = flow[explanationKey];
    if (label !== undefined || conf !== undefined || version !== undefined || explanation) {
      models[task] = {
        ...(models[task] || {}),
        label: label !== undefined ? label : models[task]?.label,
        label_name: models[task]?.label_name || (typeof label === 'string' ? label : undefined),
        confidence: conf !== undefined ? conf : models[task]?.confidence,
        version: version !== undefined ? version : models[task]?.version,
        explanation: explanation !== undefined ? explanation : models[task]?.explanation,
      };
    }
  };

  upsert('attack', 'task_attack', 'attack_confidence', 'attack_version', 'attack_explanation');
  upsert('vpn', 'task_vpn', 'vpn_confidence', 'vpn_version', 'vpn_explanation');
  upsert('anomaly', 'task_anomaly', 'anomaly_confidence', 'anomaly_version', 'anomaly_explanation');

  flow.models = models;
  return flow;
}

function formatTaskLabel(task, label) {
  const normalized = String(label || '').toLowerCase();

  if (task === 'vpn') return normalized && normalized !== '0' && normalized !== 'benign' ? 'VPN-трафик' : 'Нормальный трафик';

  if (task === 'anomaly') return normalized === '1' || normalized.includes('anom') ? 'Аномалия' : 'Нормальный трафик';
  if (task === 'attack') return normalized === '0' || normalized === 'benign' || normalized === 'normal' ? 'Нормальный трафик' : 'Атака';
  return label || '—';
}

function modelExplanation(task, label, flow) {
  const version = flow.model_version || flow.summary?.['модель'];
  const modelLabel = task === 'vpn' ? 'VPN-модель' : task === 'anomaly' ? 'Модель аномалий' : 'Модель атак';
  const verdictMap = {
    attack: { positive: 'Обнаружена атака', negative: 'Трафик выглядит нормальным' },
    vpn: { positive: 'Трафик определён как VPN', negative: 'Нормальный трафик' },
    anomaly: { positive: 'Аномалия обнаружена', negative: 'Отклонений не найдено' },
  };
  const verdictSet = verdictMap[task] || verdictMap.attack;
  const labelStr = String(label).toLowerCase();
  let verdict = 'Метка не определена';
  if (labelStr === '1' || labelStr === 'attack' || labelStr === 'vpn' || labelStr === 'anomaly') verdict = verdictSet.positive;
  else if (labelStr === '0' || labelStr === 'benign' || labelStr === 'normal') verdict = verdictSet.negative;
  else if (labelStr === 'error') verdict = 'Ошибка классификации';
  else if (labelStr === 'unknown') verdict = 'Классификация неуверенная';
  return `${modelLabel}${version ? ` v${version}` : ''}: ${verdict}`;
}

function processTrafficLabels(flow) {
  const task = flow.model_task || flow.summary?.task || 'attack';
  const labelRaw = flow.label;
  const labelNameRaw = flow.label_name;
  const isNumeric = labelRaw !== null && labelRaw !== undefined && labelRaw !== '' && !Number.isNaN(Number(labelRaw));
  const labelStr = labelRaw === undefined || labelRaw === null || labelRaw === '' ? 'unknown' : String(labelRaw).toLowerCase();
  const taskVerdicts = {
    attack: { positive: 'Атака', negative: 'Нормальный трафик' },

    vpn: { positive: 'VPN-трафик', negative: 'Нормальный трафик' },

    anomaly: { positive: 'Аномалия', negative: 'Нормальный трафик' },
  };
  const verdict = taskVerdicts[task] || taskVerdicts.attack;

  let normalizedLabel = labelStr;
  let labelName = labelNameRaw || undefined;

  if (isNumeric) {
    if (Number(labelRaw) === 1) {
      normalizedLabel = '1';
      labelName = verdict.positive;
    } else if (Number(labelRaw) === 0) {
      normalizedLabel = '0';
      labelName = verdict.negative;
    }
  }

  if (normalizedLabel === 'vpn') {
    labelName = verdict.positive;
  } else if (normalizedLabel === 'attack') {
    labelName = taskVerdicts.attack.positive;
  } else if (normalizedLabel === 'anomaly') {
    labelName = taskVerdicts.anomaly.positive;
  } else if (normalizedLabel === 'benign' || normalizedLabel === 'normal') {
    normalizedLabel = '0';
    labelName = taskVerdicts.attack.negative;
  }

  if (!labelName) {
    if (normalizedLabel === 'unknown') labelName = 'Неопределено';
    else if (normalizedLabel === 'error') labelName = 'Ошибка модели';
    else labelName = normalizedLabel;
  }

  const explanation = modelExplanation(task, normalizedLabel, flow);

  return {
    ...flow,
    label: normalizedLabel,
    label_name: labelName,
    label_display: labelName,
    label_explanation: explanation,
  };
}

function checkUnknownLabelsIssue(flow) {
  if (!flow) return flow;
  const label = String(flow.label || '').toLowerCase();
  const name = String(flow.label_name || '').toLowerCase();

  if (label === 'unknown' && (name === '0' || name === 'нормальный трафик' || name === 'normal')) {
    flow.label = '0';
  }

  if ((label === '0' || label === '1') && (!flow.label_name || flow.label_name.toLowerCase() === 'unknown')) {
    const processed = processTrafficLabels(flow);
    flow.label = processed.label;
    flow.label_name = processed.label_name;
    flow.label_display = processed.label_display;
    flow.label_explanation = processed.label_explanation;
  }

  return flow;
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
  const lines = Object.entries(sanitized).map(([key, val]) => `${escapeHtml(key)}: ${escapeHtml(formatInlineValue(val))}`);
  return lines.length ? lines.join('<br>') : '—';
}

function formatJsonPretty(obj) {
  const sanitized = sanitizeJsonValue(obj, { truncateStrings: false });
  const pretty = JSON.stringify(sanitized, (k, v) => (typeof v === 'number' ? roundDisplayNumber(v) : v), 2);
  return `<pre class="json-pretty">${escapeHtml(pretty || '—')}</pre>`;
}

function setStatusBadge(status) {
  const badge = ui.statusBadge;
  badge.classList.remove('status-running', 'status-idle', 'status-warning');
  switch (status) {
    case 'running':
      badge.textContent = 'Захват активен';
      badge.classList.add('status-running');
      break;
    case 'warning':
      badge.textContent = 'Требует внимания';
      badge.classList.add('status-warning');
      break;
    default:
      badge.textContent = 'Ожидание';
      badge.classList.add('status-idle');
      break;
  }
}

function requireAuth() {
  ui.authOverlay.classList.remove('hidden');
  ui.authLogin.focus();
}

function storeAuth(token) {
  state.authToken = token;
  sessionStorage.setItem('taAuth', token);
}

async function apiFetch(path, options = {}) {
  if (!state.authToken) throw new Error('no auth');
  const headers = Object.assign({}, options.headers || {}, {
    Authorization: 'Basic ' + state.authToken,
  });
  if (options.body && !(options.body instanceof FormData)) {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  }
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    requireAuth();
    throw new Error('unauthorized');
  }
  if (response.headers.get('content-type')?.includes('application/json')) {
    const json = await response.json();
    if (!response.ok) throw new Error(json.detail || response.statusText);
    return json;
  }
  if (!response.ok) {
    throw new Error(response.statusText || 'Request failed');
  }
  return response;
}

function updateStatusDetails(status) {
  if (!status) return;
  state.lastStatus = status;
  const lines = [];
  lines.push(`Статус: ${status.running ? 'запущено' : 'остановлено'}`);
  if (status.iface) {
    lines.push(`Интерфейс: ${status.iface}`);
  }
  if (status.bpf) {
    lines.push(`Фильтр BPF: ${status.bpf}`);
  }
  if (status.flow_timeout) {
    lines.push(`Таймаут потока: ${status.flow_timeout} с`);
  }
  if (status.use_nfstream) {
    lines.push('NFStream активен');
  } else if (status.nfstream_available === false) {
    lines.push('NFStream недоступен (пакет не установлен)');
  }
  if (status.started_at) {
    lines.push(`Старт: ${formatDate(status.started_at * 1000)}`);
  }
  ui.statusDetails.textContent = lines.join(' · ');
  document.getElementById('nfStatus').textContent = status.nfstream_available ? 'доступен' : 'недоступен';
  setStatusBadge(status.running ? 'running' : 'idle');
}

function updateLabelFilterOptions() {
  const select = ui.labelFilter;
  const current = new Set(['all']);
  for (const option of select.options) current.add(option.value);
  for (const label of state.labelCounts.keys()) {
    if (!current.has(label)) {
      const opt = document.createElement('option');
      opt.value = label;
      opt.textContent = label;
      select.appendChild(opt);
    }
  }
}

function updateCards() {
  ui.totalFlows.textContent = state.flows.length.toString();
  const suspicious = state.flows.filter((f) => !isBenign(f.label)).length;
  ui.suspiciousFlows.textContent = suspicious.toString();
  const bandwidthValues = state.flows
    .map((f) => Number(f.bytes_per_sec || (f.summary && f.summary['байт_в_сек'])) || 0)
    .filter((v) => v > 0);
  const avgBandwidth = bandwidthValues.length
    ? bandwidthValues.reduce((a, b) => a + b, 0) / bandwidthValues.length
    : 0;
  ui.bandwidth.textContent = `${formatNumber(avgBandwidth / 1024, 1)} КБ/с`;
  const last = state.flows[0];
  if (last) {
    ui.lastFlowLabel.textContent = `${last.label_display || last.label || '—'} (${formatNumber((last.score || last.score === 0 ? last.score : 0) * 100, 0)}%)`;
    const hints = [];
    if (last.summary) {
      const keys = ['tls_sni', 'http_host', 'dns_query', 'app'];
      keys.forEach((k) => {
        const value = last.summary[k];
        if (value) hints.push(`${k}: ${value}`);
      });
    }
    if (!hints.length) {
      hints.push(`Пакеты: ${last.packets}, байты: ${last.bytes}`);
    }
    if (last.label_explanation) {
      hints.push(last.label_explanation);
    }
    ui.lastFlowSummary.textContent = hints.join(' · ');
  }
}

function isBenign(label) {
  if (!label) return false;
  const normalized = String(label).toLowerCase();
  return ['benign', 'normal', 'web', 'allow', '0'].includes(normalized);
}

let labelsChart;
let trafficChart;
let destChart;

function initCharts() {
  const labelCtx = document.getElementById('labelsChart').getContext('2d');
  labelsChart = new Chart(labelCtx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Потоки',
          data: [],
          backgroundColor: '#38bdf8',
        },
      ],
    },
    options: {
      plugins: {
        legend: { display: false },
      },
      scales: {
        x: { ticks: { color: '#94a3b8' } },
        y: { ticks: { color: '#94a3b8' }, beginAtZero: true },
      },
    },
  });

  const trafficCtx = document.getElementById('trafficChart').getContext('2d');
  trafficChart = new Chart(trafficCtx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Пакеты/с',
          data: [],
          borderColor: '#0ea5e9',
          backgroundColor: 'rgba(56,189,248,0.15)',
          tension: 0.4,
          fill: true,
        },
      ],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#94a3b8' } },
        y: { ticks: { color: '#94a3b8' }, beginAtZero: true },
      },
    },
  });

  const destCtx = document.getElementById('destChart').getContext('2d');
  destChart = new Chart(destCtx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Байт',
          data: [],
          backgroundColor: 'rgba(148,163,184,0.4)',
        },
      ],
    },
    options: {
      plugins: { legend: { display: false } },
      indexAxis: 'y',
      scales: {
        x: { ticks: { color: '#94a3b8' }, beginAtZero: true },
        y: { ticks: { color: '#94a3b8' } },
      },
    },
  });
}

function updateCharts() {
  if (!labelsChart) return;
  const labels = Array.from(state.labelCounts.keys());
  const counts = labels.map((label) => state.labelCounts.get(label));
  labelsChart.data.labels = labels;
  labelsChart.data.datasets[0].data = counts;
  labelsChart.update('none');

  const trafficLabels = state.trafficHistory.map((item) => item.label);
  const trafficValues = state.trafficHistory.map((item) => item.value);
  trafficChart.data.labels = trafficLabels;
  trafficChart.data.datasets[0].data = trafficValues;
  trafficChart.update('none');

  const destinations = Array.from(state.destBytes.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 7);
  destChart.data.labels = destinations.map(([dst]) => dst);
  destChart.data.datasets[0].data = destinations.map(([, bytes]) => Math.round(bytes));
  destChart.update('none');
}

function renderTable() {
  const tbody = ui.tableBody;
  const search = ui.tableSearch.value.trim().toLowerCase();
  const selectedLabel = ui.labelFilter.value;

  // Фильтрация строк таблицы
  const filtered = state.flows.filter((flow) => {
    if (selectedLabel !== 'all' && flow.label !== selectedLabel) return false;
    if (!search) return true;
    const candidate = [
      flow.src,
      flow.dst,
      flow.src_display,
      flow.dst_display,
      flow.proto,
      flow.proto_name,
      flow.label,
      flow.label_name,
      flow.label_explanation,
      flow.sport,
      flow.dport,
      JSON.stringify(flow.summary || {}),
    ]
      .join(' ')
      .toLowerCase();
    return candidate.includes(search);
  });

  ui.tableCounter.textContent = `${filtered.length} записей`;

  const limit = state.flowLimit === 'all' ? null : Number(state.flowLimit) || 50;
  const visible = limit ? filtered.slice(0, limit) : filtered;

  // Генерация строк таблицы
  tbody.innerHTML = visible
    .map((flow) => {
      const rawLabel = flow.label_display || flow.label_name || flow.label || 'Unknown';
      const labelName = translateFeatureKey(rawLabel);
      const score = flow.score !== undefined ? `${Math.round(flow.score * 100)}%` : '—';

      // Определяем цветовую метку риска
      let labelColor = 'gray';
      if (/normal|benign|allow/i.test(rawLabel)) labelColor = 'limegreen';
      else if (/attack|malware|botnet|exploit/i.test(rawLabel)) labelColor = 'crimson';
      else if (/scan|recon|brute/i.test(rawLabel)) labelColor = 'orange';
      else if (/vpn/i.test(rawLabel)) labelColor = '#2563eb';
      else if (/аномал|anomal/i.test(rawLabel)) labelColor = '#eab308';

      // Чипы с полезными данными (SNI, DNS, HTTP и т.д.)
      const summaryChips = [];
      if (flow.summary && typeof flow.summary === 'object') {
        const interesting = ['модель', 'уверенность', 'tls_sni', 'http_host', 'dns_query', 'app'];
        for (const key of interesting) {
          if (flow.summary[key]) {
            const translatedKey = translateFeatureKey(key);
            let value = flow.summary[key];
            if (key === 'уверенность') {
              value = `${formatNumber((Number(value) || 0) * 100, 1)}%`;
            }
            summaryChips.push(`<span class="summary-chip">${translatedKey}: ${value}</span>`);
          }
        }
        if (Array.isArray(flow.summary['важные_признаки'])) {
          flow.summary['важные_признаки'].slice(0, 2).forEach((item) => {
            if (item && item.feature) {
              const value = typeof item.value === 'number' ? item.value.toFixed(2) : item.value;
              summaryChips.push(
                `<span class="summary-chip" title="${translateFeatureKey(item.feature)}">${translateFeatureKey(item.feature)}: ${value}</span>`
              );
            }
          });
        }
        const models = flow.models || flow.summary?.models || {};
        const modelNames = { attack: 'Модель атак', vpn: 'Модель VPN', anomaly: 'Модель аномалий' };
        ['attack', 'vpn', 'anomaly'].forEach((task) => {
          const data = models[task];
          if (!data) return;
          const labelText = formatTaskLabel(task, data.label_name || data.label);
          const confText = data.confidence !== undefined ? `${formatNumber((Number(data.confidence) || 0) * 100, 1)}%` : '—';
          const versionText = data.version !== undefined ? data.version : '—';
          summaryChips.push(
            `<span class="summary-chip">${modelNames[task]} v${versionText}: ${escapeHtml(labelText)} (${confText})</span>`
          );
          if (Array.isArray(data.explanation)) {
            data.explanation.slice(0, 2).forEach((item) => {
              if (item && item.feature) {
                const value = typeof item.value === 'number' ? item.value.toFixed(2) : item.value;
                summaryChips.push(
                  `<span class="summary-chip" title="${translateFeatureKey(item.feature)}">${
                    modelNames[task].replace('Модель ', '')
                  } · ${translateFeatureKey(item.feature)}: ${value}</span>`
                );
              }
            });
          }
        });
        if (!summaryChips.length) {
          summaryChips.push(
            `<span class="summary-chip">${formatNumber(
              flow.summary['байт_в_сек'] || 0,
              1
            )} Б/с</span>`
          );
        }
      }

      // Формирование HTML строки
      return `
        <tr>
          <td>${formatDate(flow.ts)}</td>
          <td>${flow.src_display || flow.src || ''}</td>
          <td>${flow.dst_display || flow.dst || ''}</td>
          <td>${flow.sport || ''} → ${flow.dport || ''}</td>
          <td>${flow.proto_name || flow.proto || ''}</td>
          <td><span style="color:${labelColor}; font-weight:600">${labelName}</span></td>
          <td>${score}</td>
          <td>${formatNumber(flow.packets)}</td>
          <td>${formatNumber(flow.bytes)}</td>
          <td>${summaryChips.join(' ')}${flow.label_explanation ? `<span class="summary-chip">${escapeHtml(flow.label_explanation)}</span>` : ''}</td>
        </tr>`;
    })
    .join('');

  if (ui.flowsPanel && !state.uiCollapsed.flows) {
    requestAnimationFrame(() => {
      ui.flowsPanel.style.maxHeight = `${ui.flowsPanel.scrollHeight}px`;
    });
  }
}


function updateLabelCounts(flow) {
  const label = flow.label || 'unknown';
  const current = state.labelCounts.get(label) || 0;
  state.labelCounts.set(label, current + 1);
}

function updateDestinations(flow) {
  const key = flow.dst || 'неизвестно';
  const current = state.destBytes.get(key) || 0;
  state.destBytes.set(key, current + (Number(flow.bytes) || 0));
}

function updateTraffic(flow) {
  const label = new Date(flow.ts).toLocaleTimeString('ru-RU', { minute: '2-digit', second: '2-digit' });
  state.trafficHistory.push({ label, value: Number(flow.packets) || 0 });
  if (state.trafficHistory.length > 40) state.trafficHistory.shift();
}

function normalizeFlowEntry(flow) {
  const safeFlow = handleNegativeValues({ ...flow });
  mergeModelResults(safeFlow);
  safeFlow.src_display = formatSourceDestination(safeFlow.src, 'Источник');
  safeFlow.dst_display = formatSourceDestination(safeFlow.dst, 'Назначение');
  safeFlow.proto_name = mapProtocolToName(safeFlow.proto);
  const labeled = processTrafficLabels(safeFlow);
  return checkUnknownLabelsIssue(labeled);
}

function addFlow(flow) {
  if (!flow) return;
  const normalized = normalizeFlowEntry(flow);
  state.flows.unshift(normalized);
  if (state.flows.length > 300) state.flows.pop();
  updateLabelCounts(normalized);
  updateDestinations(normalized);
  updateTraffic(normalized);
  updateLabelFilterOptions();
  updateCards();
  updateCharts();
  renderTable();
}

async function loadInitialData() {
  try {
    const status = await apiFetch('/status');
    updateStatusDetails(status);
    const ifaceResp = await apiFetch('/interfaces');
    populateInterfaces(ifaceResp.interfaces || []);
    const flowsResp = await apiFetch('/flows/recent?limit=200');
    state.flows = [];
    state.labelCounts = new Map();
    state.destBytes = new Map();
    state.trafficHistory = [];
    (flowsResp.items || []).reverse().forEach(addFlow);
    await loadMlDashboard();
  } catch (err) {
    console.error(err);
    ui.statusDetails.textContent = 'Ошибка загрузки данных: ' + err.message;
    setStatusBadge('warning');
  }
}

function normalizeMetricFields(source) {
  const map = {
    metric_precision: 'metric_precision',
    precision: 'metric_precision',
    metric_recall: 'metric_recall',
    recall: 'metric_recall',
    metric_f1: 'metric_f1',
    f1: 'metric_f1',
    metric_drift_resilience: 'metric_drift_resilience',
    drift_resilience: 'metric_drift_resilience',
  };
  const normalized = {};
  Object.entries(map).forEach(([key, target]) => {
    const value = source?.[key];
    if (value !== undefined && value !== null && !Number.isNaN(Number(value))) {
      normalized[target] = Number(value);
    }
  });
  return normalized;
}

function normalizeVersionEntry(entry) {
  if (entry === null || entry === undefined) return null;
  const rawVersion =
    typeof entry === 'object' && !Array.isArray(entry)
      ? entry.version ?? entry.id ?? entry
      : entry;
  const versionNumber = Number(rawVersion);
  const version = Number.isNaN(versionNumber) ? rawVersion : versionNumber;
  return {
    version,
    active: Boolean(entry && entry.active),
    ...normalizeMetricFields(entry || {}),
  };
}

function normalizeQualityMetrics(entry) {
  if (!entry) return [];
  if (Array.isArray(entry)) return entry;
  if (entry && Array.isArray(entry.versions)) return entry.versions;
  if (typeof entry === 'object') {
    return Object.keys(entry).map((key) => {
      const payload = entry[key];
      if (payload && typeof payload === 'object' && payload.version === undefined) {
        const versionNumber = Number(key);
        return { version: Number.isNaN(versionNumber) ? key : versionNumber, ...payload };
      }
      return payload;
    });
  }
  return [];
}

function normalizeVersionsResponse(task, response) {
  if (!response) return [];
  let versionsPayload = [];
  if (Array.isArray(response)) {
    versionsPayload = response;
  } else if (response && Array.isArray(response.versions)) {
    versionsPayload = response.versions;
  } else if (response && Array.isArray(response[task])) {
    versionsPayload = response[task];
  }
  return versionsPayload
    .map((item) => normalizeVersionEntry(item))
    .filter((item) => item !== null);
}

function buildMetricsMap(metricsList) {
  const metricsMap = new Map();
  metricsList.forEach((item) => {
    const normalized = normalizeVersionEntry(item);
    if (!normalized) return;
    const metrics = normalizeMetricFields(item || {});
    if (Object.keys(metrics).length) {
      metricsMap.set(String(normalized.version), metrics);
    }
  });
  return metricsMap;
}

async function loadMlDashboard() {
  const tasks = ['attack', 'vpn', 'anomaly'];
  const safeFetch = async (path) => {
    try {
      return await apiFetch(path);
    } catch (err) {
      console.warn(`Не удалось загрузить ${path}:`, err);
      return null;
    }
  };

  const [status, quality, autoUpdate, drift, predictions] = await Promise.all([
    safeFetch('/model_status'),
    safeFetch('/quality_metrics'),
    safeFetch('/auto_update_status'),
    safeFetch('/drift_status'),
    safeFetch('/ml/predictions?limit=50'),
  ]);

  state.ml.tasks = tasks;
  state.ml.active = status || {};
  state.ml.metrics = quality || {};
  state.ml.drift = drift || {};
  state.ml.autoUpdate = !!(autoUpdate && autoUpdate.enabled);
  state.ml.predictions = (predictions?.items || []).map((item) => ({ ...item }));

  const versionsResponses = await Promise.allSettled(
    tasks.map((task) => apiFetch(`/get_versions?task=${task}`))
  );

  const normalizedVersions = {};
  tasks.forEach((task, idx) => {
    const result = versionsResponses[idx];
    let versions = [];
    if (result.status === 'fulfilled') {
      versions = normalizeVersionsResponse(task, result.value);
    } else {
      console.warn(`Не удалось загрузить версии для ${task}:`, result.reason);
    }

    const qualityList = normalizeQualityMetrics(state.ml.metrics?.[task]);
    const metricsMap = buildMetricsMap(qualityList);

    if (!versions.length && qualityList.length) {
      versions = qualityList
        .map((item) => normalizeVersionEntry(item))
        .filter((item) => item !== null);
    } else {
      versions = versions.map((item) => {
        const metrics = metricsMap.get(String(item.version));
        return metrics ? { ...item, ...metrics } : item;
      });
    }

    normalizedVersions[task] = versions;
  });

  state.ml.versions = normalizedVersions;
  renderMlSection();
  renderMlPredictions();
}

function renderMlSection() {
  if (!ui.mlCards) return;
  if (ui.autoUpdateToggle) {
    ui.autoUpdateToggle.checked = !!state.ml.autoUpdate;
  }
  ui.mlCards.forEach((card) => {
    const task = card.dataset.task;
    const select = card.querySelector('[data-role="versions"]');
    const metricsBox = card.querySelector('[data-role="metrics"]');
    const driftBox = card.querySelector('[data-role="drift"]');
    const activeBox = card.querySelector('[data-role="active"]');
    const versions = state.ml.versions[task] || [];
    const activeFromVersions = versions.find((v) => v.active);
    const statusActive = state.ml.active?.[task];
    let activeVersion = activeFromVersions?.version ?? statusActive?.version ?? null;

    if (!activeVersion && versions.length) {
      activeVersion = versions[0].version;
    }

    if (select) {
      select.innerHTML = '';
      versions.forEach((item, index) => {
        const option = document.createElement('option');
        option.value = item.version;
        option.textContent = item.version;
        if (
          String(item.version) === String(activeVersion) ||
          (!activeVersion && index === 0)
        ) {
          option.selected = true;
        }
        select.appendChild(option);
      });

      if (!versions.length) {
        const emptyOption = document.createElement('option');
        emptyOption.textContent = '—';
        emptyOption.value = '';
        emptyOption.selected = true;
        select.appendChild(emptyOption);
      }

      if (activeVersion && select.options.length) {
        const matchedOption = Array.from(select.options).find(
          (opt) => String(opt.value) === String(activeVersion)
        );
        if (matchedOption) {
          select.value = matchedOption.value;
        } else if (select.options[0]) {
          select.options[0].selected = true;
          activeVersion = select.value;
        }
      }
    }

    const resolvedActiveVersion =
      activeVersion || (select && select.value) || (versions[0] && versions[0].version);
    if (activeBox) {
      activeBox.textContent = resolvedActiveVersion
        ? `Активна: ${resolvedActiveVersion}`
        : 'Нет активной версии';
    }

    const metricsSource =
      versions.find((v) => String(v.version) === String(select?.value || resolvedActiveVersion)) || null;
    if (metricsBox) {
      const metricsData = normalizeMetricFields(metricsSource || {});
      const labels = {
        metric_precision: 'Точность',
        metric_recall: 'Полнота',
        metric_f1: 'F1',
        metric_drift_resilience: 'Устойчивость к дрейфу',
      };
      const metrics = ['metric_precision', 'metric_recall', 'metric_f1', 'metric_drift_resilience']
        .map((key) => ({ key, value: metricsData[key] }))
        .filter((item) => item.value !== undefined && !Number.isNaN(Number(item.value)));
      if (metrics.length) {
        metricsBox.innerHTML = metrics
          .map((m) => `<span><strong>${labels[m.key] || m.key}</strong>: ${(m.value * 100).toFixed(1)}%</span>`)
          .join('<span class="ml-metric-divider">·</span>');
      } else {
        metricsBox.innerHTML = '<span class="ml-metric-muted">Нет метрик</span>';
      }
    }
    if (driftBox) {
      const driftInfo = state.ml.drift?.[task];
      if (driftInfo) {
        driftBox.innerHTML = buildDriftSummary(driftInfo);
        if (driftInfo.drift) {
          card.classList.add('ml-card-warning');
        } else {
          card.classList.remove('ml-card-warning');
        }
      } else {
        driftBox.innerHTML = '<div class="drift-line">Дрейф: данные недоступны</div>';
        card.classList.remove('ml-card-warning');
      }
    }
  });
}

function renderMlPredictions() {
  if (!ui.mlPredictionsBody) return;
  const limit = state.ml.predictionLimit === 'all' ? null : Number(state.ml.predictionLimit) || 20;
  const subset = limit ? state.ml.predictions.slice(0, limit) : [...state.ml.predictions];
  ui.mlPredictionsBody.innerHTML = '';

  subset.forEach((pred) => {
    const tr = document.createElement('tr');
    const ts = pred.timestamp ? formatDate(Number(pred.timestamp) * 1000) : '—';
    const taskName = translateTaskName(pred.task || 'attack');
    const labelText = translateFeatureKey(pred.label_name || pred.label || '—');
    const confText = `${formatNumber((pred.confidence || pred.score || 0) * 100, 1)}%`;
    const explanationText = Array.isArray(pred.explanation)
      ? pred.explanation
          .map((item) => `${translateFeatureKey(item.feature)}: ${
            item.value?.toFixed ? item.value.toFixed(2) : item.value
          }`)
          .join(', ')
      : pred.explanation && typeof pred.explanation === 'object'
        ? Object.entries(pred.explanation)
            .map(([k, v]) => `${translateFeatureKey(k)}: ${v}`)
            .join(', ')
        : pred.explanation || '';
    const safeExplanation = explanationText
      ? `<span class="chip-badge" title="${escapeHtml(explanationText)}">${escapeHtml(truncateString(explanationText, 80))}</span>`
      : '—';

    tr.innerHTML = `
      <td>${ts}</td>
      <td>${taskName}</td>
      <td>${escapeHtml(labelText)}</td>
      <td>${confText}</td>
      <td>${pred.version || '—'}</td>
      <td>${safeExplanation}</td>
    `;
    ui.mlPredictionsBody.appendChild(tr);
  });

  if (ui.mlPredictionsPanel && !state.uiCollapsed.mlPredictions) {
    requestAnimationFrame(() => {
      ui.mlPredictionsPanel.style.maxHeight = `${ui.mlPredictionsPanel.scrollHeight}px`;
    });
  }
}

function applyCollapsible(panel, expanded) {
  if (!panel) return;
  panel.classList.toggle('collapsed', !expanded);
  panel.classList.toggle('expanded', expanded);
  panel.style.maxHeight = expanded ? `${panel.scrollHeight}px` : '0px';
  panel.style.opacity = expanded ? '1' : '0';
}

function toggleMlPredictions() {
  state.uiCollapsed.mlPredictions = !state.uiCollapsed.mlPredictions;
  applyCollapsible(ui.mlPredictionsPanel, !state.uiCollapsed.mlPredictions);
  if (ui.mlPredictionsToggle) {
    ui.mlPredictionsToggle.textContent = state.uiCollapsed.mlPredictions ? 'Показать список' : 'Скрыть список';
  }
}

function toggleFlowsPanel() {
  state.uiCollapsed.flows = !state.uiCollapsed.flows;
  applyCollapsible(ui.flowsPanel, !state.uiCollapsed.flows);
  if (ui.flowsToggle) {
    ui.flowsToggle.textContent = state.uiCollapsed.flows ? 'Показать список' : 'Скрыть список';
  }
}

function handleMlPrediction(prediction) {
  if (!prediction) return;
  state.ml.predictions.unshift(prediction);
  if (state.ml.predictions.length > 80) {
    state.ml.predictions.pop();
  }
  if (prediction.drift) {
    state.ml.drift[prediction.task] = prediction.drift;
    if (prediction.drift.drift) {
      setStatusBadge('warning');
    }
  }
  renderMlPredictions();
  renderMlSection();
}

function handleDriftEvent(event) {
  if (!event || !event.task) return;
  state.ml.drift[event.task] = event;
  setStatusBadge('warning');
  renderMlSection();
}

function handleModelUpdate(event) {
  if (!event || !event.task) return;
  loadMlDashboard();
  const statusText = event.status === 'activated' ? '✅ Модель активирована' : '⚠️ Модель отклонена';
  ui.statusDetails.textContent = `${statusText} (${event.task} · ${event.version})`;
}

function handleAutoUpdate(event) {
  if (!event) return;
  state.ml.autoUpdate = !!event.enabled;
  renderMlSection();
}

async function handleSwitchRequest(task, version) {
  try {
    await apiFetch('/switch_model', {
      method: 'POST',
      body: JSON.stringify({ task, version }),
    });
    await loadMlDashboard();
  } catch (err) {
    alert('Не удалось переключить модель: ' + err.message);
  }
}

async function handleValidationRequest(task, version) {
  try {
    await apiFetch('/trigger_validation', {
      method: 'POST',
      body: JSON.stringify({ task, version }),
    });
    ui.statusDetails.textContent = `Валидация модели ${version} запущена`;
  } catch (err) {
    alert('Ошибка валидации: ' + err.message);
  }
}

async function toggleAutoUpdate(enabled) {
  try {
    await apiFetch('/auto_update_toggle', {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    });
    state.ml.autoUpdate = enabled;
    renderMlSection();
  } catch (err) {
    alert('Не удалось обновить настройку автообновления: ' + err.message);
    if (ui.autoUpdateToggle) {
      ui.autoUpdateToggle.checked = !enabled;
    }
  }
}
function populateInterfaces(interfaces) {
  const select = ui.iface;
  const current = select.value;
  select.innerHTML = '<option value="">Авто</option>';
  interfaces.forEach((iface) => {
    const option = document.createElement('option');
    option.value = iface;
    option.textContent = iface;
    select.appendChild(option);
  });
  if (interfaces.includes(current)) {
    select.value = current;
  }
}

function setupWebSocket() {
  if (state.websocket) {
    state.websocket.close();
  }
  const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
  const ws = new WebSocket(`${protocol}${window.location.host}/ws/live`);
  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      switch (msg.topic) {
        case 'flow':
          addFlow(msg.data);
          break;
        case 'ml_prediction':
          handleMlPrediction(msg.data);
          break;
        case 'drift':
          handleDriftEvent(msg.data);
          break;
        case 'model_update':
          handleModelUpdate(msg.data);
          break;
        case 'auto_update':
          handleAutoUpdate(msg.data);
          break;
        default:
          break;
      }
    } catch (err) {
      console.error('WS message error', err);
    }
  };
  ws.onopen = () => console.log('WebSocket открыт');
  ws.onclose = () => {
    console.warn('WebSocket закрыт, повтор через 2с');
    setTimeout(setupWebSocket, 2000);
  };
  ws.onerror = (err) => console.error('WebSocket error', err);
  state.websocket = ws;
}

async function handleStart() {
  try {
    setStatusBadge('warning');
    ui.statusDetails.textContent = 'Запуск захвата...';
    const payload = {
      iface: ui.iface.value || null,
      bpf: ui.bpf.value || null,
      flow_timeout: Number(ui.flowTimeout.value) || 30,
      use_nfstream: ui.useNfstream.checked,
    };
    const res = await apiFetch('/start_capture', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    updateStatusDetails(res.details);
  } catch (err) {
    console.error(err);
    ui.statusDetails.textContent = 'Не удалось запустить захват: ' + err.message;
    setStatusBadge('warning');
  }
}

async function handleStop() {
  try {
    const res = await apiFetch('/stop_capture', { method: 'POST' });
    updateStatusDetails(res.details);
  } catch (err) {
    console.error(err);
    ui.statusDetails.textContent = 'Ошибка остановки: ' + err.message;
    setStatusBadge('warning');
  }
}

async function handleTrain() {
  ui.trainBtn.disabled = true;
  ui.trainBtn.textContent = 'Обучение...';
  try {
    await apiFetch('/train_model', {
      method: 'POST',
      body: JSON.stringify({ demo: true }),
    });
    ui.statusDetails.textContent = 'Обучение модели запущено (в фоне).';
  } catch (err) {
    ui.statusDetails.textContent = 'Не удалось запустить обучение: ' + err.message;
  } finally {
    setTimeout(() => {
      ui.trainBtn.disabled = false;
      ui.trainBtn.textContent = 'Переобучить модель';
    }, 4000);
  }
}

async function downloadReport(path, filename) {
  try {
    const response = await apiFetch(path, { method: 'GET' });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    ui.statusDetails.textContent = 'Не удалось скачать отчёт: ' + err.message;
  }
}

function bindEvents() {
  ui.startBtn.addEventListener('click', (e) => {
    e.preventDefault();
    handleStart();
  });
  ui.stopBtn.addEventListener('click', (e) => {
    e.preventDefault();
    handleStop();
  });
  ui.trainBtn.addEventListener('click', (e) => {
    e.preventDefault();
    handleTrain();
  });
  ui.csvBtn.addEventListener('click', (e) => {
    e.preventDefault();
    downloadReport('/report/csv', 'traffic_report.csv');
  });
  ui.pdfBtn.addEventListener('click', (e) => {
    e.preventDefault();
    downloadReport('/report/pdf', 'traffic_report.pdf');
  });
  ui.labelFilter.addEventListener('change', renderTable);
  ui.tableSearch.addEventListener('input', () => {
    renderTable();
  });
  if (ui.autoUpdateToggle) {
    ui.autoUpdateToggle.addEventListener('change', (e) => {
      toggleAutoUpdate(e.target.checked);
    });
  }
  if (ui.mlCards && ui.mlCards.length) {
    ui.mlCards.forEach((card) => {
      const task = card.dataset.task;
      const select = card.querySelector('[data-role="versions"]');
      const switchBtn = card.querySelector('[data-action="switch"]');
      const validateBtn = card.querySelector('[data-action="validate"]');
      if (select) {
        select.addEventListener('change', renderMlSection);
      }
      if (switchBtn && select) {
        switchBtn.addEventListener('click', (e) => {
          e.preventDefault();
          const version = select.value || (select.options[0] && select.options[0].value);
          if (version) handleSwitchRequest(task, version);
        });
      }
      if (validateBtn && select) {
        validateBtn.addEventListener('click', (e) => {
          e.preventDefault();
          const version = select.value || (select.options[0] && select.options[0].value);
          if (version) handleValidationRequest(task, version);
        });
      }
    });
  }
  if (ui.mlRefreshBtn) {
    ui.mlRefreshBtn.addEventListener('click', (e) => {
      e.preventDefault();
      loadMlDashboard();
    });
  }
  if (ui.mlPredictionsToggle) {
    ui.mlPredictionsToggle.addEventListener('click', (e) => {
      e.preventDefault();
      toggleMlPredictions();
    });
  }
  if (ui.mlPredictionsLimit) {
    ui.mlPredictionsLimit.addEventListener('change', (e) => {
      state.ml.predictionLimit = e.target.value;
      renderMlPredictions();
    });
  }
  if (ui.flowsToggle) {
    ui.flowsToggle.addEventListener('click', (e) => {
      e.preventDefault();
      toggleFlowsPanel();
    });
  }
  if (ui.flowTableLimit) {
    ui.flowTableLimit.addEventListener('change', (e) => {
      state.flowLimit = e.target.value === 'all' ? 'all' : Number(e.target.value) || 50;
      renderTable();
    });
  }
}

function collectUi() {
  ui.authOverlay = document.getElementById('authOverlay');
  ui.authForm = document.getElementById('authForm');
  ui.authLogin = document.getElementById('authLogin');
  ui.authPassword = document.getElementById('authPassword');
  ui.statusBadge = document.getElementById('statusBadge');
  ui.statusDetails = document.getElementById('statusDetails');
  ui.totalFlows = document.getElementById('totalFlows');
  ui.suspiciousFlows = document.getElementById('suspiciousFlows');
  ui.bandwidth = document.getElementById('bandwidth');
  ui.lastFlowLabel = document.getElementById('lastFlowLabel');
  ui.lastFlowSummary = document.getElementById('lastFlowSummary');
  ui.iface = document.getElementById('iface');
  ui.bpf = document.getElementById('bpf');
  ui.flowTimeout = document.getElementById('flowTimeout');
  ui.useNfstream = document.getElementById('use_nfstream');
  ui.startBtn = document.getElementById('startBtn');
  ui.stopBtn = document.getElementById('stopBtn');
  ui.trainBtn = document.getElementById('trainBtn');
  ui.csvBtn = document.getElementById('csvBtn');
  ui.pdfBtn = document.getElementById('pdfBtn');
  ui.labelFilter = document.getElementById('labelFilter');
  ui.tableBody = document.querySelector('#flowsTable tbody');
  ui.tableSearch = document.getElementById('tableSearch');
  ui.tableCounter = document.getElementById('tableCounter');
  ui.mlGrid = document.getElementById('mlGrid');
  ui.mlCards = Array.from(document.querySelectorAll('.ml-card'));
  ui.autoUpdateToggle = document.getElementById('autoUpdateToggle');
  ui.mlPredictionsBody = document.querySelector('#mlPredictions tbody');
  ui.mlRefreshBtn = document.getElementById('refreshMl');
  ui.mlPredictionsPanel = document.getElementById('mlPredictionsPanel');
  ui.mlPredictionsToggle = document.getElementById('toggleMlPredictions');
  ui.mlPredictionsLimit = document.getElementById('mlPredictionsLimit');
  ui.flowsPanel = document.getElementById('flowsPanel');
  ui.flowsToggle = document.getElementById('toggleFlows');
  ui.flowTableLimit = document.getElementById('flowTableLimit');
}

async function verifyAuth(login, password) {
  const token = btoa(`${login}:${password}`);
  try {
    state.authToken = token;
    const res = await apiFetch('/status');
    ui.authOverlay.classList.add('hidden');
    storeAuth(token);
    updateStatusDetails(res);
    await loadInitialData();
    setupWebSocket();
  } catch (err) {
    state.authToken = null;
    ui.authPassword.value = '';
    alert('Неверный логин или пароль.');
  }
}

function initAuth() {
  const saved = sessionStorage.getItem('taAuth');
  if (saved) {
    state.authToken = saved;
    ui.authOverlay.classList.add('hidden');
    loadInitialData().then(setupWebSocket).catch(console.error);
  } else {
    requireAuth();
  }

  ui.authForm.addEventListener('submit', (e) => {
    e.preventDefault();
    verifyAuth(ui.authLogin.value, ui.authPassword.value);
  });
}

function init() {
  collectUi();
  if (ui.mlPredictionsLimit) {
    state.ml.predictionLimit = ui.mlPredictionsLimit.value || 20;
  }
  if (ui.flowTableLimit) {
    state.flowLimit = ui.flowTableLimit.value === 'all' ? 'all' : Number(ui.flowTableLimit.value) || 50;
  }
  applyCollapsible(ui.mlPredictionsPanel, true);
  applyCollapsible(ui.flowsPanel, true);
  initCharts();
  bindEvents();
  initAuth();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}