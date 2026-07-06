'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
let _activeEid = null;
let _scanPollTimer = null;
let _netPollTimer = null;
let _netScanId = null;
let _capEid = null;
let _capPollTimer = null;
let _crawlerJobId = null;
let _crawlerPollTimer = null;
let _crawlerEndpoints = [];
let _proxyAutoTimer = null;
let _burpAutoTimer = null;
let _burpItems = [];
let _reportFindings = [];
let _logCache = [];
let _pastedUrls = [];
let _scannerRequestContexts = [];
let _scanChatActive = false;
let _proxySort = { key: 'index', dir: 'asc' };
let _proxyWatermark = Number(localStorage.getItem('pentest_proxy_watermark') || 0);

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ── Utilities ─────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function statusClass(code) {
  if (!code || code === '—') return 'num';
  const n = parseInt(code);
  if (n >= 500) return 'num' + ' ' + 'status-5xx';
  if (n >= 400) return 'num';
  if (n >= 300) return 'num' + ' ' + 'status-3xx';
  return 'num';
}
function methodBadge(m) {
  const cls = { GET:'badge-get', POST:'badge-post', PUT:'badge-put', DELETE:'badge-delete' }[m?.toUpperCase()] || 'badge-info';
  return `<span class="badge ${cls}">${esc(m || 'GET')}</span>`;
}
function sevBadge(s) {
  return `<span class="badge badge-${(s||'info').toLowerCase()}">${esc(s||'info')}</span>`;
}
function confBadge(c) {
  return `<span class="badge badge-${(c||'possible').toLowerCase()}">${esc(c||'possible')}</span>`;
}

async function api(path, opts={}) {
  const r = await fetch(path, { headers: {'Content-Type':'application/json'}, ...opts });
  return r.json();
}

function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === `panel-${name}`));
  if (name === 'proxy')  { proxyLoad(); startProxyAutoRefresh(); }
  if (name === 'burp')   { burpRefresh(); startBurpAutoRefresh(); }
  if (name === 'report') { loadReport(); }
}

// ── Engagements sidebar ───────────────────────────────────────────────────────
async function loadEngagements() {
  const d = await api('/api/engagements');
  const list = d.engagements || [];
  const el = document.getElementById('eng-items');
  el.innerHTML = '';
  if (!list.length) {
    el.innerHTML = '<div style="padding:8px 6px;font-size:11px;color:#555e73;">No engagements yet</div>';
    return;
  }
  const shouldAutoSelect = !_activeEid;
  if (shouldAutoSelect) {
    _activeEid = list[0].id;
    _capEid = list[0].id;
  }
  list.forEach(eng => {
    const div = document.createElement('div');
    div.className = 'eng-item' + (eng.id === _activeEid ? ' active' : '');
    div.innerHTML = `
      <span class="eng-item-dot ${eng.status || 'idle'}"></span>
      <div class="eng-item-info">
        <div class="eng-item-name" title="${esc(eng.target_url)}">${esc(eng.name)}</div>
        <div class="eng-item-meta">${eng.status} · ${(eng.created_at||'').slice(0,10)}</div>
      </div>
      <button class="eng-item-del" title="Delete" onclick="event.stopPropagation();deleteEngagement('${eng.id}')">×</button>
    `;
    div.addEventListener('click', () => selectEngagement(eng.id));
    el.appendChild(div);
  });
  if (shouldAutoSelect) loadEngagementData(_activeEid);
}

function selectEngagement(eid) {
  _activeEid = eid;
  loadEngagements();
  loadEngagementData(eid);
}

async function newEngagement() {
  const existingTarget = (
    document.getElementById('scan-urls')?.value ||
    document.getElementById('crawl-url')?.value ||
    document.getElementById('cap-url')?.value ||
    ''
  ).trim().split(/\s+/)[0] || '';
  const target = prompt('Target URL for this engagement. This is used to filter Burp imports.', existingTarget);
  if (target === null) return;

  _activeEid = null;
  _capEid = null;
  _crawlerJobId = null;
  _crawlerEndpoints = [];
  _pastedUrls.length = 0;
  _reportFindings = [];
  _logCache = [];
  window._proxyItems = [];
  clearInterval(_scanPollTimer); _scanPollTimer = null;
  clearInterval(_capPollTimer); _capPollTimer = null;
  clearInterval(_crawlerPollTimer); _crawlerPollTimer = null;
  loadEngagements();
  switchTab('scanner');
  clearScanUI();
  clearCaptureUI();
  clearCrawlerUI();
  clearReportUI();
  renderProxyTable([]);
  document.getElementById('proxy-subtitle').textContent = 'Creating engagement...';
  document.getElementById('scan-urls').value = target.trim();
  document.getElementById('crawl-url').value = target.trim();
  document.getElementById('cap-url').value = target.trim();

  const d = await api('/api/engagements', {
    method: 'POST',
    body: JSON.stringify({ target_url: target.trim() }),
  });
  if (d.error || !d.engagement) {
    alert(d.error || 'Could not create engagement.');
    document.getElementById('proxy-subtitle').textContent = 'No engagement selected';
    return;
  }
  _activeEid = d.engagement.id;
  _capEid = d.engagement.id;
  document.querySelectorAll('.eng-item').forEach(el => el.classList.remove('active'));
  await loadEngagements();
  loadEngagementData(d.engagement.id);
  document.getElementById('proxy-subtitle').textContent = 'Saved proxy/capture rows for active engagement';
}

async function loadEngagementData(eid) {
  const d = await api(`/api/scan/${eid}/results`);
  updateScanUI(d);
  renderCaptureState(d);
  _reportFindings = d.findings || [];
  renderStats(_reportFindings);
  renderReport();
  proxyLoad();
  _capEid = eid;
  if (['running','crawling','scanning'].includes(d.status)) {
    startScanPoll();
    clearInterval(_capPollTimer);
    _capPollTimer = setInterval(pollCapture, 2500);
  } else {
    clearInterval(_scanPollTimer); _scanPollTimer = null;
    clearInterval(_capPollTimer); _capPollTimer = null;
    document.getElementById('scan-start-btn').style.display = '';
    document.getElementById('scan-stop-btn').style.display = 'none';
    document.getElementById('cap-start-btn').style.display = '';
    document.getElementById('cap-stop-btn').style.display = 'none';
  }
}

async function deleteEngagement(eid) {
  if (!confirm('Delete this engagement and all its data?')) return;
  await api(`/api/engagements/${eid}`, { method: 'DELETE' });
  if (_activeEid === eid) {
    _activeEid = null;
    _capEid = null;
    clearScanUI();
    clearCaptureUI();
    clearCrawlerUI();
    clearReportUI();
    renderProxyTable([]);
  }
  loadEngagements();
}

async function deleteAllEngagements() {
  if (!confirm('Delete ALL engagements? This cannot be undone.')) return;
  await api('/api/engagements', { method: 'DELETE' });
  _activeEid = null;
  _capEid = null;
  clearScanUI();
  clearCaptureUI();
  clearCrawlerUI();
  clearReportUI();
  document.getElementById('proxy-body').innerHTML = '';
  document.getElementById('proxy-empty').style.display = 'flex';
  loadEngagements();
}

function clearScanUI() {
  clearInterval(_scanPollTimer); _scanPollTimer = null;
  _logCache = [];
  document.getElementById('scan-logs').innerHTML = '';
  document.getElementById('scan-status-label').textContent = 'Idle';
  document.getElementById('scan-status-dot').className = 'status-dot idle';
  document.getElementById('scan-progress-fill').style.width = '0%';
  document.getElementById('scan-progress-pct').textContent = '0%';
  document.getElementById('scan-start-btn').style.display = '';
  document.getElementById('scan-stop-btn').style.display = 'none';
  setScanChatActive(false);
}

function clearCaptureUI() {
  clearInterval(_capPollTimer); _capPollTimer = null;
  document.getElementById('cap-logs').innerHTML = '';
  document.getElementById('cap-status').textContent = 'Ready';
  document.getElementById('cap-start-btn').style.display = '';
  document.getElementById('cap-stop-btn').style.display = 'none';
}

function clearCrawlerUI() {
  clearInterval(_crawlerPollTimer); _crawlerPollTimer = null;
  _crawlerEndpoints = [];
  document.getElementById('crawl-logs').innerHTML = '';
  document.getElementById('crawl-status-label').textContent = 'Idle';
  document.getElementById('crawl-status-dot').className = 'status-dot idle';
  document.getElementById('crawl-progress-fill').style.width = '0%';
  document.getElementById('crawl-progress-pct').textContent = '0%';
  document.getElementById('crawl-start-btn').style.display = '';
  document.getElementById('crawl-stop-btn').style.display = 'none';
  renderCrawlerEndpoints([]);
}

function clearReportUI() {
  _reportFindings = [];
  document.getElementById('report-findings').innerHTML = '';
  document.getElementById('report-stats').innerHTML = '';
  document.getElementById('report-empty').style.display = 'flex';
}

async function stopAll() {
  await api('/api/stop/all', { method: 'POST' });
  loadEngagements();
}

// ── Scanner ───────────────────────────────────────────────────────────────────
async function startScan() {
  const urls = document.getElementById('scan-urls').value.trim();
  if (!urls) { alert('Enter at least one target URL.'); return; }
  _pastedUrls.length = 0;
  _reportFindings = [];
  window._proxyItems = [];
  const requested = new Set(urls.split(/\n+/).map(line => line.trim()).filter(Boolean));
  const requestContexts = _scannerRequestContexts.filter(ctx => requested.has(scanLineForItem(ctx)));

  const body = {
    urls,
    request_contexts: requestContexts,
    username: document.getElementById('scan-username').value,
    password: document.getElementById('scan-password').value,
    login_url: document.getElementById('scan-login-url').value,
    app_notes: document.getElementById('scan-app-notes').value,
    repo_path: document.getElementById('scan-repo-path').value,
    agent_backend: document.getElementById('scan-backend').value,
    use_burp_proxy: document.getElementById('scan-burp-proxy').checked,
    disable_fuzzers: true,
    enable_browser: false,
  };

  const d = await api('/api/scan', { method: 'POST', body: JSON.stringify(body) });
  if (d.error) { alert(d.error); return; }

  _activeEid = d.engagement_id;
  _scannerRequestContexts = [];
  document.getElementById('scan-start-btn').style.display = 'none';
  document.getElementById('scan-stop-btn').style.display = d.status === 'needs_input' ? 'none' : '';
  document.getElementById('scan-logs').innerHTML = '';
  setScanChatActive(true, d.status === 'needs_input' ? 'Send answer to continue...' : 'Send instruction to running agent...');
  _logCache = [];
  startScanPoll();
  loadEngagements();
}

async function stopScan() {
  if (!_activeEid) return;
  await api(`/api/scan/${_activeEid}/stop`, { method: 'POST' });
  document.getElementById('scan-stop-btn').style.display = 'none';
  document.getElementById('scan-start-btn').style.display = '';
}

function startScanPoll() {
  clearInterval(_scanPollTimer);
  _scanPollTimer = setInterval(pollScan, 2500);
  pollScan();
}

async function pollScan() {
  if (!_activeEid) return;
  try {
    const d = await api(`/api/scan/${_activeEid}/results`);
    updateScanUI(d);
    if (!['running','crawling','scanning','needs_input'].includes(d.status)) {
      clearInterval(_scanPollTimer);
      _scanPollTimer = null;
      document.getElementById('scan-stop-btn').style.display = 'none';
      document.getElementById('scan-start-btn').style.display = '';
      setScanChatActive(false);
      loadEngagements();
      loadReport();
    }
  } catch (e) { console.error('pollScan', e); }
}

function updateScanUI(d) {
  const status = d.status || 'idle';
  const dot = document.getElementById('scan-status-dot');
  dot.className = `status-dot ${status}`;
  document.getElementById('scan-status-label').textContent =
    status === 'running' ? `${d.phase || 'scanning'} · ${d.findings?.length || 0} finding(s)` :
    status === 'needs_input' ? `Needs input · ${d.pending_question || 'answer required'}` :
    status === 'completed' ? `Done · ${d.findings?.length || 0} finding(s)` :
    status === 'error' ? `Error: ${d.error || ''}` : status;
  const pct = d.progress || 0;
  document.getElementById('scan-progress-fill').style.width = pct + '%';
  document.getElementById('scan-progress-pct').textContent = pct + '%';
  setScanChatActive(Boolean(d.chat_available || status === 'running' || status === 'needs_input'),
    status === 'needs_input' ? 'Send answer to continue...' : undefined);
  if (d.logs) renderLogs(d.logs);
}

function setScanChatActive(active, placeholder) {
  _scanChatActive = !!active;
  const input = document.getElementById('scan-chat');
  const btn = document.getElementById('scan-chat-send');
  if (!input || !btn) return;
  input.disabled = !_scanChatActive;
  btn.disabled = !_scanChatActive;
  input.placeholder = _scanChatActive ? (placeholder || 'Send instruction to running agent...') : 'Agent inactive';
}

function renderLogs(logs) {
  const verbose = document.getElementById('scan-verbose')?.checked;
  const el = document.getElementById('scan-logs');
  const wasAtBottom = el.scrollHeight - el.scrollTop <= el.clientHeight + 30;
  const src = logs || _logCache;
  _logCache = src;
  el.innerHTML = src
    .filter(l => verbose || l.level !== 'debug')
    .map(l => {
      const isFinding = (l.message||'').includes('FINDING') || (l.message||'').includes('confirmed');
      const isTesting = (l.message||'').startsWith('Testing') || (l.message||'').startsWith('Batch');
      const msgClass = isFinding ? 'finding' : isTesting ? 'testing' : '';
      return `<div class="log-line">
        <span class="log-time">${esc(l.time||'')}</span>
        <span class="log-phase ${l.phase||''}">[${esc(l.phase||'')}]</span>
        <span class="log-msg ${msgClass}">${esc(l.message||'')}</span>
      </div>`;
    }).join('');
  if (wasAtBottom) el.scrollTop = el.scrollHeight;
}

async function sendChat() {
  const input = document.getElementById('scan-chat');
  const msg = input.value.trim();
  if (!msg || !_activeEid) return;
  if (!_scanChatActive) {
    alert('Agent is not active. Start or resume a scan first.');
    return;
  }
  input.value = '';
  _logCache.push({ time: new Date().toTimeString().slice(0,8), phase: 'chat', message: `> ${msg}` });
  renderLogs(_logCache);
  const d = await api(`/api/scan/${_activeEid}/chat`, {
    method: 'POST',
    body: JSON.stringify({ message: msg }),
  });
  if (d.error) {
    _logCache.push({ time: new Date().toTimeString().slice(0,8), phase: 'chat', message: d.error });
  } else if (d.response) {
    _logCache.push({ time: new Date().toTimeString().slice(0,8), phase: 'agent', message: d.response });
  }
  renderLogs(_logCache);
}

// ── Crawler ───────────────────────────────────────────────────────────────────
async function startCrawler() {
  const target = document.getElementById('crawl-url').value.trim();
  if (!target) { alert('Enter a target URL.'); return; }

  const body = {
    target_url: target,
    login_url: document.getElementById('crawl-login-url').value,
    username: document.getElementById('crawl-username').value,
    password: document.getElementById('crawl-password').value,
    use_burp_proxy: document.getElementById('crawl-burp-proxy').checked,
    enable_dirbuster: document.getElementById('crawl-dirbuster').checked,
    enable_browser: document.getElementById('crawl-browser').checked,
    max_pages: document.getElementById('crawl-max-pages').value || '500',
    depth: document.getElementById('crawl-depth').value || '6',
  };

  const d = await api('/api/crawler/start', { method: 'POST', body: JSON.stringify(body) });
  if (d.error) { alert(d.error); return; }

  _crawlerJobId = d.job_id;
  _crawlerEndpoints = [];
  document.getElementById('crawl-start-btn').style.display = 'none';
  document.getElementById('crawl-stop-btn').style.display = '';
  document.getElementById('crawl-logs').innerHTML = '';
  renderCrawlerEndpoints([]);
  startCrawlerPoll();
}

function startCrawlerPoll() {
  clearInterval(_crawlerPollTimer);
  _crawlerPollTimer = setInterval(pollCrawler, 2000);
  pollCrawler();
}

async function pollCrawler() {
  if (!_crawlerJobId) return;
  try {
    const d = await api(`/api/crawler/${_crawlerJobId}`);
    updateCrawlerUI(d);
    if (!['queued','running'].includes(d.status)) {
      clearInterval(_crawlerPollTimer);
      _crawlerPollTimer = null;
      document.getElementById('crawl-stop-btn').style.display = 'none';
      document.getElementById('crawl-start-btn').style.display = '';
    }
  } catch(e) { console.error('pollCrawler', e); }
}

async function stopCrawler() {
  if (!_crawlerJobId) return;
  await api(`/api/crawler/${_crawlerJobId}/stop`, { method: 'POST' });
  document.getElementById('crawl-stop-btn').style.display = 'none';
  document.getElementById('crawl-start-btn').style.display = '';
}

function updateCrawlerUI(d) {
  const status = d.status || 'idle';
  document.getElementById('crawl-status-dot').className = `status-dot ${status}`;
  const count = d.endpoints?.length || 0;
  const detail = status === 'completed'
    ? `Done · ${count} endpoints`
    : status === 'error'
      ? `Error: ${d.error || ''}`
      : `${status}${d.phase ? ' · ' + d.phase : ''}${count ? ' · ' + count + ' endpoints' : ''}`;
  document.getElementById('crawl-status-label').textContent = detail;
  const pct = d.progress || 0;
  document.getElementById('crawl-progress-fill').style.width = pct + '%';
  document.getElementById('crawl-progress-pct').textContent = pct + '%';
  renderCrawlerLogs(d.logs || []);
  if (d.endpoints) renderCrawlerEndpoints(d.endpoints);
}

function renderCrawlerLogs(logs) {
  const el = document.getElementById('crawl-logs');
  const atBottom = el.scrollHeight - el.scrollTop <= el.clientHeight + 30;
  el.innerHTML = logs.map(l =>
    `<div class="log-line"><span class="log-time">${esc(l.time||'')}</span><span class="log-phase ${esc(l.phase||'')}">[${esc(l.phase||'')}]</span><span class="log-msg">${esc(l.message||'')}</span></div>`
  ).join('');
  if (atBottom) el.scrollTop = el.scrollHeight;
}

function crawlerEndpointRank(item) {
  try {
    const u = new URL(item.url || '');
    const path = (u.pathname || '').toLowerCase();
    if (/(sqli|xss|command|csrf|xxe|lfi|rfi|ssii|phpi|ldap|xpath|redirect|upload|idor|insecure|smgmt|jwt|ssti|deserialization)/.test(path)) return 0;
    if (path.endsWith('.php') || path.endsWith('.asp') || path.endsWith('.aspx') || path.endsWith('.jsp')) return 1;
    if (u.search) return 2;
    return 3;
  } catch (_) {
    return 4;
  }
}

function renderCrawlerEndpoints(items) {
  if (items) _crawlerEndpoints = items || [];
  const tbody = document.getElementById('crawl-endpoints-body');
  const empty = document.getElementById('crawl-empty');
  const filter = (document.getElementById('crawl-filter')?.value || '').trim().toLowerCase();
  const visible = [...(_crawlerEndpoints || [])]
    .filter(item => !filter || `${item.method || 'GET'} ${item.url || ''}`.toLowerCase().includes(filter))
    .sort((a, b) => {
      const ar = crawlerEndpointRank(a);
      const br = crawlerEndpointRank(b);
      if (ar !== br) return ar - br;
      return String(a.url || '').localeCompare(String(b.url || ''), undefined, { numeric: true });
    });
  if (!visible.length) {
    tbody.innerHTML = '';
    empty.style.display = 'flex';
    empty.querySelector('p').textContent = _crawlerEndpoints.length
      ? 'No endpoints match the current filter.'
      : 'No endpoints yet. Enter a target and start the crawler.';
    return;
  }
  empty.style.display = 'none';
  tbody.innerHTML = visible.map((item, i) => `
    <tr>
      <td class="num">${i+1}</td>
      <td>${methodBadge(item.method || 'GET')}</td>
      <td class="url-cell" title="${esc(item.url)}">
        <a class="url-link" href="${esc(item.url || '#')}" target="_blank" rel="noopener noreferrer">${esc(item.url)}</a>
      </td>
    </tr>
  `).join('');
}

function crawlerEndpointLines() {
  return (_crawlerEndpoints || []).map(e => `${(e.method || 'GET').toUpperCase()} ${e.url}`).join('\n');
}

async function crawlerCopyEndpoints() {
  const text = crawlerEndpointLines();
  if (!text) { alert('No endpoints to copy.'); return; }
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    alert(text);
  }
}

function crawlerSendToScanner() {
  const text = crawlerEndpointLines();
  if (!text) { alert('No endpoints to send.'); return; }
  document.getElementById('scan-urls').value = text;
  switchTab('scanner');
}

function crawlerSendToProxy() {
  if (!_crawlerEndpoints.length) { alert('No endpoints to add.'); return; }
  _crawlerEndpoints.forEach(e => {
    _pastedUrls.push({ method: e.method || 'GET', url: e.url, status: 0, length: 0 });
  });
  switchTab('proxy');
  proxyLoad();
}

// ── Proxy tab ─────────────────────────────────────────────────────────────────
function startProxyAutoRefresh() {
  clearInterval(_proxyAutoTimer);
  _proxyAutoTimer = setInterval(proxyLoad, 30000);
}

function isAttackValue(value) {
  const v = String(value ?? '');
  return /WHL_CANARY_|<script|onerror=|onload=|sleep\(|union\s+select|\.\.\/|;|\|\||&&|https?:\/\//i.test(v);
}

function collapseValue(value) {
  if (value === undefined || value === null || value === '') return '';
  return isAttackValue(value) ? '{attack_vector}' : '{value}';
}

function normalizeProxyUrl(rawUrl) {
  try {
    const u = new URL(rawUrl || '');
    const path = u.pathname.replace(/\/(\d+|[0-9a-f-]{8,})(?=\/|$)/gi, '/{id}');
    const params = [];
    u.searchParams.forEach((value, key) => {
      params.push(`${key}=${collapseValue(value)}`);
    });
    return params.length ? `${path}?${params.join('&')}` : path;
  } catch (_) {
    return rawUrl || '';
  }
}

function requestBodyPreview(item) {
  const body = item.request_body || item.body || '';
  if (!body) return '';
  const text = String(body).trim();
  if (!text) return '';

  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return Object.entries(parsed)
        .slice(0, 8)
        .map(([k, v]) => `${k}=${collapseValue(v)}`)
        .join('&');
    }
  } catch (_) {}

  try {
    const params = new URLSearchParams(text);
    const parts = [];
    params.forEach((value, key) => parts.push(`${key}=${collapseValue(value)}`));
    if (parts.length) return parts.slice(0, 12).join('&');
  } catch (_) {}

  return text.length > 160 ? text.slice(0, 157) + '...' : text;
}

function proxyItemKey(item) {
  const method = (item.method || 'GET').toUpperCase();
  return `${method}|${normalizeProxyUrl(item.url)}`;
}

function proxyStatusCode(item) {
  const code = item.status_code ?? item.status;
  const parsed = Number(code);
  return Number.isFinite(parsed) ? parsed : null;
}

function responseHeaderValue(item, name) {
  const target = String(name || '').toLowerCase();
  for (const header of (item.response_headers || [])) {
    const idx = String(header).indexOf(':');
    if (idx <= 0) continue;
    const key = String(header).slice(0, idx).trim().toLowerCase();
    if (key === target) return String(header).slice(idx + 1).trim();
  }
  return '';
}

function redirectedFinalItem(item) {
  const status = proxyStatusCode(item);
  if (![301, 302, 303, 307, 308].includes(status)) return null;
  const location = responseHeaderValue(item, 'Location');
  if (!location) return null;
  try {
    const finalUrl = new URL(location, item.url || window.location.href).toString();
    return {
      ...item,
      url: finalUrl,
      method: 'GET',
      status_code: 200,
      status: 200,
      response_length: item.response_length ?? item.length ?? 0,
      _redirectedFrom: item.url || '',
      _redirectStatus: status,
    };
  } catch (_) {
    return null;
  }
}

function proxyDisplayCandidate(item) {
  const status = proxyStatusCode(item);
  if (status === 200) return item;
  return redirectedFinalItem(item);
}

function isAuthGateItem(item) {
  try {
    const u = new URL(item.url || '');
    const path = (u.pathname || '/').toLowerCase();
    if (
      path === '/login' || path === '/login.php' || path.startsWith('/login.php/') ||
      path === '/signin' || path === '/signin.php' ||
      path === '/logout' || path === '/logout.php' || path.startsWith('/logout.php/')
    ) {
      return true;
    }
  } catch (_) {}
  const body = String(item.response_body || '').toLowerCase();
  const title = String(item.title || '').toLowerCase();
  return (
    title.includes('login') ||
    (body.includes('<form') && body.includes('type="password"') && (body.includes('name="login"') || body.includes('name="username"')))
  );
}

function proxySortBy(key) {
  if (_proxySort.key === key) {
    _proxySort.dir = _proxySort.dir === 'asc' ? 'desc' : 'asc';
  } else {
    _proxySort = { key, dir: 'asc' };
  }
  renderProxyTable(window._proxyItems || []);
}

function proxySortValue(item, idx) {
  if (_proxySort.key === 'index') return idx;
  if (_proxySort.key === 'method') return item.method || 'GET';
  if (_proxySort.key === 'vector') return item._vector || normalizeProxyUrl(item.url);
  if (_proxySort.key === 'body') return item._bodyPreview || requestBodyPreview(item);
  if (_proxySort.key === 'status') return Number(item.status_code || item.status || 0);
  if (_proxySort.key === 'length') return Number(item.response_length ?? item.length ?? 0);
  return '';
}

function normalizedHistoryItems(rawItems) {
  const SKIP_EXTS = ['.js','.css','.png','.jpg','.jpeg','.gif','.svg','.ico','.woff','.woff2','.ttf','.map','.pdf','.zip','.webp'];
  const SKIP_HOSTS = ['fonts.googleapis.com','fonts.gstatic.com','safebrowsing','google.com','googleapis.com','gstatic.com','passwordsleakcheck'];
  const seen = new Map();

  (rawItems || []).forEach(item => {
    try {
      const displayItem = proxyDisplayCandidate(item);
      if (!displayItem || proxyStatusCode(displayItem) !== 200) return;
      if (isAuthGateItem(displayItem)) return;
      const u = new URL(displayItem.url || '');
      if (SKIP_HOSTS.some(h => u.hostname.includes(h))) return;
      const ext = u.pathname.slice(u.pathname.lastIndexOf('.')).toLowerCase();
      if (SKIP_EXTS.includes(ext)) return;
      const enriched = {
        ...displayItem,
        _vector: normalizeProxyUrl(displayItem.url),
        _bodyPreview: requestBodyPreview(displayItem),
      };
      const key = proxyItemKey(enriched);
      if (!seen.has(key)) {
        seen.set(key, enriched);
      } else {
        const current = seen.get(key);
        if (current._redirectedFrom && !enriched._redirectedFrom) {
          seen.set(key, enriched);
        } else if (!current.request_body && enriched.request_body) {
          seen.set(key, enriched);
        }
      }
    } catch (_) {}
  });

  return [...seen.values()];
}

async function proxyLoad() {
  try {
    if (!_activeEid) {
      document.getElementById('proxy-subtitle').textContent = 'No engagement selected';
      document.getElementById('proxy-count').textContent = '';
      renderProxyTable([]);
      return;
    }
    const d = await fetch(`/api/proxy/${_activeEid}/history?limit=5000&_t=${Date.now()}`).then(r => r.json());
    document.getElementById('proxy-subtitle').textContent = 'Saved proxy/capture rows for active engagement';
    const raw = d.items || [];

    const seen = new Map();
    // Add pasted URLs first
    _pastedUrls.forEach(item => {
      const displayItem = proxyDisplayCandidate(item);
      if (!displayItem || proxyStatusCode(displayItem) !== 200) return;
      if (isAuthGateItem(displayItem)) return;
      const enriched = {
        ...displayItem,
        _vector: normalizeProxyUrl(displayItem.url),
        _bodyPreview: requestBodyPreview(displayItem),
      };
      seen.set(proxyItemKey(enriched), enriched);
    });
    // Then saved engagement rows (deduped)
    raw.forEach(item => {
      try {
        const displayItem = item;
        if (!displayItem) return;
        if (isAuthGateItem(displayItem)) return;
        const enriched = {
          ...displayItem,
          _vector: normalizeProxyUrl(displayItem.url),
          _bodyPreview: requestBodyPreview(displayItem),
        };
        const key = proxyItemKey(enriched);
        if (!seen.has(key)) {
          seen.set(key, enriched);
        } else {
          const current = seen.get(key);
          if (current._redirectedFrom && !enriched._redirectedFrom) {
            seen.set(key, enriched);
          } else if (!current.request_body && enriched.request_body) {
            seen.set(key, enriched);
          }
        }
      } catch(_) {}
    });

    const items = [...seen.values()];
    renderProxyTable(items);
  } catch(e) {
    document.getElementById('proxy-count').textContent = 'Error';
  }
}

async function proxyImportFromBurp() {
  if (!_activeEid) {
    alert('Select or start an engagement first. Proxy imports are saved per engagement.');
    return;
  }
  const btn = document.getElementById('proxy-import-burp');
  const oldText = btn ? btn.textContent : '';
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Importing…';
  }
  try {
    const d = await api(`/api/proxy/${_activeEid}/import-burp`, {
      method: 'POST',
      body: JSON.stringify({ limit: 5000 }),
    });
    if (!d.ok) {
      alert(d.error || 'Could not import from Burp.');
      return;
    }
    document.getElementById('proxy-subtitle').textContent = `Imported ${d.imported} Burp rows into this engagement`;
    await proxyLoad();
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = oldText || '⇣ Import from Burp';
    }
  }
}

function renderProxyTable(items) {
  const tbody = document.getElementById('proxy-body');
  const empty = document.getElementById('proxy-empty');
  document.getElementById('proxy-count').textContent = items.length ? items.length + (_activeEid ? ' saved rows' : ' 200 OK vectors') : '';

  if (!items.length) {
    tbody.innerHTML = '';
    empty.style.display = 'flex';
    const selectAll = document.getElementById('proxy-select-all');
    if (selectAll) selectAll.checked = false;
    return;
  }
  empty.style.display = 'none';
  const sorted = items.map((item, originalIndex) => ({
    ...item,
    _originalIndex: item._originalIndex ?? originalIndex,
    _vector: item._vector || normalizeProxyUrl(item.url),
    _bodyPreview: item._bodyPreview || requestBodyPreview(item),
  })).sort((a, b) => {
    const av = proxySortValue(a, a._originalIndex);
    const bv = proxySortValue(b, b._originalIndex);
    const cmp = typeof av === 'number' && typeof bv === 'number'
      ? av - bv
      : String(av).localeCompare(String(bv), undefined, { numeric: true });
    return _proxySort.dir === 'asc' ? cmp : -cmp;
  });

  tbody.innerHTML = sorted.map((item, i) => {
    const method = item.method || 'GET';
    const status = item.status_code || item.status || '—';
    const length = item.response_length ?? item.length ?? '—';
    const sClass = parseInt(status) >= 400 ? 'color:var(--red)' : parseInt(status) >= 300 ? 'color:var(--accent)' : 'color:var(--green)';
    const urlTitle = item._redirectedFrom
      ? `${item._redirectStatus} ${item._redirectedFrom} -> ${item.url}`
      : item.url;
    return `<tr>
      <td><input type="checkbox" class="proxy-row-select" data-index="${i}"></td>
      <td class="num">${i+1}</td>
      <td>${methodBadge(method)}</td>
      <td class="url-cell" title="${esc(urlTitle)}">
        <a class="url-link" href="${esc(item.url || '#')}" target="_blank" rel="noopener noreferrer">${esc(item._vector)}</a>
      </td>
      <td style="font-size:12px;font-weight:600;${sClass}">${esc(String(status))}</td>
      <td class="num">${typeof length === 'number' ? length.toLocaleString() : esc(String(length))}</td>
      <td>
        <span style="display:inline-flex;gap:4px;">
          <button class="btn btn-ghost btn-sm" onclick="showReqDetail(${i})">View</button>
          <button class="btn btn-primary btn-sm" onclick="sendProxyRowToScanner(${i})">Send</button>
        </span>
      </td>
    </tr>`;
  }).join('');
  window._proxyItems = sorted;
  const selectAll = document.getElementById('proxy-select-all');
  if (selectAll) selectAll.checked = false;
}

function scanLineForItem(item) {
  if (!item || !item.url) return '';
  const method = (item.method || 'GET').toUpperCase();
  return method === 'GET' ? item.url : `${method} ${item.url}`;
}

function scannerRequestContextForItem(item) {
  if (!item || !item.url) return null;
  return {
    method: (item.method || 'GET').toUpperCase(),
    url: item.url,
    status_code: item.status_code || item.status || 0,
    response_length: item.response_length ?? item.length ?? 0,
    request_headers: item.request_headers || [],
    request_body: item.request_body || item.body || '',
    response_headers: item.response_headers || [],
    response_body: item.response_body || '',
  };
}

function sendItemsToScanner(items) {
  const lines = (items || []).map(scanLineForItem).filter(Boolean);
  if (!lines.length) {
    alert('No URLs selected.');
    return;
  }
  const textarea = document.getElementById('scan-urls');
  const selectedLines = [];
  const seen = new Set();
  lines.forEach(line => {
    if (!seen.has(line)) {
      selectedLines.push(line);
      seen.add(line);
    }
  });
  const ctxSeen = new Set();
  _scannerRequestContexts = (items || [])
    .map(scannerRequestContextForItem)
    .filter(Boolean)
    .filter(ctx => {
      const key = scanLineForItem(ctx);
      if (!key || ctxSeen.has(key)) return false;
      ctxSeen.add(key);
      return true;
    });
  textarea.value = selectedLines.join('\n');
  switchTab('scanner');
  textarea.focus();
}

function selectedProxyItems() {
  return [...document.querySelectorAll('.proxy-row-select:checked')]
    .map(cb => window._proxyItems?.[Number(cb.dataset.index)])
    .filter(Boolean);
}

function toggleProxySelectAll(checked) {
  document.querySelectorAll('.proxy-row-select').forEach(cb => { cb.checked = checked; });
}

function sendProxyRowToScanner(idx) {
  const item = (window._proxyItems || [])[idx];
  sendItemsToScanner(item ? [item] : []);
}

function proxySendSelectedToScanner() {
  sendItemsToScanner(selectedProxyItems());
}

function proxySendAllToScanner() {
  sendItemsToScanner(window._proxyItems || []);
}

async function proxyClear() {
  if (!_activeEid) {
    alert('No engagement selected.');
    return;
  }
  if (!confirm('Clear proxy history for this engagement?')) return;
  await api(`/api/proxy/${_activeEid}/clear`, { method: 'POST' });
  window._proxyItems = [];
  renderProxyTable([]);
}

function showReqDetail(idx) {
  const item = (window._proxyItems || [])[idx];
  if (!item) return;
  document.getElementById('req-modal-method').textContent = item.method || 'GET';
  document.getElementById('req-modal-method').className = `badge badge-${(item.method||'get').toLowerCase()}`;
  document.getElementById('req-modal-url').textContent = item.url || '';
  document.getElementById('req-modal-status').textContent = item.status_code || item.status || '—';
  document.getElementById('req-modal-length').textContent = item.response_length ?? item.length ?? '—';
  document.getElementById('req-modal-req-headers').textContent = (item.request_headers || []).join('\n');
  document.getElementById('req-modal-req-body').textContent = item.request_body || item.body || '—';
  document.getElementById('req-modal-resp-headers').textContent = (item.response_headers || []).join('\n');
  document.getElementById('req-modal-body').textContent = (item.response_body || item.body_preview || '').slice(0, 2000);
  document.getElementById('req-modal').classList.add('open');
}

function sendToCapture(idx) {
  const item = (window._proxyItems || _burpItems)[idx];
  if (!item) return;
  sendItemsToScanner([item]);
}

// ── Capture tab ───────────────────────────────────────────────────────────────
async function captureScan() {
  const url = document.getElementById('cap-url').value.trim();
  if (!url) { alert('Enter a target URL.'); return; }
  _pastedUrls.length = 0;
  _reportFindings = [];
  window._proxyItems = [];

  const body = {
    url,
    cookie: document.getElementById('cap-cookie').value,
    login_url: document.getElementById('cap-login-url').value,
    username: document.getElementById('cap-username').value,
    password: document.getElementById('cap-password').value,
    notes: document.getElementById('cap-notes').value,
    agent_backend: document.getElementById('cap-backend').value,
  };

  const d = await api('/api/capture/scan', { method: 'POST', body: JSON.stringify(body) });
  if (d.error) { alert(d.error); return; }

  _capEid = d.engagement_id;
  _activeEid = d.engagement_id;
  document.getElementById('cap-start-btn').style.display = 'none';
  document.getElementById('cap-stop-btn').style.display = '';
  document.getElementById('cap-logs').innerHTML = '';
  document.getElementById('cap-status').textContent = 'Running…';

  clearInterval(_capPollTimer);
  _capPollTimer = setInterval(pollCapture, 2500);
  loadEngagements();
}

async function captureStop() {
  if (!_capEid) return;
  await api(`/api/scan/${_capEid}/stop`, { method: 'POST' });
  clearInterval(_capPollTimer);
  document.getElementById('cap-stop-btn').style.display = 'none';
  document.getElementById('cap-start-btn').style.display = '';
}

async function pollCapture() {
  if (!_capEid) return;
  try {
    const d = await api(`/api/scan/${_capEid}/results`);
    renderCaptureState(d);
    if (!['running'].includes(d.status)) {
      clearInterval(_capPollTimer);
      document.getElementById('cap-stop-btn').style.display = 'none';
      document.getElementById('cap-start-btn').style.display = '';
      loadEngagements();
    }
  } catch(e) { console.error('pollCapture', e); }
}

function renderCaptureState(d) {
  const logs = d.logs || [];
  const el = document.getElementById('cap-logs');
  if (el) {
    el.innerHTML = logs.map(l =>
      `<div class="log-line"><span class="log-time">${esc(l.time || '')}</span><span class="log-phase ${esc(l.phase || '')}">[${esc(l.phase || '')}]</span><span class="log-msg">${esc(l.message || '')}</span></div>`
    ).join('');
    el.scrollTop = el.scrollHeight;
  }
  const statusEl = document.getElementById('cap-status');
  if (statusEl) statusEl.textContent = `${d.status || 'unknown'} · ${(d.findings || []).length} finding(s)`;
}

// ── Report tab ────────────────────────────────────────────────────────────────
async function loadReport() {
  loadReportTemplateStatus();
  loadSourceReportsStatus();
  loadEvidenceScreenshotsStatus();
  if (!_activeEid) {
    document.getElementById('report-findings').innerHTML = '';
    document.getElementById('report-stats').innerHTML = '';
    document.getElementById('report-empty').style.display = 'flex';
    return;
  }
  const d = await api(`/api/scan/${_activeEid}/results`);
  _reportFindings = d.findings || [];
  renderStats(_reportFindings);
  renderReport();
}

function formatBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

async function loadReportTemplateStatus() {
  const el = document.getElementById('report-template-status');
  if (!el) return;
  try {
    const d = await api('/api/report/template');
    if (!d.exists) {
      el.textContent = 'No default template installed. DOCX export will use the built-in report layout.';
      return;
    }
    const sizeMb = d.size ? (d.size / 1024 / 1024).toFixed(1) : '0.0';
    const when = d.updated_at ? new Date(d.updated_at).toLocaleString() : 'unknown time';
    el.textContent = `${d.name} (${sizeMb} MB) · updated ${when}`;
  } catch (e) {
    el.textContent = 'Could not read template status.';
  }
}

async function loadSourceReportsStatus() {
  const el = document.getElementById('report-source-status');
  if (!el) return;
  try {
    const d = await api('/api/report/source-reports');
    const reports = d.reports || [];
    if (!reports.length) {
      el.textContent = 'No source reports uploaded. Final DOCX will use scanner findings only.';
      return;
    }
    const total = reports.reduce((sum, r) => sum + (r.size || 0), 0);
    el.textContent = `${reports.length} report(s) uploaded · ${formatBytes(total)} total · included in final DOCX`;
  } catch (e) {
    el.textContent = 'Could not read uploaded report list.';
  }
}

async function loadEvidenceScreenshotsStatus() {
  const el = document.getElementById('report-evidence-status');
  if (!el) return;
  try {
    const d = await api('/api/report/evidence-screenshots');
    const images = d.images || [];
    const names = images.slice(0, 8).map(i => i.name).join(', ');
    el.textContent = `${images.length} screenshot(s) in ${d.folder}${names ? ` · ${names}` : ''}`;
  } catch (e) {
    el.textContent = 'Could not read screenshot folder.';
  }
}

async function uploadReportTemplate(input) {
  const file = input.files && input.files[0];
  if (!file) return;
  const el = document.getElementById('report-template-status');
  if (el) el.textContent = `Uploading ${file.name}...`;
  try {
    const r = await fetch('/api/report/template', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'X-Filename': file.name,
      },
      body: await file.arrayBuffer(),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Template upload failed');
    if (el) el.textContent = `${d.name} saved as the default report template.`;
  } catch (e) {
    if (el) el.textContent = e.message || 'Template upload failed.';
  } finally {
    input.value = '';
    loadReportTemplateStatus();
  }
}

async function importSourceReportsFolder() {
  const el = document.getElementById('report-source-status');
  if (el) el.textContent = 'Importing DOCX reports from Downloads...';
  try {
    const r = await fetch('/api/report/source-reports/import-folder', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({}),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Import failed');
    if (el) el.textContent = `Imported ${d.imported}, skipped duplicates ${d.duplicates}, skipped ${d.skipped}.`;
  } catch (e) {
    if (el) el.textContent = e.message || 'Import failed.';
  } finally {
    loadSourceReportsStatus();
  }
}

async function uploadSourceReports(input) {
  const files = Array.from(input.files || []);
  if (!files.length) return;
  const el = document.getElementById('report-source-status');
  let ok = 0;
  try {
    for (const file of files) {
      if (el) el.textContent = `Uploading ${file.name}...`;
      const r = await fetch('/api/report/source-reports', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          'X-Filename': file.name,
        },
        body: await file.arrayBuffer(),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || `Failed uploading ${file.name}`);
      ok += 1;
    }
    if (el) el.textContent = `${ok} source report(s) uploaded.`;
  } catch (e) {
    if (el) el.textContent = e.message || 'Source report upload failed.';
  } finally {
    input.value = '';
    loadSourceReportsStatus();
  }
}

async function clearSourceReports() {
  if (!confirm('Clear uploaded source reports from the final report builder?')) return;
  const el = document.getElementById('report-source-status');
  if (el) el.textContent = 'Clearing uploaded reports...';
  try {
    await fetch('/api/report/source-reports', { method: 'DELETE' });
  } finally {
    loadSourceReportsStatus();
  }
}

function renderStats(findings) {
  const counts = { critical:0, high:0, medium:0, low:0, info:0 };
  findings.forEach(f => { const s = (f.severity||'info').toLowerCase(); if (s in counts) counts[s]++; });
  document.getElementById('report-stats').innerHTML = Object.entries(counts).map(([s,n]) =>
    `<div class="stat-card stat-${s}">
       <div class="val">${n}</div>
       <div class="lbl">${s}</div>
     </div>`
  ).join('');
}

function renderReport() {
  const findings = [..._reportFindings];
  const group = document.getElementById('report-group').value;
  const sort  = document.getElementById('report-sort').value;
  const hideUncertain = document.getElementById('report-hide-uncertain').checked;

  let filtered = findings;
  if (hideUncertain) filtered = filtered.filter(f => f.confidence === 'confirmed' || f.confidence === 'likely');

  filtered.sort((a,b) => {
    if (sort === 'severity') return (SEV_ORDER[a.severity?.toLowerCase()] ?? 9) - (SEV_ORDER[b.severity?.toLowerCase()] ?? 9);
    if (sort === 'confidence') return (a.confidence||'').localeCompare(b.confidence||'');
    return (a.url||'').localeCompare(b.url||'');
  });

  const container = document.getElementById('report-findings');
  const empty = document.getElementById('report-empty');

  if (!filtered.length) {
    container.innerHTML = '';
    empty.style.display = 'flex';
    return;
  }
  empty.style.display = 'none';

  if (group === 'none') {
    container.innerHTML = filtered.map((f,i) => findingCard(f,i)).join('');
    return;
  }

  const key = group === 'severity' ? 'severity' : 'vuln_type';
  const groups = {};
  filtered.forEach(f => {
    const g = f[key] || 'unknown';
    if (!groups[g]) groups[g] = [];
    groups[g].push(f);
  });

  const order = group === 'severity' ? ['critical','high','medium','low','info','unknown'] : Object.keys(groups).sort();
  container.innerHTML = order.filter(g => groups[g]).map(g => `
    <div style="margin-bottom:20px;">
      <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;display:flex;align-items:center;gap:8px;">
        ${group === 'severity' ? sevBadge(g) : `<span style="color:var(--text-2)">${esc(g)}</span>`}
        <span style="color:var(--text-2);font-weight:400;">${groups[g].length} finding(s)</span>
      </div>
      ${groups[g].map((f,i) => findingCard(f, g+i)).join('')}
    </div>
  `).join('');
}

function normalizeRawText(value) {
  return String(value || '').replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\r\n/g, '\n');
}

function shellQuote(value) {
  return `'${String(value ?? '').replace(/'/g, `'\\''`)}'`;
}

function parseRawRequest(raw) {
  const text = normalizeRawText(raw);
  const [head, ...bodyParts] = text.split(/\n\n/);
  const lines = (head || '').split('\n').map(l => l.trim()).filter(Boolean);
  const requestLine = lines.shift() || '';
  const match = requestLine.match(/^([A-Z]+)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i);
  return {
    method: match ? match[1].toUpperCase() : '',
    path: match ? match[2] : '',
    headers: lines.filter(l => /^[^:]+:\s*/.test(l)),
    body: bodyParts.join('\n\n').trim(),
  };
}

function absoluteUrlFromFinding(f, parsedReq) {
  const rawUrl = f.url || '';
  try {
    const base = new URL(rawUrl);
    if (parsedReq?.path && parsedReq.path.startsWith('/')) return `${base.origin}${parsedReq.path}`;
    return base.href;
  } catch (_) {
    const hostLine = (parsedReq?.headers || []).find(h => /^host:/i.test(h));
    const host = hostLine ? hostLine.split(':').slice(1).join(':').trim() : '';
    if (host && parsedReq?.path) return `http://${host}${parsedReq.path}`;
    return rawUrl;
  }
}

function buildCurlCommand(f, parsedReq, responseUrl) {
  if (f.curl_command) return normalizeRawText(f.curl_command).trim();
  const method = (f.method || parsedReq.method || 'GET').toUpperCase();
  const headers = (parsedReq.headers || [])
    .filter(h => !/^content-length:/i.test(h))
    .filter(h => !/^accept-encoding:/i.test(h));
  const body = parsedReq.body || (method !== 'GET' ? (f.payload || '') : '');
  const parts = ['curl', '-i', '-sS', '--path-as-is'];
  if (method && method !== 'GET') parts.push('-X', method);
  parts.push(shellQuote(responseUrl || f.url || ''));
  headers.forEach(h => parts.push('-H', shellQuote(h)));
  if (body) parts.push('--data-raw', shellQuote(body));
  return parts.join(' ');
}

function buildRetestSteps(f, responseUrl) {
  const method = (f.method || 'GET').toUpperCase();
  const steps = [
    `1. Open the clickable URL in a browser: ${responseUrl || f.url || 'target URL'}`,
    '2. Copy the curl command below and run it in a terminal.',
    `3. Confirm the response status and body match the finding evidence.`,
  ];
  if (f.evidence) steps.push(`4. Confirm this evidence is present: ${f.evidence}`);
  else if (f.response) steps.push('4. Confirm the Response Evidence block is present in the response.');
  else steps.push('4. Confirm the vulnerable behavior is still present.');
  steps.push(`5. After remediation, repeat the same ${method} request and confirm the evidence is gone or access is denied.`);
  return steps.join('\n');
}

function buildPocText(f, curlCommand, responseUrl) {
  const lines = [
    `PoC target: ${responseUrl || f.url || '—'}`,
    'PoC action: run the Copy/Paste Curl command exactly as shown.',
  ];
  if (f.payload) lines.push(`Payload/input: ${f.payload}`);
  if (f.response) lines.push(`Observed response evidence: ${normalizeRawText(f.response).slice(0, 500)}`);
  else if (f.evidence) lines.push(`Observed evidence: ${f.evidence}`);
  lines.push('Expected fixed behavior: request no longer returns the exposed data or vulnerable behavior.');
  return lines.join('\n');
}

function jsonArg(value) {
  return JSON.stringify(normalizeRawText(value)).replace(/</g, '\\u003c');
}

function copyText(text) {
  const value = normalizeRawText(text);
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(value).catch(() => window.prompt('Copy this text', value));
  } else {
    window.prompt('Copy this text', value);
  }
}

function findingCard(f, idx) {
  const id = `fc-${idx}`;
  const severityClass = `sev-${(f.severity || 'info').toLowerCase()}`;
  const parsedReq = parseRawRequest(f.request || '');
  const responseUrl = absoluteUrlFromFinding(f, parsedReq);
  const curlCommand = buildCurlCommand(f, parsedReq, responseUrl);
  const retestSteps = buildRetestSteps(f, responseUrl);
  const pocText = f.poc ? normalizeRawText(f.poc) : buildPocText(f, curlCommand, responseUrl);
  return `
    <div class="finding-row ${esc(severityClass)}">
      <div class="finding-summary" onclick="toggleFinding('${id}')">
        ${sevBadge(f.severity)}
        ${confBadge(f.confidence)}
        <span style="font-size:12px;font-weight:600;flex:0 0 auto;">${esc(f.vuln_type||'')}</span>
        <a class="url-link" style="flex:1;" href="${esc(responseUrl || '#')}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">${esc(responseUrl || f.url || '')}</a>
        ${methodBadge(f.method)}
        ${f.parameter ? `<code style="font-size:10px;color:var(--text-2);">${esc(f.parameter)}</code>` : ''}
      </div>
      <div class="finding-detail" id="${id}">
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
          <a class="btn btn-sm btn-ghost" href="${esc(responseUrl || '#')}" target="_blank" rel="noopener noreferrer">Open response</a>
          <button class="btn btn-sm btn-ghost" onclick="copyText(${jsonArg(curlCommand)})">Copy curl</button>
          <button class="btn btn-sm btn-ghost" onclick="copyText(${jsonArg(retestSteps)})">Copy retest steps</button>
        </div>
        <div class="detail-grid">
          <div><div class="detail-label">Evidence</div><div class="detail-val">${esc(f.evidence||'—')}</div></div>
          <div><div class="detail-label">Payload</div><div class="detail-val"><code class="mono">${esc(f.payload||'—')}</code></div></div>
          <div><div class="detail-label">Risk Reasoning</div><div class="detail-val">${esc(f.risk_reasoning||'—')}</div></div>
          <div><div class="detail-label">Attack Narrative</div><div class="detail-val">${esc(f.attack_narrative||'—')}</div></div>
        </div>
        <div style="margin-bottom:10px;"><div class="detail-label" style="margin-bottom:4px;">Retest Steps</div><pre class="code-block">${esc(retestSteps)}</pre></div>
        <div style="margin-bottom:10px;"><div class="detail-label" style="margin-bottom:4px;">Copy/Paste Curl</div><pre class="code-block">${esc(curlCommand)}</pre></div>
        <div style="margin-bottom:10px;"><div class="detail-label" style="margin-bottom:4px;">PoC</div><pre class="code-block">${esc(pocText)}</pre></div>
        ${f.request ? `<div style="margin-bottom:10px;"><div class="detail-label" style="margin-bottom:4px;">Raw Request</div><pre class="code-block" style="max-height:180px;overflow-y:auto;">${esc(normalizeRawText(f.request))}</pre></div>` : ''}
        ${f.response ? `<div><div class="detail-label" style="margin-bottom:4px;">Response Evidence</div><pre class="code-block" style="max-height:180px;overflow-y:auto;">${esc(normalizeRawText(f.response))}</pre></div>` : ''}
      </div>
    </div>`;
}

function toggleFinding(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
}

function downloadReport(fmt) {
  if (!_activeEid) { alert('Select an engagement first.'); return; }
  window.open(`/api/scan/${_activeEid}/report?format=${fmt}`, '_blank');
}

// ── Network tab ───────────────────────────────────────────────────────────────
async function netStart() {
  const targets = document.getElementById('net-targets').value.trim();
  if (!targets) { alert('Enter target IPs or hostnames.'); return; }

  const body = {
    targets,
    ports: document.getElementById('net-ports').value,
    rate: document.getElementById('net-rate').value,
    sudo_password: document.getElementById('net-sudo').value,
  };

  const d = await api('/api/network/scan', { method: 'POST', body: JSON.stringify(body) });
  if (d.error) { alert(d.error); return; }
  _netScanId = d.scan_id;

  document.getElementById('net-start-btn').style.display = 'none';
  document.getElementById('net-stop-btn').style.display = '';
  document.getElementById('net-logs').innerHTML = '';
  document.getElementById('net-status').textContent = 'Running…';

  clearInterval(_netPollTimer);
  _netPollTimer = setInterval(pollNet, 2500);
}

async function netStop() {
  if (!_netScanId) return;
  await api(`/api/network/scan/${_netScanId}/stop`, { method: 'POST' });
  clearInterval(_netPollTimer);
  document.getElementById('net-stop-btn').style.display = 'none';
  document.getElementById('net-start-btn').style.display = '';
}

async function pollNet() {
  if (!_netScanId) return;
  try {
    const d = await api(`/api/network/scan/${_netScanId}/status`);
    const logs = d.logs || [];
    const el = document.getElementById('net-logs');
    const atBottom = el.scrollHeight - el.scrollTop <= el.clientHeight + 30;
    el.innerHTML = logs.map(l =>
      `<div class="log-line"><span class="log-time">${esc(l.time||'')}</span><span class="log-phase">[${esc(l.phase||'')}]</span><span class="log-msg">${esc(l.message||'')}</span></div>`
    ).join('');
    if (atBottom) el.scrollTop = el.scrollHeight;
    document.getElementById('net-status').textContent = d.status || 'running';
    const pct = d.progress || 0;
    document.getElementById('net-progress-fill').style.width = pct + '%';
    if (!['running'].includes(d.status)) {
      clearInterval(_netPollTimer);
      document.getElementById('net-stop-btn').style.display = 'none';
      document.getElementById('net-start-btn').style.display = '';
    }
  } catch(e) { console.error('pollNet', e); }
}

// ── Burp tab ──────────────────────────────────────────────────────────────────
let _burpWatermark = Number(localStorage.getItem('pentest_burp_watermark') || 0);

function startBurpAutoRefresh() {
  clearInterval(_burpAutoTimer);
  _burpAutoTimer = setInterval(burpRefresh, 30000);
}

function burpSubTab(name) {
  ['history','issues','sitemap','repeater'].forEach(t => {
    document.getElementById(`burp-tab-${t}`)?.classList.toggle('active', t === name);
    const panel = document.getElementById(`burp-panel-${t}`);
    if (panel) { panel.style.display = t === name ? (t === 'repeater' ? 'flex' : 'block') : 'none'; }
  });
  if (name === 'issues') loadBurpIssues();
  if (name === 'sitemap') loadBurpSitemap();
}

async function burpRefresh() {
  const search = document.getElementById('burp-search').value.trim();
  const params = new URLSearchParams({ limit: '5000', _t: Date.now() });
  if (search) params.set('search', search);
  if (_burpWatermark > 0) params.set('after_index', String(_burpWatermark));

  try {
    const d = await fetch(`/api/burp/history?${params}`).then(r => r.json());

    // Update status
    const statusEl = document.getElementById('burp-status-text');
    const dot = document.getElementById('burp-dot');
    if (d.error) {
      statusEl.textContent = 'Burp not connected';
      dot.className = 'dot dot-red';
    } else {
      const total = d.total_in_history || 0;
      statusEl.textContent = _burpWatermark > 0
        ? `Burp connected — showing new items after clear point ${_burpWatermark} (${total} total in Burp)`
        : `Burp connected — ${total} total items`;
      dot.className = 'dot dot-green';
    }

    const raw = d.items || [];
    const items = normalizedHistoryItems(raw);

    _burpItems = items;
    renderBurpHistory(items);
  } catch(e) {
    document.getElementById('burp-status-text').textContent = 'Burp not connected';
    document.getElementById('burp-dot').className = 'dot dot-red';
  }
}

function renderBurpHistory(items) {
  const tbody = document.getElementById('burp-history-body');
  const empty = document.getElementById('burp-history-empty');

  if (!items.length) {
    tbody.innerHTML = '';
    const selectAll = document.getElementById('burp-select-all');
    if (selectAll) selectAll.checked = false;
    empty.innerHTML = _burpWatermark > 0
      ? '<p>No new Burp rows after the clear point. Click Show all to load existing Burp history.</p>'
      : '<p>No proxy history from Burp yet.</p>';
    empty.style.display = 'flex';
    return;
  }
  empty.style.display = 'none';
  tbody.innerHTML = items.map((item, i) => {
    const method = item.method || 'GET';
    const status = item.status_code || '—';
    const length = item.response_length ?? '—';
    const sColor = parseInt(status) >= 400 ? 'var(--red)' : parseInt(status) >= 300 ? 'var(--accent)' : 'var(--green)';
    const urlTitle = item._redirectedFrom
      ? `${item._redirectStatus} ${item._redirectedFrom} -> ${item.url}`
      : item.url;
    return `<tr>
      <td><input type="checkbox" class="burp-row-select" data-index="${i}"></td>
      <td class="num">${i+1}</td>
      <td>${methodBadge(method)}</td>
      <td class="url-cell" title="${esc(urlTitle)}">
        <a class="url-link" href="${esc(item.url || '#')}" target="_blank" rel="noopener noreferrer">${esc(item._vector || normalizeProxyUrl(item.url))}</a>
      </td>
      <td style="font-size:12px;font-weight:600;color:${sColor};">${esc(String(status))}</td>
      <td class="num">${typeof length === 'number' ? length.toLocaleString() : esc(String(length))}</td>
      <td>
        <span style="display:inline-flex;gap:4px;">
          <button class="btn btn-ghost btn-sm" onclick="burpViewItem(${i})">View</button>
          <button class="btn btn-primary btn-sm" onclick="burpSendRowToScanner(${i})">Send</button>
        </span>
      </td>
    </tr>`;
  }).join('');
  const selectAll = document.getElementById('burp-select-all');
  if (selectAll) selectAll.checked = false;
}

async function burpClearDisplay() {
  const d = await api('/api/burp/history/clear', { method: 'POST' });
  if (!d.ok) {
    alert(d.error || 'Burp is not reachable.');
    return;
  }
  _burpWatermark = Number(d.total || 0);
  localStorage.setItem('pentest_burp_watermark', String(_burpWatermark));
  _burpItems = [];
  const statusEl = document.getElementById('burp-status-text');
  if (statusEl) {
    statusEl.textContent = `Burp connected — showing new items after clear point ${_burpWatermark} (${_burpWatermark} total in Burp)`;
  }
  renderBurpHistory([]);
}

function burpShowAll() {
  _burpWatermark = 0;
  localStorage.removeItem('pentest_burp_watermark');
  burpRefresh();
}

function burpViewItem(idx) {
  const item = _burpItems[idx];
  if (!item) return;
  document.getElementById('req-modal-method').textContent = item.method || 'GET';
  document.getElementById('req-modal-method').className = `badge badge-${(item.method||'get').toLowerCase()}`;
  document.getElementById('req-modal-url').textContent = item.url || '';
  document.getElementById('req-modal-status').textContent = item.status_code || '—';
  document.getElementById('req-modal-length').textContent = item.response_length ?? '—';
  document.getElementById('req-modal-req-headers').textContent = (item.request_headers || []).join('\n');
  document.getElementById('req-modal-req-body').textContent = item.request_body || item.body || '—';
  document.getElementById('req-modal-resp-headers').textContent = (item.response_headers || []).join('\n');
  document.getElementById('req-modal-body').textContent = (item.response_body || '').slice(0,2000);
  document.getElementById('req-modal').classList.add('open');
}

function selectedBurpItems() {
  return [...document.querySelectorAll('.burp-row-select:checked')]
    .map(cb => _burpItems?.[Number(cb.dataset.index)])
    .filter(Boolean);
}

function toggleBurpSelectAll(checked) {
  document.querySelectorAll('.burp-row-select').forEach(cb => { cb.checked = checked; });
}

function burpSendRowToScanner(idx) {
  const item = _burpItems[idx];
  if (!item) return;
  sendItemsToScanner([item]);
}

function burpSendSelectedToScanner() {
  sendItemsToScanner(selectedBurpItems());
}

function burpSendAllToScanner() {
  sendItemsToScanner(_burpItems || []);
}

function burpSendToCapture(idx) {
  burpSendRowToScanner(idx);
}

async function loadBurpIssues() {
  const d = await api('/api/burp/issues');
  const el = document.getElementById('burp-issues-body');
  const issues = d.issues || d.items || [];
  if (!issues.length) { el.innerHTML = '<div class="empty-state"><p>No scanner issues found.</p></div>'; return; }
  el.innerHTML = issues.map(iss => `
    <div class="finding-row" style="margin-bottom:8px;">
      <div class="finding-summary">
        ${sevBadge(iss.severity)}
        <span style="font-size:12px;font-weight:600;">${esc(iss.issue_type||iss.name||'')}</span>
        <span class="url-cell" style="flex:1;color:var(--text-2);">${esc(iss.url||'')}</span>
      </div>
    </div>`).join('');
}

async function loadBurpSitemap() {
  const d = await api('/api/burp/sitemap');
  const el = document.getElementById('burp-sitemap-body');
  const items = d.items || d.resources || [];
  if (!items.length) { el.innerHTML = '<div class="empty-state"><p>Sitemap empty.</p></div>'; return; }
  el.innerHTML = items.map(i => `<div style="padding:3px 0;color:var(--text-2);">${esc(i.url||JSON.stringify(i))}</div>`).join('');
}

async function repSend() {
  const body = {
    host: document.getElementById('rep-host').value,
    port: parseInt(document.getElementById('rep-port').value) || 443,
    https: document.getElementById('rep-https').checked,
    request: document.getElementById('rep-request').value,
  };
  const d = await api('/api/burp/send', { method: 'POST', body: JSON.stringify(body) });
  document.getElementById('rep-response').textContent = d.response || JSON.stringify(d, null, 2);
}

// ── Burp connection status poll ───────────────────────────────────────────────
async function pollBurpStatus() {
  try {
    const d = await api('/api/burp/status');
    document.getElementById('burp-dot').className = `dot ${d.connected ? 'dot-green' : 'dot-grey'}`;
  } catch(_) {}
}

// ── Paste URLs Modal ─────────────────────────────────────────────────────────
function openPasteUrlsModal() {
  const m = document.getElementById('paste-urls-modal');
  m.style.display = 'flex';
  setTimeout(() => document.getElementById('paste-urls-input').focus(), 50);
}

function closePasteUrlsModal() {
  document.getElementById('paste-urls-modal').style.display = 'none';
  document.getElementById('paste-urls-input').value = '';
  document.getElementById('paste-urls-count').textContent = '';
}

async function submitPasteUrls() {
  const raw = document.getElementById('paste-urls-input').value;
  const entries = raw.split('\n').map(l => l.trim()).filter(l => l.length > 0).map(line => {
    const parts = line.split(/\s+/);
    if (parts.length >= 2 && ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'].includes(parts[0].toUpperCase())) {
      return { method: parts[0].toUpperCase(), url: parts.slice(1).join(' ') };
    }
    return { method: 'GET', url: line };
  });

  if (!entries.length) { alert('No URLs found.'); return; }

  // Store in persistent array so proxy refresh doesn't wipe them
  entries.forEach(e => {
    const key = (e.method||'GET') + '|' + e.url;
    if (!_pastedUrls.find(p => (p.method||'GET')+'|'+p.url === key)) {
      _pastedUrls.push({ method: e.method, url: e.url, status_code: '—', response_length: '—', _pasted: true });
    }
  });

  closePasteUrlsModal();
  proxyLoad(); // re-render with pasted URLs merged in
}

Object.assign(window, {
  burpClearDisplay,
  burpRefresh,
  burpSendAllToScanner,
  burpSendRowToScanner,
  burpSendSelectedToScanner,
  burpShowAll,
  burpSubTab,
  burpSendToCapture,
  burpViewItem,
  captureScan,
  captureStop,
  closeModal,
  closePasteUrlsModal,
  clearSourceReports,
  copyText,
  crawlerCopyEndpoints,
  crawlerSendToProxy,
  crawlerSendToScanner,
  deleteAllEngagements,
  deleteEngagement,
  downloadReport,
  importSourceReportsFolder,
  loadEvidenceScreenshotsStatus,
  loadReportTemplateStatus,
  loadSourceReportsStatus,
  loadBurpIssues,
  loadBurpSitemap,
  netStart,
  netStop,
  newEngagement,
  openPasteUrlsModal,
  proxyClear,
  proxyImportFromBurp,
  proxyLoad,
  proxySendAllToScanner,
  proxySendSelectedToScanner,
  proxySortBy,
  renderLogs,
  renderReport,
  repSend,
  sendChat,
  sendToCapture,
  showReqDetail,
  startCrawler,
  startScan,
  stopAll,
  stopCrawler,
  stopScan,
  submitPasteUrls,
  switchTab,
  toggleFinding,
  toggleBurpSelectAll,
  toggleProxySelectAll,
  uploadReportTemplate,
  uploadSourceReports,
});

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadEngagements();
  pollBurpStatus();
  setInterval(pollBurpStatus, 15000);
  setInterval(loadEngagements, 10000);

  // Paste URLs modal — live URL count
  const pasteInput = document.getElementById('paste-urls-input');
  if (pasteInput) {
    pasteInput.addEventListener('input', () => {
      const count = pasteInput.value.split('\n').map(l => l.trim()).filter(l => l).length;
      document.getElementById('paste-urls-count').textContent = count ? `${count} URL${count !== 1 ? 's' : ''}` : '';
    });
  }

  // Close modal on backdrop click
  document.getElementById('paste-urls-modal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('paste-urls-modal')) closePasteUrlsModal();
  });
});
