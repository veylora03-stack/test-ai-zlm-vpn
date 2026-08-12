// ERROR-PANEL — App Logic
// Tab router, Dashboard KPIs, Servers CRUD, Sources CRUD, Quarantine, Analytics, Toast, Confirm

'use strict';

// ── Status label map (Persian) ──────────────────────────────────────────────
const STATUS_LABELS = {
  new: 'جدید', quarantined: 'قرنطینه', pending_review: 'در انتظار بررسی',
  approved: 'تایید شده', tested: 'تست شده', failed: 'ناموفق',
  blocked: 'مسدود', archived: 'آرشیو',
  active: 'فعال', paused: 'متوقف', suspicious: 'مشکوک',
};

// ── Toast ───────────────────────────────────────────────────────────────────
// Toast now handled by ui-components.js

// ── Confirm wrapper ─────────────────────────────────────────────────────────
// Confirm now handled by ui-components.js

// ── Tab Router ──────────────────────────────────────────────────────────────
function initTabs() {
  const navLinks = document.querySelectorAll('.nav-list a[data-tab]');
  const sections = document.querySelectorAll('.tab-section');

  navLinks.forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const tab = link.getAttribute('data-tab');

      navLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');

      sections.forEach(s => s.classList.remove('active'));
      const target = document.getElementById('tab-' + tab);
      if (target) target.classList.add('active');

      // Load data on tab switch
      onTabSwitch(tab);
    });
  });
}

// Load data appropriate to the active tab
async function onTabSwitch(tab) {
  try {
    switch (tab) {
      case 'dashboard': await loadDashboard(); break;
      case 'servers':   await loadServers();   break;
      case 'sources':   await loadSources();   break;
      case 'quarantine': await loadQuarantine(); break;
      case 'analytics': await loadAnalytics(); break;
      case 'settings':  await loadSettingsTab();  break;
      case 'logs':      await loadLogsTab();      break;
    }
  } catch (err) {
    toast('خطا: ' + err.message, 'error');
  }
}

// ── Dashboard ───────────────────────────────────────────────────────────────
async function loadDashboard() {
  let analytics;
  try {
    analytics = await getAnalytics();
  } catch (_) {
    analytics = null;
  }

  const grid = document.getElementById('kpi-grid');

  if (analytics) {
    const counts = analytics.counts_by_status || {};
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    const quarantined = (counts.quarantined || 0) + (counts.pending_review || 0);
    const approved = (counts.approved || 0) + (counts.tested || 0);

    grid.innerHTML = [
      { label: 'کل پروفایل‌ها', value: total },
      { label: 'در قرنطینه', value: quarantined },
      { label: 'تایید شده', value: approved },
      { label: 'منابع فعال', value: analytics.sources_active || 0 },
    ].map(k => `
      <div class="kpi-card">
        <div class="kpi-value">${k.value}</div>
        <div class="kpi-label">${k.label}</div>
      </div>
    `).join('');
  } else {
    // Fallback: load from profiles/sources
    const [profiles, sources] = await Promise.all([listProfiles(), listSources()]);
    const total = profiles.length;
    const quarantined = profiles.filter(p => p.status === 'quarantined' || p.status === 'pending_review').length;
    const approved = profiles.filter(p => p.status === 'approved' || p.status === 'tested').length;
    const activeSources = sources.filter(s => s.status === 'active').length;

    grid.innerHTML = [
      { label: 'کل پروفایل‌ها', value: total },
      { label: 'در قرنطینه', value: quarantined },
      { label: 'تایید شده', value: approved },
      { label: 'منابع فعال', value: activeSources },
    ].map(k => `
      <div class="kpi-card">
        <div class="kpi-value">${k.value}</div>
        <div class="kpi-label">${k.label}</div>
      </div>
    `).join('');
  }

  // Top-3 lists
  const topGrid = document.getElementById('top-lists-grid');
  if (topGrid) {
    let pingTop = [], scoreTop = [];
    try {
      pingTop = await getRanking('ping', 3);
    } catch (_) {}
    try {
      scoreTop = await getRanking('score', 3);
    } catch (_) {}

    topGrid.innerHTML = `
      <div class="top-card glass">
        <h3 class="top-title">🚀 کمترین پینگ</h3>
        <ol class="top-list">
          ${pingTop.length === 0 ? '<li style="color:var(--text-muted)">داده‌ای نیست</li>' :
            pingTop.map(p => `<li><span class="top-name">${esc(p.name)}</span> <span class="top-val">${p.ping_ms !== null ? p.ping_ms.toFixed(0) + ' ms' : '—'}</span></li>`).join('')
          }
        </ol>
      </div>
      <div class="top-card glass">
        <h3 class="top-title">⭐ بهترین امتیاز</h3>
        <ol class="top-list">
          ${scoreTop.length === 0 ? '<li style="color:var(--text-muted)">داده‌ای نیست</li>' :
            scoreTop.map(p => `<li><span class="top-name">${esc(p.name)}</span> <span class="top-val">${(p.score * 100).toFixed(1)}</span></li>`).join('')
          }
        </ol>
      </div>
    `;
  }

  // Recent 5 profiles
  let profiles;
  try {
    profiles = await listProfiles();
  } catch (_) {
    profiles = [];
  }
  const recent = [...profiles].sort((a, b) => b.id - a.id).slice(0, 5);
  const list = document.getElementById('recent-profiles');
  if (recent.length === 0) {
    list.innerHTML = '<li style="color:var(--text-muted)">پروفایلی یافت نشد</li>';
  } else {
    list.innerHTML = recent.map(p => `
      <li>
        <span class="rl-name">${esc(p.name)}</span>
        <span class="rl-meta">${p.protocol} · <span class="badge badge-${p.status}">${STATUS_LABELS[p.status] || p.status}</span></span>
      </li>
    `).join('');
  }
}

// ── Servers Tab ─────────────────────────────────────────────────────────────
async function loadServers() {
  const search   = document.getElementById('servers-search').value.trim();
  const status   = document.getElementById('servers-status-filter').value;
  const protocol = document.getElementById('servers-protocol-filter').value;

  const profiles = await listProfiles({ search: search || undefined, status: status || undefined, protocol: protocol || undefined });
  renderServersTable(profiles);
}

function renderServersTable(profiles) {
  const tbody = document.getElementById('servers-tbody');
  if (profiles.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted)">نتیجه‌ای یافت نشد</td></tr>';
    return;
  }
  tbody.innerHTML = profiles.map(p => `
    <tr>
      <td>${esc(p.name)}</td>
      <td>${p.protocol}</td>
      <td style="direction:ltr;text-align:left">${esc(p.server_host || '—')}:${p.server_port || '—'}</td>
      <td>${esc(p.country_code || '—')}</td>
      <td><span class="badge badge-${p.status}">${STATUS_LABELS[p.status] || p.status}</span></td>
      <td>${p.risk_score}</td>
      <td class="actions">
        <button class="btn btn-accent btn-sm" onclick="runTestAction(${p.id})">تست</button>
        <button class="btn btn-ghost btn-sm" onclick="editProfile(${p.id})">ویرایش</button>
        <button class="btn btn-danger btn-sm" onclick="removeProfile(${p.id}, ${JSON.stringify(p.name)})">حذف</button>
      </td>
    </tr>
  `).join('');
}

async function runTestAction(id) {
  try {
    const result = await runTest(id);
    if (result.reachable) {
      toast(`تست: پینگ ${result.ping_ms !== null ? result.ping_ms.toFixed(0) + ' ms' : '—'} | از دست رفتن ${result.packet_loss_pct}%`, 'success');
    } else {
      toast('تست: غیرقابل دسترس', 'error');
    }
    await loadServers();
  } catch (err) {
    toast('خطا در تست: ' + err.message, 'error');
  }
}

function initServersToolbar() {
  document.getElementById('servers-search').addEventListener('input', debounce(loadServers, 200));
  document.getElementById('servers-status-filter').addEventListener('change', loadServers);
  document.getElementById('servers-protocol-filter').addEventListener('change', loadServers);
  document.getElementById('servers-refresh').addEventListener('click', loadServers);
  document.getElementById('servers-add').addEventListener('click', () => openProfileModal());
}

// ── Profile Modal ───────────────────────────────────────────────────────────
function openProfileModal(profile) {
  const form = document.getElementById('profile-form');
  const title = document.getElementById('modal-title');
  const idField = document.getElementById('modal-profile-id');

  if (profile) {
    title.textContent = 'ویرایش پروفایل';
    idField.value = profile.id;
    form.name.value = profile.name;
    form.protocol.value = profile.protocol;
    form.server_host.value = profile.server_host || '';
    form.server_port.value = profile.server_port || '';
    form.country_code.value = profile.country_code || '';
    form.status.value = profile.status;
    form.risk_score.value = profile.risk_score;
    form.notes.value = profile.notes || '';
  } else {
    title.textContent = 'افزودن پروفایل';
    idField.value = '';
    form.reset();
  }

  document.getElementById('profile-modal').classList.add('open');
}

function closeProfileModal() {
  document.getElementById('profile-modal').classList.remove('open');
}

async function editProfile(id) {
  try {
    const p = await getProfile(id);
    openProfileModal(p);
  } catch (err) {
    toast('خطا در بارگذاری: ' + err.message, 'error');
  }
}

async function removeProfile(id, name) {
  if (!await confirmAction(`آیا از حذف "${name}" مطمئن هستید؟`)) return;
  try {
    await deleteProfile(id);
    toast('پروفایل حذف شد', 'success');
    await loadServers();
  } catch (err) {
    toast('خطا: ' + err.message, 'error');
  }
}

function initProfileModal() {
  document.getElementById('modal-cancel').addEventListener('click', closeProfileModal);
  document.getElementById('profile-modal').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeProfileModal();
  });

  document.getElementById('profile-form').addEventListener('submit', async e => {
    e.preventDefault();
    const form = e.target;
    const id = document.getElementById('modal-profile-id').value;
    const data = {
      name: form.name.value,
      protocol: form.protocol.value,
      server_host: form.server_host.value || null,
      server_port: form.server_port.value ? parseInt(form.server_port.value) : null,
      country_code: form.country_code.value || null,
      status: form.status.value,
      risk_score: parseInt(form.risk_score.value) || 0,
      notes: form.notes.value || null,
    };

    try {
      if (id) {
        await updateProfile(id, data);
        toast('پروفایل بروزرسانی شد', 'success');
      } else {
        await createProfile(data);
        toast('پروفایل افزوده شد', 'success');
      }
      closeProfileModal();
      await loadServers();
    } catch (err) {
      toast('خطا: ' + err.message, 'error');
    }
  });
}

// ── Sources Tab ─────────────────────────────────────────────────────────────
async function loadSources() {
  const sources = await listSources();
  const container = document.getElementById('source-cards');

  if (sources.length === 0) {
    container.innerHTML = '<p style="color:var(--text-muted)">منبعی وجود ندارد</p>';
    return;
  }

  container.innerHTML = sources.map(s => `
    <div class="source-card" data-source-id="${s.id}">
      <div class="sc-header">
        <span class="sc-name">${esc(s.name)}</span>
        <span class="badge badge-${s.type}">${s.type}</span>
      </div>
      ${s.url ? `<div class="sc-url">${esc(s.url)}</div>` : ''}
      <div class="sc-meta">
        <span class="badge badge-${s.status}">${STATUS_LABELS[s.status] || s.status}</span>
        <span>⭐ ${s.reputation_score}</span>
      </div>
      ${s.last_sync_at ? `<div class="sc-meta" style="margin-top:6px"><span>🕐 همگام‌سازی: ${s.last_sync_at}</span></div>` : ''}
      ${s.last_error ? `<div style="color:#f87171;font-size:0.78rem;margin-top:4px">⚠️ ${esc(s.last_error)}</div>` : ''}
      <div class="sc-actions">
        ${s.url ? `<button class="btn btn-accent btn-sm" onclick="syncSourceAction(${s.id})">🔄 همگام‌سازی</button>` : ''}
        <button class="btn btn-danger btn-sm" onclick="removeSource(${s.id}, '${esc(s.name)}')">حذف</button>
      </div>
    </div>
  `).join('');
}

async function syncSourceAction(id) {
  try {
    const result = await syncSource(id);
    const dup = result.duplicates || 0;
    let msg = `${result.imported_count} پروفایل وارد شد`;
    if (dup > 0) msg += ` — ${dup} تکراری رد شد`;
    toast(`همگام‌سازی: ${msg}`, 'success');
    await loadSources();
  } catch (err) {
    toast('خطا در همگام‌سازی: ' + err.message, 'error');
    await loadSources();
  }
}

async function removeSource(id, name) {
  if (!await confirmAction(`آیا از حذف منبع "${name}" مطمئن هستید؟`)) return;
  try {
    await deleteSource(id);
    toast('منبع حذف شد', 'success');
    await loadSources();
  } catch (err) {
    toast('خطا: ' + err.message, 'error');
  }
}

function initSourceForm() {
  document.getElementById('source-add-form').addEventListener('submit', async e => {
    e.preventDefault();
    const form = e.target;
    const data = {
      name: form.name.value,
      type: form.type.value,
      url: form.url.value || null,
      notes: form.notes.value || null,
    };
    try {
      await createSource(data);
      toast('منبع افزوده شد', 'success');
      form.reset();
      await loadSources();
    } catch (err) {
      toast('خطا: ' + err.message, 'error');
    }
  });
}

// ── Risk level label map (Persian) ──────────────────────────────────────────
const RISK_LABELS = {
  low: 'کم', medium: 'متوسط', high: 'بالا', critical: 'بحرانی',
};
const RECOMMENDATION_LABELS = {
  approve: 'تایید خودکار', review: 'نیازمند بررسی', block: 'مسدودسازی',
};

// ── Quarantine Tab ──────────────────────────────────────────────────────────
async function loadQuarantine() {
  const quarantined = await listQuarantine();
  const tbody = document.getElementById('quarantine-tbody');

  if (quarantined.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted)">پروفایلی در قرنطینه نیست</td></tr>';
    return;
  }

  tbody.innerHTML = quarantined.map(p => {
    const scan = p.latest_scan;
    const riskBadge = scan
      ? `<span class="badge badge-risk-${scan.risk_level}">${RISK_LABELS[scan.risk_level] || scan.risk_level} (${scan.risk_score})</span>`
      : '<span style="color:var(--text-muted)">—</span>';
    const recLabel = scan
      ? `<span class="rec-label rec-${scan.recommendation}">${RECOMMENDATION_LABELS[scan.recommendation] || scan.recommendation}</span>`
      : '';
    const warningsHtml = scan && scan.warnings && scan.warnings.length > 0
      ? `<details class="scan-details"><summary>${scan.warnings.length} هشدار</summary><ul class="warning-list">${scan.warnings.map(w => `<li><strong>${esc(w.code)}</strong> (${w.weight}): ${esc(w.message)}</li>`).join('')}</ul></details>`
      : '';
    return `
    <tr>
      <td>${esc(p.name)}</td>
      <td>${p.protocol}</td>
      <td style="direction:ltr;text-align:left">${esc(p.server_host || '—')}:${p.server_port || '—'}</td>
      <td>${riskBadge} ${recLabel}</td>
      <td style="direction:ltr;text-align:left;font-size:0.75rem;color:var(--text-muted)">${p.config_ref ? esc(p.config_ref.split('/').pop()) : '—'}</td>
      <td>${warningsHtml}</td>
      <td class="actions">
        <button class="btn btn-success btn-sm" onclick="approveQuarantined(${p.id})">تایید</button>
        <button class="btn btn-warn btn-sm" onclick="rejectQuarantined(${p.id})">رد</button>
        <button class="btn btn-danger btn-sm" onclick="blockQuarantinedAction(${p.id})">مسدود و پرچم</button>
      </td>
    </tr>`;
  }).join('');
}

async function approveQuarantined(id) {
  try {
    await approveQuarantine(id);
    toast('پروفایل تایید شد', 'success');
    await loadQuarantine();
  } catch (err) {
    toast('خطا: ' + err.message, 'error');
  }
}

async function rejectQuarantined(id) {
  try {
    await rejectQuarantine(id);
    toast('پروفایل رد شد', 'success');
    await loadQuarantine();
  } catch (err) {
    toast('خطا: ' + err.message, 'error');
  }
}

async function blockQuarantinedAction(id) {
  try {
    await blockQuarantine(id);
    toast('پروفایل مسدود و پرچم شد (ریسک=۱۰۰)', 'success');
    await loadQuarantine();
  } catch (err) {
    toast('خطا: ' + err.message, 'error');
  }
}

// ── Analytics Tab ───────────────────────────────────────────────────────────
async function loadAnalytics() {
  let analytics;
  try {
    analytics = await getAnalytics();
  } catch (err) {
    document.getElementById('analytics-content').innerHTML =
      `<p style="color:var(--text-muted)">خطا در بارگذاری: ${esc(err.message)}</p>`;
    return;
  }

  const container = document.getElementById('analytics-content');
  if (!analytics) {
    container.innerHTML = '<p style="color:var(--text-muted)">داده‌ای در دسترس نیست</p>';
    return;
  }

  // Protocol distribution bar chart
  const protoData = analytics.counts_by_protocol || {};
  const protoEntries = Object.entries(protoData).sort((a, b) => b[1] - a[1]);
  const protoMax = Math.max(...protoEntries.map(e => e[1]), 1);

  // Status distribution bar chart
  const statusData = analytics.counts_by_status || {};
  const statusEntries = Object.entries(statusData).sort((a, b) => b[1] - a[1]);
  const statusMax = Math.max(...statusEntries.map(e => e[1]), 1);

  // Ping trend line chart
  const pingTrend = analytics.ping_trend || [];

  container.innerHTML = `
    <div class="analytics-grid">
      <div class="glass">
        <h3 class="chart-title">توزیع پروتکل‌ها</h3>
        ${renderHBarChart(protoEntries, protoMax, 'proto')}
      </div>
      <div class="glass">
        <h3 class="chart-title">توزیع وضعیت‌ها</h3>
        ${renderHBarChart(statusEntries, statusMax, 'status')}
      </div>
    </div>
    <div class="glass" style="margin-top:16px">
      <h3 class="chart-title">روند پینگ</h3>
      ${renderPingTrend(pingTrend)}
    </div>
    <div class="analytics-stats glass" style="margin-top:16px">
      <div class="stat-item"><span class="stat-label">میانگین ریسک</span><span class="stat-value">${(analytics.avg_risk || 0).toFixed(1)}</span></div>
      <div class="stat-item"><span class="stat-label">کل منابع</span><span class="stat-value">${analytics.sources_total || 0}</span></div>
      <div class="stat-item"><span class="stat-label">در قرنطینه</span><span class="stat-value">${analytics.quarantined_count || 0}</span></div>
    </div>
  `;
}

// ── Inline SVG Charts ───────────────────────────────────────────────────────

function renderHBarChart(entries, maxVal, prefix) {
  if (entries.length === 0) return '<p style="color:var(--text-muted);font-size:0.8rem">داده‌ای نیست</p>';

  const barHeight = 28;
  const gap = 6;
  const labelWidth = 100;
  const chartWidth = 280;
  const totalHeight = entries.length * (barHeight + gap);

  const colors = ['#7c3aed', '#06b6d4', '#4ade80', '#fbbf24', '#f87171', '#a78bfa', '#fb923c', '#67e8f9'];

  let bars = '';
  entries.forEach(([label, value], i) => {
    const y = i * (barHeight + gap);
    const barW = Math.max(2, (value / maxVal) * chartWidth);
    const color = colors[i % colors.length];
    bars += `
      <text x="${labelWidth - 8}" y="${y + barHeight / 2 + 5}" text-anchor="end" fill="#94a3b8" font-size="12" font-family="var(--font)">${esc(label)}</text>
      <rect x="${labelWidth}" y="${y}" width="${barW}" height="${barHeight}" rx="6" fill="${color}" opacity="0.85"/>
      <text x="${labelWidth + barW + 8}" y="${y + barHeight / 2 + 5}" fill="#f1f5f9" font-size="12" font-family="var(--font)">${value}</text>
    `;
  });

  return `<svg width="${labelWidth + chartWidth + 50}" height="${totalHeight}" style="direction:ltr" xmlns="http://www.w3.org/2000/svg">${bars}</svg>`;
}

function renderPingTrend(trend) {
  if (trend.length === 0) return '<p style="color:var(--text-muted);font-size:0.8rem">داده‌ای نیست</p>';

  const svgW = 600;
  const svgH = 180;
  const padL = 40;
  const padR = 16;
  const padT = 16;
  const padB = 28;
  const chartW = svgW - padL - padR;
  const chartH = svgH - padT - padB;

  const pings = trend.map(t => t.ping_ms || 0);
  const maxPing = Math.max(...pings, 1);
  const minPing = Math.min(...pings, 0);
  const range = Math.max(maxPing - minPing, 1);

  let points = '';
  let dots = '';
  pings.forEach((ping, i) => {
    const x = padL + (i / Math.max(pings.length - 1, 1)) * chartW;
    const y = padT + chartH - ((ping - minPing) / range) * chartH;
    points += `${x},${y} `;
    dots += `<circle cx="${x}" cy="${y}" r="3" fill="#06b6d4" opacity="0.9"/>`;
  });

  return `<svg width="${svgW}" height="${svgH}" style="direction:ltr" viewBox="0 0 ${svgW} ${svgH}" xmlns="http://www.w3.org/2000/svg">
    <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${svgH - padB}" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>
    <line x1="${padL}" y1="${svgH - padB}" x2="${svgW - padR}" y2="${svgH - padB}" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>
    <text x="${padL - 4}" y="${padT + 4}" text-anchor="end" fill="#64748b" font-size="10">${maxPing.toFixed(0)}</text>
    <text x="${padL - 4}" y="${svgH - padB + 4}" text-anchor="end" fill="#64748b" font-size="10">${minPing.toFixed(0)}</text>
    <polyline points="${points.trim()}" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linejoin="round"/>
    ${dots}
  </svg>`;
}

// ── Settings Tab ────────────────────────────────────────────────────────────
async function loadSettingsTab() {
  let settings;
  try {
    settings = await getSettings();
  } catch (err) {
    document.getElementById('settings-content').innerHTML =
      `<p style="color:var(--text-muted)">خطا: ${esc(err.message)}</p>`;
    return;
  }

  const weights = settings.ranking_weights || {};
  const container = document.getElementById('settings-content');

  container.innerHTML = `
    <div class="glass">
      <h3 class="chart-title">وزن‌های رتبه‌بندی</h3>
      <div class="settings-grid">
        <div class="form-group">
          <label>دانلود</label>
          <input type="range" id="w-download" min="0" max="100" value="${Math.round((weights.download || 0.35) * 100)}" class="weight-slider">
          <span class="weight-val" id="wv-download">${(weights.download || 0.35).toFixed(2)}</span>
        </div>
        <div class="form-group">
          <label>آپلود</label>
          <input type="range" id="w-upload" min="0" max="100" value="${Math.round((weights.upload || 0.20) * 100)}" class="weight-slider">
          <span class="weight-val" id="wv-upload">${(weights.upload || 0.20).toFixed(2)}</span>
        </div>
        <div class="form-group">
          <label>پینگ</label>
          <input type="range" id="w-ping" min="0" max="100" value="${Math.round((weights.ping || 0.20) * 100)}" class="weight-slider">
          <span class="weight-val" id="wv-ping">${(weights.ping || 0.20).toFixed(2)}</span>
        </div>
        <div class="form-group">
          <label>پایداری</label>
          <input type="range" id="w-stability" min="0" max="100" value="${Math.round((weights.stability || 0.15) * 100)}" class="weight-slider">
          <span class="weight-val" id="wv-stability">${(weights.stability || 0.15).toFixed(2)}</span>
        </div>
        <div class="form-group">
          <label>امنیت</label>
          <input type="range" id="w-security" min="0" max="100" value="${Math.round((weights.security || 0.10) * 100)}" class="weight-slider">
          <span class="weight-val" id="wv-security">${(weights.security || 0.10).toFixed(2)}</span>
        </div>
      </div>
      <div class="weight-sum-row">
        <span>مجموع:</span>
        <span id="weight-sum" class="weight-sum-val">1.00</span>
        <span id="weight-ok" class="weight-ok">✓</span>
      </div>
      <button class="btn btn-accent" id="save-weights-btn" style="margin-top:12px" disabled>ذخیره وزن‌ها</button>
    </div>
    <div class="glass" style="margin-top:16px">
      <h3 class="chart-title">تنظیمات تست</h3>
      <div class="settings-nums">
        <div class="form-group">
          <label>تلاش‌ها (۱-۱۰)</label>
          <input type="number" id="s-attempts" min="1" max="10" value="${settings.test_attempts || 4}">
        </div>
        <div class="form-group">
          <label>تایم‌اوت ثانیه (۱-۳۰)</label>
          <input type="number" id="s-timeout" min="1" max="30" step="0.5" value="${settings.test_timeout || 5.0}">
        </div>
        <div class="form-group">
          <label>همزمانی (۱-۱۰)</label>
          <input type="number" id="s-concurrency" min="1" max="10" value="${settings.test_concurrency || 5}">
        </div>
        <div class="form-group">
          <label>بازخوانی خودکار ثانیه (۵-۳۰۰)</label>
          <input type="number" id="s-autorefresh" min="5" max="300" value="${settings.auto_refresh_seconds || 30}">
        </div>
      </div>
      <button class="btn btn-accent" id="save-test-opts-btn" style="margin-top:12px">ذخیره تنظیمات تست</button>
    </div>
    <div class="glass" style="margin-top:16px">
      <h3 class="chart-title">بکاپ و خروجی</h3>
      <div class="settings-actions">
        <button class="btn btn-ghost" id="btn-backup">💾 بکاپ‌گیری</button>
        <button class="btn btn-ghost" id="btn-export-json">📄 خروجی JSON</button>
        <button class="btn btn-ghost" id="btn-export-csv">📊 خروجی CSV</button>
      </div>
    </div>
  `;

  // Wire up weight sliders
  const sliderKeys = ['download', 'upload', 'ping', 'stability', 'security'];
  function updateWeightSum() {
    let sum = 0;
    sliderKeys.forEach(k => {
      const v = parseInt(document.getElementById('w-' + k).value) / 100;
      document.getElementById('wv-' + k).textContent = v.toFixed(2);
      sum += v;
    });
    const sumEl = document.getElementById('weight-sum');
    const okEl = document.getElementById('weight-ok');
    const btn = document.getElementById('save-weights-btn');
    sumEl.textContent = sum.toFixed(2);
    const valid = Math.abs(sum - 1.0) < 0.001;
    okEl.textContent = valid ? '✓' : '✗';
    okEl.className = valid ? 'weight-ok' : 'weight-bad';
    btn.disabled = !valid;
  }
  sliderKeys.forEach(k => {
    document.getElementById('w-' + k).addEventListener('input', updateWeightSum);
  });
  updateWeightSum();

  // Save weights
  document.getElementById('save-weights-btn').addEventListener('click', async () => {
    const patch = { ranking_weights: {} };
    sliderKeys.forEach(k => {
      patch.ranking_weights[k] = parseInt(document.getElementById('w-' + k).value) / 100;
    });
    try {
      await updateSettings(patch);
      toast('وزن‌ها ذخیره شد', 'success');
    } catch (err) {
      toast('خطا: ' + err.message, 'error');
    }
  });

  // Save test opts
  document.getElementById('save-test-opts-btn').addEventListener('click', async () => {
    const patch = {
      test_attempts: parseInt(document.getElementById('s-attempts').value),
      test_timeout: parseFloat(document.getElementById('s-timeout').value),
      test_concurrency: parseInt(document.getElementById('s-concurrency').value),
      auto_refresh_seconds: parseInt(document.getElementById('s-autorefresh').value),
    };
    try {
      await updateSettings(patch);
      toast('تنظیمات تست ذخیره شد', 'success');
    } catch (err) {
      toast('خطا: ' + err.message, 'error');
    }
  });

  // Backup
  document.getElementById('btn-backup').addEventListener('click', async () => {
    try {
      const res = await createBackup();
      toast('بکاپ: ' + esc(res.filename || res.path), 'success');
    } catch (err) {
      toast('خطا: ' + err.message, 'error');
    }
  });

  // Export JSON
  document.getElementById('btn-export-json').addEventListener('click', async () => {
    try {
      const res = await exportData('json');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'error-panel-export.json';
      a.click(); URL.revokeObjectURL(url);
      toast('خروجی JSON دانلود شد', 'success');
    } catch (err) {
      toast('خطا: ' + err.message, 'error');
    }
  });

  // Export CSV
  document.getElementById('btn-export-csv').addEventListener('click', async () => {
    try {
      const res = await exportData('csv');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'profiles.csv';
      a.click(); URL.revokeObjectURL(url);
      toast('خروجی CSV دانلود شد', 'success');
    } catch (err) {
      toast('خطا: ' + err.message, 'error');
    }
  });
}

// ── Logs Tab ────────────────────────────────────────────────────────────────
async function loadLogsTab() {
  let logs;
  try {
    logs = await getLogs(100);
  } catch (err) {
    document.getElementById('logs-content').innerHTML =
      `<p style="color:var(--text-muted)">خطا: ${esc(err.message)}</p>`;
    return;
  }

  const tbody = document.getElementById('logs-tbody');
  if (!logs || logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">لاگی یافت نشد</td></tr>';
    return;
  }

  tbody.innerHTML = logs.map(l => {
    let detailsHtml = '';
    if (l.details_json) {
      try {
        const obj = JSON.parse(l.details_json);
        detailsHtml = `<pre class="log-details">${esc(JSON.stringify(obj, null, 1))}</pre>`;
      } catch (_) {
        detailsHtml = `<pre class="log-details">${esc(l.details_json)}</pre>`;
      }
    }
    return `
    <tr>
      <td class="log-time">${esc(l.created_at || '')}</td>
      <td><span class="badge badge-log-${esc(l.action)}">${esc(l.action)}</span></td>
      <td>${esc(l.entity_type)}</td>
      <td>${l.entity_id}</td>
      <td class="log-details-cell">${detailsHtml}</td>
    </tr>`;
  }).join('');
}

// ── Utility ─────────────────────────────────────────────────────────────────
function esc(str) {
  const div = document.createElement('span');
  div.textContent = str;
  return div.innerHTML;
}

function debounce(fn, ms) {
  let timer;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), ms);
  };
}

// ── Init ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  initTabs();
  initServersToolbar();
  initProfileModal();
  initSourceForm();

  // Initial load: Dashboard
  try {
    await loadDashboard();
  } catch (err) {
    toast('خطا در اتصال به سرور: ' + err.message, 'error');
  }
});




// ── SECURE DOM MANIPULATION (XSS Prevention) ────────────────
// Override any unsafe rendering with secure event delegation
function secureRenderProfiles(profiles) {
    const tbody = document.getElementById('profilesTableBody') || document.querySelector('tbody');
    if (!tbody) return;

    // Clear existing content safely
    while (tbody.firstChild) {
        tbody.removeChild(tbody.firstChild);
    }

    profiles.forEach(p => {
        const tr = document.createElement('tr');

        // Name cell
        const tdName = document.createElement('td');
        tdName.textContent = p.name || 'Unknown';
        tr.appendChild(tdName);

        // Protocol cell
        const tdProtocol = document.createElement('td');
        tdProtocol.textContent = p.protocol || '-';
        tr.appendChild(tdProtocol);

        // Server cell
        const tdServer = document.createElement('td');
        tdServer.textContent = `${p.server_host || '-'}:${p.server_port || '-'}`;
        tr.appendChild(tdServer);

        // Status cell
        const tdStatus = document.createElement('td');
        tdStatus.textContent = p.status || 'new';
        tr.appendChild(tdStatus);

        // Actions cell — use data attributes, NOT inline onclick
        const tdActions = document.createElement('td');

        const btnScan = document.createElement('button');
        btnScan.className = 'btn btn-primary btn-sm me-1';
        btnScan.textContent = 'اسکن';
        btnScan.dataset.action = 'scan';
        btnScan.dataset.id = p.id;
        tdActions.appendChild(btnScan);

        const btnTest = document.createElement('button');
        btnTest.className = 'btn btn-info btn-sm me-1';
        btnTest.textContent = 'تست';
        btnTest.dataset.action = 'test';
        btnScan.dataset.id = p.id;
        tdActions.appendChild(btnTest);

        const btnDelete = document.createElement('button');
        btnDelete.className = 'btn btn-danger btn-sm';
        btnDelete.textContent = 'حذف';
        btnDelete.dataset.action = 'delete';
        btnDelete.dataset.id = p.id;
        tdActions.appendChild(btnDelete);

        tr.appendChild(tdActions);
        tbody.appendChild(tr);
    });
}

// Event Delegation for Table Actions
document.addEventListener('DOMContentLoaded', () => {
    const tbody = document.getElementById('profilesTableBody') || document.querySelector('tbody');
    if (!tbody) return;

    tbody.addEventListener('click', async (event) => {
        const button = event.target.closest('button[data-action]');
        if (!button) return;

        const action = button.dataset.action;
        const id = parseInt(button.dataset.id, 10);

        if (isNaN(id)) return;

        if (action === 'scan' && typeof handleScan === 'function') {
            await handleScan(id);
        } else if (action === 'test' && typeof handleTest === 'function') {
            await handleTest(id);
        } else if (action === 'delete' && typeof handleDelete === 'function') {
            await handleDelete(id, 'Profile');
        }
    });
    
    // Override the original render function if it exists
    if (typeof window.renderProfilesTable === 'function') {
        window.renderProfilesTable = secureRenderProfiles;
    } else if (typeof window.renderServersTable === 'function') {
        window.renderServersTable = secureRenderProfiles;
    }
});
