"""Self-contained HTML report generator for NetCertGuardian.

Generates a single cert-status.html file with:
  - Scan data embedded as a JavaScript variable (no file:// CORS issues)
  - Inline CSS (no external dependencies)
  - Sortable/searchable/filterable table (vanilla JS)
  - Detail panel per host (click on row)
  - Canvas histogram of days-to-expiry distribution
  - Works 100% offline and without a web server
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Embedded CSS
# ---------------------------------------------------------------------------
_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:#f1f5f9;color:#1e293b;font-size:14px}
a{color:inherit;text-decoration:none}
.wrap{max-width:1440px;margin:0 auto;padding:20px 24px}

/* Header */
.hdr{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:20px;gap:12px;flex-wrap:wrap}
.hdr h1{font-size:22px;font-weight:700;letter-spacing:-.3px}
.hdr .meta{font-size:12px;color:#64748b}

/* Cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:14px;margin-bottom:20px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px;
  box-shadow:0 1px 3px rgba(0,0,0,.06)}
.card-lbl{font-size:11px;font-weight:600;text-transform:uppercase;
  letter-spacing:.06em;color:#64748b;margin-bottom:6px}
.card-val{font-size:30px;font-weight:800}
.card-val.red{color:#ef4444}
.card-val.amber{color:#f59e0b}
.card-val.blue{color:#3b82f6}
.card-val.slate{color:#475569}

/* Toolbar */
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.toolbar input,.toolbar select{
  padding:7px 11px;border:1px solid #cbd5e1;border-radius:7px;font-size:13px;
  background:#fff;color:#1e293b;outline:none;transition:border .15s}
.toolbar input:focus,.toolbar select:focus{border-color:#3b82f6}
.toolbar input{min-width:220px}
.badge-count{font-size:12px;color:#64748b;margin-left:auto}

/* Table */
.tbl-wrap{background:#fff;border:1px solid #e2e8f0;border-radius:10px;
  overflow:auto;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
table{width:100%;border-collapse:collapse;font-size:13px}
thead{position:sticky;top:0;z-index:2}
th{background:#f8fafc;padding:10px 14px;text-align:left;font-weight:600;
  font-size:11px;text-transform:uppercase;letter-spacing:.06em;
  color:#64748b;cursor:pointer;user-select:none;white-space:nowrap;
  border-bottom:1px solid #e2e8f0}
th:hover{background:#f1f5f9}
th.sorted-asc::after{content:' ▲'}
th.sorted-desc::after{content:' ▼'}
td{padding:9px 14px;border-top:1px solid #f1f5f9;vertical-align:middle}
tr:hover td{background:#f8fafc;cursor:pointer}
tr.selected td{background:#eff6ff}
.empty{text-align:center;color:#94a3b8;padding:40px;font-size:13px}

/* Badges */
.badge{display:inline-block;padding:2px 9px;border-radius:20px;
  font-size:11px;font-weight:700;letter-spacing:.04em}
.badge.expired{background:#fee2e2;color:#dc2626}
.badge.expiring{background:#fef3c7;color:#b45309}
.days.neg{color:#dc2626;font-weight:700}
.days.warn{color:#b45309;font-weight:600}

/* Detail panel */
.detail{display:none;background:#fff;border:1px solid #bfdbfe;border-radius:10px;
  padding:18px 20px;margin-bottom:20px;box-shadow:0 1px 4px rgba(59,130,246,.1)}
.detail.open{display:block}
.detail-hdr{display:flex;justify-content:space-between;align-items:center;
  margin-bottom:14px}
.detail-hdr h3{font-size:15px;font-weight:700}
.detail-close{cursor:pointer;font-size:18px;color:#94a3b8;
  line-height:1;padding:2px 6px;border-radius:4px}
.detail-close:hover{background:#f1f5f9}
.detail-meta{display:flex;gap:24px;flex-wrap:wrap;
  font-size:12px;color:#64748b;margin-bottom:16px}
.detail-meta span b{color:#1e293b}
.detail-certs-tbl{width:100%;border-collapse:collapse;font-size:12px}
.detail-certs-tbl th{background:#f8fafc;padding:7px 10px;text-align:left;
  border-bottom:1px solid #e2e8f0;font-size:11px;text-transform:uppercase;
  letter-spacing:.05em;color:#64748b}
.detail-certs-tbl td{padding:7px 10px;border-top:1px solid #f1f5f9}

/* Histogram */
.chart-wrap{background:#fff;border:1px solid #e2e8f0;border-radius:10px;
  padding:18px 20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.chart-wrap h3{font-size:14px;font-weight:600;margin-bottom:14px;color:#334155}
canvas{display:block}

/* Errors section */
.errors-wrap{background:#fff;border:1px solid #e2e8f0;border-radius:10px;
  padding:18px 20px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.errors-wrap h3{font-size:14px;font-weight:600;margin-bottom:12px;color:#334155}
.err-row{display:flex;gap:12px;font-size:12px;padding:5px 0;
  border-bottom:1px solid #f1f5f9;flex-wrap:wrap}
.err-row:last-child{border:none}
.err-ip{font-weight:600;min-width:130px}
.err-reason{color:#64748b}

/* Responsive */
@media(max-width:600px){
  .cards{grid-template-columns:1fr 1fr}
  .toolbar input{min-width:0;flex:1}
}
"""

# ---------------------------------------------------------------------------
# Embedded JavaScript
# ---------------------------------------------------------------------------
_JS = r"""
const D = SCAN_DATA;
const CERTS = D.problematic_certs || [];
const HOSTS_MAP = {};
(D.hosts || []).forEach(h => { HOSTS_MAP[h.hostname] = h; });

let sortKey = 'days_left', sortDir = 1;
let fStatus = 'all', fText = '';

function fmt(days) {
  if (days < 0) return `<span class="days neg">${days}</span>`;
  if (days <= 30) return `<span class="days warn">${days}</span>`;
  return `<span class="days">${days}</span>`;
}
function badge(s) {
  return s === 'expired'
    ? '<span class="badge expired">Истёк</span>'
    : '<span class="badge expiring">Истекает</span>';
}
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}
function shortSubject(s) {
  // Extract CN= if present
  const m = s.match(/CN=([^,]+)/);
  return m ? m[1] : (s.length > 55 ? s.slice(0,55)+'…' : s);
}

function renderTable() {
  let data = CERTS.filter(c => {
    if (fStatus !== 'all' && c.status !== fStatus) return false;
    if (fText) {
      const q = fText.toLowerCase();
      return c.hostname.toLowerCase().includes(q)
          || c.ip.includes(q)
          || c.subject.toLowerCase().includes(q)
          || (c.mac||'').toLowerCase().includes(q);
    }
    return true;
  });

  data.sort((a, b) => {
    let av = a[sortKey], bv = b[sortKey];
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    return av < bv ? -sortDir : av > bv ? sortDir : 0;
  });

  document.querySelector('.badge-count').textContent =
    `Показано: ${data.length} / ${CERTS.length}`;

  // Update sort indicators
  document.querySelectorAll('th[data-key]').forEach(th => {
    th.classList.remove('sorted-asc','sorted-desc');
    if (th.dataset.key === sortKey)
      th.classList.add(sortDir === 1 ? 'sorted-asc' : 'sorted-desc');
  });

  const tbody = document.getElementById('tbody');
  if (!data.length) {
    tbody.innerHTML = '<tr><td class="empty" colspan="7">Нет сертификатов по выбранным фильтрам</td></tr>';
    return;
  }

  tbody.innerHTML = data.map(c => `
    <tr onclick="showDetail('${esc(c.hostname)}')">
      <td><b>${esc(c.hostname)}</b></td>
      <td>${esc(c.ip)}</td>
      <td>${esc(c.mac||'—')}</td>
      <td title="${esc(c.subject)}">${esc(shortSubject(c.subject))}</td>
      <td>${esc(c.not_after)}</td>
      <td>${fmt(c.days_left)}</td>
      <td>${badge(c.status)}</td>
    </tr>`).join('');
}

function sortBy(key) {
  if (sortKey === key) sortDir = -sortDir; else { sortKey = key; sortDir = 1; }
  renderTable();
}

function showDetail(hostname) {
  const panel = document.getElementById('detail');
  const host = HOSTS_MAP[hostname];
  if (!host) { panel.classList.remove('open'); return; }

  document.getElementById('d-hostname').textContent = hostname;
  document.getElementById('d-ip').innerHTML = `<b>${host.ip}</b>`;
  document.getElementById('d-mac').innerHTML = `<b>${host.mac||'—'}</b>`;
  document.getElementById('d-total').innerHTML = `<b>${host.total_certs}</b>`;

  const rows = (host.certs||[]).map(c => {
    const cl = c.status === 'expired' ? 'neg' : c.status === 'expiring' ? 'warn' : '';
    return `<tr>
      <td>${esc(shortSubject(c.subject))}</td>
      <td>${esc(c.not_after)}</td>
      <td class="${cl}">${c.days_left}</td>
      <td>${c.status !== 'ok' ? badge(c.status) : '<span style="color:#22c55e">OK</span>'}</td>
      <td style="font-size:11px;color:#94a3b8;font-family:monospace">${esc(c.thumbprint.slice(0,16))}…</td>
    </tr>`;
  }).join('');

  document.getElementById('d-certs').innerHTML = rows ||
    '<tr><td colspan="5" class="empty">Нет сертификатов</td></tr>';

  panel.classList.add('open');
  panel.scrollIntoView({behavior:'smooth', block:'nearest'});

  // Highlight selected row
  document.querySelectorAll('#tbody tr').forEach(r => {
    r.classList.toggle('selected',
      r.querySelector('td b')?.textContent === hostname);
  });
}

function closeDetail() {
  document.getElementById('detail').classList.remove('open');
  document.querySelectorAll('#tbody tr').forEach(r => r.classList.remove('selected'));
}

function drawHistogram() {
  const canvas = document.getElementById('histo');
  if (!canvas || !CERTS.length) return;
  const ctx = canvas.getContext('2d');

  // Buckets: expired(<0), 1-7, 8-14, 15-21, 22-30
  const labels = ['Истёк','1-7 дн','8-14 дн','15-21 дн','22-30 дн'];
  const counts = [0,0,0,0,0];
  const colors = ['#ef4444','#f97316','#f59e0b','#eab308','#84cc16'];

  CERTS.forEach(c => {
    const d = c.days_left;
    if (d < 0) counts[0]++;
    else if (d <= 7) counts[1]++;
    else if (d <= 14) counts[2]++;
    else if (d <= 21) counts[3]++;
    else counts[4]++;
  });

  const W = canvas.width, H = canvas.height;
  const pad = {top:20, right:20, bottom:40, left:40};
  const chartW = W - pad.left - pad.right;
  const chartH = H - pad.top - pad.bottom;
  const maxVal = Math.max(...counts, 1);
  const barW = chartW / labels.length;

  ctx.clearRect(0, 0, W, H);
  ctx.font = '11px -apple-system,sans-serif';
  ctx.fillStyle = '#94a3b8';

  // Y grid lines
  const steps = Math.min(maxVal, 5);
  for (let i = 0; i <= steps; i++) {
    const v = Math.round(maxVal * i / steps);
    const y = pad.top + chartH - (chartH * i / steps);
    ctx.beginPath();
    ctx.strokeStyle = '#e2e8f0';
    ctx.lineWidth = 1;
    ctx.moveTo(pad.left, y);
    ctx.lineTo(W - pad.right, y);
    ctx.stroke();
    ctx.fillText(v, 2, y + 4);
  }

  // Bars
  counts.forEach((val, i) => {
    const x = pad.left + i * barW + barW * 0.1;
    const bw = barW * 0.8;
    const bh = val === 0 ? 0 : Math.max(2, chartH * val / maxVal);
    const y = pad.top + chartH - bh;

    ctx.fillStyle = colors[i];
    ctx.beginPath();
    ctx.roundRect(x, y, bw, bh, [4,4,0,0]);
    ctx.fill();

    // Value label on top of bar
    if (val > 0) {
      ctx.fillStyle = '#475569';
      ctx.fillText(val, x + bw/2 - 4, y - 5);
    }

    // X axis label
    ctx.fillStyle = '#64748b';
    ctx.fillText(labels[i], x + bw/2 - ctx.measureText(labels[i]).width/2,
      pad.top + chartH + 18);
  });
}

// Init
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('search').addEventListener('input', e => {
    fText = e.target.value; renderTable();
  });
  document.getElementById('status-filter').addEventListener('change', e => {
    fStatus = e.target.value; renderTable();
  });
  document.querySelectorAll('th[data-key]').forEach(th =>
    th.addEventListener('click', () => sortBy(th.dataset.key)));

  renderTable();
  drawHistogram();
});
"""


# ---------------------------------------------------------------------------
# HTML template builder
# ---------------------------------------------------------------------------

def _render_html(scan_data: Dict[str, Any]) -> str:
    ts = scan_data.get("timestamp", "")
    s = scan_data.get("summary", {})

    errors_html = ""
    for err in (scan_data.get("errors") or []):
        errors_html += (
            f'<div class="err-row">'
            f'<span class="err-ip">{err.get("ip","")}</span>'
            f'<span style="color:#94a3b8;min-width:80px">{err.get("method","")}</span>'
            f'<span class="err-reason">{err.get("reason","")}</span>'
            f'</div>\n'
        )
    if not errors_html:
        errors_html = '<p style="color:#22c55e;font-size:13px">Ошибок подключения не зафиксировано.</p>'

    data_js = json.dumps(scan_data, ensure_ascii=False, separators=(",", ":"))

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetCertGuardian — Статус сертификатов</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">

  <!-- Header -->
  <div class="hdr">
    <div>
      <h1>🔐 NetCertGuardian</h1>
      <div class="meta">Последнее сканирование: <b>{ts}</b> &nbsp;|&nbsp; Диапазон: <b>{scan_data.get("scan_range","авто")}</b></div>
    </div>
  </div>

  <!-- Summary cards -->
  <div class="cards">
    <div class="card">
      <div class="card-lbl">Обнаружено хостов</div>
      <div class="card-val slate">{s.get("total_discovered", 0)}</div>
    </div>
    <div class="card">
      <div class="card-lbl">Успешно опрошено</div>
      <div class="card-val blue">{s.get("successful", 0)}</div>
    </div>
    <div class="card">
      <div class="card-lbl">Истёкших сертификатов</div>
      <div class="card-val red">{s.get("expired", 0)}</div>
    </div>
    <div class="card">
      <div class="card-lbl">Истекают скоро</div>
      <div class="card-val amber">{s.get("expiring", 0)}</div>
    </div>
    <div class="card">
      <div class="card-lbl">Ошибок подключения</div>
      <div class="card-val slate">{s.get("failed", 0)}</div>
    </div>
  </div>

  <!-- Histogram -->
  <div class="chart-wrap">
    <h3>Распределение по срокам (проблемные сертификаты)</h3>
    <canvas id="histo" width="600" height="180"></canvas>
  </div>

  <!-- Toolbar -->
  <div class="toolbar">
    <input id="search" type="text" placeholder="Поиск по хосту, IP, субъекту…">
    <select id="status-filter">
      <option value="all">Все статусы</option>
      <option value="expired">Истёкшие</option>
      <option value="expiring">Истекающие</option>
    </select>
    <span class="badge-count"></span>
  </div>

  <!-- Main table -->
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th data-key="hostname">Хост</th>
          <th data-key="ip">IP</th>
          <th data-key="mac">MAC</th>
          <th data-key="subject">Субъект</th>
          <th data-key="not_after">Истекает</th>
          <th data-key="days_left">Дней</th>
          <th data-key="status">Статус</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>

  <!-- Detail panel -->
  <div class="detail" id="detail">
    <div class="detail-hdr">
      <h3>📋 Хост: <span id="d-hostname"></span></h3>
      <span class="detail-close" onclick="closeDetail()">✕</span>
    </div>
    <div class="detail-meta">
      <span>IP: <span id="d-ip"></span></span>
      <span>MAC: <span id="d-mac"></span></span>
      <span>Всего сертификатов: <span id="d-total"></span></span>
    </div>
    <table class="detail-certs-tbl">
      <thead>
        <tr>
          <th>Субъект</th>
          <th>Истекает</th>
          <th>Дней</th>
          <th>Статус</th>
          <th>Отпечаток</th>
        </tr>
      </thead>
      <tbody id="d-certs"></tbody>
    </table>
  </div>

  <!-- Errors -->
  <div class="errors-wrap">
    <h3>⚠️ Ошибки подключения ({s.get("failed", 0)})</h3>
    <div style="margin-top:10px">{errors_html}</div>
  </div>

</div>

<script>const SCAN_DATA={data_js};</script>
<script>{_JS}</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def generate_html(scan_data: Dict[str, Any], output_path: Path) -> None:
    """Write a self-contained HTML report to output_path.

    Args:
        scan_data: Dict as returned by reports.build_scan_json().
        output_path: Destination file path (created if needed).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html = _render_html(scan_data)
    output_path.write_text(html, encoding="utf-8")
    log.info(
        "HTML report (%d chars) → %s",
        len(html),
        output_path,
    )
