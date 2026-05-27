/* ═══════════════════════════════════════════════════════════════
   views.js — DOM rendering for all dashboard panels
   SOC Homelab Dashboard · Christian Richmond 2026
═══════════════════════════════════════════════════════════════ */

const Views = (() => {

  /* ────────────────────────────────────────────────
     KPI Row (always updated)
  ──────────────────────────────────────────────── */
  function renderKPIs() {
    const s = Engine.state;
    const uptime = Date.now() - s.sessionStartMs;

    _setText('kpi-pps',    s.pps);
    _setText('kpi-total',  utils.fmtNum(s.totalPackets));
    _setText('kpi-alerts', utils.fmtNum(s.alertCount));
    _setText('kpi-bytes',  utils.fmtBytes(s.bytesTotal));
    _setText('kpi-uptime', utils.fmtUptime(uptime));
    _setText('kpi-csv',    utils.fmtNum(s.csvLogged));
    _setText('kpi-csv-file', `packets_00${s.csvFileNum}.csv`);
    _setText('clock-chip', utils.fmtTime(new Date()));

    /* Splunk KPIs */
    _setText('splunk-events', utils.fmtNum(s.splunkSources['opnsense_syslog']));
    _setText('splunk-syslog', utils.fmtNum(s.splunkSources['pi_syslog']));
  }

  /* ────────────────────────────────────────────────
     Live Packet Feed (Overview tab)
  ──────────────────────────────────────────────── */
  const _feedMax = 80;
  let _feedFilter = 'ALL';

  function renderFeed() {
    const tbody = document.getElementById('feed-tbody');
    if (!tbody) return;

    const pkts = Engine.state.packets;
    _setText('feed-row-count', utils.fmtNum(Engine.state.totalPackets) + ' rows');

    const filtered = _feedFilter === 'ALL'
      ? pkts.slice(0, _feedMax)
      : _feedFilter === 'ALERT'
      ? pkts.filter(p => p.verdict === 'alert').slice(0, _feedMax)
      : pkts.filter(p => p.proto === _feedFilter).slice(0, _feedMax);

    tbody.innerHTML = filtered.map(p => `
      <tr class="${p.verdict === 'alert' ? 'row-alert' : p.verdict === 'suspicious' ? 'row-suspicious' : ''}">
        <td>${p.timeStr}</td>
        <td><span class="tag tag-${p.verdict}">${p.verdict}</span></td>
        <td><span class="tag tag-${p.proto.toLowerCase()}">${p.proto}</span></td>
        <td>${p.srcIP}:${p.sport}</td>
        <td>${p.dstIP}:${p.dport}</td>
        <td>${p.size} B</td>
        <td>${utils.fmtNum(p.durationMs)} ms</td>
      </tr>
    `).join('');
  }

  /* ────────────────────────────────────────────────
     Protocol Breakdown Bars
  ──────────────────────────────────────────────── */
  function renderProtoBars() {
    const el = document.getElementById('proto-bars');
    if (!el) return;
    const s = Engine.state;
    const total = Object.values(s.protoCounts).reduce((a, b) => a + b, 0) || 1;

    el.innerHTML = Object.entries(s.protoCounts).map(([proto, count]) => {
      const pct = Math.round(count / total * 100);
      const color = PROTO_COLORS[proto] || '#888';
      return `
        <div class="proto-bar-row">
          <span class="proto-bar-name">${proto}</span>
          <div class="proto-bar-bg">
            <div class="proto-bar-fill" style="width:${pct}%;background:${color}"></div>
          </div>
          <span class="proto-bar-count">${utils.fmtNum(count)}</span>
          <span class="proto-bar-pct">${pct}%</span>
        </div>
      `;
    }).join('');
  }

  /* ────────────────────────────────────────────────
     Top Suspicious IPs Panel
  ──────────────────────────────────────────────── */
  function renderIPPanel() {
    const el = document.getElementById('ip-panel');
    if (!el) return;
    const s = Engine.state;
    const sorted = Object.entries(s.suspiciousIPs)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 6);
    const max = sorted[0]?.[1] || 1;

    el.innerHTML = sorted.map(([ip, cnt]) => {
      const cls = cnt >= 3 ? 'c-red'    : cnt >= 2 ? 'c-yellow' : 'c-green';
      const txt = cnt >= 3 ? 'c-red-text' : cnt >= 2 ? 'c-yellow-text' : 'c-green-text';
      const pct = Math.round(cnt / max * 100);
      return `
        <div class="ip-row">
          <span class="ip-addr">${ip}</span>
          <div class="ip-bar-bg">
            <div class="ip-bar-fill ${cls}" style="width:${pct}%"></div>
          </div>
          <span class="ip-alert-count ${txt}">${cnt} alert${cnt !== 1 ? 's' : ''}</span>
        </div>
      `;
    }).join('');
  }

  /* ────────────────────────────────────────────────
     Packets View — full filtered table
  ──────────────────────────────────────────────── */
  let _pktProtoFilter   = 'ALL';
  let _pktVerdictFilter = 'ALL';
  let _pktIPSearch      = '';

  function renderPacketsView() {
    const tbody = document.getElementById('pkt-tbody');
    if (!tbody) return;

    let pkts = Engine.state.packets;

    if (_pktProtoFilter   !== 'ALL') pkts = pkts.filter(p => p.proto === _pktProtoFilter);
    if (_pktVerdictFilter !== 'ALL') pkts = pkts.filter(p => p.verdict === _pktVerdictFilter);
    if (_pktIPSearch) {
      const q = _pktIPSearch.trim();
      pkts = pkts.filter(p => p.srcIP.includes(q) || p.dstIP.includes(q));
    }

    tbody.innerHTML = pkts.slice(0, 200).map(p => `
      <tr class="${p.verdict === 'alert' ? 'row-alert' : p.verdict === 'suspicious' ? 'row-suspicious' : ''}">
        <td style="color:#4a5568">${p.seq}</td>
        <td>${p.timeStr}</td>
        <td>${utils.fmtNum(p.durationMs)}</td>
        <td><span class="tag tag-${p.proto.toLowerCase()}">${p.proto}</span></td>
        <td>${p.srcIP}</td>
        <td>${p.sport}</td>
        <td>${p.dstIP}</td>
        <td>${p.dport}</td>
        <td>${p.size}</td>
        <td><span class="tag tag-${p.verdict}">${p.verdict}</span></td>
        <td>${p.verdict === 'alert' ? `<span style="color:#e05252;font-size:10px">[ALERT/HIGH]</span>` : '—'}</td>
      </tr>
    `).join('');
  }

  /* ────────────────────────────────────────────────
     Alerts View
  ──────────────────────────────────────────────── */
  let _alertTypeFilter = 'ALL';

  function renderAlertsView() {
    const el = document.getElementById('alert-feed');
    if (!el) return;
    const s = Engine.state;

    _setText('alert-count-badge', `${utils.fmtNum(s.alertCount)} total`);

    let alerts = s.alerts;
    if (_alertTypeFilter !== 'ALL') {
      alerts = alerts.filter(a => a.alertType === _alertTypeFilter);
    }

    el.innerHTML = alerts.slice(0, 100).map(a => {
      const badgeCls = a.alertType === 'CONN_RATE' ? 'badge-conn'
                     : a.alertType === 'VOLUME'    ? 'badge-volume'
                     : 'badge-port';
      return `
        <div class="alert-item">
          <div class="alert-item-header">
            <span class="alert-time">${a.timeStr}</span>
            <span class="alert-type-badge ${badgeCls}">${a.typeStr}</span>
          </div>
          <div class="alert-msg">${a.msg}</div>
          <div class="alert-detail">${a.detail}</div>
        </div>
      `;
    }).join('') || '<div style="padding:20px;color:#4a5568;text-align:center;font-size:12px">No alerts match filter</div>';

    /* Port panel */
    const portEl = document.getElementById('port-panel');
    if (portEl) {
      portEl.innerHTML = Object.entries(s.portHits)
        .sort(([, a], [, b]) => b - a)
        .map(([port, hits]) => {
          const info = PORT_INFO[port] || { name: 'Unknown', risk: 'medium' };
          const riskColor = info.risk === 'critical' ? '#e05252'
                          : info.risk === 'high'     ? '#c9893a'
                          : '#7c6ff7';
          return `
            <div class="port-row">
              <span class="port-num" style="color:${riskColor}">${port}</span>
              <span class="port-desc">${info.name} <span style="color:#4a5568">[${info.risk}]</span></span>
              <span class="port-hits">${hits} hit${hits !== 1 ? 's' : ''}</span>
            </div>
          `;
        }).join('');
    }
  }

  /* ────────────────────────────────────────────────
     Infrastructure View
  ──────────────────────────────────────────────── */
  function renderInfraView() {
    /* Topology diagram */
    const topoEl = document.getElementById('topo-diagram');
    if (topoEl && topoEl.children.length === 0) {
      topoEl.innerHTML = TOPO_NODES.map((node, i) => `
        <div class="topo-node active">
          <span class="topo-icon">${node.icon}</span>
          <span class="topo-label">${node.label}</span>
          <span class="topo-sublabel">${node.sub}</span>
          <span class="topo-status"></span>
        </div>
        ${node.arrow ? `
          <div class="topo-arrow-label">
            <span class="topo-arrow-line">→</span>
            <span class="topo-arrow-text">${node.arrow}</span>
          </div>
        ` : ''}
      `).join('');
    }

    /* Component grid */
    const gridEl = document.getElementById('infra-grid');
    if (gridEl && gridEl.children.length === 0) {
      gridEl.innerHTML = INFRA_COMPONENTS.map(c => `
        <div class="infra-card">
          <div class="infra-card-header">
            <span class="infra-card-icon">${c.icon}</span>
            <span class="infra-status-dot ok"></span>
          </div>
          <div class="infra-card-name">${c.name}</div>
          <div class="infra-card-detail">${c.detail}</div>
          <div class="infra-card-detail" style="color:#3a4555">${c.ip}</div>
          <div class="infra-card-status">
            <span class="pulse-dot small"></span>
            active
          </div>
          <div class="infra-tag-row">
            ${c.tags.map(t => `<span class="infra-tag">${t}</span>`).join('')}
          </div>
        </div>
      `).join('');
    }
  }

  /* ────────────────────────────────────────────────
     Splunk View — simulated search results table
  ──────────────────────────────────────────────── */
  function renderSplunkView() {
    const tbody = document.getElementById('splunk-tbody');
    if (!tbody) return;

    tbody.innerHTML = Engine.state.splunkRows.slice(0, 30).map(r => `
      <tr class="${r.verdict === 'alert' ? 'row-alert' : r.verdict === 'suspicious' ? 'row-suspicious' : ''}">
        <td>${r.time}</td>
        <td>${r.srcIP}</td>
        <td>${r.dstIP}</td>
        <td><span class="tag tag-${r.protocol.toLowerCase()}">${r.protocol}</span></td>
        <td><span class="tag tag-${r.verdict}">${r.verdict}</span></td>
        <td>${r.size} B</td>
      </tr>
    `).join('');
  }

  /* ────────────────────────────────────────────────
     CSV Export
  ──────────────────────────────────────────────── */
  function exportCSV() {
    const header = 'seq,timestamp,duration_ms,protocol,src_ip,sport,dst_ip,dport,size_bytes,verdict,alert\n';
    const rows = Engine.state.packets.map(p =>
      [p.seq, p.timeStr, p.durationMs, p.proto, p.srcIP, p.sport, p.dstIP, p.dport, p.size, p.verdict,
       p.verdict === 'alert' ? '[ALERT/HIGH]' : ''].join(',')
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `packets_00${Engine.state.csvFileNum}.csv`;
    a.click();
  }

  /* ────────────────────────────────────────────────
     Filter + event wiring
  ──────────────────────────────────────────────── */
  function bindFilters() {
    const ff = document.getElementById('feed-filter');
    if (ff) ff.addEventListener('change', () => { _feedFilter = ff.value; renderFeed(); });

    const pf = document.getElementById('pkt-proto-filter');
    if (pf) pf.addEventListener('change', () => { _pktProtoFilter = pf.value; renderPacketsView(); });

    const vf = document.getElementById('pkt-verdict-filter');
    if (vf) vf.addEventListener('change', () => { _pktVerdictFilter = vf.value; renderPacketsView(); });

    const ip = document.getElementById('pkt-ip-search');
    if (ip) ip.addEventListener('input', () => { _pktIPSearch = ip.value; renderPacketsView(); });

    const af = document.getElementById('alert-type-filter');
    if (af) af.addEventListener('change', () => { _alertTypeFilter = af.value; renderAlertsView(); });

    const clr = document.getElementById('clear-packets-btn');
    if (clr) clr.addEventListener('click', () => {
      Engine.state.packets.length = 0;
      renderPacketsView();
    });

    const exp = document.getElementById('export-csv-btn');
    if (exp) exp.addEventListener('click', exportCSV);
  }

  /* ────────────────────────────────────────────────
     Master render (called every tick)
  ──────────────────────────────────────────────── */
  function renderAll(activeView) {
    renderKPIs();
    if (activeView === 'overview') {
      renderFeed();
      renderProtoBars();
      renderIPPanel();
    } else if (activeView === 'packets') {
      renderPacketsView();
    } else if (activeView === 'alerts') {
      renderAlertsView();
    } else if (activeView === 'splunk') {
      renderSplunkView();
    }
  }

  function renderStatic() {
    renderInfraView();
  }

  /* ─── Helper ─── */
  function _setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  return { renderAll, renderStatic, bindFilters };

})();
