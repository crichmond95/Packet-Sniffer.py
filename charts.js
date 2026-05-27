/* ═══════════════════════════════════════════════════════════════
   charts.js — Chart.js initialization and live update logic
   SOC Homelab Dashboard · Christian Richmond 2026
═══════════════════════════════════════════════════════════════ */

const Charts = (() => {

  /* Shared chart defaults */
  Chart.defaults.color = '#7a8a9e';
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size   = 10;

  const GRID_COLOR  = 'rgba(30,37,48,0.8)';
  const TICK_COLOR  = '#4a5568';

  /* ─── Verdict Donut ─── */
  let verdictChart = null;

  function initVerdictDonut() {
    const ctx = document.getElementById('verdict-donut');
    if (!ctx) return;
    const s = Engine.state;
    verdictChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Normal', 'Suspicious', 'Alert'],
        datasets: [{
          data: [
            s.verdictCounts.normal,
            s.verdictCounts.suspicious,
            s.verdictCounts.alert,
          ],
          backgroundColor: [
            'rgba(26,171,119,0.8)',
            'rgba(201,137,58,0.8)',
            'rgba(224,82,82,0.8)',
          ],
          borderColor: [
            '#1aab77',
            '#c9893a',
            '#e05252',
          ],
          borderWidth: 1,
          hoverOffset: 4,
        }],
      },
      options: {
        responsive: false,
        cutout: '65%',
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => ` ${ctx.label}: ${utils.fmtNum(ctx.raw)}`,
            },
          },
        },
        animation: { duration: 300 },
      },
    });
    renderDonutLegend();
  }

  function renderDonutLegend() {
    const s = Engine.state;
    const total = s.totalPackets || 1;
    const items = [
      { label: 'Normal',     val: s.verdictCounts.normal,     color: '#1aab77' },
      { label: 'Suspicious', val: s.verdictCounts.suspicious, color: '#c9893a' },
      { label: 'Alert',      val: s.verdictCounts.alert,      color: '#e05252' },
    ];
    const el = document.getElementById('donut-legend');
    if (!el) return;
    el.innerHTML = items.map(i => `
      <div class="legend-row">
        <span class="legend-swatch" style="background:${i.color}"></span>
        <span>${i.label}</span>
        <span style="margin-left:auto;color:#e2e8f0">${Math.round(i.val / total * 100)}%</span>
      </div>
    `).join('');
  }

  function updateVerdictDonut() {
    if (!verdictChart) return;
    const s = Engine.state;
    verdictChart.data.datasets[0].data = [
      s.verdictCounts.normal,
      s.verdictCounts.suspicious,
      s.verdictCounts.alert,
    ];
    verdictChart.update('none');
    renderDonutLegend();
  }

  /* ─── Alert Timeline Bar Chart ─── */
  let alertTimelineChart = null;

  function initAlertTimeline() {
    const ctx = document.getElementById('alert-timeline');
    if (!ctx) return;

    const labels = Array.from({ length: 10 }, (_, i) => `-${9 - i}m`);

    alertTimelineChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Alerts',
          data: [...Engine.state.alertTimeline],
          backgroundColor: 'rgba(224,82,82,0.6)',
          borderColor: '#e05252',
          borderWidth: 1,
          borderRadius: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: { color: TICK_COLOR },
            grid: { color: GRID_COLOR },
          },
          y: {
            ticks: { color: TICK_COLOR, precision: 0 },
            grid: { color: GRID_COLOR },
            beginAtZero: true,
          },
        },
        animation: { duration: 200 },
      },
    });
  }

  function updateAlertTimeline() {
    if (!alertTimelineChart) return;
    alertTimelineChart.data.datasets[0].data = [...Engine.state.alertTimeline];
    alertTimelineChart.update('none');
  }

  /* ─── Alert Type Doughnut ─── */
  let alertTypeChart = null;

  function initAlertTypeChart() {
    const ctx = document.getElementById('alert-type-chart');
    if (!ctx) return;
    const s = Engine.state;
    alertTypeChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Conn Rate', 'Volume', 'Susp Port'],
        datasets: [{
          data: [
            s.alertTypeCounts.CONN_RATE,
            s.alertTypeCounts.VOLUME,
            s.alertTypeCounts.SUSP_PORT,
          ],
          backgroundColor: [
            'rgba(61,142,240,0.75)',
            'rgba(124,111,247,0.75)',
            'rgba(201,137,58,0.75)',
          ],
          borderColor: ['#3d8ef0', '#7c6ff7', '#c9893a'],
          borderWidth: 1,
          hoverOffset: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '55%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { padding: 10, boxWidth: 10, color: '#7a8a9e' },
          },
        },
        animation: { duration: 300 },
      },
    });
  }

  function updateAlertTypeChart() {
    if (!alertTypeChart) return;
    const s = Engine.state;
    alertTypeChart.data.datasets[0].data = [
      s.alertTypeCounts.CONN_RATE,
      s.alertTypeCounts.VOLUME,
      s.alertTypeCounts.SUSP_PORT,
    ];
    alertTypeChart.update('none');
  }

  /* ─── OPNsense Firewall Line Chart ─── */
  let fwChart = null;

  function initFwChart() {
    const ctx = document.getElementById('fw-line-chart');
    if (!ctx) return;

    const labels = Array.from({ length: 12 }, (_, i) => `-${11 - i}m`);

    fwChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Allowed',
            data: [...Engine.state.fwAllowed],
            borderColor: '#1aab77',
            backgroundColor: 'rgba(26,171,119,0.08)',
            tension: 0.4,
            fill: true,
            pointRadius: 2,
            pointBackgroundColor: '#1aab77',
          },
          {
            label: 'Blocked',
            data: [...Engine.state.fwBlocked],
            borderColor: '#e05252',
            backgroundColor: 'rgba(224,82,82,0.08)',
            tension: 0.4,
            fill: true,
            pointRadius: 2,
            pointBackgroundColor: '#e05252',
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: { color: TICK_COLOR },
            grid: { color: GRID_COLOR },
          },
          y: {
            ticks: { color: TICK_COLOR },
            grid: { color: GRID_COLOR },
            beginAtZero: true,
          },
        },
        animation: { duration: 250 },
      },
    });
  }

  function updateFwChart() {
    if (!fwChart) return;
    fwChart.data.datasets[0].data = [...Engine.state.fwAllowed];
    fwChart.data.datasets[1].data = [...Engine.state.fwBlocked];
    fwChart.update('none');
  }

  /* ─── Splunk Source Doughnut ─── */
  let sourceChart = null;

  function initSourceChart() {
    const ctx = document.getElementById('source-chart');
    if (!ctx) return;
    const s = Engine.state;
    const entries = Object.entries(s.splunkSources);

    sourceChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: entries.map(([k]) => k),
        datasets: [{
          data: entries.map(([, v]) => v),
          backgroundColor: [
            'rgba(26,171,119,0.75)',
            'rgba(61,142,240,0.75)',
            'rgba(124,111,247,0.75)',
            'rgba(201,137,58,0.75)',
          ],
          borderColor: ['#1aab77', '#3d8ef0', '#7c6ff7', '#c9893a'],
          borderWidth: 1,
          hoverOffset: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '55%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { padding: 8, boxWidth: 10, color: '#7a8a9e', font: { size: 9 } },
          },
        },
        animation: { duration: 300 },
      },
    });
  }

  function updateSourceChart() {
    if (!sourceChart) return;
    const s = Engine.state;
    const vals = Object.values(s.splunkSources);
    sourceChart.data.datasets[0].data = vals;
    sourceChart.update('none');
  }

  /* ─── Init all + public update API ─── */
  function initAll() {
    initVerdictDonut();
    initAlertTimeline();
    initAlertTypeChart();
    initFwChart();
    initSourceChart();
  }

  function updateAll() {
    updateVerdictDonut();
    updateAlertTimeline();
    updateAlertTypeChart();
    updateFwChart();
    updateSourceChart();
  }

  return { initAll, updateAll };

})();
