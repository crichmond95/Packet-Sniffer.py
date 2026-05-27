/* ═══════════════════════════════════════════════════════════════
   app.js — Main entry point: tab routing, animation loop, init
   SOC Homelab Dashboard · Christian Richmond 2026
═══════════════════════════════════════════════════════════════ */

(() => {

  /* ─── Active view state ─── */
  let _activeView = 'overview';

  /* ─── Tab Navigation ─── */
  function initTabs() {
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => {
      btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        if (view === _activeView) return;

        /* Deactivate all */
        buttons.forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

        /* Activate selected */
        btn.classList.add('active');
        const viewEl = document.getElementById(`view-${view}`);
        if (viewEl) viewEl.classList.add('active');

        _activeView = view;

        /* Render static content once on first visit */
        if (view === 'infrastructure') Views.renderStatic();
      });
    });
  }

  /* ─── Main animation / simulation loop ─── */
  let _tickCount   = 0;
  let _chartTick   = 0;
  const TICK_MS    = 250;   // 4× per second (matches sniffer --rotate 4×/sec)
  const PKTS_PER_TICK  = () => utils.randInt(1, 5);  // bursts like real traffic

  function loop() {
    _tickCount++;
    _chartTick++;

    /* Generate and ingest new packets */
    const n = PKTS_PER_TICK();
    for (let i = 0; i < n; i++) {
      const pkt = Engine.generatePacket();
      Engine.ingest(pkt);
    }

    /* Advance engine state */
    Engine.tick();

    /* Render views */
    Views.renderAll(_activeView);

    /* Update charts every 4 ticks (≈1s) */
    if (_chartTick % 4 === 0) {
      Charts.updateAll();
    }

    setTimeout(loop, TICK_MS);
  }

  /* ─── Bootstrap ─── */
  function init() {
    initTabs();
    Views.bindFilters();

    /* Initialize charts (must happen after DOM ready) */
    Charts.initAll();

    /* Prime the packet buffer with 30 packets so the feed isn't empty */
    for (let i = 0; i < 30; i++) {
      Engine.ingest(Engine.generatePacket());
    }

    /* First render before loop starts */
    Views.renderAll(_activeView);
    Views.renderStatic();

    /* Kick off live loop */
    setTimeout(loop, TICK_MS);
  }

  /* Start when DOM is ready */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
