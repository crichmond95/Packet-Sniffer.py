/* ═══════════════════════════════════════════════════════════════
   engine.js — Packet generation engine & live simulation state
   SOC Homelab Dashboard · Christian Richmond 2026
═══════════════════════════════════════════════════════════════ */

const Engine = (() => {

  /* ─── Mutable runtime state (clone of seed) ─── */
  const state = {
    totalPackets:   SEED_STATE.totalPackets,
    alertCount:     SEED_STATE.alertCount,
    bytesTotal:     SEED_STATE.bytesTotal,
    csvLogged:      SEED_STATE.csvLogged,
    csvFileNum:     SEED_STATE.csvFileNum,
    sessionStartMs: SEED_STATE.sessionStartMs,

    protoCounts:    { ...SEED_STATE.protoCounts },
    suspiciousIPs:  { ...SEED_STATE.suspiciousIPs },
    verdictCounts:  { ...SEED_STATE.verdictCounts },
    fwAllowed:      [...SEED_STATE.fwAllowed],
    fwBlocked:      [...SEED_STATE.fwBlocked],
    portHits:       { ...SEED_STATE.portHits },
    alertTypeCounts:{ ...SEED_STATE.alertTypeCounts },
    alertTimeline:  [...SEED_STATE.alertTimeline],
    splunkSources:  { ...SEED_STATE.splunkSources },

    /* runtime only */
    pps:              0,
    _ppsAccum:        0,
    _lastPPSTick:     Date.now(),

    /* packet + alert ring buffers */
    packets:     [],   // all packets (capped at 2000)
    alerts:      [],   // alert objects
    splunkRows:  [],   // simulated splunk results (last 50)

    PACKET_CAP: 2000,
  };

  /* ─── Packet proto weights (realistic home-net distribution) ─── */
  const PROTO_WEIGHTS = [
    { proto: 'TCP',   w: 0.40 },
    { proto: 'UDP',   w: 0.28 },
    { proto: 'DNS',   w: 0.14 },
    { proto: 'HTTP',  w: 0.11 },
    { proto: 'HTTPS', w: 0.07 },
  ];

  function pickProto() {
    const r = Math.random();
    let acc = 0;
    for (const { proto, w } of PROTO_WEIGHTS) {
      acc += w;
      if (r <= acc) return proto;
    }
    return 'TCP';
  }

  /* ─── Port selection ─── */
  const COMMON_PORTS = [80, 443, 53, 8080, 8443, 8009, 5353, 9997, 1900, 4953];

  function pickDstPort(proto, isMalicious) {
    if (isMalicious) return utils.pick(SUSPICIOUS_PORTS);
    if (proto === 'HTTP')  return 80;
    if (proto === 'HTTPS') return 443;
    if (proto === 'DNS')   return 53;
    return utils.pick(COMMON_PORTS);
  }

  /* ─── Packet factory ─── */
  let _seq = SEED_STATE.totalPackets;

  function generatePacket() {
    _seq++;
    const proto     = pickProto();
    const srcIP     = utils.pick(HOME_IPS);
    const isBcast   = Math.random() < 0.12;
    const isExt     = Math.random() < 0.08;
    const dstIP     = isBcast ? utils.pick(BROADCAST_DSTS)
                    : isExt   ? utils.pick(EXT_IPS)
                    :           utils.pick(HOME_IPS);
    const sport     = utils.randInt(1024, 65535);

    /* Determine if this packet is suspicious or an alert */
    const connRate  = utils.randInt(1, 28);
    const isSuspPort = Math.random() < 0.04;  // ~4% chance
    const isHighRate = connRate > 20;
    const isVolume   = Math.random() < 0.01;

    let verdict = 'normal';
    let alertType = null;

    if (isSuspPort) {
      verdict = 'suspicious';
      if (Math.random() < 0.6) { verdict = 'alert'; alertType = 'SUSP_PORT'; }
    }
    if (isHighRate && verdict !== 'alert') {
      verdict = 'alert';
      alertType = 'CONN_RATE';
    }
    if (isVolume && verdict === 'normal') {
      verdict = 'alert';
      alertType = 'VOLUME';
    }

    const dstPort = pickDstPort(proto, isSuspPort);
    const size    = proto === 'UDP' ? utils.randInt(64, 400)
                  : proto === 'DNS' ? utils.randInt(50, 200)
                  : utils.randInt(100, 1400);
    const durationMs = _seq * utils.randInt(8, 15);

    const pkt = {
      seq:        _seq,
      ts:         new Date(),
      timeStr:    utils.fmtTime(new Date()),
      proto,
      srcIP,
      dstIP,
      sport,
      dport:      dstPort,
      size,
      verdict,
      alertType,
      connRate,
      durationMs,
    };

    return pkt;
  }

  /* ─── Alert factory ─── */
  function makeAlert(pkt) {
    const typeStr = ALERT_TYPES[pkt.alertType] || 'Unknown';
    let msg = '';
    let detail = '';

    if (pkt.alertType === 'CONN_RATE') {
      msg    = `[ALERT/HIGH] ${pkt.srcIP} — Possible port scan / flood`;
      detail = `${pkt.connRate} connections in 10s · threshold: 20 · port ${pkt.dport}`;
    } else if (pkt.alertType === 'VOLUME') {
      msg    = `[ALERT/HIGH] ${pkt.srcIP} — Traffic volume exceeded`;
      detail = `Source IP exceeded 5 MB threshold · proto: ${pkt.proto}`;
    } else if (pkt.alertType === 'SUSP_PORT') {
      const info = PORT_INFO[pkt.dport] || { name: 'Unknown' };
      msg    = `[ALERT/HIGH] ${pkt.srcIP} → port ${pkt.dport} (${info.name})`;
      detail = `Suspicious port hit · ${pkt.srcIP}:${pkt.sport} → ${pkt.dstIP}:${pkt.dport}`;
    }

    return {
      id:        state.alertCount,
      ts:        new Date(),
      timeStr:   utils.fmtTime(new Date()),
      alertType: pkt.alertType,
      typeStr,
      msg,
      detail,
      srcIP:     pkt.srcIP,
      dstIP:     pkt.dstIP,
      dport:     pkt.dport,
      proto:     pkt.proto,
    };
  }

  /* ─── Ingest a new packet into state ─── */
  function ingest(pkt) {
    /* Update counts */
    state.totalPackets++;
    state.bytesTotal += pkt.size;
    state._ppsAccum++;
    state.protoCounts[pkt.proto] = (state.protoCounts[pkt.proto] || 0) + 1;
    state.verdictCounts[pkt.verdict] = (state.verdictCounts[pkt.verdict] || 0) + 1;

    /* CSV tracking */
    state.csvLogged++;
    if (state.csvLogged % 5000 === 0) state.csvFileNum++;

    /* Splunk source tracking */
    state.splunkSources['sniffer_logs']++;
    if (pkt.verdict === 'alert') {
      state.splunkSources['opnsense_syslog'] += utils.randInt(0, 2);
    }

    /* Add to packet ring buffer */
    state.packets.unshift(pkt);
    if (state.packets.length > state.PACKET_CAP) {
      state.packets.pop();
    }

    /* Alerts */
    if (pkt.verdict === 'alert') {
      state.alertCount++;
      const alert = makeAlert(pkt);
      state.alerts.unshift(alert);
      if (state.alerts.length > 200) state.alerts.pop();

      /* Update suspicious IPs */
      state.suspiciousIPs[pkt.srcIP] = (state.suspiciousIPs[pkt.srcIP] || 0) + 1;

      /* Update port hits */
      if (SUSPICIOUS_PORTS.includes(pkt.dport)) {
        state.portHits[pkt.dport] = (state.portHits[pkt.dport] || 0) + 1;
      }

      /* Update alert type counts */
      state.alertTypeCounts[pkt.alertType] = (state.alertTypeCounts[pkt.alertType] || 0) + 1;

      /* Alert timeline: increment last bucket */
      state.alertTimeline[state.alertTimeline.length - 1]++;
    }

    /* Splunk table rows */
    if (state.splunkRows.length < 50 || pkt.verdict !== 'normal') {
      state.splunkRows.unshift({
        time:     pkt.timeStr,
        srcIP:    pkt.srcIP,
        dstIP:    pkt.dstIP,
        protocol: pkt.proto,
        verdict:  pkt.verdict,
        size:     pkt.size,
      });
      if (state.splunkRows.length > 50) state.splunkRows.pop();
    }
  }

  /* ─── Tick: advance OPNsense firewall and alert timeline ─── */
  let _fwTick = 0;
  function tick() {
    _fwTick++;

    /* Advance firewall ring every ~15 ticks */
    if (_fwTick % 15 === 0) {
      state.fwAllowed.shift();
      state.fwAllowed.push(utils.randInt(700, 1600));
      state.fwBlocked.shift();
      state.fwBlocked.push(utils.randInt(60, 200));
    }

    /* Advance alert timeline every ~60 ticks (≈15s) */
    if (_fwTick % 60 === 0) {
      state.alertTimeline.shift();
      state.alertTimeline.push(0);
    }

    /* Splunk syslog trickle */
    if (_fwTick % 20 === 0) {
      state.splunkSources['pi_syslog'] += utils.randInt(0, 3);
      state.splunkSources['docker_logs'] += utils.randInt(0, 1);
    }

    /* PPS: recalculate every 4 ticks (1 second) */
    if (_fwTick % 4 === 0) {
      state.pps = state._ppsAccum;
      state._ppsAccum = 0;
    }
  }

  /* ─── Public API ─── */
  return {
    state,
    generatePacket,
    ingest,
    tick,
  };

})();
