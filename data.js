/* ═══════════════════════════════════════════════════════════════
   data.js — Static reference data, constants, and seed state
   SOC Homelab Dashboard · Christian Richmond 2026
═══════════════════════════════════════════════════════════════ */

const SUSPICIOUS_PORTS = [22, 23, 3389, 4444, 6666, 1337, 31337];

const PORT_INFO = {
  22:    { name: 'SSH',        risk: 'medium' },
  23:    { name: 'Telnet',     risk: 'high'   },
  3389:  { name: 'RDP',        risk: 'high'   },
  4444:  { name: 'Metasploit', risk: 'critical' },
  6666:  { name: 'IRC / C2',   risk: 'high'   },
  1337:  { name: 'l33t / C2',  risk: 'critical' },
  31337: { name: 'BackOrifice', risk: 'critical' },
};

const ALERT_TYPES = {
  CONN_RATE:  'Connection Rate',
  VOLUME:     'Traffic Volume',
  SUSP_PORT:  'Suspicious Port',
};

const HOME_IPS = [
  '192.168.0.10',
  '192.168.0.32',
  '192.168.0.62',
  '192.168.0.99',
  '192.168.0.145',
  '192.168.0.160',
  '192.168.0.169',
  '192.168.0.176',
  '192.168.0.236',
  '192.168.0.244',
];

const EXT_IPS = [
  '8.8.8.8',
  '1.1.1.1',
  '142.250.80.14',
  '23.185.0.3',
  '104.18.25.44',
];

const BROADCAST_DSTS = [
  '192.168.0.255',
  '255.255.255.255',
  '224.0.0.251',
  '239.255.255.250',
];

const PROTO_LIST = ['TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS'];

const PROTO_COLORS = {
  TCP:   '#3d8ef0',
  UDP:   '#7c6ff7',
  DNS:   '#22d3ee',
  HTTP:  '#c9893a',
  HTTPS: '#1aab77',
};

const VERDICT_COLORS = {
  normal:     '#1aab77',
  suspicious: '#c9893a',
  alert:      '#e05252',
};

/* ─── Infrastructure Component Data ─── */
const INFRA_COMPONENTS = [
  {
    icon: '🖥️',
    name: 'Mac Pro 2017',
    detail: '32 GB RAM · VMware Fusion Pro host',
    ip: '192.168.0.1',
    status: 'active',
    tags: ['Hypervisor', 'Host'],
  },
  {
    icon: '🐧',
    name: 'Ubuntu Server 22.04',
    detail: '8 GB RAM · 100 GB disk · 192.168.0.62',
    ip: '192.168.0.62',
    status: 'active',
    tags: ['VM', 'Bridged', '4 cores'],
  },
  {
    icon: '🔎',
    name: 'Splunk Enterprise',
    detail: 'v9.2.1 · :8000 web · :9997 recv',
    ip: '192.168.0.62:8000',
    status: 'active',
    tags: ['SIEM', 'Indexing'],
  },
  {
    icon: '🔒',
    name: 'OPNsense Firewall',
    detail: 'amd64 DVD · syslog → Splunk',
    ip: '192.168.0.1',
    status: 'active',
    tags: ['Firewall', 'Router', 'v24.1'],
  },
  {
    icon: '🫐',
    name: 'Raspberry Pi 5',
    detail: 'ARM64 · eth0 · sniffer host',
    ip: '192.168.0.x',
    status: 'active',
    tags: ['Sniffer', 'Docker', 'Pi-hole'],
  },
  {
    icon: '📡',
    name: 'Splunk Forwarder',
    detail: 'ARM64 .deb · v10.2.2 · port 9997',
    ip: 'Pi → 192.168.0.62',
    status: 'active',
    tags: ['syslog', 'Docker logs', 'CSV'],
  },
  {
    icon: '🌐',
    name: 'Pi-hole',
    detail: 'Docker · Network DNS + ad-blocking',
    ip: '192.168.0.x',
    status: 'active',
    tags: ['DNS', 'Docker'],
  },
  {
    icon: '🏠',
    name: 'Home Assistant',
    detail: 'Docker · Home automation hub',
    ip: '192.168.0.x',
    status: 'active',
    tags: ['Automation', 'Docker'],
  },
  {
    icon: '🎬',
    name: 'Jellyfin',
    detail: 'Docker · Media server',
    ip: '192.168.0.x',
    status: 'active',
    tags: ['Media', 'Docker'],
  },
  {
    icon: '☁️',
    name: 'Nextcloud',
    detail: 'Docker · File storage service',
    ip: '192.168.0.x',
    status: 'active',
    tags: ['Files', 'Docker'],
  },
  {
    icon: '🔑',
    name: 'Tailscale VPN',
    detail: 'Secure remote access · all nodes',
    ip: 'Mesh VPN',
    status: 'active',
    tags: ['VPN', 'Remote'],
  },
  {
    icon: '📦',
    name: 'Portainer',
    detail: 'Docker management UI · stacks',
    ip: '192.168.0.x',
    status: 'active',
    tags: ['Docker', 'Mgmt'],
  },
];

/* ─── Topology diagram nodes ─── */
const TOPO_NODES = [
  { icon: '🌐', label: 'Internet', sub: 'WAN', arrow: 'NAT →' },
  { icon: '🔒', label: 'OPNsense', sub: 'Firewall/Router', arrow: 'LAN →' },
  { icon: '🫐', label: 'Raspberry Pi 5', sub: 'eth0 · Sniffer', arrow: 'syslog →' },
  { icon: '🔎', label: 'Splunk', sub: '192.168.0.62:8000', arrow: null },
];

/* ─── Seed / historical data (simulates 72-hr capture) ─── */
const SEED_STATE = {
  totalPackets:   40000,
  alertCount:     7,
  bytesTotal:     52_400_000,   // ~52 MB
  csvLogged:      40124,
  csvFileNum:     4,
  sessionStartMs: Date.now() - 72 * 3600 * 1000,  // 72 hours ago

  protoCounts: {
    TCP:   18200,
    UDP:   12400,
    DNS:    5800,
    HTTP:   2900,
    HTTPS:   700,
  },

  suspiciousIPs: {
    '192.168.0.169': 4,
    '192.168.0.236': 3,
    '192.168.0.99':  1,
  },

  verdictCounts: {
    normal:     39800,
    suspicious:   120,
    alert:         80,
  },

  /* OPNsense firewall history (last 12 ticks) */
  fwAllowed: [980, 1140, 870, 1320, 1050, 1200, 1080, 1400, 960, 1250, 1100, 1300],
  fwBlocked: [120,   98, 145,   87,  160,  105,  130,   92, 118,  140,   88,  115],

  /* Port hit counts */
  portHits: {
    22:    14,
    23:     3,
    3389:   6,
    4444:   2,
    6666:   5,
    1337:   1,
    31337:  1,
  },

  /* Alert type distribution */
  alertTypeCounts: {
    CONN_RATE:  18,
    VOLUME:      9,
    SUSP_PORT:  32,
  },

  /* Alert timeline — past 10 minutes, one bucket per min */
  alertTimeline: [0, 2, 1, 3, 0, 1, 4, 2, 1, 3],

  /* Splunk source breakdown */
  splunkSources: {
    'sniffer_logs':   40124,
    'opnsense_syslog': 1284,
    'pi_syslog':        604,
    'docker_logs':       12,
  },
};

/* Utility helpers used across modules */
const utils = {
  randInt: (a, b) => Math.floor(Math.random() * (b - a + 1)) + a,
  pick:    (arr) => arr[Math.floor(Math.random() * arr.length)],
  fmtTime: (d) => (d || new Date()).toTimeString().slice(0, 8),
  fmtBytes: (b) => {
    if (b >= 1_000_000) return (b / 1_000_000).toFixed(1) + ' MB';
    if (b >= 1_000)     return (b / 1_000).toFixed(1) + ' KB';
    return b + ' B';
  },
  fmtNum: (n) => n.toLocaleString(),
  pad2: (n) => String(n).padStart(2, '0'),
  fmtUptime: (ms) => {
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${utils.pad2(h)}:${utils.pad2(m)}:${utils.pad2(sec)}`;
  },
};
