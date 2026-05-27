# Packet sniffer & Homelab Dashboard
**Christian Richmond — Cybersecurity Capstone 2026**

A live, interactive Security Operations Center (SOC) dashboard built to visualize and analyze data from a Python packet sniffer running on a Raspberry Pi 5, with Splunk Enterprise as the SIEM backend.

---

## 🔗 Live Demo
Open `index.html` directly in any modern browser — no server required.

---

## 📁 Project Structure

```
soc-dashboard/
├── index.html          # Main entry point (single-page app, 5 views)
├── css/
│   └── main.css        # Full stylesheet — industrial dark terminal aesthetic
└── js/
    ├── data.js         # Static reference data, seed state, utility helpers
    ├── engine.js       # Packet generation engine & simulation state machine
    ├── charts.js       # Chart.js chart initialization and live update logic
    ├── views.js        # DOM rendering for all 5 dashboard panels
    └── app.js          # Main entry point: tab routing, animation loop, init
```

---

## 🖥️ Features

### 5 Interactive Views

| View | Description |
|------|-------------|
| **Overview** | KPI row, live packet feed, protocol bars, suspicious IP panel, verdict donut |
| **Packet Feed** | Full filterable/searchable packet table with CSV export |
| **Alerts** | Alert log, alert timeline chart, alert type breakdown, suspicious port panel |
| **Infrastructure** | Network topology diagram + all 12 homelab components |
| **Splunk / SIEM** | Firewall event chart, source breakdown, simulated Splunk search results |

### Live Simulation Engine
- Generates realistic home-network traffic at **4× per second** (matching sniffer refresh rate)
- Seeds from **40,000 packet** baseline (reflecting 72-hour continuous capture)
- Accurate protocol weight distribution: TCP 40% · UDP 28% · DNS 14% · HTTP 11% · HTTPS 7%
- Anomaly detection mirrors real sniffer logic:
  - **Connection Rate** — fires when `connRate > 20` (10s sliding window)
  - **Traffic Volume** — per-IP byte threshold (5 MB)
  - **Suspicious Ports** — 22, 23, 3389, 4444, 6666, 1337, 31337

### Data Export
- **Export CSV** button downloads `packets_00N.csv` with all fields:  
  `seq, timestamp, duration_ms, protocol, src_ip, sport, dst_ip, dport, size_bytes, verdict, alert`

---

## 🏗️ Homelab Infrastructure (Modeled)

| Component | Details |
|-----------|---------|
| Mac Pro 2017 | 32 GB RAM · VMware Fusion Pro hypervisor |
| Ubuntu Server 22.04 VM | 8 GB RAM · 100 GB disk · bridged (192.168.0.62) |
| Splunk Enterprise 9.2.1 | SIEM · web UI :8000 · receives on port 9997 |
| OPNsense VM | amd64 · firewall/router · syslog → Splunk |
| Raspberry Pi 5 | ARM64 · eth0 · packet sniffer host |
| Splunk Universal Forwarder | ARM64 .deb · v10.2.2 |
| Pi-hole | Docker · network DNS + ad-blocking |
| Home Assistant | Docker · home automation hub |
| Jellyfin / Nextcloud | Docker · media + file services |
| Tailscale VPN | Secure remote access to all nodes |
| Portainer | Docker management UI |

---

## 🐍 Packet Sniffer (Python — Raspberry Pi 5)

The dashboard visualizes output from a Python sniffer built with **Scapy**:

```bash
sudo python3 sniffer.py \
  --interface eth0 \
  --threshold 20 \
  --volume-mb 5 \
  --window 10 \
  --rotate 30 \
  --output /var/log/sniffer.csv \
  --filter tcp udp dns http https
```

**CLI Flags:** `--interface` · `--filter` · `--output` · `--threshold` · `--volume-mb` · `--window` · `--no-dashboard` · `--quiet` · `--alert-only` · `--rotate` · `--version`

---

## 📊 Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Vanilla HTML5 · CSS3 · JavaScript (ES6+) |
| Charts | Chart.js 4.4.1 |
| Fonts | JetBrains Mono · Inter (Google Fonts) |
| Packet capture | Python · Scapy |
| SIEM | Splunk Enterprise 9.2.1 |
| Firewall | OPNsense 24.1 |
| Infrastructure | VMware Fusion Pro · Docker · Raspberry Pi OS Lite 64-bit |

---

```

---

## 📅 Project Timeline

| Week | Milestone |
|------|-----------|
| 1 (Mar 25) | Raspberry Pi setup · Scapy sniffer v1 · protocol detection |
| 5 | Docker services · Tailscale VPN · Pi-hole · Home Assistant |
| 6 | Splunk Enterprise VM · Universal Forwarder · anomaly detection |
| 7 | Debugging · argparse CLI · rich terminal dashboard · CSV logging |
| 8 | Live capture (40,000+ packets) · real alerts fired |
| 9 | OPNsense firewall · CLI hardening · --quiet / --alert-only flags |
| 10 | 72-hour continuous capture · PPS counter · log rotation · CSV verdict column |
| 11–12 | Final report · presentation · GitHub · demo video |

---

*Cybersecurity Independent Project · May 2026*
