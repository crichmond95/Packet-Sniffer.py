# 🕵️ Raspberry Pi Packet Sniffer & SOC Homelab

**Capstone / Independent Cybersecurity Project | Christian Richmond | 2026**

A fully functional network packet sniffer built in Python on a Raspberry Pi 5, integrated into a personal SOC analyst homelab with a live SIEM pipeline. This project was built from scratch over 10 weeks — from a bare Pi to a full detection stack with anomaly alerts, terminal dashboard, CLI configuration, and Splunk indexing.

---

## 📋 Project Overview

The goal was to demonstrate a hands-on understanding of:
- Network protocols and packet capture techniques
- Python scripting with real network data
- Anomaly detection and alerting logic
- Building and operating a SOC analyst environment

The packet sniffer runs on a Raspberry Pi 5, captures live traffic from a real home network, and forwards logs to Splunk Enterprise running on a local Ubuntu VM — the full detection pipeline (Pi → sniffer → OPNsense firewall → Splunk) is operational.

---

## ✅ Features

### Packet Sniffer
| Feature | Description |
|---|---|
| Protocol filtering | HTTP, HTTPS, DNS, TCP, UDP — priority ordered to prevent misclassification |
| Packet size extraction | `len(pkt)` captures full frame size including headers |
| JSON logging | Structured JSON per packet written to `packets.log` |
| CSV logging | `packets.csv` with timestamp, protocol, src/dst IP:port, size, verdict, duration_ms |
| In-memory statistics | Per-protocol packet counts + total bytes, printed on exit |
| Connection rate detection | Sliding 10-second window; alert fires above configurable threshold (default 20 conns/IP) |
| Traffic volume detection | Per-IP byte accumulator; alert fires above configurable MB threshold |
| Suspicious port detection | Ports 22, 23, 3389, 4444, 6666, 1337, 31337 flagged on detection |
| Alert system | `[ALERT/HIGH]` printed in red ANSI to terminal + written to log |
| CLI via argparse | Full flag set — see usage below |
| Live terminal dashboard | Protocol stats, top 10 IPs, alert count, PPS — refreshes 4×/sec via `rich` |
| Log rotation | `--rotate N` creates a new CSV every N minutes (`packets_001.csv`, `packets_002.csv`, …) |
| Headless operation | `--quiet` and `--alert-only` flags enable background service mode via `nohup` |

### SOC Homelab Infrastructure
| Component | Details |
|---|---|
| Raspberry Pi 5 | ARM64 — packet sniffer host + log source endpoint |
| Mac Pro 2017 (32 GB) | Hypervisor host running VMware Fusion Pro |
| Ubuntu Server 22.04 VM | 8 GB RAM, 100 GB disk, bridged networking (192.168.0.62) |
| Splunk Enterprise 9.2.1 | SIEM — web UI at `192.168.0.62:8000`, receives logs on port 9997 |
| OPNsense VM | amd64 firewall/router — syslog forwarded to Splunk (1,200+ events/hr) |
| Splunk Universal Forwarder | ARM64 `.deb` — forwards syslog, sniffer CSV, and Docker logs to Splunk |
| Pi-hole | Network-wide DNS ad blocking via Docker on the Pi |
| Home Assistant | Home automation hub via Docker on the Pi |
| Jellyfin / Nextcloud | Media + file services via Docker on the Pi |
| Tailscale VPN | Secure remote access to all homelab services |

---

## 🚀 Usage

```bash
# Basic capture on wlan0
sudo python3 sniffer.py --interface wlan0

# Filter to TCP traffic only, output to file
sudo python3 sniffer.py --interface eth0 --filter tcp --output /var/log/sniffer.csv

# Run headless as a background service with log rotation every 30 minutes
sudo nohup python3 sniffer.py --interface eth0 --no-dashboard --quiet \
  --output /var/log/sniffer.csv --rotate 30 &

# Custom alert thresholds
sudo python3 sniffer.py --interface eth0 --threshold 15 --volume-mb 3 --window 10

# Log only packets that triggered an alert
sudo python3 sniffer.py --interface eth0 --alert-only

# Print version
python3 sniffer.py --version
```

### CLI Flags
| Flag | Description |
|---|---|
| `--interface` | Network interface to listen on (e.g. `eth0`, `wlan0`) |
| `--filter` | BPF filter string (e.g. `tcp port 80`) |
| `--output` | Path for CSV output file |
| `--threshold` | Connection rate alert threshold (connections per window, default 20) |
| `--volume-mb` | Traffic volume alert threshold in MB per source IP |
| `--window` | Sliding window size in seconds for rate detection (default 10) |
| `--no-dashboard` | Disable live terminal dashboard |
| `--quiet` | Suppress dashboard; print alerts only |
| `--alert-only` | Log only packets that triggered an alert to CSV |
| `--rotate N` | Rotate CSV log every N minutes |
| `--version` | Print sniffer version and exit |

---

## 📦 Installation

```bash
# Update and install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip tcpdump wireshark -y

# Install Python libraries
pip3 install scapy rich

# Enable promiscuous mode on your interface
sudo ip link set eth0 promisc on

# Run with root privileges (required for raw packet capture)
sudo python3 sniffer.py --interface eth0
```

---

## 📊 Sample Output

```
Starting packet sniffer... Press Ctrl+C to stop.

[+] 192.168.0.24 -> 8.8.8.8 | Protocol: UDP
    Sport: 55234 -> Dport: 53

[ALERT/HIGH] 17:28:34 — Possible port scan / flood from 192.168.0.169 (22 conns in 10s)

[TCP] 192.168.0.236:34798 -> 192.168.0.160:8009  176B
[UDP] 192.168.0.99:42410  -> 192.168.0.255:15600  77B
```

**Live alert triage from homelab capture:**
| Alert | Source IP | Verdict |
|---|---|---|
| 22 conns in 10s | 192.168.0.169 | High connection rate — likely port scan or aggressive client |
| 21–22 conns in 10s | 192.168.0.236 | Sustained TCP to port 8009 — Chromecast (normal but high-rate) |
| UDP → 255.255.255.255:6667 | Multiple IPs | Broadcast UDP — UPnP/mDNS discovery, expected |
| UDP → 239.255.255.250:15600 | 192.168.0.99 | Multicast — DLNA/UPnP service discovery, normal |

---

## 🧠 Key Concepts

| Concept | Description |
|---|---|
| Protocol Numbers | `6` = TCP, `17` = UDP, `1` = ICMP — carried in every IP header |
| Promiscuous Mode | Allows the NIC to capture all packets on the segment, not just those addressed to the Pi |
| BPF Filters | Berkeley Packet Filter syntax used by Scapy/tcpdump to isolate traffic by protocol, port, or IP |
| Scapy Layers | Packets are stacked layers (Ethernet → IP → TCP/UDP). Each layer is inspectable independently |
| Sliding Window | Connection rate measured over a rolling N-second window to detect bursts without false positives |
| SIEM (Splunk) | Security Information and Event Management — indexes and searches all log data across the stack |
| `store=False` | Prevents Scapy from buffering packets in memory — essential for long captures on low-RAM hardware |

---

## 🛠️ Lessons Learned

1. **Use heredoc to write Python from the terminal.** `cat > sniffer.py << 'EOF'` eliminates all indentation errors caused by mixing tabs and spaces when typing line by line.
2. **Always run with `sudo`.** Raw packet capture requires root on Linux — `sudo python3 sniffer.py`.
3. **Set VM networking to Bridged, not NAT.** NAT prevents the Pi from reaching a Splunk VM on the same subnet.
4. **Raspberry Pi OS uses `journald` by default.** Install `rsyslog` to create `/var/log/syslog` as a forwardable log source for Splunk.
5. **Test stateful features across restarts.** Running the sniffer for 72 hours revealed a log rotation edge case that only appeared on process restart — not during a single run.
6. **Switch early when a tool repeatedly fails.** OPNsense installed and configured easily after pfSense failed repeatedly — retrying a broken tool wastes time.
7. **Structured logging pays off immediately.** Adding a `verdict` column to the CSV made post-capture analysis in Google Sheets take seconds instead of manual row scanning.
8. **Design for headless operation from the start.** `--quiet` and `--alert-only` made the sniffer practical as a background service on the Pi — these should have been added earlier.

---

## 📁 File Structure

```
.
├── sniffer.py          # Main packet sniffer
├── packets.log         # JSON log — one entry per captured packet
├── packets.csv         # CSV log — all fields + verdict + duration_ms
├── packets_001.csv     # Rotated CSV logs (--rotate flag)
├── packets_002.csv
└── README.md
```

---

## 🔧 Tech Stack

**Languages:** Python 3  
**Libraries:** Scapy, rich, argparse, csv, logging, collections  
**Tools:** tcpdump, Wireshark, Splunk Enterprise, Splunk Universal Forwarder, Docker, Portainer, VMware Fusion Pro, OPNsense, Tailscale  
**Hardware:** Raspberry Pi 5 (ARM64), Mac Pro 2017 (hypervisor)  
**OS:** Raspberry Pi OS Lite 64-bit, Ubuntu Server 22.04 LTS  

---

## 📅 Project Timeline

| Weeks | Focus |
|---|---|
| 1–4 | Environment setup, Scapy basics, live capture, promiscuous mode, Wireshark |
| 5 | Homelab foundation (Pi 5 + Docker + Tailscale VPN); sniffer v1 with JSON logging |
| 6 | Splunk SIEM deployment on Ubuntu VM; anomaly detection logic (rate, volume, ports) |
| 7 | Full debug session (heredoc rewrite); argparse CLI; rich terminal dashboard; CSV logging |
| 8 | Live capture on homelab network; real alert triage; full feature wrap-up |
| 9 | OPNsense firewall deployment; CLI hardening (`--quiet`, `--alert-only`, `--version`) |
| 10 | Dashboard upgrades (PPS, color coding, top suspicious IPs); CSV improvements; 72-hour continuous capture |
| 11–12 | Final system testing, technical report, presentation, demo video *(upcoming)* |
