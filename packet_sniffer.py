from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
import logging
import time
import json
from collections import defaultdict

logging.basicConfig(
    filename="packets.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

stats = {
    "total": 0,
    "http": 0,
    "dns": 0,
    "tcp": 0,
    "udp": 0,
    "other": 0,
    "total_bytes": 0
}

def get_protocol(pkt):
    if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
        return "HTTP"
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "OTHER"

def get_size(pkt):
    return len(pkt)  

def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    proto  = get_protocol(pkt)
    size   = get_size(pkt)
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    src_port = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else None)
    dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None)

    stats["total"] += 1
    stats["total_bytes"] += size
    stats[proto.lower() if proto.lower() in stats else "other"] += 1

    record = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "protocol": proto,
        "src": f"{src_ip}:{src_port}",
        "dst": f"{dst_ip}:{dst_port}",
        "size": size
    }
    logging.info(json.dumps(record))

    print(f"[{proto:5}] {src_ip}:{src_port} → {dst_ip}:{dst_port}  {size}B")

    detect_anomalies(src_ip, dst_ip, dst_port, size, proto)

def print_stats():
    print("\n── Packet Statistics ─────────────────────")
    for k, v in stats.items():
        print(f"  {k:15}: {v}")
    print("──────────────────────────────────────────\n")
connection_tracker  = defaultdict(list)   # ip → [timestamps]
volume_tracker      = defaultdict(int)    # ip → bytes
alert_log           = []

SUSPICIOUS_PORTS    = {22, 23, 3389, 4444, 6666, 1337, 31337}
CONN_THRESHOLD      = 20    # connections per 10 seconds = suspicious
VOLUME_THRESHOLD    = 5_000_000  # 5 MB per IP = suspicious

def alert(level, msg):
    """Central alert system."""
    entry = f"[ALERT/{level}] {time.strftime('%H:%M:%S')} — {msg}"
    alert_log.append(entry)
    logging.warning(entry)
    print(f"\033[91m{entry}\033[0m")  # red in terminal

def detect_anomalies(src_ip, dst_ip, dst_port, size, proto):
    now = time.time()

    # ── Repeated connections from same IP ──────────────────
    connection_tracker[src_ip].append(now)
    # Keep only last 10 seconds
    connection_tracker[src_ip] = [t for t in connection_tracker[src_ip] if now - t < 10]
    if len(connection_tracker[src_ip]) > CONN_THRESHOLD:
        alert("HIGH", f"Possible port scan / flood from {src_ip} "
                      f"({len(connection_tracker[src_ip])} conns in 10s)")

    # ── Unusual traffic volume ─────────────────────────────
    volume_tracker[src_ip] += size
    if volume_tracker[src_ip] > VOLUME_THRESHOLD:
        alert("MEDIUM", f"High traffic volume from {src_ip}: "
                        f"{volume_tracker[src_ip] / 1_000_000:.2f} MB")
        volume_tracker[src_ip] = 0  # reset to avoid spam

    # ── Suspicious ports ───────────────────────────────────
    if dst_port in SUSPICIOUS_PORTS:
        alert("HIGH", f"Traffic to suspicious port {dst_port} "
                      f"from {src_ip} → {dst_ip} [{proto}]")
if __name__ == "__main__":
    import atexit
    atexit.register(print_stats)

    print("Starting packet capture… (Ctrl+C to stop)\n")
    try:
        sniff(
            prn=process_packet,
            store=False,          # don't buffer in RAM
            filter="ip",          # BPF filter — only IP packets
            # iface="eth0",       # uncomment to lock to an interface
        )
    except KeyboardInterrupt:
        print("\nCapture stopped.")
        print_stats()

#!/usr/bin/env python3
"""
Packet Sniffer — Upgraded Build
Features: CLI (argparse), live stats dashboard (rich), CSV logging with timestamps
Requires: scapy, rich
  pip install scapy rich
Run with: sudo python3 packet_sniffer.py --interface eth0
"""

import argparse
import atexit
import csv
import json
import logging
import os
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scapy.all import sniff, IP, TCP, UDP, DNS, Raw

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="Network interface to sniff on (e.g. eth0, wlan0)\nDefault: Scapy auto-selects"
    )
    parser.add_argument(
        "--filter", "-f",
        default=None,
        dest="bpf_filter",
        help="BPF filter string (e.g. 'tcp', 'udp port 53')\nDefault: capture all"
    )
    parser.add_argument(
        "--output", "-o",
        default="packets",
        help="Base name for output files (no extension)\nDefault: packets  →  packets.log + packets.csv"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=20,
        help="Connection count threshold per IP before alert fires\nDefault: 20"
    )
    parser.add_argument(
        "--volume-mb",
        type=float,
        default=5.0,
        help="Traffic volume threshold in MB per IP before alert fires\nDefault: 5.0"
    )
    parser.add_argument(
        "--window", "-w",
        type=int,
        default=10,
        help="Sliding window in seconds for connection rate tracking\nDefault: 10"
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable the live rich dashboard (plain terminal output only)"
    )
    return parser.parse_args()


# ─────────────────────────────────────────────
# GLOBALS (populated after arg parse)
# ─────────────────────────────────────────────

args = parse_args()

SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 6666, 1337, 31337}
VOLUME_THRESHOLD = int(args.volume_mb * 1_000_000)
CONN_THRESHOLD   = args.threshold
WINDOW_SECONDS   = args.window

stats = {
    "total":   0,
    "HTTP":    0,
    "DNS":     0,
    "TCP":     0,
    "UDP":     0,
    "OTHER":   0,
    "bytes":   0,
    "alerts":  0,
}

connection_tracker = defaultdict(list)   # ip → [timestamps]
volume_tracker     = defaultdict(int)    # ip → bytes
top_ips            = defaultdict(int)    # ip → packet count

console = Console()

# ─────────────────────────────────────────────
# LOGGING — JSON log
# ─────────────────────────────────────────────

log_path = f"{args.output}.log"
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format="%(message)s"
)

# ─────────────────────────────────────────────
# CSV LOGGING
# ─────────────────────────────────────────────

csv_path   = f"{args.output}.csv"
_csv_file  = open(csv_path, "w", newline="")
_csv_writer = csv.DictWriter(
    _csv_file,
    fieldnames=["timestamp", "protocol", "src_ip", "src_port",
                "dst_ip",   "dst_port", "size_bytes", "alert"]
)
_csv_writer.writeheader()

def write_csv(timestamp, protocol, src_ip, src_port, dst_ip, dst_port, size, alert=""):
    _csv_writer.writerow({
        "timestamp":  timestamp,
        "protocol":   protocol,
        "src_ip":     src_ip,
        "src_port":   src_port,
        "dst_ip":     dst_ip,
        "dst_port":   dst_port,
        "size_bytes": size,
        "alert":      alert,
    })
    _csv_file.flush()


# ─────────────────────────────────────────────
# ALERT
# ─────────────────────────────────────────────

def alert(message, src_ip="", dst_ip="", protocol="", size=0):
    stats["alerts"] += 1
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tag = f"[ALERT] {message}"

    # Write to JSON log
    logging.warning(json.dumps({
        "time":     ts,
        "level":    "ALERT",
        "message":  message,
        "src_ip":   src_ip,
    }))

    # Write to CSV with alert column filled
    write_csv(ts, protocol, src_ip, "", dst_ip, "", size, alert=message)

    # Print if no dashboard
    if args.no_dashboard:
        console.print(f"[bold red]{tag}[/bold red]")


# ─────────────────────────────────────────────
# PROTOCOL DETECTION
# ─────────────────────────────────────────────

def get_protocol(pkt):
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if tcp.dport in (80, 8080) or tcp.sport in (80, 8080):
            return "HTTP"
        if tcp.dport == 443 or tcp.sport == 443:
            return "HTTPS"
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "OTHER"


# ─────────────────────────────────────────────
# ANOMALY DETECTION
# ─────────────────────────────────────────────

def detect_anomalies(src_ip, size):
    now = time.time()

    # Connection rate
    connection_tracker[src_ip].append(now)
    connection_tracker[src_ip] = [
        t for t in connection_tracker[src_ip]
        if now - t <= WINDOW_SECONDS
    ]
    if len(connection_tracker[src_ip]) > CONN_THRESHOLD:
        alert(
            f"High connection rate from {src_ip} "
            f"({len(connection_tracker[src_ip])} in {WINDOW_SECONDS}s)",
            src_ip=src_ip
        )

    # Volume
    volume_tracker[src_ip] += size
    if volume_tracker[src_ip] > VOLUME_THRESHOLD:
        alert(
            f"High volume from {src_ip} "
            f"({volume_tracker[src_ip] / 1_000_000:.2f} MB)",
            src_ip=src_ip
        )
        volume_tracker[src_ip] = 0  # reset to prevent spam


def check_suspicious_ports(src_ip, sport, dport, protocol, size):
    flagged = set()
    if sport in SUSPICIOUS_PORTS:
        flagged.add(sport)
    if dport in SUSPICIOUS_PORTS:
        flagged.add(dport)
    for port in flagged:
        alert(
            f"Suspicious port {port} — {src_ip}",
            src_ip=src_ip,
            protocol=protocol,
            size=size
        )


# ─────────────────────────────────────────────
# PACKET PROCESSOR
# ─────────────────────────────────────────────

def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    protocol  = get_protocol(pkt)
    size      = len(pkt)
    src_ip    = pkt[IP].src
    dst_ip    = pkt[IP].dst
    src_port  = 0
    dst_port  = 0
    ts        = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    # Update stats
    stats["total"] += 1
    stats["bytes"] += size
    stats[protocol if protocol in stats else "OTHER"] += 1
    top_ips[src_ip] += 1

    # JSON log
    record = {
        "time":     ts,
        "protocol": protocol,
        "src_ip":   src_ip,
        "src_port": src_port,
        "dst_ip":   dst_ip,
        "dst_port": dst_port,
        "size":     size,
    }
    logging.info(json.dumps(record))

    # CSV log
    write_csv(ts, protocol, src_ip, src_port, dst_ip, dst_port, size)

    # Anomaly checks
    detect_anomalies(src_ip, size)
    if src_port or dst_port:
        check_suspicious_ports(src_ip, src_port, dst_port, protocol, size)

    # Plain output (no dashboard)
    if args.no_dashboard:
        console.print(
            f"[cyan]{ts}[/cyan] [green]{protocol:<6}[/green] "
            f"{src_ip}:{src_port} → {dst_ip}:{dst_port}  "
            f"[dim]{size}B[/dim]"
        )


# ─────────────────────────────────────────────
# RICH DASHBOARD
# ─────────────────────────────────────────────

def build_dashboard():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="stats"),
        Layout(name="top_ips"),
        Layout(name="alerts_panel"),
    )

    # Header
    layout["header"].update(
        Panel(
            Text("● PACKET SNIFFER", style="bold green", justify="center"),
            style="green",
        )
    )

    # Stats table
    stats_table = Table(show_header=True, header_style="bold cyan", expand=True)
    stats_table.add_column("Protocol", style="cyan")
    stats_table.add_column("Packets", justify="right")

    proto_order = ["HTTP", "HTTPS", "DNS", "TCP", "UDP", "OTHER"]
    for proto in proto_order:
        count = stats.get(proto, 0)
        stats_table.add_row(proto, str(count))

    stats_table.add_row("─" * 10, "─" * 8)
    stats_table.add_row("[bold]TOTAL[/bold]", f"[bold]{stats['total']}[/bold]")
    stats_table.add_row("Bytes", f"{stats['bytes']:,}")

    layout["stats"].update(Panel(stats_table, title="[bold]Protocols[/bold]"))

    # Top IPs table
    ip_table = Table(show_header=True, header_style="bold magenta", expand=True)
    ip_table.add_column("Source IP")
    ip_table.add_column("Packets", justify="right")

    sorted_ips = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]
    for ip, count in sorted_ips:
        ip_table.add_row(ip, str(count))

    layout["top_ips"].update(Panel(ip_table, title="[bold]Top Source IPs[/bold]"))

    # Alerts panel
    alert_text = Text()
    alert_text.append(f"Alerts fired: ", style="bold")
    alert_text.append(
        str(stats["alerts"]),
        style="bold red" if stats["alerts"] > 0 else "bold green"
    )
    alert_text.append(f"\n\nLog file:  {log_path}\n", style="dim")
    alert_text.append(f"CSV file:  {csv_path}\n", style="dim")
    alert_text.append(
        f"\nInterface: {args.interface or 'auto'}\n"
        f"BPF filter: {args.bpf_filter or 'none'}\n"
        f"Conn threshold: {CONN_THRESHOLD}/{WINDOW_SECONDS}s\n"
        f"Volume threshold: {args.volume_mb} MB",
        style="dim"
    )
    layout["alerts_panel"].update(Panel(alert_text, title="[bold]Status[/bold]"))

    # Footer
    layout["footer"].update(
        Panel(
            Text("Ctrl+C to stop and print summary", justify="center", style="dim"),
            style="dim"
        )
    )

    return layout


# ─────────────────────────────────────────────
# EXIT SUMMARY
# ─────────────────────────────────────────────

def print_summary():
    console.print("\n[bold cyan]─── Session Summary ───[/bold cyan]")
    console.print(f"  Total packets : {stats['total']}")
    console.print(f"  Total bytes   : {stats['bytes']:,}")
    for proto in ["HTTP", "HTTPS", "DNS", "TCP", "UDP", "OTHER"]:
        console.print(f"  {proto:<8}      : {stats.get(proto, 0)}")
    console.print(f"  Alerts fired  : [bold red]{stats['alerts']}[/bold red]")
    console.print(f"\n  Log → {log_path}")
    console.print(f"  CSV → {csv_path}")

atexit.register(print_summary)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        console.print("[bold red]Error:[/bold red] Run with sudo — raw packet capture requires root.")
        sys.exit(1)

    console.print(
        f"[bold green]Starting sniffer[/bold green] — "
        f"interface=[cyan]{args.interface or 'auto'}[/cyan]  "
        f"filter=[cyan]{args.bpf_filter or 'none'}[/cyan]"
    )

    if args.no_dashboard:
        sniff(
            iface=args.interface,
            filter=args.bpf_filter,
            prn=process_packet,
            store=False
        )
    else:
        with Live(build_dashboard(), refresh_per_second=2, screen=True) as live:
            def refresh_loop(pkt):
                process_packet(pkt)
                live.update(build_dashboard())

            sniff(
                iface=args.interface,
                filter=args.bpf_filter,
                prn=refresh_loop,
                store=False
            )


if __name__ == "__main__":
    main()
