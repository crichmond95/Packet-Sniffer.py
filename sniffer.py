from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        print(f"[+] {src} → {dst} | Protocol: {proto}")
        if TCP in packet:
            print(f"    TCP | Sport: {packet[TCP].sport} → Dport: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP | Sport: {packet[UDP].sport} → Dport: {packet[UDP].dport}")

print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(iface="wlan0", prn=packet_callback, store=False, count=50)
