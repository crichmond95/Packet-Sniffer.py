import argparse

parser = argparse.ArgumentParser(
    description="Raspberry Pi Network IDS"
)

parser.add_argument(
    "--quiet",
    action="store_true",
    help="Disable live dashboard"
)

parser.add_argument(
    "--alert-only",
    action="store_true",
    help="Show only alerts"
)

parser.add_argument(
    "--rotate",
    type=int,
    help="Rotate logs every N minutes"
)

args = parser.parse_args()

from colorama import Fore, init

init()

print(Fore.GREEN + "NORMAL")
print(Fore.YELLOW + "WATCH")
print(Fore.RED + "ALERT")


packet_count = 50 
packet_count += 1
import time
start_time = time.time()
elapsed = time.time() - start_time
print(f"Time taken: {elapsed} seconds")
pps = packet_count / elapsed

print(f"PPS: {pps:.2f}")

from collections import defaultdict

suspicious_ips = defaultdict(int)

suspicious_ips["src_192.168.0.236"] = suspicious_ips.get("src_192.168.0.236", 0) + 1

print("\nTop Suspicious IPs")

for ip, count in sorted(
    suspicious_ips.items(),
    key=lambda x: x[1],
    reverse=True
)[:5]:

    print(f"{ip} -> {count}")
