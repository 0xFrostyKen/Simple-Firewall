import os
import sys
from scapy.all import sniff, IP
import time

from log_alerts import log_event
from sprayer_prevention import detect_spray_attack
from signature_detection import is_malware_signature, detect_syn_scan
from utils import read_ip_file

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

if os.geteuid() != 0:
    print("This script requires root privileges.")
    sys.exit(1)

whitelist_ips = read_ip_file("whitelist.txt")
blacklist_ips = read_ip_file("blacklist.txt")

packet_count = {}
start_time = [0]
blocked_ips = set()

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        return

    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return

    if is_malware_signature(packet, src_ip):
        return

    detect_spray_attack(packet, src_ip, packet_count, start_time, blocked_ips, THRESHOLD)
    # syn scan call
    if detect_syn_scan(packet):
        return

print("Monitoring network traffic...")
start_time[0] = time.time()
sniff(filter="ip", prn=packet_callback)

