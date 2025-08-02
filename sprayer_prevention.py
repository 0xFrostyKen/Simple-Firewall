import os
import time
from log_alerts import log_event

def detect_spray_attack(packet, src_ip, packet_count, start_time, blocked_ips, threshold):
    packet_count[src_ip] = packet_count.get(src_ip, 0) + 1
    current_time = time.time()
    interval = current_time - start_time[0]

    if interval >= 1:
        for ip, count in packet_count.items():
            rate = count / interval
            if rate > threshold and ip not in blocked_ips:
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(f"Blocking IP: {ip}, packet rate: {rate}")
                print(f"Blocking IP: {ip}, packet rate: {rate}")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time
