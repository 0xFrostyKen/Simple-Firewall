import os
from scapy.all import TCP
from log_alerts import log_event

# Can be expanded into JSON later
MALWARE_SIGNATURES = {
    "Nimda": "GET /scripts/root.exe"
}

def is_malware_signature(packet, src_ip):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = str(packet[TCP].payload)

        for name, signature in MALWARE_SIGNATURES.items():
            if signature in payload:
                os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
                log_event(f"Blocking {name} signature from IP: {src_ip}")
                print(f"Blocking {name} signature from IP: {src_ip}")
                return True
    return False
