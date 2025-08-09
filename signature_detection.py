import os
from scapy.all import TCP, IP
from log_alerts import log_event
from time import time 
from collections import defaultdict



# this signatures are not final its just there since sql and xss itself has a big attack surface, will be worked on in the future
MALWARE_SIGNATURES = {
    "Nimda": re.compile(r"GET /scripts/roots\.exe", re.IGNORECASE),
    "SQL Injection": re.compile(r"(union select|select \* from)", re.IGNORECASE),
    "XSS Attempt": re.compile(r"<script. *?>", re.IGNORECASE),
    "Shellcode NOP sled": re.compile(r"(\x90{5,})"),
}


def is_malware_signature(packet, src_ip):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        raw_payload = bytes(packet[TCP].payload)
        payload = raw_payload.decode('utf-8', errors='ignore').lower()

        for name, signature in MALWARE_SIGNATURES.items():
            if signature.search(payload):
                os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
                log_event(f"Blocking {name} signature from IP: {src_ip}")
                print(f"Blocking {name} signature from IP: {src_ip}")
                return True
    return False

# SYNC Packet Detection 

# initializing a threshold calculation value 

syn_count = defaultdict(int) # creates a integer dictionary
syn_timestamps = defaultdict(list) # creates a list dictionary

SYN_THRESHOLD = 15 # the threshold for the ammount of syn packets to be eligible for logging
TIME_WINDOW = 10  # in seconds, rate of time in which syn packets need to come 

def detect_syn_scan(packet):
    # checking to see if the is a tcp packet
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]


        # this checks if the packet has a S flag and then logs it
        # syn flag is 1 bit and its hex value is 0x02 so we are making sure we get syn flag 
        if tcp_layer.flags & 0x02:
            src_ip = ip_layer.src
            current_time = time()
        

            # cleaning timestamps that are older than the threshold 
            filtered_timestamp = []
            for t in syn_timestamps[src_ip]:
                if current_time - t < TIME_WINDOW:
                    filtered_timestamp.append(t)
            # just adds the current time to filtered timestamp for future verification and then sends it to syn_timestamps[src_ip]
            filtered_timestamp.append(current_time)
            syn_timestamps[src_ip] = filtered_timestamp
            
            # counts the amount of syn messages
            syn_count[src_ip] = len(syn_timestamps[src_ip])
            
            # logs the messages 
            if syn_count[src_ip] > SYN_THRESHOLD:
                from log_alerts import log_event
                log_event(f"Potential SYN Scan {src_ip} ({syn_count[src_ip]} SYN scans within {TIME_WINDOW}s)")
                print(f"SYN scan detected from {src_ip}")
                return True
    return False
            


