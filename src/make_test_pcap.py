import os
from scapy.all import Ether, IP, TCP, ICMP, Raw, wrpcap

src, dst = "192.168.0.103", "203.0.113.5"
pkts = [
    Ether()/IP(src=src, dst=dst)/TCP(sport=40000, dport=80, flags=0),
    Ether()/IP(src=src, dst=dst)/TCP(sport=40001, dport=80, flags="FPU"),
    Ether()/IP(src=src, dst=dst)/ICMP()/Raw(b"A" * 1400),
    Ether()/IP(src=src, dst=dst)/TCP(sport=40002, dport=80, flags="PA")
        /Raw(b"POST /login HTTP/1.1\r\nHost: test\r\n\r\nuser=admin&password=secret123"),
]

out = os.path.join(os.path.dirname(__file__), "..", "captures", "test_anomalies.pcap")
wrpcap(out, pkts)
print("Saved", os.path.abspath(out))