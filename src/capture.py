import os
import sys
from datetime import datetime
from scapy.all import sniff, wrpcap

CAPTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "captures")


def capture(count=100, iface=None, bpf=None, timeout=None):
    print(f"Capturing up to {count} packets (filter: {bpf or 'none'})...")
    packets = sniff(count=count, iface=iface, filter=bpf, timeout=timeout)

    filename = datetime.now().strftime("capture_%Y%m%d_%H%M%S.pcap")
    path = os.path.abspath(os.path.join(CAPTURE_DIR, filename))
    wrpcap(path, packets)

    print(f"Saved {len(packets)} packets to {path}")
    return path


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    bpf = sys.argv[2] if len(sys.argv) > 2 else None
    capture(count=count, iface="Wi-Fi", bpf=bpf, timeout=120)