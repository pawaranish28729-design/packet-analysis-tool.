import os
import socket
import subprocess
import time
from datetime import datetime
from scapy.all import AsyncSniffer, wrpcap

CAPTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "captures")
TARGET = "scanme.nmap.org"


def main():
    ip = socket.gethostbyname(TARGET)
    print(f"Target {TARGET} = {ip}")

    sniffer = AsyncSniffer(iface="Wi-Fi", filter=f"host {ip}")
    sniffer.start()
    time.sleep(2)  # let the sniffer get ready

    print("Running Nmap scan...")
    subprocess.run(["nmap", "-F", TARGET])

    time.sleep(2)  # catch the last packets
    packets = sniffer.stop()

    filename = datetime.now().strftime("scan_%Y%m%d_%H%M%S.pcap")
    path = os.path.abspath(os.path.join(CAPTURE_DIR, filename))
    wrpcap(path, packets)
    print(f"Saved {len(packets)} packets to {path}")


if __name__ == "__main__":
    main()