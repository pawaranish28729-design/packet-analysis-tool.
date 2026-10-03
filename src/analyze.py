import os
import sys
import glob
from collections import Counter
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, Raw

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")
BAD_IPS_FILE = os.path.join(BASE_DIR, "data", "bad_ips.txt")

SCAN_THRESHOLD = 15
SUSPICIOUS_FLAGS = {
    0x00: "NULL scan (no flags set)",
    0x29: "XMAS scan (FIN+PSH+URG)",
    0x01: "FIN-only packet",
    0x03: "SYN+FIN (illegal combination)",
}
LARGE_ICMP_BYTES = 1000
CLEARTEXT_PORTS = {21, 23, 80, 110, 143}
CLEARTEXT_KEYWORDS = [b"password=", b"passwd=", b"pwd=",
                      b"authorization: basic", b"login="]


def latest_capture():
    files = glob.glob(os.path.join(CAPTURE_DIR, "*.pcap*"))
    return max(files, key=os.path.getmtime) if files else None


def load(path):
    return rdpcap(path)


def summarize(packets):
    protocols = Counter()
    sources = Counter()
    destinations = Counter()

    for pkt in packets:
        if pkt.haslayer(TCP):
            protocols["TCP"] += 1
        elif pkt.haslayer(UDP):
            protocols["UDP"] += 1
        elif pkt.haslayer(ICMP):
            protocols["ICMP"] += 1
        else:
            protocols["Other"] += 1

        if pkt.haslayer(IP):
            sources[pkt[IP].src] += 1
            destinations[pkt[IP].dst] += 1
        elif pkt.haslayer(IPv6):
            sources[pkt[IPv6].src] += 1
            destinations[pkt[IPv6].dst] += 1

    return {
        "protocols": dict(protocols.most_common()),
        "sources": sources.most_common(5),
        "destinations": destinations.most_common(5),
    }


def load_bad_ips():
    if not os.path.exists(BAD_IPS_FILE):
        return set()
    with open(BAD_IPS_FILE) as f:
        return {line.strip() for line in f
                if line.strip() and not line.startswith("#")}


def check_bad_ips(packets, bad_ips):
    findings = []
    for i, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(IP):
            continue
        src, dst = pkt[IP].src, pkt[IP].dst
        for ip in (src, dst):
            if ip in bad_ips:
                findings.append({
                    "packet": i,
                    "type": "Blocklisted IP",
                    "detail": f"{src} -> {dst} (matched {ip})",
                })
    return findings


def detect_port_scans(packets, threshold=SCAN_THRESHOLD):
    ports_by_pair = {}
    first_packet = {}

    for i, pkt in enumerate(packets, start=1):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            tcp = pkt[TCP]
            # SYN set, ACK not set = a connection attempt
            if (int(tcp.flags) & 0x12) == 0x02:
                pair = (pkt[IP].src, pkt[IP].dst)
                ports_by_pair.setdefault(pair, set()).add(tcp.dport)
                first_packet.setdefault(pair, i)

    findings = []
    for (src, dst), ports in ports_by_pair.items():
        if len(ports) >= threshold:
            findings.append({
                "packet": first_packet[(src, dst)],
                "type": "Port scan",
                "detail": f"{src} probed {len(ports)} ports on {dst}",
            })
    return findings


def check_tcp_flags(packets):
    findings = []
    for i, pkt in enumerate(packets, start=1):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            flags = int(pkt[TCP].flags) & 0x3F
            if flags in SUSPICIOUS_FLAGS:
                findings.append({
                    "packet": i,
                    "type": "Odd TCP flags",
                    "detail": (f"{pkt[IP].src} -> {pkt[IP].dst}:{pkt[TCP].dport}"
                               f" {SUSPICIOUS_FLAGS[flags]}"),
                })
    return findings


def check_large_icmp(packets):
    findings = []
    for i, pkt in enumerate(packets, start=1):
        if pkt.haslayer(IP) and pkt.haslayer(ICMP) and len(pkt) > LARGE_ICMP_BYTES:
            findings.append({
                "packet": i,
                "type": "Large ICMP",
                "detail": f"{pkt[IP].src} -> {pkt[IP].dst} ({len(pkt)} bytes)",
            })
    return findings


def check_cleartext(packets):
    findings = []
    for i, pkt in enumerate(packets, start=1):
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp = pkt[TCP]
            if tcp.dport in CLEARTEXT_PORTS or tcp.sport in CLEARTEXT_PORTS:
                data = bytes(pkt[Raw].load).lower()
                if any(kw in data for kw in CLEARTEXT_KEYWORDS):
                    findings.append({
                        "packet": i,
                        "type": "Cleartext credentials",
                        "detail": (f"{pkt[IP].src} -> {pkt[IP].dst}:{tcp.dport}"
                                   " sent a login/password in plain text"),
                    })
    return findings


def cap(findings, limit=20):
    """Keep reports readable: show the first `limit`, summarize the rest."""
    if len(findings) <= limit:
        return findings
    shown = findings[:limit]
    shown.append({
        "packet": findings[limit]["packet"],
        "type": findings[0]["type"],
        "detail": f"...and {len(findings) - limit} more of the same",
    })
    return shown


def analyze(path):
    packets = load(path)
    result = summarize(packets)
    result["file"] = os.path.basename(path)
    result["total"] = len(packets)
    result["findings"] = (
        cap(check_bad_ips(packets, load_bad_ips()))
        + detect_port_scans(packets)
        + cap(check_tcp_flags(packets))
        + cap(check_large_icmp(packets))
        + cap(check_cleartext(packets))
    )
    return result


def print_result(result):
    print(f"Loaded {result['total']} packets from {result['file']}")

    print("\nPackets by protocol:")
    for proto, n in result["protocols"].items():
        print(f"  {proto:<6} {n}")

    print("\nTop 5 source IPs:")
    for ip, n in result["sources"]:
        print(f"  {ip:<40} {n}")

    print("\nTop 5 destination IPs:")
    for ip, n in result["destinations"]:
        print(f"  {ip:<40} {n}")

    print("\nThreat findings:")
    if not result["findings"]:
        print("  None found")
    for f in result["findings"]:
        print(f"  [Packet {f['packet']}] {f['type']}: {f['detail']}")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else latest_capture()
    if not path:
        print("No capture files found in captures/")
        sys.exit(1)
    print_result(analyze(path))