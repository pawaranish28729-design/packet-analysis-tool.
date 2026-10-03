# Packet Analysis Tool

Mini Project 1 (Cyber Security): a Python tool that captures network traffic, analyzes it for suspicious activity, and generates an HTML report of the findings.

## Objective

Monitor and analyze network traffic for potential security threats. The tool covers three tasks:

1. **Packet capture**: capture live traffic with Scapy (Wireshark is used to verify captures).
2. **Packet analysis**: detect malicious IPs, unusual traffic patterns, and header/payload anomalies.
3. **Reporting**: generate a detailed report of threats and anomalies.

## Tools and requirements

| Tool | Version used | Purpose |
|------|--------------|---------|
| Python | 3.14.2 | Main language |
| Scapy | 2.7.0 | Packet capture, reading and crafting |
| Wireshark | 4.6.9 | Visual verification of captures |
| Npcap | 1.88 | Windows capture driver |
| Nmap | 7.991 | Generates a real port scan for testing |
| matplotlib, Jinja2 | latest | Report charts and HTML template |

Tested on Windows 10. Packet capture needs the Npcap driver, and some systems require running the terminal as Administrator.

## Setup

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Install Wireshark (with Npcap) and Nmap from their official websites.

## Project structure

```
packet-analysis-tool/
├── captures/          # saved .pcap files
├── data/
│   └── bad_ips.txt    # blocklist of malicious IPs (one per line)
├── reports/           # generated HTML reports
├── src/
│   ├── capture.py         # live packet capture
│   ├── analyze.py         # analysis and detection engine
│   ├── report.py          # HTML report generator
│   ├── scan_test.py       # captures an Nmap scan for testing
│   └── make_test_pcap.py  # builds a synthetic capture with known anomalies
└── README.md
```

## Usage

```
python src\capture.py 100            # capture 100 packets from the Wi-Fi adapter
python src\analyze.py                # analyze the newest capture
python src\analyze.py captures\file.pcap   # analyze a specific capture
python src\report.py                 # generate an HTML report for the newest capture
python src\scan_test.py              # capture an Nmap scan of scanme.nmap.org
python src\make_test_pcap.py         # build a synthetic test capture
```

Only capture traffic on networks you own or have permission to monitor, and only scan hosts you are allowed to scan (`scanme.nmap.org` permits light scans).

## Detections

| Detector | What it looks for | Why it matters |
|----------|-------------------|----------------|
| Blocklisted IP | Any packet to or from an address listed in `data/bad_ips.txt` | Communication with known malicious hosts |
| Port scan | One source sending SYN packets to 15 or more different ports on one target | Reconnaissance, e.g. an Nmap scan |
| Odd TCP flags | NULL, XMAS, FIN-only and SYN+FIN packets | Stealth scanning techniques |
| Large ICMP | ICMP packets over 1000 bytes | Possible ICMP tunneling or flooding |
| Cleartext credentials | Keywords such as `password=` in unencrypted traffic on ports 21, 23, 80, 110, 143 | Credentials exposed in plain text |

Each finding records the packet number, threat type and details, and appears in both the console output and the report.

## Report

`report.py` produces a single self-contained HTML file in `reports/` with:

- Capture file name, total packets and generation time
- A summary line (number of suspicious findings)
- A threat findings table
- A protocol breakdown chart and table
- Top source and destination IP addresses

## Testing and results

| Test | Capture | Result |
|------|---------|--------|
| Normal browsing | 100 packets of everyday browsing | No threats found, so no false alarms |
| Real port scan | 213 packets, made with `nmap -F scanme.nmap.org` | Port scan detected: 192.168.0.103 probed 100 ports on 45.33.32.156 |
| Synthetic anomalies | `test_anomalies.pcap` (4 packets) | 8 findings: blocklisted IP (4), NULL scan, XMAS scan, large ICMP (1442 bytes), cleartext credentials on port 80 |

## Limitations

- Detection thresholds are fixed (for example, 15 ports for a scan) and may need tuning for busy networks.
- IP-based checks only cover IPv4. IPv6 packets are counted in the summary but not checked against the blocklist.
- Cleartext detection only inspects a few common unencrypted ports and a short keyword list. Encrypted traffic (HTTPS) cannot be inspected.
- The blocklist is manual. A real deployment would load a regularly updated threat feed.
- The tool analyzes saved captures rather than monitoring continuously.

## Possible improvements

- Load blocklists automatically from public threat intelligence feeds
- Add detection for DNS anomalies and high-volume traffic (flooding)
- Support IPv6 in all detectors
- Add a live monitoring mode and alerting