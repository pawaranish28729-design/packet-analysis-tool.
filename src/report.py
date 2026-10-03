import os
import sys
import io
import base64
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from jinja2 import Environment

from analyze import analyze, latest_capture

REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Packet Analysis Report</title>
<style>
  body { font-family: Arial, sans-serif; margin: 40px auto; max-width: 900px; color: #222; }
  h1 { border-bottom: 3px solid #1f4e79; padding-bottom: 8px; }
  h2 { color: #1f4e79; margin-top: 32px; }
  table { border-collapse: collapse; width: 100%; margin-top: 8px; }
  th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
  th { background: #1f4e79; color: white; }
  .ok { color: #1a7f37; font-weight: bold; }
  .bad { color: #b42318; font-weight: bold; }
  .meta { color: #555; }
</style>
</head>
<body>
<h1>Packet Analysis Report</h1>
<p class="meta">
  Capture file: <b>{{ r.file }}</b><br>
  Total packets: <b>{{ r.total }}</b><br>
  Generated: {{ generated }}
</p>

<h2>Summary</h2>
{% if r.findings %}
  <p class="bad">{{ r.findings|length }} suspicious finding(s) detected.</p>
{% else %}
  <p class="ok">No threats detected.</p>
{% endif %}

<h2>Threat Findings</h2>
{% if r.findings %}
<table>
  <tr><th>Packet #</th><th>Type</th><th>Details</th></tr>
  {% for f in r.findings %}
  <tr><td>{{ f.packet }}</td><td>{{ f.type }}</td><td>{{ f.detail }}</td></tr>
  {% endfor %}
</table>
{% else %}
<p>None found.</p>
{% endif %}

<h2>Protocol Breakdown</h2>
<img src="data:image/png;base64,{{ chart }}" alt="Packets by protocol" style="max-width:100%">
<table>
  <tr><th>Protocol</th><th>Packets</th></tr>
  {% for proto, n in r.protocols.items() %}
  <tr><td>{{ proto }}</td><td>{{ n }}</td></tr>
  {% endfor %}
</table>

<h2>Top Source IPs</h2>
<table>
  <tr><th>IP address</th><th>Packets</th></tr>
  {% for ip, n in r.sources %}
  <tr><td>{{ ip }}</td><td>{{ n }}</td></tr>
  {% endfor %}
</table>

<h2>Top Destination IPs</h2>
<table>
  <tr><th>IP address</th><th>Packets</th></tr>
  {% for ip, n in r.destinations %}
  <tr><td>{{ ip }}</td><td>{{ n }}</td></tr>
  {% endfor %}
</table>
</body>
</html>
"""


def make_chart(protocols):
    fig, ax = plt.subplots(figsize=(6, 3.5))
    ax.bar(list(protocols.keys()), list(protocols.values()), color="#1f4e79")
    ax.set_ylabel("Packets")
    ax.set_title("Packets by protocol")
    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()


def build_report(path):
    result = analyze(path)
    env = Environment(autoescape=True)
    html = env.from_string(TEMPLATE).render(
        r=result,
        chart=make_chart(result["protocols"]),
        generated=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
    )

    os.makedirs(REPORT_DIR, exist_ok=True)
    name = datetime.now().strftime("report_%Y%m%d_%H%M%S.html")
    out = os.path.abspath(os.path.join(REPORT_DIR, name))
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Report saved to {out}")
    return out


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else latest_capture()
    if not path:
        print("No capture files found in captures/")
        sys.exit(1)
    out = build_report(path)
    try:
        os.startfile(out)
    except Exception:
        pass