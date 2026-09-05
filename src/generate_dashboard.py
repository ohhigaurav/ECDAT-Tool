import json

TIER_COLORS = {
    "CRITICAL": "#e24b4a",
    "HIGH": "#ba7517",
    "MEDIUM": "#ef9f27",
    "LOW": "#639922",
}

with open("ecdat_output.json") as f:
    data = json.load(f)

rows = ""
for c in data["components"]:
    color = TIER_COLORS.get(c["risk_tier"], "#888")
    rows += f"""
    <tr>
      <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;">{c['risk_tier']}</span></td>
      <td>{c['algorithm']}</td>
      <td>{c['purpose']}</td>
      <td>{c['source']}:{c['line']}</td>
      <td>{c['recommendation']}</td>
    </tr>"""

html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ECDAT — Migration Command Center</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #222; }}
h1 {{ font-size: 22px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #eee; font-size: 14px; }}
th {{ background: #f7f7f7; }}
.subtitle {{ color: #666; font-size: 14px; }}
</style></head>
<body>
<h1>ECDAT — Migration Command Center (demo)</h1>
<p class="subtitle">{len(data['components'])}x cryptographic assets discovered on seeded sample repository</p>
<table>
<tr><th>Risk</th><th>Algorithm</th><th>Purpose</th><th>Location</th><th>Recommendation</th></tr>
{rows}
</table>
</body></html>"""

with open("dashboard.html", "w") as f:
    f.write(html)
print("dashboard.html generated")
