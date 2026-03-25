import json
import os
from datetime import datetime
from rich.console import Console

console = Console()

os.makedirs("reports/output", exist_ok=True)

def generate_json(domain: str, data: dict) -> str:
    filename = f"reports/output/{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report = {
        "meta": {
            "tool":      "OSINT Recon Tool",
            "version":   "1.0.0",
            "target":    domain,
            "timestamp": datetime.now().isoformat(),
        },
        "results": data
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)
    console.print(f"\n[green]✅  JSON report saved → {filename}[/green]")
    return filename


def generate_html(domain: str, data: dict) -> str:
    filename = f"reports/output/{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def section(title: str, content: str) -> str:
        return f"""
        <div class="section">
            <h2>{title}</h2>
            <div class="content">{content}</div>
        </div>"""

    def dict_to_table(d: dict) -> str:
        if not d:
            return "<p class='empty'>No data found.</p>"
        rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in d.items() if v)
        return f"<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>"

    def list_to_ul(lst: list) -> str:
        if not lst:
            return "<p class='empty'>None found.</p>"
        items = "".join(f"<li>{i}</li>" for i in lst)
        return f"<ul>{items}</ul>"

    # Build sections
    sections_html = ""

    # DNS
    dns = data.get("dns", {})
    if dns:
        dns_content = dict_to_table({k: ", ".join(v) if isinstance(v, list) else str(v) for k, v in dns.items()})
        sections_html += section("🌐 DNS Records", dns_content)

    # WHOIS
    whois = data.get("whois", {})
    if whois:
        sections_html += section("📋 WHOIS Information", dict_to_table(whois))

    # SSL
    ssl = data.get("ssl", {})
    if ssl:
        ssl_display = dict(ssl)
        ssl_display["sans"] = ", ".join(ssl.get("sans", [])[:20])
        sections_html += section("🔐 SSL Certificate", dict_to_table(ssl_display))

    # SecurityTrails
    st = data.get("securitytrails", {})
    if st:
        subs = st.get("subdomains", [])
        sections_html += section(
            f"🔍 SecurityTrails — Subdomains ({len(subs)} found)",
            list_to_ul(subs[:100])
        )
        dns_hist = st.get("dns_history", [])
        if dns_hist:
            rows = ""
            for r in dns_hist[:10]:
                vals = r.get("values", [{}])
                ip = vals[0].get("ip", "N/A") if vals else "N/A"
                rows += f"<tr><td>{ip}</td><td>{r.get('first_seen','')}</td><td>{r.get('last_seen','')}</td></tr>"
            hist_table = f"<table><thead><tr><th>IP</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>{rows}</tbody></table>"
            sections_html += section("📅 DNS History", hist_table)

    # Ports
    ports = data.get("ports", {})
    if ports:
        open_ports = ports.get("open_ports", {})
        rows = ""
        for port, info in sorted(open_ports.items()):
            risk_class = "risk-high" if info.get("risk") else "risk-normal"
            rows += f"<tr><td>{port}</td><td>{info['service']}</td><td class='{risk_class}'>{'⚠️ HIGH' if info['risk'] else 'Normal'}</td><td>{info.get('banner','')}</td></tr>"
        port_table = f"<table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Banner</th></tr></thead><tbody>{rows}</tbody></table>"
        sections_html += section(f"🔌 Open Ports — {ports.get('ip','')}", port_table)

    # Tech
    tech = data.get("tech", {})
    if tech:
        tech_info = {
            "Detected Technologies": ", ".join(tech.get("detected", [])) or "None",
            "Server":                tech.get("server", "N/A"),
            "Powered By":            tech.get("powered_by", "N/A"),
            "Missing Security Headers": ", ".join(tech.get("missing_security_headers", [])) or "None ✅",
        }
        sections_html += section("🛠️ Technology Stack", dict_to_table(tech_info))

    # Emails
    emails = data.get("emails", {})
    if emails and emails.get("emails"):
        sections_html += section("📧 Email Harvest", list_to_ul(emails.get("emails", [])))

    # Shodan
    shodan = data.get("shodan", {})
    if shodan:
        shodan_display = {k: ", ".join(v) if isinstance(v, list) else str(v) for k, v in shodan.items()}
        sections_html += section("👁️ Shodan Intelligence", dict_to_table(shodan_display))

    # Geolocation
    geo = data.get("geo", {})
    if geo:
        sections_html += section("🌍 IP Geolocation", dict_to_table(geo))

    # VirusTotal
    vt = data.get("virustotal", {})
    if vt:
        vt_display = {k: ", ".join(v) if isinstance(v, list) else str(v) for k, v in vt.items() if k != "subdomains"}
        sections_html += section("🦠 VirusTotal Report", dict_to_table(vt_display))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Report — {domain}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 30px;
        }}
        .header {{
            background: linear-gradient(135deg, #161b22, #21262d);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2rem;
            color: #58a6ff;
            margin-bottom: 10px;
        }}
        .header .meta {{
            color: #8b949e;
            font-size: 0.9rem;
        }}
        .header .target {{
            font-size: 1.3rem;
            color: #3fb950;
            margin: 10px 0;
            font-weight: bold;
        }}
        .section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .section h2 {{
            font-size: 1.1rem;
            color: #58a6ff;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 1px solid #30363d;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
        }}
        th {{
            background: #21262d;
            color: #8b949e;
            text-align: left;
            padding: 8px 12px;
            border-bottom: 1px solid #30363d;
        }}
        td {{
            padding: 8px 12px;
            border-bottom: 1px solid #21262d;
            word-break: break-all;
        }}
        tr:hover td {{ background: #1c2128; }}
        ul {{ list-style: none; padding: 0; display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 6px; }}
        ul li {{
            background: #21262d;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.85rem;
            color: #79c0ff;
        }}
        .risk-high {{ color: #f85149; font-weight: bold; }}
        .risk-normal {{ color: #3fb950; }}
        .empty {{ color: #6e7681; font-style: italic; }}
        .footer {{
            text-align: center;
            color: #6e7681;
            font-size: 0.8rem;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 OSINT Reconnaissance Report</h1>
        <div class="target">🎯 {domain}</div>
        <div class="meta">Generated: {ts} &nbsp;|&nbsp; Tool: OSINT Recon v1.0.0</div>
    </div>

    {sections_html}

    <div class="footer">
        ⚠️ This report is for authorized security testing only. Use responsibly.
    </div>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)

    console.print(f"[green]✅  HTML report saved → {filename}[/green]")
    return filename


def generate(domain: str, data: dict, fmt: str = "html") -> str:
    if fmt == "json":
        return generate_json(domain, data)
    elif fmt == "html":
        return generate_html(domain, data)
    elif fmt == "both":
        generate_json(domain, data)
        return generate_html(domain, data)
    else:
        return generate_html(domain, data)
