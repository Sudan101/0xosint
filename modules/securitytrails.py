import requests
from config import Config
from rich.console import Console
from rich.table import Table

console = Console()

BASE_URL = "https://api.securitytrails.com/v1"

def _headers():
    return {
        "APIKEY": Config.SECURITYTRAILS_API_KEY,
        "Content-Type": "application/json"
    }

def get_subdomains(domain: str) -> list:
    try:
        r = requests.get(f"{BASE_URL}/domain/{domain}/subdomains", headers=_headers(), timeout=15)
        data = r.json()
        return [f"{s}.{domain}" for s in data.get("subdomains", [])]
    except Exception as e:
        console.print(f"[red]SecurityTrails subdomains error: {e}[/red]")
        return []

def get_domain_info(domain: str) -> dict:
    try:
        r = requests.get(f"{BASE_URL}/domain/{domain}", headers=_headers(), timeout=15)
        return r.json()
    except Exception as e:
        console.print(f"[red]SecurityTrails domain info error: {e}[/red]")
        return {}

def get_dns_history(domain: str) -> list:
    try:
        r = requests.get(f"{BASE_URL}/history/{domain}/dns/a", headers=_headers(), timeout=15)
        return r.json().get("records", [])
    except Exception as e:
        console.print(f"[red]SecurityTrails DNS history error: {e}[/red]")
        return []

def get_whois_history(domain: str) -> dict:
    try:
        r = requests.get(f"{BASE_URL}/domain/{domain}/whois", headers=_headers(), timeout=15)
        return r.json()
    except Exception as e:
        console.print(f"[red]SecurityTrails WHOIS history error: {e}[/red]")
        return {}

def get_associated_domains(domain: str) -> list:
    try:
        r = requests.get(f"{BASE_URL}/domain/{domain}/associated-domains", headers=_headers(), timeout=15)
        return r.json().get("records", [])
    except Exception as e:
        console.print(f"[red]SecurityTrails associated domains error: {e}[/red]")
        return []

def run(domain: str) -> dict:
    console.print(f"\n[bold cyan][SECURITYTRAILS][/bold cyan] Running SecurityTrails recon on [bold]{domain}[/bold]...")
    results = {}

    # --- Subdomains ---
    subs = get_subdomains(domain)
    results["subdomains"] = subs

    sub_table = Table(title=f"Subdomains ({len(subs)} found)", header_style="bold magenta")
    sub_table.add_column("Subdomain", style="cyan")
    for s in subs[:50]:
        sub_table.add_row(s)
    if len(subs) > 50:
        sub_table.add_row(f"... and {len(subs)-50} more")
    console.print(sub_table)

    # --- Domain Info ---
    info = get_domain_info(domain)
    results["domain_info"] = info
    if info:
        info_table = Table(title="Domain Overview", header_style="bold magenta")
        info_table.add_column("Field", style="cyan", width=20)
        info_table.add_column("Value", style="white")
        hostname = info.get("hostname", "")
        alexa    = info.get("alexa_rank", "N/A")
        tags     = ", ".join(info.get("tags", [])) or "None"
        info_table.add_row("Hostname",   hostname)
        info_table.add_row("Alexa Rank", str(alexa))
        info_table.add_row("Tags",       tags)
        console.print(info_table)

    # --- DNS History ---
    history = get_dns_history(domain)
    results["dns_history"] = history
    if history:
        hist_table = Table(title="Historical DNS (A Records)", header_style="bold magenta")
        hist_table.add_column("IP Address",  style="yellow")
        hist_table.add_column("First Seen",  style="white")
        hist_table.add_column("Last Seen",   style="white")
        for record in history[:10]:
            values = record.get("values", [{}])
            ip     = values[0].get("ip", "N/A") if values else "N/A"
            hist_table.add_row(
                ip,
                record.get("first_seen", "N/A"),
                record.get("last_seen",  "N/A")
            )
        console.print(hist_table)

    return results
