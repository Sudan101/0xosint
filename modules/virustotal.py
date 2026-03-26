import requests
from config import Config
from rich.console import Console
from rich.table import Table

console = Console()

BASE_URL = "https://www.virustotal.com/api/v3"

def run(domain: str) -> dict:
    if not Config.VIRUSTOTAL_API_KEY or Config.VIRUSTOTAL_API_KEY.startswith("your_"):
        console.print("[yellow][VIRUSTOTAL] Skipped — No API key configured[/yellow]")
        return {}

    console.print(f"\n[bold cyan][VIRUSTOTAL][/bold cyan] Checking [bold]{domain}[/bold] on VirusTotal...")

    headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
    results = {}

    try:
        # Domain report
        r = requests.get(f"{BASE_URL}/domains/{domain}", headers=headers, timeout=15)
        data = r.json().get("data", {}).get("attributes", {})

        stats       = data.get("last_analysis_stats", {})
        categories  = data.get("categories", {})
        reputation  = data.get("reputation", 0)
        malicious   = stats.get("malicious", 0)
        suspicious  = stats.get("suspicious", 0)

        results = {
            "reputation":  reputation,
            "malicious":   malicious,
            "suspicious":  suspicious,
            "categories":  categories,
        }

        table = Table(title="VirusTotal Report", header_style="bold magenta")
        table.add_column("Field",    style="cyan", width=20)
        table.add_column("Value",    style="white")

        rep_style  = "red" if reputation < 0 else "green"
        mal_style  = "red" if malicious > 0  else "green"

        table.add_row("Reputation Score", f"[{rep_style}]{reputation}[/{rep_style}]")
        table.add_row("Malicious Detections", f"[{mal_style}]{malicious}[/{mal_style}]")
        table.add_row("Suspicious Detections", str(suspicious))
        if categories:
            table.add_row("Categories", ", ".join(categories.values()))

        console.print(table)

        # Subdomains from VT
        r2 = requests.get(f"{BASE_URL}/domains/{domain}/subdomains", headers=headers, timeout=15)
        vt_subs = [item["id"] for item in r2.json().get("data", [])]
        results["subdomains"] = vt_subs

        if vt_subs:
            sub_table = Table(title=f"VirusTotal Subdomains ({len(vt_subs)})", header_style="bold magenta")
            sub_table.add_column("Subdomain", style="cyan")
            for s in vt_subs[:20]:
                sub_table.add_row(s)
            console.print(sub_table)

    except Exception as e:
        console.print(f"[red]VirusTotal lookup failed: {e}[/red]")

    return results
