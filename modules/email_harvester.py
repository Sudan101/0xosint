import requests
from config import Config
from rich.console import Console
from rich.table import Table

console = Console()

def run(domain: str) -> dict:
    results = {"emails": [], "source": ""}

    if not Config.HUNTER_API_KEY or Config.HUNTER_API_KEY.startswith("your_"):
        console.print("[yellow][EMAIL] Hunter.io skipped — No API key configured[/yellow]")
        return results

    console.print(f"\n[bold cyan][EMAIL][/bold cyan] Harvesting emails for [bold]{domain}[/bold]...")

    try:
        params = {
            "domain":  domain,
            "api_key": Config.HUNTER_API_KEY,
            "limit":   20,
        }
        r = requests.get("https://api.hunter.io/v2/domain-search", params=params, timeout=15)
        data = r.json().get("data", {})
        emails = [e["value"] for e in data.get("emails", [])]
        org    = data.get("organization", "")
        pattern= data.get("pattern", "")

        results["emails"]       = emails
        results["organization"] = org
        results["pattern"]      = pattern
        results["source"]       = "hunter.io"

        table = Table(title=f"Emails Found ({len(emails)})", header_style="bold magenta")
        table.add_column("Email",       style="cyan")
        table.add_column("Type",        style="white")
        table.add_column("Confidence",  style="white")

        for email_obj in data.get("emails", []):
            table.add_row(
                email_obj.get("value", ""),
                email_obj.get("type",  ""),
                str(email_obj.get("confidence", "")) + "%"
            )

        if org:
            console.print(f"  Organization: [bold]{org}[/bold]")
        if pattern:
            console.print(f"  Email pattern: [bold]{pattern}@{domain}[/bold]")

        console.print(table)

    except Exception as e:
        console.print(f"[red]Email harvest failed: {e}[/red]")

    return results
