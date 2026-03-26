import whois
from rich.console import Console
from rich.table import Table

console = Console()

def run(domain: str) -> dict:
    console.print(f"\n[bold cyan][WHOIS][/bold cyan] Looking up [bold]{domain}[/bold]...")
    results = {}

    try:
        w = whois.whois(domain)

        fields = {
            "Registrar":         w.registrar,
            "Creation Date":     str(w.creation_date),
            "Expiration Date":   str(w.expiration_date),
            "Updated Date":      str(w.updated_date),
            "Name Servers":      ", ".join(w.name_servers) if isinstance(w.name_servers, list) else str(w.name_servers),
            "Status":            ", ".join(w.status) if isinstance(w.status, list) else str(w.status),
            "Emails":            ", ".join(w.emails) if isinstance(w.emails, list) else str(w.emails),
            "Organization":      str(w.org),
            "Country":           str(w.country),
        }

        table = Table(title="WHOIS Information", header_style="bold magenta")
        table.add_column("Field", style="cyan", width=20)
        table.add_column("Value", style="white")

        for field, value in fields.items():
            if value and value != "None":
                table.add_row(field, value)
                results[field] = value

        console.print(table)

    except Exception as e:
        console.print(f"[red]WHOIS lookup failed: {e}[/red]")

    return results
