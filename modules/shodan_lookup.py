from config import Config
from rich.console import Console
from rich.table import Table

console = Console()

def run(domain: str, ip: str = None) -> dict:
    if not Config.SHODAN_API_KEY or Config.SHODAN_API_KEY.startswith("your_"):
        console.print("[yellow][SHODAN] Skipped — No API key configured[/yellow]")
        return {}

    try:
        import shodan
        api = shodan.Shodan(Config.SHODAN_API_KEY)

        console.print(f"\n[bold cyan][SHODAN][/bold cyan] Looking up [bold]{domain}[/bold] on Shodan...")

        # Resolve IP if not provided
        if not ip:
            import socket
            ip = socket.gethostbyname(domain)

        host = api.host(ip)
        results = {
            "ip":           host.get("ip_str"),
            "org":          host.get("org"),
            "os":           host.get("os"),
            "ports":        host.get("ports", []),
            "vulns":        list(host.get("vulns", {}).keys()),
            "hostnames":    host.get("hostnames", []),
            "country":      host.get("country_name"),
            "city":         host.get("city"),
        }

        table = Table(title=f"Shodan Info — {ip}", header_style="bold magenta")
        table.add_column("Field",  style="cyan", width=20)
        table.add_column("Value",  style="white")
        table.add_row("IP",        results["ip"])
        table.add_row("Org",       results["org"] or "N/A")
        table.add_row("OS",        results["os"]  or "Unknown")
        table.add_row("Country",   results["country"] or "N/A")
        table.add_row("City",      results["city"]    or "N/A")
        table.add_row("Hostnames", ", ".join(results["hostnames"]) or "None")
        table.add_row("Open Ports",", ".join(map(str, results["ports"])))

        if results["vulns"]:
            table.add_row("[red]CVEs Found[/red]", "[red]" + ", ".join(results["vulns"]) + "[/red]")

        console.print(table)
        return results

    except Exception as e:
        console.print(f"[red]Shodan lookup failed: {e}[/red]")
        return {}
