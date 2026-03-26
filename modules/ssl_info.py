import ssl
import socket
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

def run(domain: str) -> dict:
    console.print(f"\n[bold cyan][SSL][/bold cyan] Fetching certificate info for [bold]{domain}[/bold]...")
    results = {}

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()

        subject    = dict(x[0] for x in cert.get("subject", []))
        issuer     = dict(x[0] for x in cert.get("issuer", []))
        not_before = cert.get("notBefore", "")
        not_after  = cert.get("notAfter", "")
        sans       = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        # Check expiry
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.utcnow()).days
        expiry_note = f"[red]⚠️  EXPIRES IN {days_left} DAYS[/red]" if days_left < 30 else f"{days_left} days remaining"

        table = Table(title="SSL Certificate", header_style="bold magenta")
        table.add_column("Field", style="cyan", width=22)
        table.add_column("Value", style="white")

        table.add_row("Common Name",      subject.get("commonName", "N/A"))
        table.add_row("Organization",     subject.get("organizationName", "N/A"))
        table.add_row("Issued By",        issuer.get("organizationName", "N/A"))
        table.add_row("Valid From",       not_before)
        table.add_row("Valid Until",      not_after)
        table.add_row("Expiry Status",    expiry_note)
        table.add_row("SANs Count",       str(len(sans)))

        if sans:
            table.add_row("SANs (subdomains)", "\n".join(sans[:20]))

        console.print(table)

        results = {
            "common_name":    subject.get("commonName"),
            "issuer":         issuer.get("organizationName"),
            "valid_from":     not_before,
            "valid_until":    not_after,
            "days_remaining": days_left,
            "sans":           sans,
        }

    except Exception as e:
        console.print(f"[red]SSL lookup failed: {e}[/red]")

    return results
