import dns.resolver
import dns.zone
import dns.query
from rich.console import Console
from rich.table import Table

console = Console()

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]

def run(domain: str) -> dict:
    results = {}
    console.print(f"\n[bold cyan][DNS][/bold cyan] Enumerating records for [bold]{domain}[/bold]...")

    table = Table(title="DNS Records", header_style="bold magenta")
    table.add_column("Type", style="cyan", width=10)
    table.add_column("Value", style="white")

    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            values = [str(r) for r in answers]
            results[record_type] = values
            for v in values:
                table.add_row(record_type, v)
        except Exception:
            pass

    # SPF / DMARC / DKIM
    for special in [f"_dmarc.{domain}", f"_domainkey.{domain}"]:
        try:
            answers = dns.resolver.resolve(special, "TXT")
            for r in answers:
                table.add_row("TXT (Special)", f"{special} → {str(r)}")
                results.setdefault("TXT_SPECIAL", []).append(f"{special}: {str(r)}")
        except Exception:
            pass

    # Zone Transfer Attempt
    ns_list = results.get("NS", [])
    for ns in ns_list:
        try:
            ns_ip = str(dns.resolver.resolve(ns.rstrip("."), "A")[0])
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            results["ZONE_TRANSFER"] = f"⚠️  Zone transfer SUCCESSFUL on {ns} — VULNERABILITY!"
            table.add_row("[red]ZONE XFER[/red]", f"[red]SUCCESS on {ns}[/red]")
        except Exception:
            pass

    console.print(table)
    return results
