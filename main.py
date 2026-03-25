#!/usr/bin/env python3
"""
OSINT Recon Tool — Domain Intelligence Gathering
Usage: python main.py <domain> [options]
"""

import argparse
import sys
import time
from rich.console import Console
from rich.rule import Rule

from config import Config
from utils.banner import print_banner
from utils.helpers import is_valid_domain, clean_domain, resolve_domain
import modules.dns_enum       as dns_module
import modules.whois_lookup   as whois_module
import modules.ssl_info       as ssl_module
import modules.port_scanner   as port_module
import modules.securitytrails as st_module
import modules.tech_detection as tech_module
import modules.email_harvester as email_module
import modules.shodan_lookup  as shodan_module
import modules.ip_geolocation as geo_module
import modules.virustotal     as vt_module
from reports.report_generator import generate

console = Console()


def parse_args():
    parser = argparse.ArgumentParser(
        description="🔍 OSINT Domain Reconnaissance Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --all
  python main.py example.com --dns --whois --ssl
  python main.py example.com --all --report html
  python main.py example.com --all --report both
        """
    )

    parser.add_argument("domain", help="Target domain (e.g. example.com)")

    # Module flags
    parser.add_argument("--all",    action="store_true", help="Run ALL modules")
    parser.add_argument("--dns",    action="store_true", help="DNS enumeration")
    parser.add_argument("--whois",  action="store_true", help="WHOIS lookup")
    parser.add_argument("--ssl",    action="store_true", help="SSL certificate info")
    parser.add_argument("--ports",  action="store_true", help="Port scanning")
    parser.add_argument("--st",     action="store_true", help="SecurityTrails recon (mandatory API)")
    parser.add_argument("--tech",   action="store_true", help="Technology stack detection")
    parser.add_argument("--emails", action="store_true", help="Email harvesting")
    parser.add_argument("--shodan", action="store_true", help="Shodan lookup")
    parser.add_argument("--geo",    action="store_true", help="IP geolocation")
    parser.add_argument("--vt",     action="store_true", help="VirusTotal lookup")

    # Output
    parser.add_argument(
        "--report",
        choices=["html", "json", "both"],
        default="html",
        help="Report format (default: html)"
    )
    parser.add_argument("--no-report", action="store_true", help="Skip report generation")

    return parser.parse_args()


def print_summary(domain: str, results: dict, elapsed: float):
    console.print()
    console.print(Rule("[bold cyan]Scan Summary[/bold cyan]"))
    console.print(f"  🎯 Target        : [bold]{domain}[/bold]")
    console.print(f"  ⏱️  Time Elapsed  : {elapsed:.1f}s")
    console.print(f"  📦 Modules Run   : {len(results)}")

    # Highlight interesting findings
    findings = []

    if "securitytrails" in results:
        subs = results["securitytrails"].get("subdomains", [])
        if subs:
            findings.append(f"🔎 {len(subs)} subdomains discovered")

    if "ports" in results:
        open_ports = results["ports"].get("open_ports", {})
        risky = [p for p, i in open_ports.items() if i.get("risk")]
        if risky:
            findings.append(f"⚠️  High-risk ports open: {', '.join(map(str, risky))}")

    if "dns" in results:
        if "ZONE_TRANSFER" in results["dns"]:
            findings.append("🚨 DNS Zone Transfer VULNERABILITY detected!")

    if "tech" in results:
        missing = results["tech"].get("missing_security_headers", [])
        if missing:
            findings.append(f"🛡️  Missing security headers: {', '.join(missing)}")

    if "ssl" in results:
        days = results["ssl"].get("days_remaining", 999)
        if days < 30:
            findings.append(f"🔐 SSL certificate expires in {days} days!")

    if "virustotal" in results:
        mal = results["virustotal"].get("malicious", 0)
        if mal > 0:
            findings.append(f"🦠 VirusTotal: {mal} malicious detections!")

    if findings:
        console.print()
        console.print("  [bold yellow]Notable Findings:[/bold yellow]")
        for f in findings:
            console.print(f"    → {f}")

    console.print()


def main():
    print_banner()
    args = parse_args()

    # Validate & clean domain
    domain = clean_domain(args.domain)

    if not is_valid_domain(domain):
        console.print(f"[red]❌  Invalid domain format: {domain}[/red]")
        sys.exit(1)

    # Validate API keys
    Config.validate()

    console.print(f"[bold green]🎯 Target:[/bold green] [bold]{domain}[/bold]")
    console.print(f"[dim]Starting reconnaissance...[/dim]\n")

    results = {}
    start   = time.time()

    run_all = args.all

    # --- DNS ---
    if run_all or args.dns:
        results["dns"] = dns_module.run(domain)

    # --- WHOIS ---
    if run_all or args.whois:
        results["whois"] = whois_module.run(domain)

    # --- SSL ---
    if run_all or args.ssl:
        results["ssl"] = ssl_module.run(domain)

    # --- SecurityTrails (always run if --all, or --st) ---
    if run_all or args.st:
        results["securitytrails"] = st_module.run(domain)

    # --- Port Scan ---
    if run_all or args.ports:
        ip = resolve_domain(domain)
        results["ports"] = port_module.run(domain, ip=ip)

    # --- Tech Detection ---
    if run_all or args.tech:
        results["tech"] = tech_module.run(domain)

    # --- Email Harvest ---
    if run_all or args.emails:
        results["emails"] = email_module.run(domain)

    # --- Shodan ---
    if run_all or args.shodan:
        ip = results.get("ports", {}).get("ip") or resolve_domain(domain)
        results["shodan"] = shodan_module.run(domain, ip=ip)

    # --- IP Geolocation ---
    if run_all or args.geo:
        results["geo"] = geo_module.run(domain)

    # --- VirusTotal ---
    if run_all or args.vt:
        results["virustotal"] = vt_module.run(domain)

    # --- No modules selected ---
    if not results:
        console.print("[yellow]⚠️  No modules selected. Use --all or pick specific modules.[/yellow]")
        console.print("    Run [bold]python main.py --help[/bold] for options.")
        sys.exit(0)

    elapsed = time.time() - start
    print_summary(domain, results, elapsed)

    # --- Report ---
    if not args.no_report:
        console.print(Rule("[bold cyan]Report Generation[/bold cyan]"))
        generate(domain, results, fmt=args.report)

    console.print("\n[bold green]✅  Scan complete![/bold green]\n")


if __name__ == "__main__":
    main()
