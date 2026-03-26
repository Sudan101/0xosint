import requests
import subprocess
import shutil
import json
import os
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

def run_httpx(subdomains: list, domain: str) -> list:
    """Run httpx on all discovered subdomains with -sc -ip -td -server flags"""

    # Check httpx is available
    if not shutil.which("httpx"):
        console.print("[yellow][HTTPX] httpx not found in PATH — skipping probe[/yellow]")
        return []

    if not subdomains:
        console.print("[yellow][HTTPX] No subdomains to probe[/yellow]")
        return []

    console.print(f"\n[bold cyan][HTTPX][/bold cyan] Probing [bold]{len(subdomains)}[/bold] subdomains with httpx...")
    console.print(f"  [dim]Flags: -sc (status code) -ip (IP) -td (title) -server (server header)[/dim]\n")

    # Write subdomains to a temp file
    os.makedirs("reports/output", exist_ok=True)
    tmp_file = f"reports/output/{domain}_subs.txt"
    with open(tmp_file, "w") as f:
        f.write("\n".join(subdomains))

    results = []

    try:
        cmd = [
            "httpx",
            "-l", tmp_file,
            "-sc",        # status code
            "-ip",        # ip address
            "-td",        # title detection
            "-server",    # server header
            "-silent",    # clean output
            "-json",      # JSON output for parsing
            "-timeout", "10",
            "-threads", "50",
        ]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse JSON output line by line
        alive = []
        for line in process.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                entry = json.loads(line)
                alive.append({
                    "url":         entry.get("url", ""),
                    "status_code": entry.get("status_code", ""),
                    "ip":          entry.get("host", ""),
                    "title":       entry.get("title", ""),
                    "server":      entry.get("webserver", ""),
                    "tech":        ", ".join(entry.get("tech", [])),
                })
            except json.JSONDecodeError:
                # Fallback: plain text line
                alive.append({"url": line, "status_code": "", "ip": "", "title": "", "server": "", "tech": ""})

        results = alive

        # Display results table
        table = Table(
            title=f"HTTPX Results — {len(results)} alive hosts",
            header_style="bold magenta",
            show_lines=True
        )
        table.add_column("URL",         style="cyan",   max_width=40)
        table.add_column("Status",      style="white",  width=8)
        table.add_column("IP",          style="yellow", width=16)
        table.add_column("Title",       style="green",  max_width=30)
        table.add_column("Server",      style="blue",   max_width=20)

        for host in results:
            # Color code status
            sc = str(host["status_code"])
            if sc.startswith("2"):
                sc_styled = f"[green]{sc}[/green]"
            elif sc.startswith("3"):
                sc_styled = f"[yellow]{sc}[/yellow]"
            elif sc.startswith("4"):
                sc_styled = f"[red]{sc}[/red]"
            elif sc.startswith("5"):
                sc_styled = f"[bold red]{sc}[/bold red]"
            else:
                sc_styled = sc

            table.add_row(
                host["url"],
                sc_styled,
                host["ip"],
                host["title"],
                host["server"],
            )

        console.print(table)
        console.print(f"\n  [green]✅  {len(results)} live hosts discovered out of {len(subdomains)} subdomains[/green]")

        # Save raw results to file
        out_file = f"reports/output/{domain}_httpx.txt"
        with open(out_file, "w") as f:
            for h in results:
                f.write(f"{h['url']} [{h['status_code']}] [{h['ip']}] [{h['title']}] [{h['server']}]\n")
        console.print(f"  [dim]HTTPX results saved → {out_file}[/dim]")

    except subprocess.TimeoutExpired:
        console.print("[red][HTTPX] Timed out after 5 minutes[/red]")
    except Exception as e:
        console.print(f"[red][HTTPX] Error: {e}[/red]")

    # Cleanup temp file
    try:
        os.remove(tmp_file)
    except Exception:
        pass

    return results


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

    # --- HTTPX Probing on all subdomains ---
    httpx_results = run_httpx(subs, domain)
    results["httpx"] = httpx_results

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

