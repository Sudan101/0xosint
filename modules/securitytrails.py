import requests
import subprocess
import shutil
import json
import os
from config import Config
from modules import nuclei_waf
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
    """
    2-Pass HTTPX Probing:
    Pass 1 — Fast alive check (high threads, low timeout)
    Pass 2 — Detailed scan only on live hosts (-sc -ip -td -server)
    """

    if not shutil.which("httpx"):
        console.print("[yellow][HTTPX] httpx not found in PATH — skipping[/yellow]")
        return []

    if not subdomains:
        console.print("[yellow][HTTPX] No subdomains to probe[/yellow]")
        return []

    os.makedirs("reports/output", exist_ok=True)
    tmp_all   = f"reports/output/{domain}_subs_all.txt"
    tmp_alive = f"reports/output/{domain}_subs_alive.txt"

    # Write all subdomains to file
    with open(tmp_all, "w") as f:
        f.write("\n".join(subdomains))

    total = len(subdomains)

    # ─────────────────────────────────────────────
    # PASS 1 — Fast alive check
    # High threads, short timeout, no extra flags
    # ─────────────────────────────────────────────
    console.print(f"\n[bold cyan][HTTPX][/bold cyan] Pass 1 — Alive check on [bold]{total}[/bold] subdomains...")
    console.print(f"  [dim]Threads: 200 | Timeout: 3s | Goal: find live hosts fast[/dim]")

    alive_hosts = []

    try:
        pass1_cmd = [
            "httpx",
            "-l",        tmp_all,
            "-silent",
            "-threads",  "200",
            "-timeout",  "3",
            "-no-color",
        ]

        # Dynamic timeout: 1s per subdomain / threads, min 60s max 600s
        pass1_timeout = max(60, min(600, (total // 200) * 10 + 60))

        p1 = subprocess.run(
            pass1_cmd,
            capture_output=True,
            text=True,
            timeout=pass1_timeout
        )

        alive_hosts = [line.strip() for line in p1.stdout.strip().split("\n") if line.strip()]

        console.print(f"  [green]✅  Pass 1 complete — {len(alive_hosts)} live hosts found out of {total}[/green]")

        # Save alive hosts
        with open(tmp_alive, "w") as f:
            f.write("\n".join(alive_hosts))

    except subprocess.TimeoutExpired:
        console.print(f"[red][HTTPX] Pass 1 timed out — trying with whatever was found[/red]")
    except Exception as e:
        console.print(f"[red][HTTPX] Pass 1 error: {e}[/red]")
        return []

    if not alive_hosts:
        console.print("[yellow][HTTPX] No live hosts found in Pass 1[/yellow]")
        return []

    # ─────────────────────────────────────────────
    # PASS 2 — Detailed scan on alive hosts only
    # -sc -ip -td -server flags
    # ─────────────────────────────────────────────
    console.print(f"\n[bold cyan][HTTPX][/bold cyan] Pass 2 — Detailed scan on [bold]{len(alive_hosts)}[/bold] live hosts...")
    console.print(f"  [dim]Flags: -sc -ip -td -server | Threads: 100 | Timeout: 10s[/dim]")

    results = []

    try:
        pass2_cmd = [
            "httpx",
            "-l",       tmp_alive,
            "-sc",                  # status code
            "-ip",                  # ip address
            "-td",                  # title detection
            "-server",              # server header
            "-silent",
            "-json",                # JSON for parsing
            "-threads", "100",
            "-timeout", "10",
        ]

        pass2_timeout = max(60, len(alive_hosts) * 2)

        p2 = subprocess.run(
            pass2_cmd,
            capture_output=True,
            text=True,
            timeout=pass2_timeout
        )

        for line in p2.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                results.append({
                    "url":         entry.get("url", ""),
                    "status_code": entry.get("status_code", ""),
                    "ip":          entry.get("host", ""),
                    "title":       entry.get("title", ""),
                    "server":      entry.get("webserver", ""),
                    "tech":        ", ".join(entry.get("tech", [])),
                })
            except json.JSONDecodeError:
                results.append({
                    "url": line, "status_code": "",
                    "ip": "", "title": "", "server": "", "tech": ""
                })

        # ── Display results table ──
        table = Table(
            title=f"HTTPX Detailed Results — {len(results)} hosts",
            header_style="bold magenta",
            show_lines=True
        )
        table.add_column("URL",     style="cyan",   max_width=45)
        table.add_column("Status",  style="white",  width=8)
        table.add_column("IP",      style="yellow", width=16)
        table.add_column("Title",   style="green",  max_width=30)
        table.add_column("Server",  style="blue",   max_width=20)

        for host in results:
            sc = str(host["status_code"])
            if sc.startswith("2"):   sc_styled = f"[green]{sc}[/green]"
            elif sc.startswith("3"): sc_styled = f"[yellow]{sc}[/yellow]"
            elif sc.startswith("4"): sc_styled = f"[red]{sc}[/red]"
            elif sc.startswith("5"): sc_styled = f"[bold red]{sc}[/bold red]"
            else:                    sc_styled = sc

            table.add_row(
                host["url"],
                sc_styled,
                host["ip"],
                host["title"],
                host["server"],
            )

        console.print(table)
        console.print(f"\n  [green]✅  Pass 2 complete — {len(results)} hosts with full details[/green]")

        # Save final results
        out_file = f"reports/output/{domain}_httpx.txt"
        with open(out_file, "w") as f:
            f.write(f"HTTPX Results for {domain}\n")
            f.write("=" * 60 + "\n\n")
            for h in results:
                f.write(f"{h['url']} [{h['status_code']}] [{h['ip']}] [{h['title']}] [{h['server']}]\n")
        console.print(f"  [dim]Results saved → {out_file}[/dim]")

    except subprocess.TimeoutExpired:
        console.print("[red][HTTPX] Pass 2 timed out[/red]")
    except Exception as e:
        console.print(f"[red][HTTPX] Pass 2 error: {e}[/red]")

    # Cleanup temp files
    for f in [tmp_all, tmp_alive]:
        try:
            os.remove(f)
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

    # --- HTTPX 2-Pass Probing ---
    httpx_results = run_httpx(subs, domain)
    results["httpx"] = httpx_results

    # --- Nuclei WAF Detection on live hosts ---
    if httpx_results:
        live_urls = [h["url"] for h in httpx_results if h.get("url")]
        waf_results = nuclei_waf.run(live_urls, domain)
        results["waf"] = waf_results
    else:
        results["waf"] = []

    # --- Domain Info ---
    info = get_domain_info(domain)
    results["domain_info"] = info
    if info:
        info_table = Table(title="Domain Overview", header_style="bold magenta")
        info_table.add_column("Field", style="cyan", width=20)
        info_table.add_column("Value", style="white")
        info_table.add_row("Hostname",   info.get("hostname", ""))
        info_table.add_row("Alexa Rank", str(info.get("alexa_rank", "N/A")))
        info_table.add_row("Tags",       ", ".join(info.get("tags", [])) or "None")
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

