import subprocess
import shutil
import json
from rich.console import Console
from rich.table import Table

console = Console()

def run(targets: list, domain: str) -> list:
    """
    Run nuclei WAF detection templates on live hosts
    Uses: nuclei -tags waf
    """

    if not shutil.which("nuclei"):
        console.print("[yellow][NUCLEI] nuclei not found in PATH — skipping WAF detection[/yellow]")
        return []

    if not targets:
        console.print("[yellow][NUCLEI] No targets to scan for WAF[/yellow]")
        return []

    console.print(f"\n[bold cyan][NUCLEI][/bold cyan] WAF Detection on [bold]{len(targets)}[/bold] live hosts...")
    console.print(f"  [dim]Templates: -tags waf | nuclei by ProjectDiscovery[/dim]")

    results = []

    # Write targets to temp file
    import os
    os.makedirs("reports/output", exist_ok=True)
    tmp_file = f"reports/output/{domain}_nuclei_targets.txt"
    with open(tmp_file, "w") as f:
        f.write("\n".join(targets))

    try:
        cmd = [
            "nuclei",
            "-l",        tmp_file,
            "-tags",     "waf",
            "-silent",
            "-json",
            "-timeout",  "10",
            "-rate-limit", "50",
            "-concurrency", "20",
        ]

        # Dynamic timeout based on target count
        timeout = max(120, len(targets) * 5)

        console.print(f"  [dim]Scanning... (timeout: {timeout}s)[/dim]")

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse JSON output
        waf_found   = []
        no_waf      = []
        targets_hit = set()

        for line in process.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                host      = entry.get("host", "")
                template  = entry.get("template-id", "")
                name      = entry.get("info", {}).get("name", "")
                severity  = entry.get("info", {}).get("severity", "info")
                matched   = entry.get("matched-at", host)

                waf_found.append({
                    "host":     host,
                    "waf":      name.replace("Detect", "").replace("WAF", "").strip(),
                    "template": template,
                    "severity": severity,
                    "matched":  matched,
                })
                targets_hit.add(host)
                results.append({
                    "host":    host,
                    "waf":     name,
                    "detected": True
                })

            except json.JSONDecodeError:
                continue

        # Mark targets with no WAF detected
        for t in targets:
            if t not in targets_hit:
                results.append({
                    "host":     t,
                    "waf":      "None detected",
                    "detected": False
                })

        # ── Display Results Table ──
        table = Table(
            title=f"WAF Detection Results — {len(waf_found)} WAF(s) found",
            header_style="bold magenta",
            show_lines=True
        )
        table.add_column("Host",        style="cyan",  max_width=45)
        table.add_column("WAF",         style="white", max_width=25)
        table.add_column("Status",      style="white", width=20)
        table.add_column("Template",    style="dim",   max_width=30)

        # Show WAF detected first
        for w in waf_found:
            table.add_row(
                w["host"],
                f"[bold red]{w['waf']}[/bold red]",
                "[red]⚠️  WAF DETECTED[/red]",
                w["template"],
            )

        # Show a sample of no-WAF hosts (max 10)
        no_waf_hosts = [t for t in targets if t not in targets_hit]
        for h in no_waf_hosts[:10]:
            table.add_row(h, "[green]None[/green]", "[green]✅ No WAF[/green]", "")
        if len(no_waf_hosts) > 10:
            table.add_row(f"... and {len(no_waf_hosts)-10} more", "[green]None[/green]", "[green]✅ No WAF[/green]", "")

        console.print(table)
        console.print(f"\n  [red]⚠️  WAF detected on {len(waf_found)} host(s)[/red]")
        console.print(f"  [green]✅  {len(no_waf_hosts)} host(s) with no WAF detected[/green]")

        # Save results
        out_file = f"reports/output/{domain}_waf.txt"
        with open(out_file, "w") as f:
            f.write(f"WAF Detection Results — {domain}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"WAF Detected ({len(waf_found)}):\n")
            for w in waf_found:
                f.write(f"  {w['host']} → {w['waf']}\n")
            f.write(f"\nNo WAF ({len(no_waf_hosts)}):\n")
            for h in no_waf_hosts:
                f.write(f"  {h}\n")
        console.print(f"  [dim]WAF results saved → {out_file}[/dim]")

    except subprocess.TimeoutExpired:
        console.print("[red][NUCLEI] WAF scan timed out[/red]")
    except Exception as e:
        console.print(f"[red][NUCLEI] Error: {e}[/red]")

    # Cleanup
    try:
        os.remove(tmp_file)
    except Exception:
        pass

    return results

