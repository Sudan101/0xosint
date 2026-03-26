import socket
import requests
from config import Config
from rich.console import Console
from rich.table import Table

console = Console()

def run(domain: str) -> dict:
    console.print(f"\n[bold cyan][GEO][/bold cyan] IP Geolocation for [bold]{domain}[/bold]...")
    results = {}

    try:
        ip = socket.gethostbyname(domain)

        # Use IPInfo if key available, else free ip-api.com
        if Config.IPINFO_API_KEY and not Config.IPINFO_API_KEY.startswith("your_"):
            r = requests.get(
                f"https://ipinfo.io/{ip}/json",
                headers={"Authorization": f"Bearer {Config.IPINFO_API_KEY}"},
                timeout=10
            )
            data = r.json()
            results = {
                "ip":       data.get("ip"),
                "hostname": data.get("hostname"),
                "org":      data.get("org"),
                "city":     data.get("city"),
                "region":   data.get("region"),
                "country":  data.get("country"),
                "timezone": data.get("timezone"),
                "loc":      data.get("loc"),
            }
        else:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query", timeout=10)
            data = r.json()
            results = {
                "ip":       data.get("query"),
                "org":      data.get("org"),
                "isp":      data.get("isp"),
                "asn":      data.get("as"),
                "city":     data.get("city"),
                "region":   data.get("regionName"),
                "country":  data.get("country"),
                "timezone": data.get("timezone"),
                "loc":      f"{data.get('lat')},{data.get('lon')}",
            }

        table = Table(title=f"IP Geolocation — {ip}", header_style="bold magenta")
        table.add_column("Field",   style="cyan", width=15)
        table.add_column("Value",   style="white")
        for k, v in results.items():
            if v:
                table.add_row(k.capitalize(), str(v))

        console.print(table)

    except Exception as e:
        console.print(f"[red]Geolocation failed: {e}[/red]")

    return results
