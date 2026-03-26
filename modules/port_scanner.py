import socket
import concurrent.futures
from rich.console import Console
from rich.table import Table

console = Console()

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

HIGH_RISK_PORTS = {6379, 27017, 9200, 3306, 5432, 3389, 23, 445}

def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False

def grab_banner(ip: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            return s.recv(256).decode(errors="ignore").strip()[:80]
    except Exception:
        return ""

def run(domain: str, ip: str = None) -> dict:
    console.print(f"\n[bold cyan][PORTS][/bold cyan] Scanning common ports on [bold]{domain}[/bold]...")

    if not ip:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            console.print("[red]Could not resolve domain to IP[/red]")
            return {}

    console.print(f"  [dim]Resolved to: {ip}[/dim]")
    open_ports = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                banner = grab_banner(ip, port)
                open_ports[port] = {
                    "service": COMMON_PORTS[port],
                    "banner":  banner,
                    "risk":    port in HIGH_RISK_PORTS
                }

    table = Table(title=f"Open Ports — {ip}", header_style="bold magenta")
    table.add_column("Port",    style="cyan", width=8)
    table.add_column("Service", style="white", width=15)
    table.add_column("Risk",    style="white", width=10)
    table.add_column("Banner",  style="dim")

    for port, info in sorted(open_ports.items()):
        risk_label = "[red]HIGH ⚠️[/red]"  if info["risk"] else "[green]Normal[/green]"
        table.add_row(str(port), info["service"], risk_label, info["banner"])

    console.print(table)
    console.print(f"  [green]Found {len(open_ports)} open port(s)[/green]")
    return {"ip": ip, "open_ports": open_ports}
