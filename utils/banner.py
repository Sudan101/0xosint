from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

def print_banner():
    banner = Text()
    banner.append("\n")
    banner.append("  ██████╗ ███████╗██╗███╗   ██╗████████╗\n", style="bold cyan")
    banner.append("  ██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝\n", style="bold cyan")
    banner.append("  ██████╔╝███████╗██║██╔██╗ ██║   ██║   \n", style="bold cyan")
    banner.append("  ██╔══██╗╚════██║██║██║╚██╗██║   ██║   \n", style="bold cyan")
    banner.append("  ██║  ██║███████║██║██║ ╚████║   ██║   \n", style="bold cyan")
    banner.append("  ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   \n", style="bold cyan")
    banner.append("\n")
    banner.append("  Domain OSINT Reconnaissance Tool\n", style="bold white")
    banner.append("  For authorized security testing only\n", style="dim")

    console.print(Panel(banner, border_style="cyan", expand=False))
    console.print()
