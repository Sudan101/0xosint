import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # ✅ MANDATORY
    SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")

    # ⚠️ OPTIONAL
    SHODAN_API_KEY         = os.getenv("SHODAN_API_KEY")
    HUNTER_API_KEY         = os.getenv("HUNTER_API_KEY")
    VIRUSTOTAL_API_KEY     = os.getenv("VIRUSTOTAL_API_KEY")
    IPINFO_API_KEY         = os.getenv("IPINFO_API_KEY")

    # Request settings
    REQUEST_TIMEOUT        = 10
    MAX_THREADS            = 20

    @staticmethod
    def validate():
        from rich.console import Console
        console = Console()

        errors = []

        if not Config.SECURITYTRAILS_API_KEY or Config.SECURITYTRAILS_API_KEY == "your_securitytrails_key_here":
            errors.append("❌  SECURITYTRAILS_API_KEY is missing or not set — THIS IS REQUIRED")

        if errors:
            console.print("\n[bold red]== CONFIGURATION ERROR ==[/bold red]")
            for e in errors:
                console.print(f"  {e}", style="bold red")
            console.print("\n[yellow]→ Copy .env.example to .env and add your API keys[/yellow]")
            console.print("[yellow]→ Get your free key at: https://securitytrails.com/app/account/credentials[/yellow]\n")
            exit(1)

        # Warnings for optional keys
        optional = {
            "SHODAN_API_KEY":     ("Shodan module",        "https://account.shodan.io/"),
            "HUNTER_API_KEY":     ("Email harvest module", "https://hunter.io/api-keys"),
            "VIRUSTOTAL_API_KEY": ("VirusTotal module",    "https://www.virustotal.com/gui/my-apikey"),
            "IPINFO_API_KEY":     ("IP Geolocation (enhanced)", "https://ipinfo.io/account/token"),
        }

        console.print("\n[bold cyan]== API Key Status ==[/bold cyan]")
        console.print(f"  [green]✅  SECURITYTRAILS_API_KEY — Active[/green]")
        for key, (label, url) in optional.items():
            val = getattr(Config, key)
            if not val or val.startswith("your_"):
                console.print(f"  [yellow]⚠️   {key} not set — {label} disabled[/yellow]")
            else:
                console.print(f"  [green]✅  {key} — Active[/green]")
        print()
