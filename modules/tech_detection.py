import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

console = Console()

TECH_SIGNATURES = {
    "WordPress":   ["wp-content", "wp-includes", "WordPress"],
    "Drupal":      ["Drupal", "/sites/default/files"],
    "Joomla":      ["Joomla", "/components/com_"],
    "Shopify":     ["cdn.shopify.com", "Shopify.theme"],
    "Wix":         ["wix.com", "X-Wix-Published-Version"],
    "React":       ["__react", "react-dom"],
    "Vue.js":      ["vue.js", "__vue__"],
    "Angular":     ["ng-version", "angular.min.js"],
    "jQuery":      ["jquery.min.js", "jquery.js"],
    "Bootstrap":   ["bootstrap.min.css", "bootstrap.min.js"],
    "Cloudflare":  ["cloudflare", "cf-ray"],
    "AWS":         ["amazonaws.com", "x-amz"],
    "Nginx":       ["nginx"],
    "Apache":      ["apache", "Apache"],
    "IIS":         ["IIS", "Microsoft-IIS"],
    "PHP":         ["x-powered-by: php", ".php"],
    "ASP.NET":     ["x-aspnet-version", "asp.net"],
}

def run(domain: str) -> dict:
    console.print(f"\n[bold cyan][TECH][/bold cyan] Detecting technologies on [bold]{domain}[/bold]...")
    results = {"detected": [], "headers": {}, "cms": None}

    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{domain}",
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True
            )
            body    = r.text.lower()
            headers = {k.lower(): v.lower() for k, v in r.headers.items()}
            results["headers"] = dict(r.headers)
            results["status_code"] = r.status_code
            results["final_url"]   = r.url

            for tech, signatures in TECH_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in body or sig.lower() in str(headers):
                        if tech not in results["detected"]:
                            results["detected"].append(tech)

            # Server header
            server = headers.get("server", "")
            if server:
                results["server"] = server

            # X-Powered-By
            powered = headers.get("x-powered-by", "")
            if powered:
                results["powered_by"] = powered

            # Security headers check
            security_headers = {
                "strict-transport-security": "HSTS",
                "x-frame-options":           "Clickjack Protection",
                "x-content-type-options":    "MIME Sniffing Protection",
                "content-security-policy":   "CSP",
                "x-xss-protection":          "XSS Protection",
                "referrer-policy":           "Referrer Policy",
            }
            missing_security = []
            for h, label in security_headers.items():
                if h not in headers:
                    missing_security.append(label)
            results["missing_security_headers"] = missing_security
            break

        except Exception:
            continue

    table = Table(title="Technology Detection", header_style="bold magenta")
    table.add_column("Category",   style="cyan", width=25)
    table.add_column("Details",    style="white")

    table.add_row("Detected Technologies", ", ".join(results["detected"]) or "None detected")
    if results.get("server"):
        table.add_row("Server",       results["server"])
    if results.get("powered_by"):
        table.add_row("Powered By",   results["powered_by"])
    if results.get("missing_security_headers"):
        table.add_row(
            "[red]Missing Security Headers[/red]",
            "[red]" + ", ".join(results["missing_security_headers"]) + "[/red]"
        )

    console.print(table)
    return results
