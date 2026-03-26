# 🔍 OSINT Recon Tool

A Python-based OSINT (Open Source Intelligence) domain reconnaissance tool. Point it at a domain and it automatically gathers intelligence from multiple sources — DNS records, WHOIS, subdomains, open ports, technology stack, emails, geolocation, and more.

> ⚠️ **Legal Notice:** This tool is intended for authorized security testing, penetration testing, and bug bounty hunting only. Never use it against domains you do not own or have explicit written permission to test.

---

## 📸 Sample Output

```
  ██████╗ ███████╗██╗███╗   ██╗████████╗
  ██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝
  ██████╔╝███████╗██║██╔██╗ ██║   ██║
  ██╔══██╗╚════██║██║██║╚██╗██║   ██║
  ██║  ██║███████║██║██║ ╚████║   ██║
  ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝

  Domain OSINT Reconnaissance Tool

🎯 Target: example.com

[DNS]            Enumerating records...
[WHOIS]          Looking up domain registration...
[SSL]            Fetching certificate info...
[SECURITYTRAILS] Running full recon...
[PORTS]          Scanning common ports...
[TECH]           Detecting technologies...

── Scan Summary ────────────────────────────────
  🎯 Target        : example.com
  ⏱️  Time Elapsed  : 18.4s
  📦 Modules Run   : 6

  Notable Findings:
    → 🔎 47 subdomains discovered
    → ⚠️  High-risk ports open: 6379, 3306
    → 🛡️  Missing security headers: CSP, HSTS
```

---

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Sudan101/0xosint.git
cd 0xosint
```

### 2. Create a Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API Keys

```bash
cp .env.example .env
nano .env   # or use any text editor
```

Fill in your keys in `.env`:

```env
# ✅ MANDATORY
SECURITYTRAILS_API_KEY=your_key_here

# ⚠️ Optional
SHODAN_API_KEY=your_key_here
HUNTER_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
IPINFO_API_KEY=your_key_here
```

---

## 🔑 API Keys

| Service | Required? | Free Tier | Sign Up |
|---|---|---|---|
| **SecurityTrails** | ✅ **MANDATORY** | 50 req/month | [securitytrails.com](https://securitytrails.com/app/account/credentials) |
| **Shodan** | ⚠️ Optional | 1 credit/query | [shodan.io](https://account.shodan.io/) |
| **Hunter.io** | ⚠️ Optional | 25 req/month | [hunter.io](https://hunter.io/api-keys) |
| **VirusTotal** | ⚠️ Optional | 500 req/day | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| **IPInfo** | ⚠️ Optional | 50k req/month | [ipinfo.io](https://ipinfo.io/account/token) |

> If optional keys are missing, those modules are gracefully **skipped** — the tool still runs fully with just SecurityTrails.

---

## 🚀 Usage

### Run all modules

```bash
python 0xosint.py example.com --all
```

### Run specific modules

```bash
python main.py example.com --dns --whois --ssl
python main.py example.com --st --ports --tech
python main.py example.com --emails --shodan --vt
```

### Choose report format

```bash
python main.py example.com --all --report html    # HTML report (default)
python main.py example.com --all --report json    # JSON report
python main.py example.com --all --report both    # Both formats
python main.py example.com --all --no-report      # No report
```

### Full help

```bash
python main.py --help
```

---

## 📦 Modules

| Flag | Module | Description | API Required |
|---|---|---|---|
| `--dns` | DNS Enumeration | A, MX, NS, TXT, CNAME, SOA + zone transfer test | ❌ No |
| `--whois` | WHOIS Lookup | Registrar, dates, nameservers, contacts | ❌ No |
| `--ssl` | SSL/TLS Info | Cert details, SANs (subdomains!), expiry check | ❌ No |
| `--st` | SecurityTrails | Subdomains, DNS history, WHOIS history | ✅ **Mandatory** |
| `--ports` | Port Scanner | 18 common ports + banner grabbing + risk flags | ❌ No |
| `--tech` | Tech Detection | CMS, frameworks, server, missing security headers | ❌ No |
| `--emails` | Email Harvester | Emails, patterns via Hunter.io | ⚠️ Optional |
| `--shodan` | Shodan Lookup | Open ports, CVEs, OS, ISP | ⚠️ Optional |
| `--geo` | IP Geolocation | IP, ASN, ISP, country, city, coords | ⚠️ Optional |
| `--vt` | VirusTotal | Malicious detections, reputation, categories | ⚠️ Optional |

---

## 📁 Project Structure

```
osint_tool/
├── main.py                    # CLI entry point
├── config.py                  # API key management & validation
├── requirements.txt
├── .env.example               # API key template
├── .env                       # Your keys (NEVER commit!)
├── .gitignore
│
├── modules/
│   ├── dns_enum.py            # DNS records + zone transfer
│   ├── whois_lookup.py        # WHOIS data
│   ├── ssl_info.py            # SSL/TLS certificate
│   ├── securitytrails.py      # SecurityTrails API (MANDATORY)
│   ├── port_scanner.py        # Port scanning + banners
│   ├── tech_detection.py      # Technology fingerprinting
│   ├── email_harvester.py     # Email discovery via Hunter.io
│   ├── shodan_lookup.py       # Shodan intelligence
│   ├── ip_geolocation.py      # IP + geo data
│   └── virustotal.py          # VirusTotal reputation
│
├── reports/
│   ├── report_generator.py    # HTML + JSON report builder
│   └── output/                # Generated reports saved here
│
└── utils/
    ├── banner.py              # ASCII banner
    ├── logger.py              # Logging
    └── helpers.py             # Shared utilities
```

---

## 📊 Reports

Reports are saved to `reports/output/` and named:
```
example.com_20240315_142301.html
example.com_20240315_142301.json
```

The **HTML report** includes:
- Dark-themed professional layout
- All module results in organized tables
- Color-coded risk indicators
- Notable findings highlighted in red

---

## 🛠️ Development

### Run tests

```bash
# Test with a domain you own
python main.py yourdomain.com --dns --whois --ssl
```

### Add a new module

1. Create `modules/your_module.py` with a `run(domain) -> dict` function
2. Import it in `main.py`
3. Add a CLI flag with `argparse`
4. Add results to the `results` dict
5. Add a section in `reports/report_generator.py`

---

## 🔒 Security & Privacy

- API keys are stored in `.env` — **never hardcoded**
- `.env` is in `.gitignore` — **never committed to Git**
- Reports may contain sensitive data — store securely
- Always obtain written authorization before scanning any domain

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Pull requests are welcome! Please:
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-module`
3. Commit your changes: `git commit -m 'Add new module'`
4. Push and open a Pull Request

---

## ⭐ Acknowledgements

Built with:
- [SecurityTrails API](https://securitytrails.com) — Core recon engine
- [Rich](https://github.com/Textualize/rich) — Terminal formatting
- [dnspython](https://www.dnspython.org/) — DNS toolkit
- [Shodan](https://shodan.io) — Internet intelligence
- [Hunter.io](https://hunter.io) — Email discovery

