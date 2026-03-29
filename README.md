# Reaver - Modular Reconnaissance Tool

A clean, fast recon-oriented pipeline for attack surface understanding and planning.

```
 ██▀███  ▓█████ ▄▄▄    ██▒   █▓▓█████  ██▀███  
▓██ ▒ ██▒▓█   ▀▒████▄ ▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
▓██ ░▄█ ▒▒███  ▒██  ▀█▄▓██  █▒░▒███   ▓██ ░▄█ ▒
▒██▀▀█▄  ▒▓█  ▄░██▄▄▄▄██▒██ █░░▒▓█  ▄ ▒██▀▀█▄  
░██▓ ▒██▒░▒████▒▓█   ▓██▒▒▀█░  ░▒████▒░██▓ ▒██▒
░ ▒▓ ░▒▓░░░ ▒░ ░▒▒   ▓▒█░░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
  ░▒ ░ ▒░ ░ ░  ░ ▒   ▒▒ ░░ ░░   ░ ░  ░  ░▒ ░ ▒░
  ░░   ░    ░    ░   ▒     ░░     ░     ░░   ░ 
   ░        ░  ░     ░  ░   ░     ░  ░   ░     
                           ░                   
```

## Features

- **Asset Expansion** - Resolve domains to IPs, handle subdomains
- **Port Scanning** - Fast socket-based port detection (or nmap)
- **Service Discovery** - Detect open ports and services
- **Web Fingerprinting** - Identify technologies (LuCI, WordPress, Apache, etc.)
- **Endpoint Discovery** - Find admin panels, login pages, APIs
- **CVE Matching** - Built-in CVE database with links to NVD
- **Nuclei Integration** - Run vulnerability templates (requires nuclei)
- **Intelligence Layer** - Rank targets by value, generate recommendations

## Installation

```bash
# Clone or download the tool
cd Reaver

# Install dependencies
pip install -r requirements.txt

# Install nmap (recommended for full port scans)
# On Kali: apt install nmap
# On Windows: Download from https://nmap.org
```

## Usage

```bash
# Single target
python main.py -t example.com

# IP address
python main.py -t 192.168.1.1

# Multiple targets
python main.py example.com 192.168.1.1 api.example.com

# From file
python main.py -f targets.txt

# Fast scan (fewer ports)
python main.py -t example.com --fast

# JSON output
python main.py -t example.com -o json

# Skip nuclei scan
python main.py -t example.com --nmap-only
```

## Options

```
-t, --target          Single target (domain or IP)
-f, --file            File containing targets
-o, --output          Output format (json/text)
--fast                Fast scan (common ports only)
--nmap-only           Run only nmap scan
--cve-file            Path to CVE database (NVD JSON)
--nuclei-tags         Nuclei tags (default: exposure,misconfig,tech)
--threads             Number of threads
--timeout             Request timeout
--no-color            Disable colored output
```

## Example Output

```
>>> 192.168.1.1

  Services (3):
    - http ()
    - https ()

  URLs (3):
    - http://192.168.1.1:80
    - https://192.168.1.1:443

  Potential CVEs:
    - GHSA-vvj6-7362-pjrw (luci) [HIGH] XSS
      Link: https://github.com/openwrt/luci/security/advisories/GHSA-vvj6-7362-pjrw

  Intelligence:
    - High severity: GHSA-vvj6-7362-pjrw (XSS) - POTENTIAL RCE
```

## Project Structure

```
Reaver/
├── main.py                 # CLI entry point
├── requirements.txt         # Python dependencies
├── core/
│   ├── orchestrator.py     # Main scan pipeline
│   ├── aggregator.py       # Host data aggregation
│   └── intelligence.py     # Ranking & recommendations
├── modules/
│   ├── nmap.py            # Port scanning
│   ├── nuclei.py          # Vulnerability templates
│   ├── http.py            # Web fingerprinting
│   ├── cve.py             # CVE matching
│   ├── cve_db.py          # Built-in CVE database
│   └── discovery.py       # Endpoint enumeration
└── utils/
    ├── normalizer.py      # Input normalization
    └── parser.py          # Output parsers
```

## Requirements

- Python 3.8+
- colorama (included in requirements.txt)
- nmap (optional, for full port scans)
- nuclei (optional, for vulnerability scanning)

## Notes

- On Windows, socket-based scanning is used as fallback
- On Linux/Kali, nmap is used for better results
- Built-in CVE database covers common services (Apache, Nginx, OpenWrt/LuCI, WordPress, etc.)
- Add `--cve-file` with NVD JSON for more comprehensive CVE matching

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any target you do not own.
