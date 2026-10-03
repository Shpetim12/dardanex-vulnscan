# vulnscan v1.0.0

The first public release of vulnscan, a permission-gated Python command-line tool for authorized network vulnerability assessment and education.

## Highlights

- DNS resolution with IPv4, IPv6, and best-effort reverse lookups.
- Nmap-backed quick, default, and full TCP service/version scans.
- NIST NVD API v2 CVE keyword lookup with caching, rate limiting, retries, and optional API-key support.
- HTTP security-header analysis with disclosure-header reporting and A–F grading.
- Branded TXT and JSON reports with CVE severity summaries.
- Installable Python package with a `vulnscan` console command.

## Install

```bash
git clone https://github.com/Shpetim12/dardanex-vulnscan.git
cd dardanex-vulnscan
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install .
```

Install the Nmap binary separately: [Windows installer](https://nmap.org/download), `sudo apt install nmap` on Debian/Ubuntu, or `brew install nmap` on macOS.

> [!WARNING]
> vulnscan is for authorized security testing and education only. Scan only systems you own or have explicit permission to test. The author and Dardanex accept no liability for misuse.
