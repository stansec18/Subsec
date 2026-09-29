# 🛡️ Subsec — Multi-Source Subdomain Enumeration & Takeover Detector

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-1.0-orange.svg)

**Subsec** is a subdomain enumeration and takeover-detection tool for penetration testers, bug bounty hunters, and security researchers. It pulls from multiple passive intelligence sources, supports multi-threaded brute forcing, checks every resolved host for dangling-CNAME subdomain takeover, and produces reports in four formats.

---

## ✨ Features

- 🔍 **Multi-Source Passive Enumeration**
  - Free, always on: crt.sh, AlienVault OTX, CertSpotter, HackerTarget, RapidDNS, Wayback Machine (CDX API — surfaces old/forgotten subdomains no longer linked anywhere live, which is exactly the kind of abandoned infra that goes dangling)
  - Optional (need your own API key): Shodan, VirusTotal, Censys, FOFA, Google (via the official Custom Search JSON API — not scraping google.com, which breaks their ToS)
  - Experimental, opt-in only: findsubdomains.com (unofficial page scrape, no published API — may break anytime)

- ⚡ **Multi-threaded Brute-force Engine**
  - Configurable thread count
  - Bundled wordlist, or bring your own with `-w`

- 🚨 **Subdomain Takeover Detection**
  - 25 fingerprinted services: GitHub Pages, Heroku, AWS S3, Azure, Netlify, Vercel, Firebase, Shopify, Fastly, Webflow, and more
  - Flags **both** takeover signals: a CNAME that never resolves at all (dangling CNAME) *and* a CNAME that resolves but returns a known "unclaimed resource" page

- 🌐 **HTTP Liveness Fingerprinting**
  - Status code, page title, `Server` header, content length per live host
  - Redirects are captured, not silently followed — you see the 301/302 *and* where it points

- 📁 **Directory Brute Forcing**
  - Runs against every live subdomain after enumeration
  - Filtered to configurable "interesting" status codes (200/204/301/302/307/401/403/500 by default)
  - Optional extension appending (`--dirb-extensions php,bak,env`)

- 📊 **Four Output Formats**
  - JSON, CSV, TXT, and a dark-theme HTML report — pick with `--format`

---

## 📦 Installation

```bash
git clone https://github.com/stansec18/Subsec.git
cd Subsec
pip install -r requirements.txt
```

`dnspython` is the only dependency — it enables proper CNAME-chain resolution. The tool still runs without it, with weaker takeover detection.

---

## 🚀 Usage

### Basic passive scan
```bash
python3 Subsec.py -d example.com
```

### Passive + brute force
```bash
python3 Subsec.py -d example.com -b -o results
```

### Full scan: passive + brute force + takeover detection
```bash
python3 Subsec.py -d example.com -b --takeover -t 80 -o full_report
```

### Custom wordlist
```bash
python3 Subsec.py -d example.com -b -w wordlists/custom.txt -o results
```

### Choose output formats
```bash
python3 Subsec.py -d example.com -o report --format json
python3 Subsec.py -d example.com -o report --format json,csv
python3 Subsec.py -d example.com -o report --format all
```

### Skip HTTP probing (DNS-only, faster)
```bash
python3 Subsec.py -d example.com --no-http -o results
```

### Full pipeline: passive + brute force + takeover + directory brute force
```bash
python3 Subsec.py -d example.com -b --takeover --dirb -t 80 -o full --format all
```

### Use external intelligence sources (Shodan, VirusTotal, Censys, FOFA, Google)
```bash
export SHODAN_API_KEY="your_key"
export VT_API_KEY="your_key"
python3 Subsec.py -d example.com --takeover -o report
```
Sources without a configured key are skipped automatically — the tool tells you which ones and how to enable them, it never fails the whole scan over a missing key.

### Restrict which passive sources run
```bash
python3 Subsec.py -d example.com --sources crtsh,shodan,virustotal
```

---

## 🔑 Getting API keys for the optional sources

| Source | Get a key at | Free tier? |
|---|---|---|
| Shodan | https://account.shodan.io/register | Yes, limited queries |
| VirusTotal | https://www.virustotal.com/gui/join-us | Yes, 500 req/day |
| Censys | https://search.censys.io/account/api | Yes, limited queries |
| FOFA | https://fofa.info/user/register | Yes, limited queries |
| Google Custom Search | https://programmablesearchengine.google.com/ (create an engine set to search the entire web) + https://console.cloud.google.com/apis/credentials (enable "Custom Search API", create a key) | Yes, 100 queries/day |

Pass keys via CLI flags (`--shodan-key`, `--vt-key`, etc.) or environment variables (`SHODAN_API_KEY`, `VT_API_KEY`, `CENSYS_API_ID`/`CENSYS_API_SECRET`, `FOFA_EMAIL`/`FOFA_KEY`, `GOOGLE_API_KEY`/`GOOGLE_CX`) — env vars are recommended so keys never end up in shell history or scan output.

**findsubdomains.com** needs no key but is off by default since it's an unofficial scrape of their results page with no published API — enable explicitly with `--enable-findsubdomains` if you want to try it, understanding it may break or stop working without notice.

---

## 🛠️ Command Line Arguments

| Argument | Description | Default |
|---|---|---|
| `-d`, `--domain` | Target domain | **Required** |
| `-o`, `--output` | Output filename base (no extension) | - |
| `-t`, `--threads` | Thread count | `50` |
| `-b`, `--bruteforce` | Enable wordlist brute force | Disabled |
| `-w`, `--wordlist` | Custom wordlist path | `wordlists/common.txt` |
| `--takeover` | Enable takeover detection | Disabled |
| `--no-http` | Skip HTTP liveness probing | Disabled |
| `--skip-passive` | Skip passive source enumeration | Disabled |
| `-v`, `--verbose` | Verbose output | Disabled |
| `--format` | Output formats: `json,csv,txt,html` or `all` | `all` |
| `--sources` | Comma-separated passive sources to use, or `all` | `all` |
| `--shodan-key` / `$SHODAN_API_KEY` | Shodan API key | - |
| `--vt-key` / `$VT_API_KEY` | VirusTotal API key | - |
| `--censys-id` / `--censys-secret` | Censys API credentials | - |
| `--fofa-email` / `--fofa-key` | FOFA credentials | - |
| `--google-api-key` / `--google-cx` | Google Custom Search API key + engine ID | - |
| `--enable-findsubdomains` | Enable experimental findsubdomains.com scrape | Disabled |
| `--dirb` | Enable directory brute forcing on live subdomains | Disabled |
| `--dirb-wordlist` | Path wordlist for dir brute force | `wordlists/dirs.txt` |
| `--dirb-extensions` | Extensions to append to each word, e.g. `php,bak` | - |
| `--dirb-threads` | Threads per host for dir brute force | `20` |
| `--dirb-status` | Status codes worth reporting | `200,204,301,302,307,401,403,500` |
| `--dirb-delay` | Delay in seconds before each dir request | `0` |

---

## 📁 Project Structure

```
Subsec/
│
├── Subsec.py
├── requirements.txt
├── README.md
│
└── wordlists/
    └── common.txt
```

---

## ⚠️ Disclaimer

This tool is intended **only for educational purposes and authorized security testing**.

- Only scan domains you own or have explicit written permission to test.
- Do not use this tool for unauthorized reconnaissance or access.
- Takeover candidates flagged by this tool are **not confirmed vulnerabilities** — always verify manually (e.g. by attempting a controlled registration on the third-party service, per the target's bug bounty scope/rules) before reporting.
- The author assumes no responsibility for misuse or damage caused by this software.
- Always comply with applicable laws and the rules of any program you test against.

---

## 📜 License

MIT License.
