# 🛡️ Subsec — Multi-Source Subdomain Enumeration & Takeover Detector

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-1.0-orange.svg)

**Subsec** is a subdomain enumeration and takeover-detection tool for penetration testers, bug bounty hunters, and security researchers. It pulls from multiple passive intelligence sources, supports multi-threaded brute forcing, checks every resolved host for dangling-CNAME subdomain takeover, and produces reports in four formats.

---

## ✨ Features

- 🔍 **Multi-Source Passive Enumeration**
  - crt.sh
  - AlienVault OTX
  - CertSpotter
  - HackerTarget
  - RapidDNS

- ⚡ **Multi-threaded Brute-force Engine**
  - Configurable thread count
  - Bundled wordlist, or bring your own with `-w`

- 🚨 **Subdomain Takeover Detection**
  - 25 fingerprinted services: GitHub Pages, Heroku, AWS S3, Azure, Netlify, Vercel, Firebase, Shopify, Fastly, Webflow, and more
  - Flags **both** takeover signals: a CNAME that never resolves at all (dangling CNAME) *and* a CNAME that resolves but returns a known "unclaimed resource" page

- 🌐 **HTTP Liveness Fingerprinting**
  - Status code, page title, `Server` header, content length per live host

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
