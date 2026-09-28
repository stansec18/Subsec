#!/usr/bin/env python3
"""
Subsec.py — Multi-source subdomain enumeration + subdomain takeover detector.

Passive sources : crt.sh, AlienVault OTX, RapidDNS, CertSpotter, HackerTarget
Active           : optional multi-threaded wordlist brute force
Liveness check   : HTTP status, page title, server header per resolved host
Takeover check   : CNAME-chain fingerprinting against 20+ known vulnerable
                   services, using BOTH signals used by tools like
                   subjack/nuclei:
                     (a) CNAME points at a third-party service but the chain
                         never resolves to an IP at all  -> dangling CNAME
                     (b) CNAME resolves, but the HTTP response body contains
                         that service's known "unclaimed resource" text
Output           : json, csv, txt, html (dark-theme report) — pick with --format

"""

import argparse
import concurrent.futures
import csv
import html
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

USER_AGENT = "Subsec/1.0 (+authorized-security-testing)"
PRINT_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Takeover fingerprint database
# ---------------------------------------------------------------------------
FINGERPRINTS = [
    {"service": "GitHub Pages", "cname": ["github.io", "github.map.fastly.net"],
     "body": ["There isn't a GitHub Pages site here", "404: Not Found"]},
    {"service": "Heroku", "cname": ["herokuapp.com", "herokudns.com", "herokussl.com"],
     "body": ["No such app", "herokucdn.com/error-pages/no-such-app.html"]},
    {"service": "AWS S3", "cname": ["s3.amazonaws.com", "s3-website", "s3.dualstack"],
     "body": ["NoSuchBucket", "The specified bucket does not exist"]},
    {"service": "Shopify", "cname": ["myshopify.com"],
     "body": ["Sorry, this shop is currently unavailable"]},
    {"service": "Fastly", "cname": ["fastly.net"],
     "body": ["Fastly error: unknown domain"]},
    {"service": "Pantheon", "cname": ["pantheonsite.io"],
     "body": ["The gods are wise", "404 error unknown site"]},
    {"service": "Tumblr", "cname": ["domains.tumblr.com"],
     "body": ["Whatever you were looking for doesn't currently exist"]},
    {"service": "WordPress.com", "cname": ["wordpress.com"],
     "body": ["Do you want to register"]},
    {"service": "Zendesk", "cname": ["zendesk.com"],
     "body": ["Help Center Closed"]},
    {"service": "Unbounce", "cname": ["unbouncepages.com"],
     "body": ["The requested URL was not found on this server"]},
    {"service": "Surge.sh", "cname": ["surge.sh"],
     "body": ["project not found"]},
    {"service": "Netlify", "cname": ["netlify.app", "netlifyglobalcdn.com"],
     "body": ["Not Found - Request ID"]},
    {"service": "Cargo Collective", "cname": ["cargocollective.com"],
     "body": ["404 Not Found"]},
    {"service": "Bitbucket", "cname": ["bitbucket.io"],
     "body": ["Repository not found"]},
    {"service": "Azure", "cname": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                                    "trafficmanager.net", "blob.core.windows.net"],
     "body": ["404 Web Site not found"]},
    {"service": "Ghost", "cname": ["ghost.io"],
     "body": ["The thing you were looking for is no longer here"]},
    {"service": "Statuspage", "cname": ["statuspage.io"],
     "body": ["You are being"]},
    {"service": "UserVoice", "cname": ["uservoice.com"],
     "body": ["This UserVoice subdomain is currently available"]},
    {"service": "Webflow", "cname": ["proxy-ssl.webflow.com"],
     "body": ["The page you are looking for doesn't exist or has been moved"]},
    {"service": "Vercel", "cname": ["vercel-dns.com", "cname.vercel-dns.com"],
     "body": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"]},
    {"service": "Firebase", "cname": ["firebaseapp.com", "web.app"],
     "body": ["Site Not Found", "The specified bucket does not exist"]},
    {"service": "Cargo", "cname": ["cargo.site"],
     "body": ["If you're moving your domain away from Cargo"]},
    {"service": "Intercom", "cname": ["custom.intercom.help"],
     "body": ["This page is reserved for artists", "uninstalled"]},
    {"service": "Help Scout", "cname": ["helpscoutdocs.com"],
     "body": ["No settings were found for this company"]},
    {"service": "Readme.io", "cname": ["readme.io"],
     "body": ["Project doesnt exist... yet!"]},
]


@dataclass
class HostResult:
    subdomain: str
    source: str = ""
    resolves: bool = False
    ip_addresses: list = field(default_factory=list)
    cname_chain: list = field(default_factory=list)
    http_status: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_length: Optional[int] = None
    takeover_suspected: bool = False
    takeover_service: Optional[str] = None
    takeover_evidence: Optional[str] = None
    error: Optional[str] = None


def vprint(msg, verbose):
    if verbose:
        with PRINT_LOCK:
            print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Passive sources
# ---------------------------------------------------------------------------
def _get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def source_crtsh(domain, verbose=False):
    found = set()
    try:
        raw = _get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = json.loads("[" + raw.replace("}{", "},{") + "]")
        for entry in data:
            for line in entry.get("name_value", "").split("\n"):
                line = line.strip().lstrip("*.").lower()
                if line.endswith(domain):
                    found.add(line)
    except Exception as e:
        vprint(f"[!] crt.sh failed: {e}", verbose)
    return found


def source_alienvault(domain, verbose=False):
    found = set()
    try:
        raw = _get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=15)
        data = json.loads(raw)
        for entry in data.get("passive_dns", []):
            h = entry.get("hostname", "").strip().lower()
            if h.endswith(domain):
                found.add(h)
    except Exception as e:
        vprint(f"[!] AlienVault OTX failed: {e}", verbose)
    return found


def source_certspotter(domain, verbose=False):
    found = set()
    try:
        raw = _get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}"
            f"&include_subdomains=true&expand=dns_names",
            timeout=15,
        )
        data = json.loads(raw)
        for entry in data:
            for name in entry.get("dns_names", []):
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain):
                    found.add(name)
    except Exception as e:
        vprint(f"[!] CertSpotter failed: {e}", verbose)
    return found


def source_hackertarget(domain, verbose=False):
    found = set()
    try:
        raw = _get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if "error" in raw.lower() and "," not in raw:
            return found
        for line in raw.splitlines():
            parts = line.split(",")
            if parts and parts[0].strip().lower().endswith(domain):
                found.add(parts[0].strip().lower())
    except Exception as e:
        vprint(f"[!] HackerTarget failed: {e}", verbose)
    return found


def source_rapiddns(domain, verbose=False):
    found = set()
    try:
        raw = _get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=20)
        for m in re.finditer(r'<td>([a-zA-Z0-9_.-]+\.' + re.escape(domain) + r')</td>', raw):
            found.add(m.group(1).lower())
    except Exception as e:
        vprint(f"[!] RapidDNS failed: {e}", verbose)
    return found


PASSIVE_SOURCES = {
    "crtsh": source_crtsh,
    "alienvault": source_alienvault,
    "certspotter": source_certspotter,
    "hackertarget": source_hackertarget,
    "rapiddns": source_rapiddns,
}


def run_passive_enumeration(domain, verbose=False):
    """Run every passive source concurrently, tag each hit with its source."""
    hits = {}  # subdomain -> set of sources
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PASSIVE_SOURCES)) as pool:
        futures = {pool.submit(fn, domain, verbose): name for name, fn in PASSIVE_SOURCES.items()}
        for fut in concurrent.futures.as_completed(futures):
            name = futures[fut]
            try:
                found = fut.result()
                vprint(f"[*] {name}: {len(found)} names", verbose)
                for sub in found:
                    hits.setdefault(sub, set()).add(name)
            except Exception as e:
                vprint(f"[!] {name} raised {e}", verbose)
    return hits


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------
def resolve_host(sub):
    result = HostResult(subdomain=sub)
    if HAVE_DNSPYTHON:
        r = dns.resolver.Resolver()
        r.lifetime = 5
        current, seen = sub, set()
        while current not in seen:
            seen.add(current)
            try:
                ans = r.resolve(current, "CNAME")
                target = str(ans[0].target).rstrip(".")
                result.cname_chain.append(target)
                current = target
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                break
            except Exception:
                break
        try:
            a_ans = r.resolve(sub, "A")
            result.ip_addresses = [str(x) for x in a_ans]
            result.resolves = True
        except dns.resolver.NXDOMAIN:
            result.error = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            result.resolves = bool(result.cname_chain)
        except Exception as e:
            result.error = str(e)
    else:
        try:
            result.ip_addresses = [socket.gethostbyname(sub)]
            result.resolves = True
        except socket.gaierror:
            result.error = "NXDOMAIN"
    return result


# ---------------------------------------------------------------------------
# Liveness / HTTP fingerprinting
# ---------------------------------------------------------------------------
def http_probe(result: HostResult, timeout=8):
    body = ""
    for scheme in ("https", "http"):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(f"{scheme}://{result.subdomain}/",
                                          headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                result.http_status = resp.getcode()
                result.server = resp.headers.get("Server")
                raw = resp.read(50000)
                result.content_length = len(raw)
                body = raw.decode("utf-8", errors="ignore")
            break
        except urllib.error.HTTPError as e:
            result.http_status = e.code
            result.server = e.headers.get("Server") if e.headers else None
            try:
                body = e.read(50000).decode("utf-8", errors="ignore")
                result.content_length = len(body)
            except Exception:
                pass
            break
        except Exception:
            continue

    if body:
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            result.title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    return body


# ---------------------------------------------------------------------------
# Takeover detection
# ---------------------------------------------------------------------------
def check_takeover(result: HostResult, body_cache: dict, timeout=8):
    chain_str = " ".join(result.cname_chain).lower()
    fp = next((f for f in FINGERPRINTS if any(i in chain_str for i in f["cname"])), None)
    if not fp:
        return

    if result.cname_chain and not result.resolves:
        result.takeover_suspected = True
        result.takeover_service = fp["service"]
        result.takeover_evidence = "CNAME points to third-party service but does not resolve (dangling CNAME)"
        return

    body = body_cache.get(result.subdomain)
    if body is None:
        body = http_probe(result, timeout=timeout)
        body_cache[result.subdomain] = body

    for sig in fp["body"]:
        if sig.lower() in (body or "").lower():
            result.takeover_suspected = True
            result.takeover_service = fp["service"]
            result.takeover_evidence = f'Response body contains signature: "{sig}"'
            break


# ---------------------------------------------------------------------------
# Per-host pipeline
# ---------------------------------------------------------------------------
def process_host(sub, source_tag, do_http, do_takeover, timeout, verbose):
    result = resolve_host(sub)
    result.source = source_tag
    body_cache = {}
    try:
        if result.resolves and do_http:
            body_cache[sub] = http_probe(result, timeout=timeout)
        if do_takeover:
            check_takeover(result, body_cache, timeout=timeout)
    except Exception as e:
        result.error = (result.error + "; " if result.error else "") + f"probe error: {e}"
    vprint(f"[+] {sub} resolved={result.resolves}", verbose)
    return result


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------
def write_json(path, meta, results):
    payload = dict(meta)
    payload["subdomains"] = [asdict(r) for r in results]
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def write_csv(path, results):
    fields = ["subdomain", "source", "resolves", "ip_addresses", "cname_chain",
              "http_status", "title", "server", "content_length",
              "takeover_suspected", "takeover_service", "takeover_evidence", "error"]
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(fields)
        for r in results:
            d = asdict(r)
            d["ip_addresses"] = ";".join(d["ip_addresses"])
            d["cname_chain"] = " -> ".join(d["cname_chain"])
            w.writerow([d[k] for k in fields])


def write_txt(path, meta, results):
    resolved = [r for r in results if r.resolves]
    vulnerable = [r for r in results if r.takeover_suspected]
    with open(path, "w") as f:
        f.write(f"Subsec scan report\n")
        f.write(f"Domain: {meta['domain']}\n")
        f.write(f"Timestamp: {meta['timestamp']}\n")
        f.write(f"Total candidates: {meta['total_subdomains']}   Resolved: {len(resolved)}\n")
        f.write("=" * 70 + "\n\nLIVE SUBDOMAINS\n" + "=" * 70 + "\n")
        for r in sorted(resolved, key=lambda x: x.subdomain):
            flag = " [POTENTIAL TAKEOVER]" if r.takeover_suspected else ""
            ips = ",".join(r.ip_addresses) or "-"
            cname = " -> ".join(r.cname_chain) or "-"
            status = r.http_status if r.http_status is not None else "-"
            f.write(f"{r.subdomain:<40} ip={ips:<18} status={status!s:<5} cname={cname}{flag}\n")
        f.write("\n" + "=" * 70 + f"\nTAKEOVER CANDIDATES ({len(vulnerable)})\n" + "=" * 70 + "\n")
        if not vulnerable:
            f.write("None found.\n")
        for r in vulnerable:
            f.write(f"\n{r.subdomain}\n  service : {r.takeover_service}\n"
                    f"  cname   : {' -> '.join(r.cname_chain)}\n"
                    f"  evidence: {r.takeover_evidence}\n")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Subsec Report — {domain}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1117; color:#c9d1d9; font-family: "Segoe UI", Roboto, sans-serif; margin:0; padding:2rem; }}
  h1 {{ color:#58a6ff; margin-bottom:0.2rem; }}
  .meta {{ color:#8b949e; margin-bottom:1.5rem; font-size:0.9rem; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1rem 1.4rem; margin-bottom:1.5rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.88rem; }}
  th, td {{ text-align:left; padding:0.45rem 0.6rem; border-bottom:1px solid #21262d; vertical-align:top; }}
  th {{ color:#8b949e; text-transform:uppercase; font-size:0.72rem; letter-spacing:0.04em; }}
  tr:hover {{ background:#1c2128; }}
  .badge {{ display:inline-block; padding:0.15rem 0.55rem; border-radius:999px; font-size:0.75rem; font-weight:600; }}
  .badge-danger {{ background:#3d1418; color:#ff7b72; border:1px solid #f8514933; }}
  .badge-ok {{ background:#0f2a1a; color:#3fb950; border:1px solid #3fb95033; }}
  .stat {{ display:inline-block; margin-right:2rem; }}
  .stat b {{ font-size:1.5rem; display:block; color:#e6edf3; }}
  .stat span {{ color:#8b949e; font-size:0.8rem; }}
  code {{ background:#21262d; padding:0.1rem 0.35rem; border-radius:4px; font-size:0.85em; }}
</style></head>
<body>
  <h1>🛡️ Subsec Report</h1>
  <div class="meta">Domain: <code>{domain}</code> &nbsp;•&nbsp; Generated: {timestamp}</div>

  <div class="card">
    <div class="stat"><b>{total}</b><span>Candidates</span></div>
    <div class="stat"><b>{alive}</b><span>Resolved / Live</span></div>
    <div class="stat"><b style="color:{takeover_color}">{takeover_count}</b><span>Takeover candidates</span></div>
  </div>

  <div class="card">
    <h2>Takeover candidates</h2>
    {takeover_table}
  </div>

  <div class="card">
    <h2>All resolved subdomains</h2>
    {main_table}
  </div>

  <p style="color:#6e7681; font-size:0.8rem;">Generated by Subsec — verify all takeover candidates manually before reporting.</p>
</body></html>
"""


def render_table(rows, headers):
    if not rows:
        return "<p style='color:#6e7681;'>None.</p>"
    out = ["<table><thead><tr>"]
    out += [f"<th>{h}</th>" for h in headers]
    out.append("</tr></thead><tbody>")
    out += rows
    out.append("</tbody></table>")
    return "".join(out)


def write_html(path, meta, results):
    resolved = sorted([r for r in results if r.resolves], key=lambda x: x.subdomain)
    vulnerable = [r for r in results if r.takeover_suspected]

    main_rows = []
    for r in resolved:
        badge = '<span class="badge badge-danger">TAKEOVER</span>' if r.takeover_suspected else ""
        main_rows.append(
            "<tr>"
            f"<td>{html.escape(r.subdomain)}</td>"
            f"<td>{html.escape(','.join(r.ip_addresses) or '-')}</td>"
            f"<td>{html.escape(r.http_status and str(r.http_status) or '-')}</td>"
            f"<td>{html.escape(r.title or '-')}</td>"
            f"<td>{html.escape(r.server or '-')}</td>"
            f"<td>{badge}</td>"
            "</tr>"
        )
    main_table = render_table(main_rows, ["Subdomain", "IP", "Status", "Title", "Server", "Flag"])

    tk_rows = []
    for r in vulnerable:
        tk_rows.append(
            "<tr>"
            f"<td>{html.escape(r.subdomain)}</td>"
            f"<td>{html.escape(r.takeover_service or '-')}</td>"
            f"<td>{html.escape(' -> '.join(r.cname_chain))}</td>"
            f"<td>{html.escape(r.takeover_evidence or '-')}</td>"
            "</tr>"
        )
    takeover_table = render_table(tk_rows, ["Subdomain", "Service", "CNAME chain", "Evidence"])

    page = HTML_TEMPLATE.format(
        domain=html.escape(meta["domain"]),
        timestamp=html.escape(meta["timestamp"]),
        total=meta["total_subdomains"],
        alive=len(resolved),
        takeover_count=len(vulnerable),
        takeover_color="#ff7b72" if vulnerable else "#3fb950",
        takeover_table=takeover_table,
        main_table=main_table,
    )
    with open(path, "w") as f:
        f.write(page)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        prog="Subsec.py",
        description="Multi-source subdomain enumeration + takeover detection. "
                     "Only use against domains you are authorized to test.",
    )
    ap.add_argument("-d", "--domain", required=True, help="Target domain, e.g. example.com")
    ap.add_argument("-o", "--output", help="Output filename base (without extension)")
    ap.add_argument("-t", "--threads", type=int, default=50, help="Thread count (default 50)")
    ap.add_argument("-b", "--bruteforce", action="store_true", help="Enable wordlist brute force")
    ap.add_argument("-w", "--wordlist", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                               "wordlists", "common.txt"),
                     help="Wordlist for brute force (default: wordlists/common.txt)")
    ap.add_argument("--takeover", action="store_true", help="Enable subdomain takeover detection")
    ap.add_argument("--no-http", action="store_true", help="Skip HTTP liveness probing (faster, DNS-only)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    ap.add_argument("--format", default="all", help="Output formats: json,csv,txt,html or 'all' (default: all)")
    ap.add_argument("--skip-passive", action="store_true", help="Skip passive source enumeration")
    args = ap.parse_args()

    if not HAVE_DNSPYTHON:
        print("[!] dnspython not installed — CNAME-chain visibility will be limited.")
        print("    pip install dnspython --break-system-packages\n")

    domain = args.domain.strip().lower()
    hits = {}  # subdomain -> set(sources)

    if not args.skip_passive:
        print(f"[*] Running passive enumeration against {domain} "
              f"({len(PASSIVE_SOURCES)} sources) ...")
        hits = run_passive_enumeration(domain, args.verbose)
        print(f"[*] Passive sources found {len(hits)} unique candidates")

    if args.bruteforce:
        if not os.path.exists(args.wordlist):
            print(f"[!] Wordlist not found: {args.wordlist}")
            sys.exit(1)
        with open(args.wordlist, errors="ignore") as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
        print(f"[*] Brute-forcing {len(words)} candidates from {args.wordlist} ...")
        for w in words:
            hits.setdefault(f"{w}.{domain}", set()).add("bruteforce")

    hits.setdefault(domain, set()).add("apex")

    if not hits:
        print("[!] No candidates found. Try -b with a wordlist.")
        sys.exit(1)

    total = len(hits)
    print(f"[*] Resolving{'​ + probing HTTP' if not args.no_http else ''}"
          f"{' + checking takeover' if args.takeover else ''} for {total} candidates "
          f"using {args.threads} threads ...\n")

    results = []
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(process_host, sub, ",".join(sorted(srcs)),
                        not args.no_http, args.takeover, 8, args.verbose): sub
            for sub, srcs in hits.items()
        }
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
            done += 1
            if done % 50 == 0 or done == total:
                print(f"[*] Progress: {done}/{total}", file=sys.stderr)

    elapsed = time.time() - t0
    resolved = [r for r in results if r.resolves]
    vulnerable = [r for r in results if r.takeover_suspected]

    print(f"\n[+] Completed in {elapsed:.1f}s — {len(resolved)}/{total} resolved, "
          f"{len(vulnerable)} potential takeover(s).\n")

    print("=" * 78)
    print(f"{'SUBDOMAIN':<38}{'IP':<18}{'STATUS':<8}{'FLAG'}")
    print("=" * 78)
    for r in sorted(resolved, key=lambda x: x.subdomain):
        flag = "⚠ POTENTIAL TAKEOVER" if r.takeover_suspected else ""
        ip = (r.ip_addresses[0] if r.ip_addresses else "-")
        status = str(r.http_status) if r.http_status else "-"
        print(f"{r.subdomain:<38}{ip:<18}{status:<8}{flag}")

    if vulnerable:
        print("\n" + "=" * 78)
        print(f"TAKEOVER CANDIDATES ({len(vulnerable)}) — verify manually before reporting")
        print("=" * 78)
        for r in vulnerable:
            print(f"\n  {r.subdomain}")
            print(f"    service : {r.takeover_service}")
            print(f"    cname   : {' -> '.join(r.cname_chain)}")
            print(f"    evidence: {r.takeover_evidence}")

    if args.output:
        fmt = args.format.lower()
        formats = {"json", "csv", "txt", "html"} if fmt == "all" else set(f.strip() for f in fmt.split(","))
        meta = {
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_subdomains": total,
            "alive_subdomains": len(resolved),
            "takeover_count": len(vulnerable),
        }
        base = args.output
        written = []
        if "json" in formats:
            write_json(f"{base}.json", meta, results); written.append(f"{base}.json")
        if "csv" in formats:
            write_csv(f"{base}.csv", results); written.append(f"{base}.csv")
        if "txt" in formats:
            write_txt(f"{base}.txt", meta, results); written.append(f"{base}.txt")
        if "html" in formats:
            write_html(f"{base}.html", meta, results); written.append(f"{base}.html")
        print(f"\n[*] Reports written: {', '.join(written)}")


if __name__ == "__main__":
    main()
