#!/usr/bin/env python3
"""
Subsec.py — Multi-source subdomain enumeration, HTTP fingerprinting,
directory brute forcing, and subdomain takeover detection.

Passive sources (free, always on)  : crt.sh, AlienVault OTX, CertSpotter,
                                      HackerTarget, RapidDNS, Wayback Machine
Passive sources (need API keys)    : Shodan, VirusTotal, Censys, FOFA,
                                      Google (Custom Search JSON API)
Passive source (experimental)      : findsubdomains.com — unofficial page
                                      scrape, no published API; opt-in only
                                      via --enable-findsubdomains
Subdomain active                   : optional multi-threaded wordlist brute
                                      force
HTTP fingerprint                   : status code (redirects captured, not
                                      silently followed), page title, server
                                      header, content length, scheme
Takeover check                     : CNAME-chain fingerprinting against 25
                                      known vulnerable services, using both
                                      signals used by tools like subjack/nuclei:
                                        (a) dangling CNAME — points at a
                                            third-party service but never
                                            resolves to an IP at all
                                        (b) CNAME resolves, but the HTTP body
                                            contains that service's known
                                            "unclaimed resource" text
Directory brute                    : optional path brute force against every
                                      live subdomain, filtered to a
                                      configurable set of "interesting"
                                      status codes
Output                             : json, csv, txt, html (dark-theme report)

Only scan domains you own or are explicitly authorized to test.
"""

import argparse
import base64
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

USER_AGENT = "Subsec/1.2 (+authorized-security-testing)"
PRINT_LOCK = threading.Lock()
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Terminal colors (no-op if stdout isn't a TTY, e.g. piped to a file)
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty()


def c(text, code):
    if not _USE_COLOR:
        return str(text)
    return f"\033[{code}m{text}\033[0m"


def status_color(status):
    if status is None:
        return c("-", "90")
    s = int(status)
    if 200 <= s < 300:
        return c(s, "32")
    if 300 <= s < 400:
        return c(s, "36")
    if 400 <= s < 500:
        return c(s, "33")
    if s >= 500:
        return c(s, "31")
    return str(s)


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
    scheme: Optional[str] = None
    http_status: Optional[int] = None
    redirect_location: Optional[str] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_length: Optional[int] = None
    takeover_suspected: bool = False
    takeover_service: Optional[str] = None
    takeover_evidence: Optional[str] = None
    dirb_hits: list = field(default_factory=list)
    error: Optional[str] = None


def vprint(msg, verbose):
    if verbose:
        with PRINT_LOCK:
            print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# A urllib opener that does NOT silently follow redirects.
# ---------------------------------------------------------------------------
class NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response
    https_response = http_response


_NOREDIRECT_OPENER = urllib.request.build_opener(NoRedirect)


def _fetch(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    resp = _NOREDIRECT_OPENER.open(req, timeout=timeout)
    try:
        status = resp.getcode()
        headers = resp.headers
        body = resp.read(50000)
    finally:
        resp.close()
    return status, headers, body


def _get(url, timeout=15, headers=None):
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def _owned_by(host, domain):
    """True if host is domain itself or a genuine subdomain of it
    (dot-boundary check — 'not-example.com' must NOT match 'example.com')."""
    host = host.rstrip(".")
    return host == domain or host.endswith("." + domain)


# ---------------------------------------------------------------------------
# Passive sources — free, no key required
# ---------------------------------------------------------------------------
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
                if _owned_by(line, domain):
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
            if _owned_by(h, domain):
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
                if _owned_by(name, domain):
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
            if parts and _owned_by(parts[0].strip().lower(), domain):
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


def source_wayback(domain, verbose=False):
    """
    Wayback Machine's CDX API — free, no key. Pulls every distinct hostname
    ever archived under *.domain, which often surfaces old/forgotten
    subdomains no longer linked from anywhere live (good takeover-hunting
    ground, since abandoned infra is exactly what goes dangling).
    """
    found = set()
    try:
        url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
               f"&output=json&fl=original&collapse=urlkey&limit=100000")
        raw = _get(url, timeout=30)
        data = json.loads(raw)
        for row in data[1:]:  # first row is the header ["original"]
            original = row[0] if row else ""
            m = re.match(r"https?://([^/:?#]+)", original)
            if m:
                host = m.group(1).lower()
                if _owned_by(host, domain):
                    found.add(host)
    except Exception as e:
        vprint(f"[!] Wayback Machine failed: {e}", verbose)
    return found


# ---------------------------------------------------------------------------
# Passive sources — require API keys
# ---------------------------------------------------------------------------
def source_shodan(domain, api_key, verbose=False):
    found = set()
    try:
        raw = _get(f"https://api.shodan.io/dns/domain/{domain}?key={api_key}", timeout=20)
        data = json.loads(raw)
        for sub in data.get("subdomains", []):
            if sub:
                found.add(f"{sub}.{domain}".lower())
    except Exception as e:
        vprint(f"[!] Shodan failed: {e}", verbose)
    return found


def source_virustotal(domain, api_key, verbose=False):
    found = set()
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
        pages = 0
        while url and pages < 10:  # cap pagination to be considerate of quota
            raw = _get(url, timeout=15, headers={"x-apikey": api_key})
            data = json.loads(raw)
            for item in data.get("data", []):
                sub_id = item.get("id", "").lower()
                if _owned_by(sub_id, domain):
                    found.add(sub_id)
            url = data.get("links", {}).get("next")
            pages += 1
    except Exception as e:
        vprint(f"[!] VirusTotal failed: {e}", verbose)
    return found


def source_censys(domain, api_id, api_secret, verbose=False):
    found = set()
    try:
        auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        body = json.dumps({"q": f"names: {domain}", "per_page": 100}).encode()
        req = urllib.request.Request(
            "https://search.censys.io/api/v2/certificates/search",
            data=body, method="POST",
            headers={"User-Agent": USER_AGENT, "Authorization": f"Basic {auth}",
                     "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        data = json.loads(raw)
        for hit in data.get("result", {}).get("hits", []):
            for name in hit.get("names", []):
                name = name.strip().lstrip("*.").lower()
                if _owned_by(name, domain):
                    found.add(name)
    except Exception as e:
        vprint(f"[!] Censys failed: {e} (Censys's API schema changes occasionally — "
               f"check current docs if this keeps failing)", verbose)
    return found


def source_fofa(domain, email, key, verbose=False):
    found = set()
    try:
        query = f'domain="{domain}"'
        qbase64 = base64.b64encode(query.encode()).decode()
        url = (f"https://fofa.info/api/v1/search/all?email={email}&key={key}"
               f"&qbase64={qbase64}&size=500&fields=host")
        raw = _get(url, timeout=20)
        data = json.loads(raw)
        if data.get("error"):
            vprint(f"[!] FOFA error: {data.get('errmsg')}", verbose)
            return found
        for row in data.get("results", []):
            host = row[0] if isinstance(row, list) else row
            host = re.sub(r"^https?://", "", str(host)).split(":")[0].strip().lower()
            if _owned_by(host, domain):
                found.add(host)
    except Exception as e:
        vprint(f"[!] FOFA failed: {e}", verbose)
    return found


def source_google_cse(domain, api_key, cx, verbose=False):
    """
    Uses the official Google Programmable Search (Custom Search JSON API) —
    NOT scraping google.com directly, which breaks Google's ToS and gets
    blocked quickly. Free tier is 100 queries/day; each call here uses a few.
    """
    found = set()
    try:
        for start in (1, 11, 21):
            url = (f"https://www.googleapis.com/customsearch/v1?key={api_key}&cx={cx}"
                   f"&q=site:{domain}&num=10&start={start}")
            raw = _get(url, timeout=15)
            data = json.loads(raw)
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                m = re.search(r"https?://([a-zA-Z0-9_.-]+)", item.get("link", ""))
                if m:
                    host = m.group(1).lower()
                    if _owned_by(host, domain):
                        found.add(host)
            if "nextPage" not in data.get("queries", {}):
                break
    except Exception as e:
        vprint(f"[!] Google CSE failed: {e}", verbose)
    return found


def source_findsubdomains(domain, verbose=False):
    """
    EXPERIMENTAL. findsubdomains.com has no published API, so this scrapes
    its public results page. It may break at any time and is not guaranteed
    to respect that site's terms of use — that's why it's opt-in only
    (--enable-findsubdomains), never run by default.
    """
    found = set()
    try:
        raw = _get(f"https://findsubdomains.com/subdomains-of/{domain}", timeout=15)
        for m in re.finditer(r'([a-zA-Z0-9_-]+\.' + re.escape(domain) + r')', raw):
            found.add(m.group(1).lower())
    except Exception as e:
        vprint(f"[!] findsubdomains.com failed: {e}", verbose)
    return found


def build_passive_sources(domain, args, verbose):
    """Returns (active_sources: {name: zero-arg callable}, skipped: [reason strings])."""
    active = {}
    skipped = []

    free = {
        "crtsh": lambda: source_crtsh(domain, verbose),
        "alienvault": lambda: source_alienvault(domain, verbose),
        "certspotter": lambda: source_certspotter(domain, verbose),
        "hackertarget": lambda: source_hackertarget(domain, verbose),
        "rapiddns": lambda: source_rapiddns(domain, verbose),
        "wayback": lambda: source_wayback(domain, verbose),
    }

    requested = None
    if args.sources.lower() != "all":
        requested = {s.strip().lower() for s in args.sources.split(",") if s.strip()}

    def want(name):
        return requested is None or name in requested

    for name, fn in free.items():
        if want(name):
            active[name] = fn

    shodan_key = args.shodan_key or os.environ.get("SHODAN_API_KEY")
    if want("shodan"):
        if shodan_key:
            active["shodan"] = lambda: source_shodan(domain, shodan_key, verbose)
        else:
            skipped.append("shodan (no key — set --shodan-key or $SHODAN_API_KEY)")

    vt_key = args.vt_key or os.environ.get("VT_API_KEY")
    if want("virustotal"):
        if vt_key:
            active["virustotal"] = lambda: source_virustotal(domain, vt_key, verbose)
        else:
            skipped.append("virustotal (no key — set --vt-key or $VT_API_KEY)")

    censys_id = args.censys_id or os.environ.get("CENSYS_API_ID")
    censys_secret = args.censys_secret or os.environ.get("CENSYS_API_SECRET")
    if want("censys"):
        if censys_id and censys_secret:
            active["censys"] = lambda: source_censys(domain, censys_id, censys_secret, verbose)
        else:
            skipped.append("censys (no credentials — set --censys-id/--censys-secret "
                            "or $CENSYS_API_ID/$CENSYS_API_SECRET)")

    fofa_email = args.fofa_email or os.environ.get("FOFA_EMAIL")
    fofa_key = args.fofa_key or os.environ.get("FOFA_KEY")
    if want("fofa"):
        if fofa_email and fofa_key:
            active["fofa"] = lambda: source_fofa(domain, fofa_email, fofa_key, verbose)
        else:
            skipped.append("fofa (no credentials — set --fofa-email/--fofa-key "
                            "or $FOFA_EMAIL/$FOFA_KEY)")

    google_key = args.google_api_key or os.environ.get("GOOGLE_API_KEY")
    google_cx = args.google_cx or os.environ.get("GOOGLE_CX")
    if want("google"):
        if google_key and google_cx:
            active["google"] = lambda: source_google_cse(domain, google_key, google_cx, verbose)
        else:
            skipped.append("google (no key/CX — set --google-api-key/--google-cx "
                            "or $GOOGLE_API_KEY/$GOOGLE_CX)")

    if args.enable_findsubdomains and want("findsubdomains"):
        active["findsubdomains"] = lambda: source_findsubdomains(domain, verbose)

    return active, skipped


def run_passive_enumeration(sources, verbose=False):
    hits = {}
    if not sources:
        return hits
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = {pool.submit(fn): name for name, fn in sources.items()}
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
# Liveness / HTTP fingerprinting (redirect-aware)
# ---------------------------------------------------------------------------
def http_probe(result: HostResult, timeout=8):
    body = b""
    for scheme in ("https", "http"):
        try:
            status, headers, raw = _fetch(f"{scheme}://{result.subdomain}/", timeout)
            result.scheme = scheme
            result.http_status = status
            result.server = headers.get("Server")
            result.content_length = len(raw)
            if 300 <= status < 400:
                result.redirect_location = headers.get("Location")
            body = raw
            break
        except urllib.error.HTTPError as e:
            result.scheme = scheme
            result.http_status = e.code
            result.server = e.headers.get("Server") if e.headers else None
            try:
                body = e.read(50000)
                result.content_length = len(body)
            except Exception:
                pass
            break
        except Exception:
            continue

    if body:
        text = body.decode("utf-8", errors="ignore")
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if m:
            result.title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
        return text
    return ""


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
# Directory brute forcing
# ---------------------------------------------------------------------------
def build_dirb_paths(wordlist_path, extensions):
    with open(wordlist_path, errors="ignore") as f:
        words = [w.strip().lstrip("/") for w in f if w.strip() and not w.startswith("#")]
    paths = list(words)
    if extensions:
        exts = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()]
        for w in words:
            if "." in w:
                continue
            for ext in exts:
                paths.append(f"{w}.{ext}")
    return sorted(set(paths))


def dirb_one(base_url, path, timeout, status_filter, delay):
    if delay:
        time.sleep(delay)
    url = f"{base_url}/{path}"
    try:
        status, headers, raw = _fetch(url, timeout)
        if status in status_filter:
            return {
                "path": "/" + path,
                "status": status,
                "length": len(raw),
                "redirect": headers.get("Location") if 300 <= status < 400 else None,
            }
    except urllib.error.HTTPError as e:
        if e.code in status_filter:
            return {"path": "/" + path, "status": e.code, "length": 0, "redirect": None}
    except Exception:
        pass
    return None


def run_dirb(result: HostResult, paths, threads, timeout, status_filter, delay, verbose):
    if not (result.resolves and result.scheme):
        return
    base_url = f"{result.scheme}://{result.subdomain}"
    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(dirb_one, base_url, p, timeout, status_filter, delay) for p in paths]
        for fut in concurrent.futures.as_completed(futures):
            hit = fut.result()
            if hit:
                hits.append(hit)
                vprint(f"    [dirb] {result.subdomain}{hit['path']} -> {hit['status']}", verbose)
    hits.sort(key=lambda h: h["path"])
    result.dirb_hits = hits


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
              "scheme", "http_status", "redirect_location", "title", "server",
              "content_length", "takeover_suspected", "takeover_service",
              "takeover_evidence", "dirb_hits", "error"]
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(fields)
        for r in results:
            d = asdict(r)
            d["ip_addresses"] = ";".join(d["ip_addresses"])
            d["cname_chain"] = " -> ".join(d["cname_chain"])
            d["dirb_hits"] = ";".join(f"{h['path']}:{h['status']}" for h in d["dirb_hits"])
            w.writerow([d[k] for k in fields])


def write_txt(path, meta, results):
    resolved = [r for r in results if r.resolves]
    vulnerable = [r for r in results if r.takeover_suspected]
    dirb_hosts = [r for r in results if r.dirb_hits]
    with open(path, "w") as f:
        f.write("Subsec scan report\n")
        f.write(f"Domain: {meta['domain']}\n")
        f.write(f"Timestamp: {meta['timestamp']}\n")
        f.write(f"Sources used: {meta.get('sources_used', '-')}\n")
        f.write(f"Total candidates: {meta['total_subdomains']}   Resolved: {len(resolved)}\n")
        f.write("=" * 78 + "\n\nLIVE SUBDOMAINS\n" + "=" * 78 + "\n")
        for r in sorted(resolved, key=lambda x: x.subdomain):
            flag = " [POTENTIAL TAKEOVER]" if r.takeover_suspected else ""
            ips = ",".join(r.ip_addresses) or "-"
            cname = " -> ".join(r.cname_chain) or "-"
            status = r.http_status if r.http_status is not None else "-"
            redirect = f" -> {r.redirect_location}" if r.redirect_location else ""
            f.write(f"{r.subdomain:<40} ip={ips:<18} status={status!s:<5}{redirect} cname={cname}{flag}\n")

        f.write("\n" + "=" * 78 + f"\nTAKEOVER CANDIDATES ({len(vulnerable)})\n" + "=" * 78 + "\n")
        if not vulnerable:
            f.write("None found.\n")
        for r in vulnerable:
            f.write(f"\n{r.subdomain}\n  service : {r.takeover_service}\n"
                    f"  cname   : {' -> '.join(r.cname_chain)}\n"
                    f"  evidence: {r.takeover_evidence}\n")

        f.write("\n" + "=" * 78 + f"\nDIRECTORY BRUTE-FORCE HITS ({sum(len(r.dirb_hits) for r in dirb_hosts)})\n" + "=" * 78 + "\n")
        if not dirb_hosts:
            f.write("None found.\n")
        for r in dirb_hosts:
            f.write(f"\n{r.subdomain}\n")
            for h in r.dirb_hits:
                redirect = f" -> {h['redirect']}" if h["redirect"] else ""
                f.write(f"  {h['path']:<40} status={h['status']}{redirect}\n")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Subsec Report — {domain}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1117; color:#c9d1d9; font-family: "Segoe UI", Roboto, sans-serif; margin:0; padding:2rem; }}
  h1 {{ color:#58a6ff; margin-bottom:0.2rem; }}
  h2 {{ font-size:1.1rem; color:#e6edf3; }}
  .meta {{ color:#8b949e; margin-bottom:1.5rem; font-size:0.9rem; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1rem 1.4rem; margin-bottom:1.5rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.85rem; }}
  th, td {{ text-align:left; padding:0.45rem 0.6rem; border-bottom:1px solid #21262d; vertical-align:top; }}
  th {{ color:#8b949e; text-transform:uppercase; font-size:0.72rem; letter-spacing:0.04em; }}
  tr:hover {{ background:#1c2128; }}
  .badge {{ display:inline-block; padding:0.15rem 0.55rem; border-radius:999px; font-size:0.75rem; font-weight:600; }}
  .badge-danger {{ background:#3d1418; color:#ff7b72; border:1px solid #f8514933; }}
  .st-2xx {{ color:#3fb950; font-weight:600; }}
  .st-3xx {{ color:#58a6ff; font-weight:600; }}
  .st-4xx {{ color:#d29922; font-weight:600; }}
  .st-5xx {{ color:#ff7b72; font-weight:600; }}
  .stat {{ display:inline-block; margin-right:2rem; }}
  .stat b {{ font-size:1.5rem; display:block; color:#e6edf3; }}
  .stat span {{ color:#8b949e; font-size:0.8rem; }}
  code {{ background:#21262d; padding:0.1rem 0.35rem; border-radius:4px; font-size:0.85em; }}
</style></head>
<body>
  <h1>🛡️ Subsec Report</h1>
  <div class="meta">Domain: <code>{domain}</code> &nbsp;•&nbsp; Generated: {timestamp} &nbsp;•&nbsp; Sources: {sources_used}</div>

  <div class="card">
    <div class="stat"><b>{total}</b><span>Candidates</span></div>
    <div class="stat"><b>{alive}</b><span>Resolved / Live</span></div>
    <div class="stat"><b style="color:{takeover_color}">{takeover_count}</b><span>Takeover candidates</span></div>
    <div class="stat"><b>{dirb_count}</b><span>Dir brute-force hits</span></div>
  </div>

  <div class="card">
    <h2>Takeover candidates</h2>
    {takeover_table}
  </div>

  <div class="card">
    <h2>All resolved subdomains</h2>
    {main_table}
  </div>

  <div class="card">
    <h2>Directory brute-force hits</h2>
    {dirb_table}
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


def status_class(status):
    if status is None:
        return ""
    s = int(status)
    if 200 <= s < 300:
        return "st-2xx"
    if 300 <= s < 400:
        return "st-3xx"
    if 400 <= s < 500:
        return "st-4xx"
    return "st-5xx"


def write_html(path, meta, results):
    resolved = sorted([r for r in results if r.resolves], key=lambda x: x.subdomain)
    vulnerable = [r for r in results if r.takeover_suspected]
    dirb_hosts = [r for r in results if r.dirb_hits]

    main_rows = []
    for r in resolved:
        badge = '<span class="badge badge-danger">TAKEOVER</span>' if r.takeover_suspected else ""
        status_html = f'<span class="{status_class(r.http_status)}">{r.http_status}</span>' if r.http_status else "-"
        redirect = html.escape(r.redirect_location) if r.redirect_location else "-"
        main_rows.append(
            "<tr>"
            f"<td>{html.escape(r.subdomain)}</td>"
            f"<td>{html.escape(','.join(r.ip_addresses) or '-')}</td>"
            f"<td>{status_html}</td>"
            f"<td>{redirect}</td>"
            f"<td>{html.escape(r.title or '-')}</td>"
            f"<td>{html.escape(r.server or '-')}</td>"
            f"<td>{badge}</td>"
            "</tr>"
        )
    main_table = render_table(main_rows, ["Subdomain", "IP", "Status", "Redirect", "Title", "Server", "Flag"])

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

    dirb_rows = []
    dirb_total = 0
    for r in dirb_hosts:
        for h in r.dirb_hits:
            dirb_total += 1
            status_html = f'<span class="{status_class(h["status"])}">{h["status"]}</span>'
            dirb_rows.append(
                "<tr>"
                f"<td>{html.escape(r.subdomain)}</td>"
                f"<td>{html.escape(h['path'])}</td>"
                f"<td>{status_html}</td>"
                f"<td>{h['length']}</td>"
                f"<td>{html.escape(h['redirect']) if h['redirect'] else '-'}</td>"
                "</tr>"
            )
    dirb_table = render_table(dirb_rows, ["Subdomain", "Path", "Status", "Length", "Redirect"])

    page = HTML_TEMPLATE.format(
        domain=html.escape(meta["domain"]),
        timestamp=html.escape(meta["timestamp"]),
        sources_used=html.escape(meta.get("sources_used", "-")),
        total=meta["total_subdomains"],
        alive=len(resolved),
        takeover_count=len(vulnerable),
        takeover_color="#ff7b72" if vulnerable else "#3fb950",
        dirb_count=dirb_total,
        takeover_table=takeover_table,
        main_table=main_table,
        dirb_table=dirb_table,
    )
    with open(path, "w") as f:
        f.write(page)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_status_filter(s):
    return set(int(x.strip()) for x in s.split(",") if x.strip())


def main():
    ap = argparse.ArgumentParser(
        prog="Subsec.py",
        description="Multi-source subdomain enumeration, HTTP fingerprinting, "
                     "directory brute forcing, and takeover detection. "
                     "Only use against domains you are authorized to test.",
    )
    ap.add_argument("-d", "--domain", required=True, help="Target domain, e.g. example.com")
    ap.add_argument("-o", "--output", help="Output filename base (without extension)")
    ap.add_argument("-t", "--threads", type=int, default=50, help="Thread count for subdomain resolution (default 50)")
    ap.add_argument("-b", "--bruteforce", action="store_true", help="Enable subdomain wordlist brute force")
    ap.add_argument("-w", "--wordlist", default=os.path.join(SCRIPT_DIR, "wordlists", "common.txt"),
                     help="Wordlist for subdomain brute force (default: wordlists/common.txt)")
    ap.add_argument("--takeover", action="store_true", help="Enable subdomain takeover detection")
    ap.add_argument("--no-http", action="store_true", help="Skip HTTP liveness probing (faster, DNS-only)")
    ap.add_argument("--timeout", type=int, default=8, help="HTTP timeout in seconds (default 8)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    ap.add_argument("--format", default="all", help="Output formats: json,csv,txt,html or 'all' (default: all)")
    ap.add_argument("--skip-passive", action="store_true", help="Skip passive source enumeration entirely")
    ap.add_argument("--sources", default="all",
                     help="Comma-separated list of passive sources to use, or 'all' (default). "
                          "Names: crtsh,alienvault,certspotter,hackertarget,rapiddns,wayback,"
                          "shodan,virustotal,censys,fofa,google,findsubdomains")

    ext = ap.add_argument_group("external intelligence sources (optional, need API keys/credentials)")
    ext.add_argument("--shodan-key", help="Shodan API key (or set $SHODAN_API_KEY)")
    ext.add_argument("--vt-key", help="VirusTotal API key (or set $VT_API_KEY)")
    ext.add_argument("--censys-id", help="Censys API ID (or set $CENSYS_API_ID)")
    ext.add_argument("--censys-secret", help="Censys API secret (or set $CENSYS_API_SECRET)")
    ext.add_argument("--fofa-email", help="FOFA account email (or set $FOFA_EMAIL)")
    ext.add_argument("--fofa-key", help="FOFA API key (or set $FOFA_KEY)")
    ext.add_argument("--google-api-key", help="Google Custom Search API key (or set $GOOGLE_API_KEY)")
    ext.add_argument("--google-cx", help="Google Programmable Search Engine ID (or set $GOOGLE_CX)")
    ext.add_argument("--enable-findsubdomains", action="store_true",
                      help="Enable the experimental, unofficial findsubdomains.com scrape (off by default)")

    dirb = ap.add_argument_group("directory brute forcing")
    dirb.add_argument("--dirb", action="store_true", help="Enable directory/path brute forcing on live subdomains")
    dirb.add_argument("--dirb-wordlist", default=os.path.join(SCRIPT_DIR, "wordlists", "dirs.txt"),
                       help="Wordlist of paths (default: wordlists/dirs.txt)")
    dirb.add_argument("--dirb-extensions", default="",
                       help="Comma-separated extensions to append to each word, e.g. php,html,bak")
    dirb.add_argument("--dirb-threads", type=int, default=20, help="Threads per host for dir brute force (default 20)")
    dirb.add_argument("--dirb-status", default="200,204,301,302,307,401,403,500",
                       help="Comma-separated status codes worth reporting")
    dirb.add_argument("--dirb-delay", type=float, default=0.0, help="Delay in seconds before each dir request")

    args = ap.parse_args()

    if not HAVE_DNSPYTHON:
        print("[!] dnspython not installed — CNAME-chain visibility will be limited.")
        print("    pip install dnspython --break-system-packages\n")

    domain = args.domain.strip().lower()
    hits = {}
    sources_used = []

    if not args.skip_passive:
        active_sources, skipped = build_passive_sources(domain, args, args.verbose)
        print(f"[*] Passive sources active: {', '.join(sorted(active_sources)) or 'none'}")
        for s in skipped:
            print(f"[*] Skipping {s}")
        print(f"[*] Running passive enumeration against {domain} ...")
        hits = run_passive_enumeration(active_sources, args.verbose)
        sources_used = sorted(active_sources)
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
        print("[!] No candidates found. Try -b with a wordlist, or configure API keys for more sources.")
        sys.exit(1)

    total = len(hits)
    do_http = not args.no_http
    print(f"[*] Resolving{' + probing HTTP' if do_http else ''}"
          f"{' + checking takeover' if args.takeover else ''} for {total} candidates "
          f"using {args.threads} threads ...\n")

    results = []
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(process_host, sub, ",".join(sorted(srcs)), do_http, args.takeover, args.timeout, args.verbose): sub
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

    print(f"\n[+] Subdomain phase completed in {elapsed:.1f}s — {len(resolved)}/{total} resolved, "
          f"{len(vulnerable)} potential takeover(s).\n")

    print("=" * 88)
    print(f"{'SUBDOMAIN':<38}{'IP':<18}{'STATUS':<10}{'REDIRECT / FLAG'}")
    print("=" * 88)
    for r in sorted(resolved, key=lambda x: x.subdomain):
        ip = (r.ip_addresses[0] if r.ip_addresses else "-")
        tail = f"-> {r.redirect_location}" if r.redirect_location else ""
        if r.takeover_suspected:
            tail = (tail + "  " if tail else "") + c("⚠ POTENTIAL TAKEOVER", "31;1")
        print(f"{r.subdomain:<38}{ip:<18}{status_color(r.http_status):<10}{tail}")

    if vulnerable:
        print("\n" + "=" * 88)
        print(f"TAKEOVER CANDIDATES ({len(vulnerable)}) — verify manually before reporting")
        print("=" * 88)
        for r in vulnerable:
            print(f"\n  {r.subdomain}")
            print(f"    service : {r.takeover_service}")
            print(f"    cname   : {' -> '.join(r.cname_chain)}")
            print(f"    evidence: {r.takeover_evidence}")

    if args.dirb:
        if not os.path.exists(args.dirb_wordlist):
            print(f"\n[!] Dir wordlist not found: {args.dirb_wordlist} — skipping directory brute force.")
        else:
            targets = [r for r in resolved if r.scheme]
            paths = build_dirb_paths(args.dirb_wordlist, args.dirb_extensions)
            status_filter = parse_status_filter(args.dirb_status)
            print(f"\n[*] Directory brute-forcing {len(targets)} live host(s) with {len(paths)} paths each "
                  f"({args.dirb_threads} threads/host) ...")
            t1 = time.time()
            for i, r in enumerate(targets, 1):
                run_dirb(r, paths, args.dirb_threads, args.timeout, status_filter, args.dirb_delay, args.verbose)
                print(f"[*] [{i}/{len(targets)}] {r.subdomain}: {len(r.dirb_hits)} interesting path(s)", file=sys.stderr)
            print(f"[+] Directory brute force completed in {time.time() - t1:.1f}s\n")

            all_hits = [(r, h) for r in targets for h in r.dirb_hits]
            print("=" * 88)
            print(f"DIRECTORY BRUTE-FORCE HITS ({len(all_hits)})")
            print("=" * 88)
            if not all_hits:
                print("None found.")
            for r, h in all_hits:
                redirect = f" -> {h['redirect']}" if h["redirect"] else ""
                print(f"{r.subdomain}{h['path']:<40} {status_color(h['status'])}{redirect}")

    if args.output:
        fmt = args.format.lower()
        formats = {"json", "csv", "txt", "html"} if fmt == "all" else set(f.strip() for f in fmt.split(","))
        meta = {
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_subdomains": total,
            "alive_subdomains": len(resolved),
            "takeover_count": len(vulnerable),
            "sources_used": ", ".join(sources_used) if sources_used else "-",
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
