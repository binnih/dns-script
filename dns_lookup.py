#!/usr/bin/env python3
"""
dns_lookup.py - Comprehensive DNS record lookup tool

Usage:
  python3 dns_lookup.py example.com
  python3 dns_lookup.py example.com another.com
  python3 dns_lookup.py -f domains.txt
  python3 dns_lookup.py -f domains.txt -r A MX TXT
  python3 dns_lookup.py example.com --json
  python3 dns_lookup.py example.com --resolver 8.8.8.8
  python3 dns_lookup.py example.com --whois
  python3 dns_lookup.py example.com --mail-audit
  python3 dns_lookup.py example.com --axfr
  python3 dns_lookup.py example.com --http
  python3 dns_lookup.py example.com --ssl
  python3 dns_lookup.py example.com --rbl
  python3 dns_lookup.py example.com --cdn
  python3 dns_lookup.py example.com --mx-ports
  python3 dns_lookup.py example.com --subdomains
  python3 dns_lookup.py example.com --propagation
  python3 dns_lookup.py example.com --dns-timing
  python3 dns_lookup.py example.com --all-checks
  python3 dns_lookup.py example.com --output results.txt
"""

import sys
import argparse
import json
import socket
import re
import urllib.request
import urllib.error
import ssl
import time
import ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

# ── Dependency check ──────────────────────────────────────────────────────────

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    import dns.query
    import dns.zone
    import dns.flags
except ImportError:
    print("Missing dependency: dnspython")
    print("Install with: pip3 install dnspython")
    sys.exit(1)

WHOIS_AVAILABLE = False
try:
    import whois as pywhois
    WHOIS_AVAILABLE = True
except ImportError:
    pass

# ── Colors ────────────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

def no_color():
    for attr in vars(C):
        if not attr.startswith("_"):
            setattr(C, attr, "")

# ── Record types ──────────────────────────────────────────────────────────────

ALL_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR",
             "SRV", "CAA", "DNSKEY", "DS", "TLSA", "NAPTR", "SSHFP"]

DESCRIPTIONS = {
    "A":      "IPv4 address",
    "AAAA":   "IPv6 address",
    "MX":     "Mail exchange",
    "NS":     "Name servers",
    "TXT":    "Text / SPF / DKIM / DMARC",
    "CNAME":  "Canonical name alias",
    "SOA":    "Start of authority",
    "PTR":    "Reverse DNS pointer",
    "SRV":    "Service locator",
    "CAA":    "Cert Authority Authorization",
    "DNSKEY": "DNSSEC public key",
    "DS":     "DNSSEC delegation signer",
    "TLSA":   "TLS cert association (DANE)",
    "NAPTR":  "Naming auth pointer (VoIP)",
    "SSHFP":  "SSH fingerprint",
}

PROPAGATION_RESOLVERS = [
    ("Cloudflare",   "1.1.1.1"),
    ("Google",       "8.8.8.8"),
    ("Quad9",        "9.9.9.9"),
    ("OpenDNS",      "208.67.222.222"),
    ("Comodo",       "8.26.56.26"),
    ("Level3",       "209.244.0.3"),
]

# Common RBLs to check
RBL_LISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "pbl.spamhaus.org",
    "sbl.spamhaus.org",
    "xbl.spamhaus.org",
    "dnsbl-1.uceprotect.net",
    "db.wpbl.info",
    "ix.dnsbl.manitu.net",
]

# CDN/hosting fingerprints: (name, match_field, pattern)
CDN_SIGNATURES = [
    ("Cloudflare",      "ns",    r"\.cloudflare\.com$"),
    ("Cloudflare",      "a",     r"^(104\.|172\.6[4-9]\.|172\.7[0-9]\.|172\.8[0-9]\.|172\.9[0-9]\.|172\.1[0-1][0-9]\.|172\.12[0-7]\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.)"),
    ("AWS CloudFront",  "cname", r"\.cloudfront\.net$"),
    ("AWS CloudFront",  "a",     r"^(13\.32\.|13\.35\.|13\.249\.|52\.84\.|52\.85\.|54\.230\.|54\.239\.|64\.252\.|99\.84\.|205\.251\.)"),
    ("AWS",             "ns",    r"\.awsdns-"),
    ("Azure",           "ns",    r"\.azure-dns\."),
    ("Azure CDN",       "cname", r"\.(azureedge\.net|azurefd\.net)$"),
    ("Fastly",          "cname", r"\.fastly\.net$"),
    ("Fastly",          "a",     r"^(151\.101\.|199\.27\.|23\.235\.)"),
    ("Akamai",          "cname", r"\.(akamaiedge\.net|akamaicd\.net|akamai\.net|edgesuite\.net|edgekey\.net)$"),
    ("Google Cloud",    "ns",    r"\.googledomains\.com$"),
    ("Google Cloud",    "a",     r"^(34\.49\.|34\.50\.|34\.8[0-9]\.|34\.9[0-9]\.|34\.1[0-1][0-9]\.|34\.12[0-7]\.)"),
    ("Vercel",          "cname", r"\.vercel\.app$"),
    ("Netlify",         "cname", r"\.netlify\.app$"),
    ("GitHub Pages",    "cname", r"\.github\.io$"),
    ("Bunny CDN",       "cname", r"\.b-cdn\.net$"),
    ("StackPath",       "cname", r"\.stackpathcdn\.com$"),
    ("Sucuri",          "a",     r"^(192\.124\.249\.|185\.93\.228\.|66\.248\.200\.|208\.109\.)"),
]

# Common subdomains to probe
COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "pop3", "imap",
    "ftp", "sftp", "ssh", "vpn", "remote", "rdp",
    "api", "dev", "staging", "test", "beta", "demo",
    "admin", "portal", "dashboard", "panel", "cpanel", "whm", "plesk",
    "ns1", "ns2", "ns3", "ns4",
    "mx", "mx1", "mx2",
    "webmail", "autodiscover", "autoconfig",
    "shop", "store", "blog", "forum", "wiki",
    "git", "gitlab", "jenkins", "jira", "confluence",
    "monitor", "nagios", "grafana", "kibana",
    "cdn", "static", "assets", "media", "img",
    "app", "mobile", "m",
]

# ── Record formatting ─────────────────────────────────────────────────────────

def format_record(rtype, rdata):
    if rtype == "MX":
        return f"[prio {rdata.preference:>5}]  {rdata.exchange}"
    if rtype == "SOA":
        return (f"mname={rdata.mname}  rname={rdata.rname}  "
                f"serial={rdata.serial}  refresh={rdata.refresh}  "
                f"retry={rdata.retry}  expire={rdata.expire}  "
                f"minimum={rdata.minimum}")
    if rtype == "SRV":
        return f"[prio {rdata.priority} w {rdata.weight}]  {rdata.target}:{rdata.port}"
    if rtype == "CAA":
        return f"[flags {rdata.flags}]  {rdata.tag.decode()} = {rdata.value.decode()}"
    if rtype == "TXT":
        parts = [p.decode(errors="replace") if isinstance(p, bytes) else p
                 for p in rdata.strings]
        return " ".join(parts)
    return str(rdata)


def lookup(domain, rtype, resolver):
    answers = resolver.resolve(domain, rtype)
    return [(answers.rrset.ttl, format_record(rtype, r)) for r in answers]


# ── Pretty printer ────────────────────────────────────────────────────────────

def print_domain_header(domain, index=None, total=None):
    label = f"  {domain}  "
    if index is not None:
        label = f"  [{index}/{total}] {domain}  "
    width = max(len(label) + 4, 60)
    bar = "─" * width
    print(f"\n{C.BOLD}{C.CYAN}┌{bar}┐{C.RESET}")
    pad = width - len(label)
    lpad = pad // 2
    rpad = pad - lpad
    print(f"{C.BOLD}{C.CYAN}│{' ' * lpad}{C.WHITE}{label}{C.CYAN}{' ' * rpad}│{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}└{bar}┘{C.RESET}")


def print_section_header(title, color=None):
    color = color or C.YELLOW
    pad = max(1, 50 - len(title))
    print(f"\n  {C.BOLD}{color}── {title} {'─' * pad}{C.RESET}")


def print_section(rtype, records):
    desc = DESCRIPTIONS.get(rtype, "")
    print(f"\n  {C.BOLD}{C.YELLOW}{rtype:<8}{C.DIM}{C.WHITE}  {desc}{C.RESET}")
    print(f"  {C.DIM}{'─' * 56}{C.RESET}")
    for ttl, val in records:
        ttl_str = f"{C.DIM}[TTL {ttl:>6}]{C.RESET}"
        print(f"  {ttl_str}  {C.GREEN}{val}{C.RESET}")


def print_no_record(rtype):
    desc = DESCRIPTIONS.get(rtype, "")
    print(f"\n  {C.DIM}{rtype:<8}  {desc}  —  no record{C.RESET}")


def print_error(rtype, err):
    print(f"\n  {C.RED}{rtype:<8}  ERROR: {err}{C.RESET}")


def ok(msg):   return f"{C.GREEN}✔  {msg}{C.RESET}"
def warn(msg): return f"{C.YELLOW}⚠  {msg}{C.RESET}"
def fail(msg): return f"{C.RED}✘  {msg}{C.RESET}"
def info(msg): return f"{C.BLUE}ℹ  {msg}{C.RESET}"


# ── Core DNS lookup ───────────────────────────────────────────────────────────

def query_domain(domain, types, resolver):
    results = {}
    for rtype in types:
        try:
            records = lookup(domain, rtype, resolver)
            results[rtype] = {"status": "ok", "records": records}
        except dns.resolver.NXDOMAIN:
            results[rtype] = {"status": "nxdomain"}
        except dns.resolver.NoAnswer:
            results[rtype] = {"status": "noanswer"}
        except dns.resolver.NoNameservers:
            results[rtype] = {"status": "error", "msg": "No nameservers available"}
        except dns.exception.Timeout:
            results[rtype] = {"status": "error", "msg": "Query timed out"}
        except Exception as e:
            results[rtype] = {"status": "error", "msg": str(e)}
    return results


def display_results(domain, results, hide_empty=False):
    for rtype, data in results.items():
        status = data["status"]
        if status == "ok":
            print_section(rtype, data["records"])
        elif status == "noanswer":
            if not hide_empty:
                print_no_record(rtype)
        elif status == "nxdomain":
            print(f"\n  {C.RED}NXDOMAIN — domain does not exist{C.RESET}")
            break
        else:
            print_error(rtype, data.get("msg", "unknown error"))


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def do_whois(domain):
    print_section_header("WHOIS", C.MAGENTA)
    if not WHOIS_AVAILABLE:
        print(f"  {warn('python-whois not installed — run: pip3 install python-whois')}")
        return
    try:
        w = pywhois.whois(domain)

        def fmt_date(d):
            if d is None: return "—"
            if isinstance(d, list): d = d[0]
            return d.strftime("%Y-%m-%d") if hasattr(d, "strftime") else str(d)

        registrar   = w.registrar or "—"
        created     = fmt_date(w.creation_date)
        updated     = fmt_date(w.updated_date)
        expires     = fmt_date(w.expiration_date)
        status      = w.status or "—"
        nameservers = w.name_servers or []

        exp_color = C.GREEN
        try:
            exp_dt = w.expiration_date
            if isinstance(exp_dt, list): exp_dt = exp_dt[0]
            days_left = (exp_dt - datetime.now()).days
            if days_left < 30:   exp_color = C.RED
            elif days_left < 90: exp_color = C.YELLOW
            expires = f"{expires}  ({days_left} days)"
        except Exception:
            pass

        print(f"  {C.DIM}Registrar   :{C.RESET}  {registrar}")
        print(f"  {C.DIM}Created     :{C.RESET}  {created}")
        print(f"  {C.DIM}Updated     :{C.RESET}  {updated}")
        print(f"  {C.DIM}Expires     :{C.RESET}  {exp_color}{expires}{C.RESET}")
        statuses = status if isinstance(status, list) else [status]
        for s in statuses[:3]:
            print(f"  {C.DIM}Status      :{C.RESET}  {s}")
        for ns in sorted(set(str(n).lower() for n in nameservers)):
            print(f"  {C.DIM}Nameserver  :{C.RESET}  {ns}")
    except Exception as e:
        print(f"  {fail(f'WHOIS failed: {e}')}")


# ── Mail audit: SPF / DKIM / DMARC ───────────────────────────────────────────

def parse_spf(txt):
    findings = []
    if "+all" in txt:
        findings.append(("fail", "'+all' allows ANY server to send — no SPF protection"))
    elif "~all" in txt:
        findings.append(("warn", "'~all' softfail — servers may still accept spoofed mail"))
    elif "-all" in txt:
        findings.append(("ok",   "'-all' hard fail — only listed servers may send"))
    elif "?all" in txt:
        findings.append(("warn", "'?all' neutral — no guidance, treat as no SPF"))
    else:
        findings.append(("warn", "No 'all' mechanism — incomplete SPF record"))

    for inc in re.findall(r"include:(\S+)", txt):
        findings.append(("info", f"Includes: {inc}"))
    for r in re.findall(r"redirect=(\S+)", txt):
        findings.append(("info", f"Redirects to: {r}"))

    lc = len(re.findall(r"\b(include|a|mx|ptr|exists|redirect)[:=]", txt))
    if lc > 10:
        findings.append(("warn", f"~{lc} DNS lookups — SPF limit is 10, may cause PermError"))
    return findings


def parse_dmarc(txt):
    findings = []
    p = re.search(r"\bp=(\w+)", txt)
    policy = p.group(1).lower() if p else None
    if policy == "none":
        findings.append(("warn", "p=none — monitoring only, no enforcement"))
    elif policy == "quarantine":
        findings.append(("ok",   "p=quarantine — failing mail goes to spam"))
    elif policy == "reject":
        findings.append(("ok",   "p=reject — failing mail is rejected"))
    else:
        findings.append(("warn", f"Unknown or missing policy: {policy}"))

    sp = re.search(r"\bsp=(\w+)", txt)
    if sp:
        findings.append(("info", f"Subdomain policy: sp={sp.group(1)}"))

    pct = re.search(r"\bpct=(\d+)", txt)
    if pct and int(pct.group(1)) < 100:
        findings.append(("warn", f"pct={pct.group(1)} — policy only applied to {pct.group(1)}% of mail"))

    rua = re.search(r"\brua=([^\s;]+)", txt)
    if rua:
        findings.append(("info", f"Aggregate reports → {rua.group(1)}"))
    else:
        findings.append(("warn", "No rua= tag — not receiving aggregate reports"))
    return findings


def check_dkim(domain, resolver, extra_selectors=None):
    selectors = [
        "default", "google", "k1", "k2", "mail", "mx",
        "selector1", "selector2", "dkim", "smtp", "email",
        "proofpoint", "mimecast", "s1", "s2",
    ]
    if extra_selectors:
        selectors = list(extra_selectors) + [s for s in selectors if s not in extra_selectors]

    found = []
    for sel in selectors:
        qname = f"{sel}._domainkey.{domain}"
        try:
            answers = resolver.resolve(qname, "TXT")
            for r in answers:
                txt = " ".join(p.decode(errors="replace") if isinstance(p, bytes) else p
                               for p in r.strings)
                if "v=DKIM1" in txt or "p=" in txt:
                    found.append((sel, txt))
        except Exception:
            pass
    return found


def do_mail_audit(domain, resolver, dkim_selector=None):
    print_section_header("MAIL AUDIT  (SPF / DKIM / DMARC)", C.MAGENTA)

    # SPF
    print(f"\n  {C.BOLD}SPF{C.RESET}")
    spf_records = []
    try:
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            txt = " ".join(p.decode(errors="replace") if isinstance(p, bytes) else p
                           for p in r.strings)
            if txt.startswith("v=spf1"):
                spf_records.append(txt)
    except Exception:
        pass

    if not spf_records:
        print(f"  {fail('No SPF record found')}")
    elif len(spf_records) > 1:
        print(f"  {fail(f'{len(spf_records)} SPF records found — must be exactly one')}")
        for r in spf_records:
            print(f"  {C.DIM}  {r}{C.RESET}")
    else:
        print(f"  {C.DIM}  {spf_records[0]}{C.RESET}")
        for level, msg in parse_spf(spf_records[0]):
            if level == "ok":     print(f"  {ok(msg)}")
            elif level == "warn": print(f"  {warn(msg)}")
            elif level == "fail": print(f"  {fail(msg)}")
            else:                 print(f"  {info(msg)}")

    # Mail deliverability score
    spf_score  = 1 if len(spf_records) == 1 and any(l == "ok"   for l, _ in (parse_spf(spf_records[0]) if spf_records else [])) else 0
    dmarc_score = 0
    dkim_score  = 0

    # DMARC
    print(f"\n  {C.BOLD}DMARC{C.RESET}")
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = " ".join(p.decode(errors="replace") if isinstance(p, bytes) else p
                           for p in r.strings)
            if "DMARC1" in txt:
                print(f"  {C.DIM}  {txt}{C.RESET}")
                findings = parse_dmarc(txt)
                for level, msg in findings:
                    if level == "ok":     print(f"  {ok(msg)}")
                    elif level == "warn": print(f"  {warn(msg)}")
                    elif level == "fail": print(f"  {fail(msg)}")
                    else:                 print(f"  {info(msg)}")
                if any(l == "ok" for l, _ in findings):
                    dmarc_score = 1
    except dns.resolver.NXDOMAIN:
        print(f"  {fail('No DMARC record (_dmarc.' + domain + ' NXDOMAIN)')}")
    except dns.resolver.NoAnswer:
        print(f"  {fail('No DMARC record found')}")
    except Exception as e:
        print(f"  {fail(f'DMARC lookup failed: {e}')}")

    # DKIM
    print(f"\n  {C.BOLD}DKIM  (common selectors){C.RESET}")
    extra = [dkim_selector] if dkim_selector else None
    dkim_found = check_dkim(domain, resolver, extra_selectors=extra)
    if not dkim_found:
        print(f"  {warn('No DKIM records found for common selectors')}")
        print(f"  {C.DIM}  Use --dkim-selector SELECTOR to check a specific one{C.RESET}")
    else:
        dkim_score = 1
        for sel, txt in dkim_found:
            display = txt if len(txt) < 100 else txt[:97] + "..."
            print(f"  {ok(f'selector={sel}')}")
            print(f"  {C.DIM}  {display}{C.RESET}")

    # Deliverability score
    score = spf_score + dmarc_score + dkim_score
    score_colors = [C.RED, C.RED, C.YELLOW, C.GREEN]
    labels       = ["Poor", "Weak", "Fair", "Good"]
    sc = score_colors[score]
    lb = labels[score]
    print(f"\n  {C.BOLD}Deliverability score:{C.RESET}  {sc}{C.BOLD}{score}/3  {lb}{C.RESET}")


# ── Zone transfer (AXFR) ──────────────────────────────────────────────────────

def do_axfr(domain, resolver):
    print_section_header("ZONE TRANSFER (AXFR)", C.MAGENTA)
    ns_list = []
    try:
        answers = resolver.resolve(domain, "NS")
        ns_list = [str(r.target).rstrip(".") for r in answers]
    except Exception as e:
        print(f"  {fail(f'Could not get NS records: {e}')}")
        return

    if not ns_list:
        print(f"  {fail('No NS records found')}")
        return

    any_success = False
    for ns in ns_list:
        try:
            ns_ip = socket.gethostbyname(ns)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            print(f"  {C.RED}{C.BOLD}✘ ZONE TRANSFER SUCCEEDED on {ns} — security risk!{C.RESET}")
            names = sorted(z.nodes.keys())
            for name in names[:50]:
                node = z[name]
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        print(f"  {C.YELLOW}  {name}.{domain}.  {rdataset.ttl}  {rdataset.rdtype}  {rdata}{C.RESET}")
            if len(names) > 50:
                print(f"  {C.DIM}  ... and {len(names) - 50} more records{C.RESET}")
            any_success = True
        except dns.exception.FormError:
            print(f"  {ok(f'AXFR refused by {ns}')}")
        except Exception as e:
            err = str(e)
            if "refused" in err.lower():
                print(f"  {ok(f'AXFR refused by {ns}')}")
            else:
                print(f"  {info(f'{ns}: {err}')}")

    if not any_success:
        print(f"  {ok('Zone transfer blocked on all nameservers — good')}")


# ── HTTP / HTTPS check ────────────────────────────────────────────────────────

def http_check_one(url, timeout=8):
    chain = []
    current = url
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for _ in range(10):
        try:
            req = urllib.request.Request(
                current,
                headers={"User-Agent": "dns-lookup-tool/1.0"},
                method="HEAD"
            )
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx),
                NoRedirect()
            )
            try:
                resp = opener.open(req, timeout=timeout)
                chain.append((current, resp.status))
                return current, resp.status, chain, None
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    location = e.headers.get("Location", "")
                    chain.append((current, e.code))
                    if not location:
                        return current, e.code, chain, None
                    if location.startswith("/"):
                        from urllib.parse import urlparse
                        p = urlparse(current)
                        location = f"{p.scheme}://{p.netloc}{location}"
                    current = location
                    continue
                chain.append((current, e.code))
                return current, e.code, chain, None
        except urllib.error.URLError as e:
            return current, None, chain, str(e.reason)
        except Exception as e:
            return current, None, chain, str(e)
    return current, None, chain, "Too many redirects"


def status_color(code):
    if code is None:      return C.RED
    if 200 <= code < 300: return C.GREEN
    if 300 <= code < 400: return C.YELLOW
    if code >= 400:       return C.RED
    return C.WHITE


def do_http_check(domain):
    print_section_header("HTTP / HTTPS", C.MAGENTA)
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        final, code, chain, err = http_check_one(url)

        if err and not chain:
            print(f"  {fail(f'{scheme.upper()}  {err}')}")
            continue

        for i, (u, c) in enumerate(chain):
            sc = status_color(c)
            arrow = "→ " if i < len(chain) - 1 else "  "
            print(f"  {sc}{c}{C.RESET}  {arrow}{C.DIM}{u}{C.RESET}")

        if err:
            print(f"  {fail(err)}")
        else:
            sc = status_color(code)
            label = "Live" if code and 200 <= code < 400 else "Problem"
            print(f"  {sc}{C.BOLD}{label}{C.RESET}  final={sc}{code}{C.RESET}  {C.DIM}{final}{C.RESET}")


# ── SSL / TLS certificate check ───────────────────────────────────────────────

def do_ssl_check(domain, timeout=8):
    print_section_header("SSL / TLS CERTIFICATE", C.MAGENTA)
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=timeout),
            server_hostname=domain
        )
        cert = conn.getpeercert()
        conn.close()

        subject   = dict(x[0] for x in cert.get("subject", []))
        issuer    = dict(x[0] for x in cert.get("issuer", []))
        not_before = cert.get("notBefore", "")
        not_after  = cert.get("notAfter",  "")
        sans       = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        protocol   = conn.version() if hasattr(conn, "version") else "unknown"

        cn       = subject.get("commonName", "—")
        issuer_o = issuer.get("organizationName", issuer.get("commonName", "—"))

        # Parse expiry
        exp_color = C.GREEN
        days_left = None
        try:
            exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_dt.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            if days_left < 14:   exp_color = C.RED
            elif days_left < 30: exp_color = C.YELLOW
        except Exception:
            pass

        # Check domain match
        domain_match = any(
            re.fullmatch(re.escape(s).replace(r"\*", "[^.]+"), domain)
            for s in sans
        ) or cn == domain or cn.startswith("*.") and domain.endswith(cn[1:])

        print(f"  {C.DIM}Common Name :{C.RESET}  {cn}")
        print(f"  {C.DIM}Issuer      :{C.RESET}  {issuer_o}")
        print(f"  {C.DIM}Valid from  :{C.RESET}  {not_before}")
        exp_str = not_after
        if days_left is not None:
            exp_str = f"{not_after}  ({days_left} days)"
        print(f"  {C.DIM}Expires     :{C.RESET}  {exp_color}{exp_str}{C.RESET}")
        print(f"  {C.DIM}SANs        :{C.RESET}  {', '.join(sans[:10])}{'...' if len(sans) > 10 else ''}")

        if domain_match:
            print(f"  {ok(f'Certificate matches {domain}')}")
        else:
            print(f"  {fail(f'Certificate does NOT match {domain}')}")

        # Self-signed check
        if subject == issuer:
            print(f"  {warn('Self-signed certificate')}")
        else:
            print(f"  {ok(f'Signed by: {issuer_o}')}")

    except ssl.SSLCertVerificationError as e:
        print(f"  {fail(f'Certificate verification failed: {e}')}")
    except ConnectionRefusedError:
        print(f"  {fail('Port 443 refused — no HTTPS listener')}")
    except socket.timeout:
        print(f"  {fail('Connection timed out')}")
    except Exception as e:
        print(f"  {fail(f'SSL check failed: {e}')}")


# ── RBL / blacklist check ─────────────────────────────────────────────────────

def rbl_check_one(ip_rev, rbl):
    query = f"{ip_rev}.{rbl}"
    try:
        dns.resolver.resolve(query, "A")
        return rbl, True, None
    except dns.resolver.NXDOMAIN:
        return rbl, False, None
    except Exception as e:
        return rbl, None, str(e)


def do_rbl_check(domain, resolver):
    print_section_header("BLACKLIST / RBL CHECK", C.MAGENTA)

    # Collect IPs from A records
    ips = []
    try:
        answers = resolver.resolve(domain, "A")
        ips = [str(r) for r in answers]
    except Exception:
        pass

    if not ips:
        print(f"  {warn('No A records found — cannot check RBL')}")
        return

    for ip in ips:
        print(f"\n  {C.BOLD}IP: {ip}{C.RESET}")
        try:
            rev = ".".join(reversed(ip.split(".")))
        except Exception:
            print(f"  {fail('Could not reverse IP')}")
            continue

        listed_on = []
        errors    = []
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(rbl_check_one, rev, rbl): rbl for rbl in RBL_LISTS}
            for fut in as_completed(futures):
                rbl, listed, err = fut.result()
                if listed:
                    listed_on.append(rbl)
                elif err:
                    errors.append((rbl, err))

        if not listed_on:
            print(f"  {ok(f'Clean on all {len(RBL_LISTS)} checked blacklists')}")
        else:
            for rbl in sorted(listed_on):
                print(f"  {fail(f'LISTED on {rbl}')}")
            print(f"  {C.DIM}  {len(RBL_LISTS) - len(listed_on)} lists clean{C.RESET}")

        if errors:
            print(f"  {C.DIM}  {len(errors)} lists could not be checked (timeout/error){C.RESET}")


# ── CDN / hosting detection ───────────────────────────────────────────────────

def do_cdn_detect(domain, resolver):
    print_section_header("CDN / HOSTING DETECTION", C.MAGENTA)

    detected = set()

    # Gather NS, A, CNAME values
    ns_vals, a_vals, cname_vals = [], [], []
    for rtype, store in [("NS", ns_vals), ("A", a_vals), ("CNAME", cname_vals)]:
        try:
            answers = resolver.resolve(domain, rtype)
            for r in answers:
                store.append(str(r).rstrip(".").lower())
        except Exception:
            pass

    field_map = {"ns": ns_vals, "a": a_vals, "cname": cname_vals}

    for name, field, pattern in CDN_SIGNATURES:
        values = field_map.get(field, [])
        for val in values:
            if re.search(pattern, val, re.IGNORECASE):
                detected.add(name)

    if detected:
        for name in sorted(detected):
            print(f"  {ok(name)}")
    else:
        print(f"  {info('No known CDN/hosting provider detected')}")
        if a_vals:
            print(f"  {C.DIM}  A record(s): {', '.join(a_vals[:4])}{C.RESET}")


# ── MX port reachability ──────────────────────────────────────────────────────

def check_port(host, port, timeout=5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def do_mx_ports(domain, resolver):
    print_section_header("MX REACHABILITY", C.MAGENTA)

    mx_hosts = []
    try:
        answers = resolver.resolve(domain, "MX")
        mx_hosts = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers])
    except Exception as e:
        print(f"  {fail(f'Could not get MX records: {e}')}")
        return

    if not mx_hosts:
        print(f"  {fail('No MX records found')}")
        return

    ports = [25, 465, 587]
    port_labels = {25: "SMTP", 465: "SMTPS", 587: "Submission"}

    for prio, host in mx_hosts:
        print(f"\n  {C.BOLD}[prio {prio:>5}]  {host}{C.RESET}")
        try:
            ip = socket.gethostbyname(host)
            print(f"  {C.DIM}  resolves to {ip}{C.RESET}")
        except Exception:
            print(f"  {warn(f'  Could not resolve {host}')}")
            continue

        for port in ports:
            open_ = check_port(host, port)
            label = port_labels.get(port, str(port))
            if open_:
                print(f"  {ok(f'Port {port:<4} ({label}) open')}")
            else:
                print(f"  {C.DIM}✘  Port {port:<4} ({label}) closed/filtered{C.RESET}")


# ── Subdomain probe ───────────────────────────────────────────────────────────

def probe_subdomain(sub, domain, timeout):
    fqdn = f"{sub}.{domain}"
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            answers = r.resolve(fqdn, rtype)
            vals = [str(a) for a in answers]
            return sub, fqdn, rtype, vals
        except Exception:
            pass
    return sub, fqdn, None, []


def do_subdomain_check(domain, timeout=5.0, extra=None):
    print_section_header("SUBDOMAIN PROBE", C.MAGENTA)

    subs = list(COMMON_SUBDOMAINS)
    if extra:
        subs = list(extra) + [s for s in subs if s not in extra]

    found = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(probe_subdomain, sub, domain, timeout): sub for sub in subs}
        for fut in as_completed(futures):
            sub, fqdn, rtype, vals = fut.result()
            if rtype:
                found.append((sub, fqdn, rtype, vals))

    if not found:
        print(f"  {info('No common subdomains found')}")
        return

    found.sort(key=lambda x: x[0])
    print(f"  {C.DIM}Found {len(found)} subdomain(s):{C.RESET}")
    for sub, fqdn, rtype, vals in found:
        val_str = ", ".join(vals[:3])
        if len(vals) > 3: val_str += "..."
        print(f"  {C.GREEN}{fqdn:<40}{C.RESET}  {C.DIM}{rtype}  {val_str}{C.RESET}")


# ── DNS timing ────────────────────────────────────────────────────────────────

def time_query(label, ns_ip, domain, rtype, timeout):
    r = dns.resolver.Resolver()
    r.nameservers = [ns_ip]
    r.lifetime = timeout
    start = time.monotonic()
    try:
        r.resolve(domain, rtype)
        ms = (time.monotonic() - start) * 1000
        return label, ms, None
    except Exception as e:
        ms = (time.monotonic() - start) * 1000
        return label, ms, str(e)


def bar(ms, max_ms=500, width=20):
    filled = int(min(ms / max_ms, 1.0) * width)
    b = "█" * filled + "░" * (width - filled)
    if ms < 100:  color = C.GREEN
    elif ms < 250: color = C.YELLOW
    else:          color = C.RED
    return f"{color}{b}{C.RESET}"


def do_dns_timing(domain, timeout=5.0):
    print_section_header("DNS TIMING", C.MAGENTA)

    resolvers = list(PROPAGATION_RESOLVERS)

    # Add authoritative NS
    try:
        sys_r = dns.resolver.Resolver()
        sys_r.lifetime = timeout
        ns_answers = sys_r.resolve(domain, "NS")
        for r in ns_answers:
            ns_host = str(r.target).rstrip(".")
            try:
                ns_ip = socket.gethostbyname(ns_host)
                short = ns_host.split(".")[0]
                resolvers.append((f"Auth:{short}", ns_ip))
            except Exception:
                pass
    except Exception:
        pass

    results = {}
    with ThreadPoolExecutor(max_workers=len(resolvers)) as ex:
        futures = {
            ex.submit(time_query, label, ip, domain, "A", timeout): label
            for label, ip in resolvers
        }
        for fut in as_completed(futures):
            label, ms, err = fut.result()
            results[label] = (ms, err)

    print(f"  {C.DIM}Query type: A  |  bar scale: 0–500ms{C.RESET}\n")
    for label, ip in resolvers:
        ms, err = results.get(label, (0, "no result"))
        label_str = f"{label:<22}"
        if err and "NXDOMAIN" not in err and "NoAnswer" not in err:
            print(f"  {C.DIM}{label_str}  ERROR: {err}{C.RESET}")
        else:
            b = bar(ms)
            ms_str = f"{ms:>6.1f} ms"
            col = C.GREEN if ms < 100 else (C.YELLOW if ms < 250 else C.RED)
            print(f"  {C.DIM}{label_str}{C.RESET}  {b}  {col}{ms_str}{C.RESET}")


# ── Propagation check ─────────────────────────────────────────────────────────

def propagation_query(label, ns_ip, domain, rtype, timeout):
    r = dns.resolver.Resolver()
    r.nameservers = [ns_ip]
    r.lifetime = timeout
    try:
        answers = r.resolve(domain, rtype)
        vals = sorted(set(format_record(rtype, rd) for rd in answers))
        return label, vals, None
    except dns.resolver.NXDOMAIN:
        return label, [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return label, [], "NOANSWER"
    except dns.exception.Timeout:
        return label, [], "TIMEOUT"
    except Exception as e:
        return label, [], str(e)


def do_propagation(domain, types, timeout=5.0):
    print_section_header("PROPAGATION CHECK", C.MAGENTA)

    resolvers = list(PROPAGATION_RESOLVERS)

    try:
        sys_r = dns.resolver.Resolver()
        sys_r.lifetime = timeout
        ns_answers = sys_r.resolve(domain, "NS")
        for r in ns_answers:
            ns_host = str(r.target).rstrip(".")
            try:
                ns_ip = socket.gethostbyname(ns_host)
                short = ns_host.split(".")[0]
                resolvers.append((f"Auth:{short}", ns_ip))
            except Exception:
                pass
    except Exception:
        pass

    check_types = types if types != ALL_TYPES else ["A", "AAAA", "MX", "NS"]

    for rtype in check_types:
        print(f"\n  {C.BOLD}{C.YELLOW}{rtype}{C.RESET}  {C.DIM}{DESCRIPTIONS.get(rtype, '')}{C.RESET}")
        print(f"  {C.DIM}{'─' * 56}{C.RESET}")

        results = {}
        with ThreadPoolExecutor(max_workers=len(resolvers)) as ex:
            futures = {
                ex.submit(propagation_query, label, ip, domain, rtype, timeout): label
                for label, ip in resolvers
            }
            for fut in as_completed(futures):
                label, vals, err = fut.result()
                results[label] = (vals, err)

        answer_strs = [
            tuple(sorted(v)) for v, e in results.values() if e is None and v
        ]
        consensus_vals = set(Counter(answer_strs).most_common(1)[0][0]) if answer_strs else set()

        for label, ip in resolvers:
            vals, err = results.get(label, ([], "no result"))
            label_str = f"{label:<22}"
            if err:
                color = C.RED if err not in ("NOANSWER",) else C.DIM
                print(f"  {C.DIM}{label_str}{C.RESET}  {color}{err}{C.RESET}")
            else:
                match = set(vals) == consensus_vals
                indicator = f"{C.GREEN}✔{C.RESET}" if match else f"{C.RED}✘{C.RESET}"
                val_str = ", ".join(vals) if vals else "—"
                if len(val_str) > 70: val_str = val_str[:67] + "..."
                col = C.GREEN if match else C.RED
                print(f"  {C.DIM}{label_str}{C.RESET}  {indicator}  {col}{val_str}{C.RESET}")

        if consensus_vals:
            cs = ", ".join(sorted(consensus_vals))
            if len(cs) > 100: cs = cs[:97] + "..."
            print(f"  {C.DIM}  consensus: {cs}{C.RESET}")


# ── JSON output ───────────────────────────────────────────────────────────────

def to_json(all_results):
    out = {}
    for domain, results in all_results.items():
        out[domain] = {}
        for rtype, data in results.items():
            if data["status"] == "ok":
                out[domain][rtype] = [
                    {"ttl": ttl, "value": val} for ttl, val in data["records"]
                ]
            else:
                out[domain][rtype] = {"error": data["status"], "msg": data.get("msg", "")}
    return json.dumps(out, indent=2)


# ── Resolver builder ──────────────────────────────────────────────────────────

def build_resolver(nameserver=None, timeout=5.0):
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    if nameserver:
        try:
            socket.inet_aton(nameserver)
            resolved_ip = nameserver
        except socket.error:
            try:
                resolved_ip = socket.gethostbyname(nameserver)
            except socket.gaierror as e:
                print(f"{C.RED}Error: could not resolve resolver hostname '{nameserver}': {e}{C.RESET}")
                sys.exit(1)
        r.nameservers = [resolved_ip]
    return r


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Comprehensive DNS lookup tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  dns_lookup.py example.com
  dns_lookup.py example.com -r A MX TXT
  dns_lookup.py -f domains.txt
  dns_lookup.py example.com --whois
  dns_lookup.py example.com --mail-audit
  dns_lookup.py example.com --mail-audit --dkim-selector selector1
  dns_lookup.py example.com --axfr
  dns_lookup.py example.com --http
  dns_lookup.py example.com --ssl
  dns_lookup.py example.com --rbl
  dns_lookup.py example.com --cdn
  dns_lookup.py example.com --mx-ports
  dns_lookup.py example.com --subdomains
  dns_lookup.py example.com --dns-timing
  dns_lookup.py example.com --propagation -r A MX
  dns_lookup.py example.com --all-checks
  dns_lookup.py example.com --all-checks --output report.txt
""")
    p.add_argument("domains",          nargs="*", help="One or more domain names")
    p.add_argument("-f", "--file",     help="Text file with one domain per line")
    p.add_argument("-r", "--records",  nargs="+", metavar="TYPE", default=ALL_TYPES,
                   help=f"Record types to query (default: all)\nAvailable: {' '.join(ALL_TYPES)}")
    p.add_argument("--resolver",       help="DNS resolver IP or hostname (default: system)")
    p.add_argument("--timeout",        type=float, default=5.0,
                   help="Query timeout in seconds (default: 5)")
    p.add_argument("--hide-empty",     action="store_true",
                   help="Don't show record types with no data")
    p.add_argument("--no-color",       action="store_true", help="Disable color output")
    p.add_argument("--json",           action="store_true", help="Output DNS records as JSON")
    p.add_argument("--output",         metavar="FILE",
                   help="Save output to file (in addition to stdout)")

    p.add_argument("--whois",          action="store_true",
                   help="Show WHOIS info (requires: pip3 install python-whois)")
    p.add_argument("--mail-audit",     action="store_true",
                   help="Analyse SPF, DKIM, DMARC + deliverability score")
    p.add_argument("--dkim-selector",  help="Extra DKIM selector to check")
    p.add_argument("--axfr",           action="store_true",
                   help="Attempt zone transfer on all NS")
    p.add_argument("--http",           action="store_true",
                   help="Check HTTP/HTTPS reachability and follow redirects")
    p.add_argument("--ssl",            action="store_true",
                   help="Check SSL/TLS certificate (expiry, issuer, SANs, match)")
    p.add_argument("--rbl",            action="store_true",
                   help=f"Check IPs against {len(RBL_LISTS)} spam blacklists")
    p.add_argument("--cdn",            action="store_true",
                   help="Detect CDN or hosting provider from NS/A/CNAME records")
    p.add_argument("--mx-ports",       action="store_true",
                   help="Check MX hosts for open ports 25/465/587")
    p.add_argument("--subdomains",     action="store_true",
                   help=f"Probe {len(COMMON_SUBDOMAINS)} common subdomains for A/AAAA/CNAME")
    p.add_argument("--dns-timing",     action="store_true",
                   help="Measure query response time across public resolvers + auth NS")
    p.add_argument("--propagation",    action="store_true",
                   help="Check propagation across public resolvers + authoritative NS")
    p.add_argument("--all-checks",     action="store_true",
                   help="Run all checks")
    return p.parse_args()


def load_domains_from_file(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        print(f"{C.RED}Error: file not found: {path}{C.RESET}")
        sys.exit(1)


class Tee:
    """Write to both stdout and a file."""
    def __init__(self, filepath):
        self.terminal = sys.stdout
        self.logfile  = open(filepath, "w", encoding="utf-8")

    def write(self, msg):
        self.terminal.write(msg)
        # Strip ANSI codes for file output
        clean = re.sub(r"\033\[[0-9;]*m", "", msg)
        self.logfile.write(clean)

    def flush(self):
        self.terminal.flush()
        self.logfile.flush()

    def close(self):
        self.logfile.close()


def main():
    args = parse_args()

    if args.no_color:
        no_color()

    tee = None
    if args.output:
        tee = Tee(args.output)
        sys.stdout = tee

    domains = list(args.domains)
    if args.file:
        domains += load_domains_from_file(args.file)

    if not domains:
        print(f"{C.RED}Error: provide at least one domain or use -f <file>{C.RESET}")
        sys.exit(1)

    types = [t.upper() for t in args.records]
    invalid = [t for t in types if t not in ALL_TYPES]
    if invalid:
        print(f"{C.YELLOW}Warning: unknown record types ignored: {', '.join(invalid)}{C.RESET}")
        types = [t for t in types if t in ALL_TYPES]

    resolver = build_resolver(args.resolver, args.timeout)

    run_whois       = args.whois       or args.all_checks
    run_mail_audit  = args.mail_audit  or args.all_checks
    run_axfr        = args.axfr        or args.all_checks
    run_http        = args.http        or args.all_checks
    run_ssl         = args.ssl         or args.all_checks
    run_rbl         = args.rbl         or args.all_checks
    run_cdn         = args.cdn         or args.all_checks
    run_mx_ports    = args.mx_ports    or args.all_checks
    run_subdomains  = args.subdomains  or args.all_checks
    run_dns_timing  = args.dns_timing  or args.all_checks
    run_propagation = args.propagation or args.all_checks

    if not args.json:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ns = args.resolver or "system"
        print(f"\n{C.BOLD}{C.WHITE}DNS Lookup  {C.DIM}{ts}  resolver={ns}{C.RESET}")
        print(f"{C.DIM}Querying {len(domains)} domain(s) for: {', '.join(types)}{C.RESET}")
        if args.output:
            print(f"{C.DIM}Saving output to: {args.output}{C.RESET}")

    all_results = {}
    total = len(domains)

    for i, domain in enumerate(domains, 1):
        domain = domain.lower().rstrip(".")

        if not args.json:
            print_domain_header(domain, i, total)

        results = query_domain(domain, types, resolver)
        all_results[domain] = results

        if not args.json:
            display_results(domain, results, hide_empty=args.hide_empty)

            if run_whois:       do_whois(domain)
            if run_mail_audit:  do_mail_audit(domain, resolver, dkim_selector=args.dkim_selector)
            if run_axfr:        do_axfr(domain, resolver)
            if run_http:        do_http_check(domain)
            if run_ssl:         do_ssl_check(domain, timeout=args.timeout)
            if run_rbl:         do_rbl_check(domain, resolver)
            if run_cdn:         do_cdn_detect(domain, resolver)
            if run_mx_ports:    do_mx_ports(domain, resolver)
            if run_subdomains:  do_subdomain_check(domain, timeout=args.timeout)
            if run_dns_timing:  do_dns_timing(domain, timeout=args.timeout)
            if run_propagation: do_propagation(domain, types, timeout=args.timeout)

    if args.json:
        print(to_json(all_results))
    else:
        print(f"\n{C.DIM}Done. {total} domain(s) queried.{C.RESET}\n")

    if tee:
        sys.stdout = tee.terminal
        tee.close()
        print(f"{C.DIM}Output saved to: {args.output}{C.RESET}")


if __name__ == "__main__":
    main()#!/usr/bin/env python3
"""
dns_lookup.py - Comprehensive DNS record lookup tool

Usage:
  python3 dns_lookup.py example.com
  python3 dns_lookup.py example.com another.com
  python3 dns_lookup.py -f domains.txt
  python3 dns_lookup.py -f domains.txt -r A MX TXT
  python3 dns_lookup.py example.com --json
  python3 dns_lookup.py example.com --resolver 8.8.8.8
  python3 dns_lookup.py example.com --whois
  python3 dns_lookup.py example.com --mail-audit
  python3 dns_lookup.py example.com --axfr
  python3 dns_lookup.py example.com --http
  python3 dns_lookup.py example.com --propagation
  python3 dns_lookup.py example.com --propagation -r A MX
  python3 dns_lookup.py example.com --all-checks
"""

import sys
import argparse
import json
import socket
import re
import urllib.request
import urllib.error
import ssl
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

# ── Dependency check ──────────────────────────────────────────────────────────

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    import dns.query
    import dns.zone
    import dns.flags
except ImportError:
    print("Missing dependency: dnspython")
    print("Install with: pip3 install dnspython")
    sys.exit(1)

WHOIS_AVAILABLE = False
try:
    import whois as pywhois
    WHOIS_AVAILABLE = True
except ImportError:
    pass

# ── Colors ────────────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

def no_color():
    for attr in vars(C):
        if not attr.startswith("_"):
            setattr(C, attr, "")

# ── Record types ──────────────────────────────────────────────────────────────

ALL_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR",
             "SRV", "CAA", "DNSKEY", "DS", "TLSA", "NAPTR", "SSHFP"]

DESCRIPTIONS = {
    "A":      "IPv4 address",
    "AAAA":   "IPv6 address",
    "MX":     "Mail exchange",
    "NS":     "Name servers",
    "TXT":    "Text / SPF / DKIM / DMARC",
    "CNAME":  "Canonical name alias",
    "SOA":    "Start of authority",
    "PTR":    "Reverse DNS pointer",
    "SRV":    "Service locator",
    "CAA":    "Cert Authority Authorization",
    "DNSKEY": "DNSSEC public key",
    "DS":     "DNSSEC delegation signer",
    "TLSA":   "TLS cert association (DANE)",
    "NAPTR":  "Naming auth pointer (VoIP)",
    "SSHFP":  "SSH fingerprint",
}

PROPAGATION_RESOLVERS = [
    ("Cloudflare",   "1.1.1.1"),
    ("Google",       "8.8.8.8"),
    ("Quad9",        "9.9.9.9"),
    ("OpenDNS",      "208.67.222.222"),
    ("Comodo",       "8.26.56.26"),
    ("Level3",       "209.244.0.3"),
]

# ── Record formatting ─────────────────────────────────────────────────────────

def format_record(rtype, rdata):
    if rtype == "MX":
        return f"[prio {rdata.preference:>5}]  {rdata.exchange}"
    if rtype == "SOA":
        return (f"mname={rdata.mname}  rname={rdata.rname}  "
                f"serial={rdata.serial}  refresh={rdata.refresh}  "
                f"retry={rdata.retry}  expire={rdata.expire}  "
                f"minimum={rdata.minimum}")
    if rtype == "SRV":
        return f"[prio {rdata.priority} w {rdata.weight}]  {rdata.target}:{rdata.port}"
    if rtype == "CAA":
        return f"[flags {rdata.flags}]  {rdata.tag.decode()} = {rdata.value.decode()}"
    if rtype == "TXT":
        parts = [p.decode(errors="replace") if isinstance(p, bytes) else p
                 for p in rdata.strings]
        return " ".join(parts)
    return str(rdata)


def lookup(domain, rtype, resolver):
    answers = resolver.resolve(domain, rtype)
    return [(answers.rrset.ttl, format_record(rtype, r)) for r in answers]


# ── Pretty printer ────────────────────────────────────────────────────────────

def print_domain_header(domain, index=None, total=None):
    label = f"  {domain}  "
    if index is not None:
        label = f"  [{index}/{total}] {domain}  "
    width = max(len(label) + 4, 60)
    bar = "─" * width
    print(f"\n{C.BOLD}{C.CYAN}┌{bar}┐{C.RESET}")
    pad = width - len(label)
    lpad = pad // 2
    rpad = pad - lpad
    print(f"{C.BOLD}{C.CYAN}│{' ' * lpad}{C.WHITE}{label}{C.CYAN}{' ' * rpad}│{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}└{bar}┘{C.RESET}")


def print_section_header(title, color=None):
    color = color or C.YELLOW
    pad = max(1, 50 - len(title))
    print(f"\n  {C.BOLD}{color}── {title} {'─' * pad}{C.RESET}")


def print_section(rtype, records):
    desc = DESCRIPTIONS.get(rtype, "")
    print(f"\n  {C.BOLD}{C.YELLOW}{rtype:<8}{C.DIM}{C.WHITE}  {desc}{C.RESET}")
    print(f"  {C.DIM}{'─' * 56}{C.RESET}")
    for ttl, val in records:
        ttl_str = f"{C.DIM}[TTL {ttl:>6}]{C.RESET}"
        print(f"  {ttl_str}  {C.GREEN}{val}{C.RESET}")


def print_no_record(rtype):
    desc = DESCRIPTIONS.get(rtype, "")
    print(f"\n  {C.DIM}{rtype:<8}  {desc}  —  no record{C.RESET}")


def print_error(rtype, err):
    print(f"\n  {C.RED}{rtype:<8}  ERROR: {err}{C.RESET}")


def ok(msg):   return f"{C.GREEN}✔  {msg}{C.RESET}"
def warn(msg): return f"{C.YELLOW}⚠  {msg}{C.RESET}"
def fail(msg): return f"{C.RED}✘  {msg}{C.RESET}"
def info(msg): return f"{C.BLUE}ℹ  {msg}{C.RESET}"


# ── Core DNS lookup ───────────────────────────────────────────────────────────

def query_domain(domain, types, resolver):
    results = {}
    for rtype in types:
        try:
            records = lookup(domain, rtype, resolver)
            results[rtype] = {"status": "ok", "records": records}
        except dns.resolver.NXDOMAIN:
            results[rtype] = {"status": "nxdomain"}
        except dns.resolver.NoAnswer:
            results[rtype] = {"status": "noanswer"}
        except dns.resolver.NoNameservers:
            results[rtype] = {"status": "error", "msg": "No nameservers available"}
        except dns.exception.Timeout:
            results[rtype] = {"status": "error", "msg": "Query timed out"}
        except Exception as e:
            results[rtype] = {"status": "error", "msg": str(e)}
    return results


def display_results(domain, results, hide_empty=False):
    for rtype, data in results.items():
        status = data["status"]
        if status == "ok":
            print_section(rtype, data["records"])
        elif status == "noanswer":
            if not hide_empty:
                print_no_record(rtype)
        elif status == "nxdomain":
            print(f"\n  {C.RED}NXDOMAIN — domain does not exist{C.RESET}")
            break
        else:
            print_error(rtype, data.get("msg", "unknown error"))


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def do_whois(domain):
    print_section_header("WHOIS", C.MAGENTA)
    if not WHOIS_AVAILABLE:
        print(f"  {warn('python-whois not installed — run: pip3 install python-whois')}")
        return
    try:
        w = pywhois.whois(domain)

        def fmt_date(d):
            if d is None: return "—"
            if isinstance(d, list): d = d[0]
            return d.strftime("%Y-%m-%d") if hasattr(d, "strftime") else str(d)

        registrar   = w.registrar or "—"
        created     = fmt_date(w.creation_date)
        updated     = fmt_date(w.updated_date)
        expires     = fmt_date(w.expiration_date)
        status      = w.status or "—"
        nameservers = w.name_servers or []

        exp_color = C.GREEN
        try:
            exp_dt = w.expiration_date
            if isinstance(exp_dt, list): exp_dt = exp_dt[0]
            days_left = (exp_dt - datetime.now()).days
            if days_left < 30:   exp_color = C.RED
            elif days_left < 90: exp_color = C.YELLOW
            expires = f"{expires}  ({days_left} days)"
        except Exception:
            pass

        print(f"  {C.DIM}Registrar   :{C.RESET}  {registrar}")
        print(f"  {C.DIM}Created     :{C.RESET}  {created}")
        print(f"  {C.DIM}Updated     :{C.RESET}  {updated}")
        print(f"  {C.DIM}Expires     :{C.RESET}  {exp_color}{expires}{C.RESET}")
        statuses = status if isinstance(status, list) else [status]
        for s in statuses[:3]:
            print(f"  {C.DIM}Status      :{C.RESET}  {s}")
        for ns in sorted(set(str(n).lower() for n in nameservers)):
            print(f"  {C.DIM}Nameserver  :{C.RESET}  {ns}")
    except Exception as e:
        print(f"  {fail(f'WHOIS failed: {e}')}")


# ── Mail audit: SPF / DKIM / DMARC ───────────────────────────────────────────

def parse_spf(txt):
    findings = []
    if "+all" in txt:
        findings.append(("fail", "'+all' allows ANY server to send — no SPF protection"))
    elif "~all" in txt:
        findings.append(("warn", "'~all' softfail — servers may still accept spoofed mail"))
    elif "-all" in txt:
        findings.append(("ok",   "'-all' hard fail — only listed servers may send"))
    elif "?all" in txt:
        findings.append(("warn", "'?all' neutral — no guidance, treat as no SPF"))
    else:
        findings.append(("warn", "No 'all' mechanism — incomplete SPF record"))

    for inc in re.findall(r"include:(\S+)", txt):
        findings.append(("info", f"Includes: {inc}"))
    for r in re.findall(r"redirect=(\S+)", txt):
        findings.append(("info", f"Redirects to: {r}"))

    lc = len(re.findall(r"\b(include|a|mx|ptr|exists|redirect)[:=]", txt))
    if lc > 10:
        findings.append(("warn", f"~{lc} DNS lookups — SPF limit is 10, may cause PermError"))
    return findings


def parse_dmarc(txt):
    findings = []
    p = re.search(r"\bp=(\w+)", txt)
    policy = p.group(1).lower() if p else None
    if policy == "none":
        findings.append(("warn", "p=none — monitoring only, no enforcement"))
    elif policy == "quarantine":
        findings.append(("ok",   "p=quarantine — failing mail goes to spam"))
    elif policy == "reject":
        findings.append(("ok",   "p=reject — failing mail is rejected"))
    else:
        findings.append(("warn", f"Unknown or missing policy: {policy}"))

    sp = re.search(r"\bsp=(\w+)", txt)
    if sp:
        findings.append(("info", f"Subdomain policy: sp={sp.group(1)}"))

    pct = re.search(r"\bpct=(\d+)", txt)
    if pct and int(pct.group(1)) < 100:
        findings.append(("warn", f"pct={pct.group(1)} — policy only applied to {pct.group(1)}% of mail"))

    rua = re.search(r"\brua=([^\s;]+)", txt)
    if rua:
        findings.append(("info", f"Aggregate reports → {rua.group(1)}"))
    else:
        findings.append(("warn", "No rua= tag — not receiving aggregate reports"))
    return findings


def check_dkim(domain, resolver, extra_selectors=None):
    selectors = [
        "default", "google", "k1", "k2", "mail", "mx",
        "selector1", "selector2", "dkim", "smtp", "email",
        "proofpoint", "mimecast", "s1", "s2",
    ]
    if extra_selectors:
        selectors = list(extra_selectors) + [s for s in selectors if s not in extra_selectors]

    found = []
    for sel in selectors:
        qname = f"{sel}._domainkey.{domain}"
        try:
            answers = resolver.resolve(qname, "TXT")
            for r in answers:
                txt = " ".join(p.decode(errors="replace") if isinstance(p, bytes) else p
                               for p in r.strings)
                if "v=DKIM1" in txt or "p=" in txt:
                    found.append((sel, txt))
        except Exception:
            pass
    return found


def do_mail_audit(domain, resolver, dkim_selector=None):
    print_section_header("MAIL AUDIT  (SPF / DKIM / DMARC)", C.MAGENTA)

    # SPF
    print(f"\n  {C.BOLD}SPF{C.RESET}")
    spf_records = []
    try:
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            txt = " ".join(p.decode(errors="replace") if isinstance(p, bytes) else p
                           for p in r.strings)
            if txt.startswith("v=spf1"):
                spf_records.append(txt)
    except Exception:
        pass

    if not spf_records:
        print(f"  {fail('No SPF record found')}")
    elif len(spf_records) > 1:
        print(f"  {fail(f'{len(spf_records)} SPF records found — must be exactly one')}")
        for r in spf_records:
            print(f"  {C.DIM}  {r}{C.RESET}")
    else:
        print(f"  {C.DIM}  {spf_records[0]}{C.RESET}")
        for level, msg in parse_spf(spf_records[0]):
            if level == "ok":     print(f"  {ok(msg)}")
            elif level == "warn": print(f"  {warn(msg)}")
            elif level == "fail": print(f"  {fail(msg)}")
            else:                 print(f"  {info(msg)}")

    # DMARC
    print(f"\n  {C.BOLD}DMARC{C.RESET}")
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = " ".join(p.decode(errors="replace") if isinstance(p, bytes) else p
                           for p in r.strings)
            if "DMARC1" in txt:
                print(f"  {C.DIM}  {txt}{C.RESET}")
                for level, msg in parse_dmarc(txt):
                    if level == "ok":     print(f"  {ok(msg)}")
                    elif level == "warn": print(f"  {warn(msg)}")
                    elif level == "fail": print(f"  {fail(msg)}")
                    else:                 print(f"  {info(msg)}")
    except dns.resolver.NXDOMAIN:
        print(f"  {fail('No DMARC record (_dmarc.' + domain + ' NXDOMAIN)')}")
    except dns.resolver.NoAnswer:
        print(f"  {fail('No DMARC record found')}")
    except Exception as e:
        print(f"  {fail(f'DMARC lookup failed: {e}')}")

    # DKIM
    print(f"\n  {C.BOLD}DKIM  (common selectors){C.RESET}")
    extra = [dkim_selector] if dkim_selector else None
    dkim_found = check_dkim(domain, resolver, extra_selectors=extra)
    if not dkim_found:
        print(f"  {warn('No DKIM records found for common selectors')}")
        print(f"  {C.DIM}  Use --dkim-selector SELECTOR to check a specific one{C.RESET}")
    else:
        for sel, txt in dkim_found:
            display = txt if len(txt) < 100 else txt[:97] + "..."
            print(f"  {ok(f'selector={sel}')}")
            print(f"  {C.DIM}  {display}{C.RESET}")


# ── Zone transfer (AXFR) ──────────────────────────────────────────────────────

def do_axfr(domain, resolver):
    print_section_header("ZONE TRANSFER (AXFR)", C.MAGENTA)
    ns_list = []
    try:
        answers = resolver.resolve(domain, "NS")
        ns_list = [str(r.target).rstrip(".") for r in answers]
    except Exception as e:
        print(f"  {fail(f'Could not get NS records: {e}')}")
        return

    if not ns_list:
        print(f"  {fail('No NS records found')}")
        return

    any_success = False
    for ns in ns_list:
        try:
            ns_ip = socket.gethostbyname(ns)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            print(f"  {C.RED}{C.BOLD}✘ ZONE TRANSFER SUCCEEDED on {ns} — security risk!{C.RESET}")
            names = sorted(z.nodes.keys())
            for name in names[:50]:
                node = z[name]
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        print(f"  {C.YELLOW}  {name}.{domain}.  {rdataset.ttl}  {rdataset.rdtype}  {rdata}{C.RESET}")
            if len(names) > 50:
                print(f"  {C.DIM}  ... and {len(names) - 50} more records{C.RESET}")
            any_success = True
        except dns.exception.FormError:
            print(f"  {ok(f'AXFR refused by {ns}')}")
        except Exception as e:
            err = str(e)
            if "refused" in err.lower():
                print(f"  {ok(f'AXFR refused by {ns}')}")
            else:
                print(f"  {info(f'{ns}: {err}')}")

    if not any_success:
        print(f"  {ok('Zone transfer blocked on all nameservers — good')}")


# ── HTTP / HTTPS check ────────────────────────────────────────────────────────

def http_check_one(url, timeout=8):
    chain = []
    current = url
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for _ in range(10):
        try:
            req = urllib.request.Request(
                current,
                headers={"User-Agent": "dns-lookup-tool/1.0"},
                method="HEAD"
            )
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx),
                NoRedirect()
            )
            try:
                resp = opener.open(req, timeout=timeout)
                chain.append((current, resp.status))
                return current, resp.status, chain, None
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    location = e.headers.get("Location", "")
                    chain.append((current, e.code))
                    if not location:
                        return current, e.code, chain, None
                    if location.startswith("/"):
                        from urllib.parse import urlparse
                        p = urlparse(current)
                        location = f"{p.scheme}://{p.netloc}{location}"
                    current = location
                    continue
                chain.append((current, e.code))
                return current, e.code, chain, None
        except urllib.error.URLError as e:
            return current, None, chain, str(e.reason)
        except Exception as e:
            return current, None, chain, str(e)
    return current, None, chain, "Too many redirects"


def status_color(code):
    if code is None:           return C.RED
    if 200 <= code < 300:      return C.GREEN
    if 300 <= code < 400:      return C.YELLOW
    if code >= 400:            return C.RED
    return C.WHITE


def do_http_check(domain):
    print_section_header("HTTP / HTTPS", C.MAGENTA)
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        final, code, chain, err = http_check_one(url)

        if err and not chain:
            print(f"  {fail(f'{scheme.upper()}  {err}')}")
            continue

        for i, (u, c) in enumerate(chain):
            sc = status_color(c)
            arrow = "→ " if i < len(chain) - 1 else "  "
            print(f"  {sc}{c}{C.RESET}  {arrow}{C.DIM}{u}{C.RESET}")

        if err:
            print(f"  {fail(err)}")
        else:
            sc = status_color(code)
            label = "Live" if code and 200 <= code < 400 else "Problem"
            print(f"  {sc}{C.BOLD}{label}{C.RESET}  final={sc}{code}{C.RESET}  {C.DIM}{final}{C.RESET}")


# ── Propagation check ─────────────────────────────────────────────────────────

def propagation_query(label, ns_ip, domain, rtype, timeout):
    r = dns.resolver.Resolver()
    r.nameservers = [ns_ip]
    r.lifetime = timeout
    try:
        answers = r.resolve(domain, rtype)
        vals = sorted(set(format_record(rtype, rd) for rd in answers))
        return label, vals, None
    except dns.resolver.NXDOMAIN:
        return label, [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return label, [], "NOANSWER"
    except dns.exception.Timeout:
        return label, [], "TIMEOUT"
    except Exception as e:
        return label, [], str(e)


def do_propagation(domain, types, timeout=5.0):
    print_section_header("PROPAGATION CHECK", C.MAGENTA)

    resolvers = list(PROPAGATION_RESOLVERS)

    # Add authoritative nameservers
    try:
        sys_r = dns.resolver.Resolver()
        sys_r.lifetime = timeout
        ns_answers = sys_r.resolve(domain, "NS")
        for r in ns_answers:
            ns_host = str(r.target).rstrip(".")
            try:
                ns_ip = socket.gethostbyname(ns_host)
                short = ns_host.split(".")[0]
                resolvers.append((f"Auth:{short}", ns_ip))
            except Exception:
                pass
    except Exception:
        pass

    check_types = types if types != ALL_TYPES else ["A", "AAAA", "MX", "NS"]

    for rtype in check_types:
        print(f"\n  {C.BOLD}{C.YELLOW}{rtype}{C.RESET}  {C.DIM}{DESCRIPTIONS.get(rtype, '')}{C.RESET}")
        print(f"  {C.DIM}{'─' * 56}{C.RESET}")

        results = {}
        with ThreadPoolExecutor(max_workers=len(resolvers)) as ex:
            futures = {
                ex.submit(propagation_query, label, ip, domain, rtype, timeout): label
                for label, ip in resolvers
            }
            for fut in as_completed(futures):
                label, vals, err = fut.result()
                results[label] = (vals, err)

        answer_strs = [
            tuple(sorted(v)) for v, e in results.values() if e is None and v
        ]
        consensus_vals = set(Counter(answer_strs).most_common(1)[0][0]) if answer_strs else set()

        for label, ip in resolvers:
            vals, err = results.get(label, ([], "no result"))
            label_str = f"{label:<22}"
            if err:
                color = C.RED if err not in ("NOANSWER",) else C.DIM
                print(f"  {C.DIM}{label_str}{C.RESET}  {color}{err}{C.RESET}")
            else:
                match = set(vals) == consensus_vals
                indicator = f"{C.GREEN}✔{C.RESET}" if match else f"{C.RED}✘{C.RESET}"
                val_str = ", ".join(vals) if vals else "—"
                if len(val_str) > 70:
                    val_str = val_str[:67] + "..."
                col = C.GREEN if match else C.RED
                print(f"  {C.DIM}{label_str}{C.RESET}  {indicator}  {col}{val_str}{C.RESET}")

        if consensus_vals:
            cs = ", ".join(sorted(consensus_vals))
            if len(cs) > 100: cs = cs[:97] + "..."
            print(f"  {C.DIM}  consensus: {cs}{C.RESET}")


# ── JSON output ───────────────────────────────────────────────────────────────

def to_json(all_results):
    out = {}
    for domain, results in all_results.items():
        out[domain] = {}
        for rtype, data in results.items():
            if data["status"] == "ok":
                out[domain][rtype] = [
                    {"ttl": ttl, "value": val} for ttl, val in data["records"]
                ]
            else:
                out[domain][rtype] = {"error": data["status"], "msg": data.get("msg", "")}
    return json.dumps(out, indent=2)


# ── Resolver builder ──────────────────────────────────────────────────────────

def build_resolver(nameserver=None, timeout=5.0):
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    if nameserver:
        try:
            socket.inet_aton(nameserver)
            resolved_ip = nameserver
        except socket.error:
            try:
                resolved_ip = socket.gethostbyname(nameserver)
            except socket.gaierror as e:
                print(f"{C.RED}Error: could not resolve resolver hostname '{nameserver}': {e}{C.RESET}")
                sys.exit(1)
        r.nameservers = [resolved_ip]
    return r


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Comprehensive DNS lookup tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  dns_lookup.py example.com
  dns_lookup.py example.com -r A MX TXT
  dns_lookup.py -f domains.txt
  dns_lookup.py example.com --whois
  dns_lookup.py example.com --mail-audit
  dns_lookup.py example.com --mail-audit --dkim-selector selector1
  dns_lookup.py example.com --axfr
  dns_lookup.py example.com --http
  dns_lookup.py example.com --propagation
  dns_lookup.py example.com --propagation -r A MX
  dns_lookup.py example.com --all-checks
  dns_lookup.py -f domains.txt --resolver 1.1.1.1 --json
""")
    p.add_argument("domains",         nargs="*", help="One or more domain names")
    p.add_argument("-f", "--file",    help="Text file with one domain per line")
    p.add_argument("-r", "--records", nargs="+", metavar="TYPE", default=ALL_TYPES,
                   help=f"Record types to query (default: all)\nAvailable: {' '.join(ALL_TYPES)}")
    p.add_argument("--resolver",      help="DNS resolver IP or hostname (default: system)")
    p.add_argument("--timeout",       type=float, default=5.0,
                   help="Query timeout in seconds (default: 5)")
    p.add_argument("--hide-empty",    action="store_true",
                   help="Don't show record types with no data")
    p.add_argument("--no-color",      action="store_true", help="Disable color output")
    p.add_argument("--json",          action="store_true", help="Output DNS records as JSON")
    p.add_argument("--whois",         action="store_true",
                   help="Show WHOIS info (requires: pip3 install python-whois)")
    p.add_argument("--mail-audit",    action="store_true",
                   help="Analyse SPF, DKIM, DMARC records")
    p.add_argument("--dkim-selector", help="Extra DKIM selector to check (used with --mail-audit)")
    p.add_argument("--axfr",          action="store_true",
                   help="Attempt zone transfer on all NS")
    p.add_argument("--http",          action="store_true",
                   help="Check HTTP/HTTPS reachability and follow redirects")
    p.add_argument("--propagation",   action="store_true",
                   help="Check propagation across public resolvers + authoritative NS")
    p.add_argument("--all-checks",    action="store_true",
                   help="Run all checks: whois + mail-audit + axfr + http + propagation")
    return p.parse_args()


def load_domains_from_file(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        print(f"{C.RED}Error: file not found: {path}{C.RESET}")
        sys.exit(1)


def main():
    args = parse_args()

    if args.no_color:
        no_color()

    domains = list(args.domains)
    if args.file:
        domains += load_domains_from_file(args.file)

    if not domains:
        print(f"{C.RED}Error: provide at least one domain or use -f <file>{C.RESET}")
        sys.exit(1)

    types = [t.upper() for t in args.records]
    invalid = [t for t in types if t not in ALL_TYPES]
    if invalid:
        print(f"{C.YELLOW}Warning: unknown record types ignored: {', '.join(invalid)}{C.RESET}")
        types = [t for t in types if t in ALL_TYPES]

    resolver = build_resolver(args.resolver, args.timeout)

    run_whois       = args.whois       or args.all_checks
    run_mail_audit  = args.mail_audit  or args.all_checks
    run_axfr        = args.axfr        or args.all_checks
    run_http        = args.http        or args.all_checks
    run_propagation = args.propagation or args.all_checks

    if not args.json:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ns = args.resolver or "system"
        print(f"\n{C.BOLD}{C.WHITE}DNS Lookup  {C.DIM}{ts}  resolver={ns}{C.RESET}")
        print(f"{C.DIM}Querying {len(domains)} domain(s) for: {', '.join(types)}{C.RESET}")

    all_results = {}
    total = len(domains)

    for i, domain in enumerate(domains, 1):
        domain = domain.lower().rstrip(".")

        if not args.json:
            print_domain_header(domain, i, total)

        results = query_domain(domain, types, resolver)
        all_results[domain] = results

        if not args.json:
            display_results(domain, results, hide_empty=args.hide_empty)

            if run_whois:
                do_whois(domain)
            if run_mail_audit:
                do_mail_audit(domain, resolver, dkim_selector=args.dkim_selector)
            if run_axfr:
                do_axfr(domain, resolver)
            if run_http:
                do_http_check(domain)
            if run_propagation:
                do_propagation(domain, types, timeout=args.timeout)

    if args.json:
        print(to_json(all_results))
    else:
        print(f"\n{C.DIM}Done. {total} domain(s) queried.{C.RESET}\n")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
dns_lookup.py - Comprehensive DNS record lookup tool
Usage:
  python3 dns_lookup.py example.com
  python3 dns_lookup.py example.com another.com
  python3 dns_lookup.py -f domains.txt
  python3 dns_lookup.py -f domains.txt -r A MX TXT
  python3 dns_lookup.py example.com --json
  python3 dns_lookup.py example.com --resolver 8.8.8.8
"""

import sys
import argparse
import json
import socket
from datetime import datetime

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
except ImportError:
    print("Missing dependency: dnspython")
    print("Install with: pip3 install dnspython")
    sys.exit(1)

# ── Colors ────────────────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"

def no_color():
    for attr in vars(C):
        if not attr.startswith("_"):
            setattr(C, attr, "")

# ── Record types & handlers ───────────────────────────────────────────────────

ALL_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR",
             "SRV", "CAA", "DNSKEY", "DS", "TLSA", "NAPTR", "SSHFP"]

DESCRIPTIONS = {
    "A":      "IPv4 address",
    "AAAA":   "IPv6 address",
    "MX":     "Mail exchange",
    "NS":     "Name servers",
    "TXT":    "Text / SPF / DKIM / DMARC",
    "CNAME":  "Canonical name alias",
    "SOA":    "Start of authority",
    "PTR":    "Reverse DNS pointer",
    "SRV":    "Service locator",
    "CAA":    "Cert Authority Authorization",
    "DNSKEY": "DNSSEC public key",
    "DS":     "DNSSEC delegation signer",
    "TLSA":   "TLS cert association (DANE)",
    "NAPTR":  "Naming auth pointer (VoIP)",
    "SSHFP":  "SSH fingerprint",
}

def format_record(rtype, rdata):
    """Return a human-readable string for a record."""
    s = str(rdata)
    if rtype == "MX":
        return f"[prio {rdata.preference:>5}]  {rdata.exchange}"
    if rtype == "SOA":
        return (f"mname={rdata.mname}  rname={rdata.rname}  "
                f"serial={rdata.serial}  refresh={rdata.refresh}  "
                f"retry={rdata.retry}  expire={rdata.expire}  "
                f"minimum={rdata.minimum}")
    if rtype == "SRV":
        return f"[prio {rdata.priority} w {rdata.weight}]  {rdata.target}:{rdata.port}"
    if rtype == "CAA":
        return f"[flags {rdata.flags}]  {rdata.tag.decode()} = {rdata.value.decode()}"
    if rtype == "TXT":
        # Join multi-string TXT records
        parts = [p.decode(errors="replace") if isinstance(p, bytes) else p
                 for p in rdata.strings]
        return " ".join(parts)
    return s


def lookup(domain, rtype, resolver):
    """Return list of (ttl, formatted_string) or raise dns.exception."""
    answers = resolver.resolve(domain, rtype)
    return [(answers.rrset.ttl, format_record(rtype, r)) for r in answers]


# ── Pretty printer ────────────────────────────────────────────────────────────

def print_domain_header(domain, index=None, total=None):
    label = f"  {domain}  "
    if index is not None:
        label = f"  [{index}/{total}] {domain}  "
    width = max(len(label) + 4, 60)
    bar = "─" * width
    print(f"\n{C.BOLD}{C.CYAN}┌{bar}┐{C.RESET}")
    pad = width - len(label)
    lpad = pad // 2
    rpad = pad - lpad
    print(f"{C.BOLD}{C.CYAN}│{' ' * lpad}{C.WHITE}{label}{C.CYAN}{' ' * rpad}│{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}└{bar}┘{C.RESET}")


def print_section(rtype, records, ttl_col=True):
    desc = DESCRIPTIONS.get(rtype, "")
    print(f"\n  {C.BOLD}{C.YELLOW}{rtype:<8}{C.DIM}{C.WHITE}  {desc}{C.RESET}")
    print(f"  {C.DIM}{'─' * 56}{C.RESET}")
    for ttl, val in records:
        ttl_str = f"{C.DIM}[TTL {ttl:>6}]{C.RESET}" if ttl_col else ""
        print(f"  {ttl_str}  {C.GREEN}{val}{C.RESET}")


def print_no_record(rtype):
    desc = DESCRIPTIONS.get(rtype, "")
    print(f"\n  {C.DIM}{rtype:<8}  {desc}  —  no record{C.RESET}")


def print_error(rtype, err):
    print(f"\n  {C.RED}{rtype:<8}  ERROR: {err}{C.RESET}")


# ── Core lookup logic ─────────────────────────────────────────────────────────

def query_domain(domain, types, resolver, json_mode=False):
    results = {}
    for rtype in types:
        try:
            records = lookup(domain, rtype, resolver)
            results[rtype] = {"status": "ok", "records": records}
        except dns.resolver.NXDOMAIN:
            results[rtype] = {"status": "nxdomain"}
        except dns.resolver.NoAnswer:
            results[rtype] = {"status": "noanswer"}
        except dns.resolver.NoNameservers:
            results[rtype] = {"status": "error", "msg": "No nameservers available"}
        except dns.exception.Timeout:
            results[rtype] = {"status": "error", "msg": "Query timed out"}
        except Exception as e:
            results[rtype] = {"status": "error", "msg": str(e)}
    return results


def display_results(domain, results, hide_empty=False):
    for rtype, data in results.items():
        status = data["status"]
        if status == "ok":
            print_section(rtype, data["records"])
        elif status == "noanswer":
            if not hide_empty:
                print_no_record(rtype)
        elif status == "nxdomain":
            print(f"\n  {C.RED}NXDOMAIN — domain does not exist{C.RESET}")
            break
        else:
            print_error(rtype, data.get("msg", "unknown error"))


# ── JSON output ───────────────────────────────────────────────────────────────

def to_json(all_results):
    out = {}
    for domain, results in all_results.items():
        out[domain] = {}
        for rtype, data in results.items():
            if data["status"] == "ok":
                out[domain][rtype] = [
                    {"ttl": ttl, "value": val} for ttl, val in data["records"]
                ]
            else:
                out[domain][rtype] = {"error": data["status"],
                                       "msg": data.get("msg", "")}
    return json.dumps(out, indent=2)


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Comprehensive DNS lookup tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  dns_lookup.py example.com
  dns_lookup.py example.com another.com -r A MX TXT
  dns_lookup.py -f domains.txt
  dns_lookup.py -f domains.txt --resolver 1.1.1.1 --json
  dns_lookup.py example.com --hide-empty
""")
    p.add_argument("domains", nargs="*", help="One or more domain names")
    p.add_argument("-f", "--file", help="Text file with one domain per line")
    p.add_argument("-r", "--records", nargs="+", metavar="TYPE",
                   default=ALL_TYPES,
                   help=f"Record types to query (default: all)\nAvailable: {' '.join(ALL_TYPES)}")
    p.add_argument("--resolver", default=None,
                   help="DNS resolver IP (default: system resolver)")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="Query timeout in seconds (default: 5)")
    p.add_argument("--json", action="store_true", help="Output as JSON")
    p.add_argument("--hide-empty", action="store_true",
                   help="Don't show record types with no data")
    p.add_argument("--no-color", action="store_true", help="Disable color output")
    return p.parse_args()


def load_domains_from_file(path):
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return lines
    except FileNotFoundError:
        print(f"{C.RED}Error: file not found: {path}{C.RESET}")
        sys.exit(1)


def build_resolver(nameserver=None, timeout=5.0):
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    if nameserver:
        try:
            socket.inet_aton(nameserver)
            resolved_ip = nameserver
        except socket.error:
            try:
                resolved_ip = socket.gethostbyname(nameserver)
            except socket.gaierror as e:
                print(f"Error: could not resolve resolver hostname '{nameserver}': {e}")
                sys.exit(1)
        r.nameservers = [resolved_ip]
    return r


def main():
    args = parse_args()

    if args.no_color:
        no_color()

    # Collect domains
    domains = list(args.domains)
    if args.file:
        domains += load_domains_from_file(args.file)

    if not domains:
        print(f"{C.RED}Error: provide at least one domain or use -f <file>{C.RESET}")
        sys.exit(1)

    # Normalise record type names
    types = [t.upper() for t in args.records]
    invalid = [t for t in types if t not in ALL_TYPES]
    if invalid:
        print(f"{C.YELLOW}Warning: unknown record types ignored: {', '.join(invalid)}{C.RESET}")
        types = [t for t in types if t in ALL_TYPES]

    resolver = build_resolver(args.resolver, args.timeout)

    # Print header
    if not args.json:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ns = args.resolver or "system"
        print(f"\n{C.BOLD}{C.WHITE}DNS Lookup  {C.DIM}{ts}  resolver={ns}{C.RESET}")
        print(f"{C.DIM}Querying {len(domains)} domain(s) for: {', '.join(types)}{C.RESET}")

    all_results = {}
    total = len(domains)
    for i, domain in enumerate(domains, 1):
        domain = domain.lower().rstrip(".")
        results = query_domain(domain, types, resolver)
        all_results[domain] = results
        if not args.json:
            print_domain_header(domain, i, total)
            display_results(domain, results, hide_empty=args.hide_empty)

    if args.json:
        print(to_json(all_results))
    else:
        print(f"\n{C.DIM}Done. {total} domain(s) queried.{C.RESET}\n")


if __name__ == "__main__":
    main()
