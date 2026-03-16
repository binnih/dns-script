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
