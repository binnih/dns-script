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
