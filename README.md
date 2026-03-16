# dns_lookup.py

Comprehensive DNS record lookup tool for single domains or bulk lists from a file.

Includes: WHOIS · Mail audit (SPF/DKIM/DMARC) · Email header analyser · Zone transfer test · HTTP check · SSL/TLS cert · Certificate chain · RBL/blacklist · CDN detection · MX port check · Port scan · Subdomain probe · DNS timing · Propagation check · DNSSEC validation · Reverse DNS · IPv6 readiness · Bulk summary table · File output

---

## Requirements

Python 3.6+. Install dependencies with:

```bash
pip3 install -r requirements.txt
```

---

## Usage

```
python3 dns_lookup.py [domains ...] [options]
```

```bash
# Single domain
python3 dns_lookup.py example.com

# Multiple domains
python3 dns_lookup.py example.com another.com third.com

# From a file — one domain per line, # lines are comments
python3 dns_lookup.py -f domains.txt
```

Example `domains.txt`:
```
# Production sites
example.com
another.com

# Client domains
client1.com
client2.is
```

---

## Options

| Flag | Description |
|------|-------------|
| `-f`, `--file FILE` | Text file with one domain per line |
| `-r`, `--records TYPE [...]` | Record types to query (default: all) |
| `--resolver IP/HOST` | Use a specific DNS resolver (IP or hostname) |
| `--timeout SECONDS` | Query timeout in seconds (default: 5) |
| `--hide-empty` | Skip record types that return no data |
| `--no-color` | Disable color output |
| `--json` | Output DNS records as JSON |
| `--output FILE` | Save full output to file (ANSI codes stripped) |
| `--whois` | Show WHOIS info |
| `--mail-audit` | Analyse SPF, DKIM, DMARC + deliverability score |
| `--dkim-selector SEL` | Extra DKIM selector to check alongside common ones |
| `--mail-headers` | Analyse raw email headers pasted from stdin |
| `--axfr` | Attempt zone transfer on all nameservers |
| `--http` | Check HTTP/HTTPS and follow redirect chain |
| `--ssl` | Check SSL/TLS certificate (expiry, issuer, SANs, match) |
| `--cert-chain` | Verify full SSL certificate chain |
| `--rbl` | Check IPs against 12 spam blacklists |
| `--cdn` | Detect CDN or hosting provider |
| `--mx-ports` | Check MX hosts for open ports 25/465/587 |
| `--portscan` | Scan 20 common ports on domain A record IPs |
| `--subdomains` | Probe 50+ common subdomains for A/AAAA/CNAME |
| `--dns-timing` | Measure query response time across resolvers |
| `--propagation` | Check propagation across public + authoritative resolvers |
| `--dnssec` | Validate DNSSEC chain of trust |
| `--rdns` | Check reverse DNS consistency (PTR + forward confirmation) |
| `--ipv6` | Check IPv6 readiness (AAAA, MX IPv6, PTR) |
| `--summary` | Print one-line-per-domain summary table at end |
| `--all-checks` | Run all checks |
| `--watch N` | Re-query every N seconds, highlight changes |
| `--compare A B` | Compare DNS records of two domains side by side |
| `--init-config` | Create default config file at `~/.dns_lookup.conf` |

---

## Record types

All queried by default:

| Type | Description |
|------|-------------|
| `A` | IPv4 address |
| `AAAA` | IPv6 address |
| `MX` | Mail exchange |
| `NS` | Name servers |
| `TXT` | Text records — SPF, DKIM, DMARC, verification tokens |
| `CNAME` | Canonical name alias |
| `SOA` | Start of authority |
| `PTR` | Reverse DNS pointer |
| `SRV` | Service locator |
| `CAA` | Certification Authority Authorization |
| `DNSKEY` | DNSSEC public key |
| `DS` | DNSSEC delegation signer |
| `TLSA` | TLS certificate association (DANE) |
| `NAPTR` | Naming authority pointer (VoIP/SIP) |
| `SSHFP` | SSH fingerprint |

---

## Feature details

### WHOIS (`--whois`)
Registrar, created/updated/expiry dates, domain status, nameservers. Expiry colour-coded: green (>90 days), yellow (<90), red (<30). Requires `python-whois`.

### Mail audit (`--mail-audit`)
**SPF** — detects `+all` / `~all` / `-all`, lists includes, warns if lookup count exceeds the RFC limit of 10.  
**DMARC** — reports policy (`none`/`quarantine`/`reject`), `pct=` coverage, missing `rua=`.  
**DKIM** — probes 15 common selectors automatically.  
**Deliverability score** — combined 0–3 rating (Poor / Weak / Fair / Good).

### Email header analyser (`--mail-headers`)
Paste raw email headers from stdin. Parses `Authentication-Results` for SPF/DKIM/DMARC pass/fail, lists every received hop, extracts key headers (From, Return-Path, X-Originating-IP, etc.), and does a quick RBL check on the originating IP. Useful when a client reports mail going to spam.

### Zone transfer (`--axfr`)
Attempts AXFR against every NS. Flags a successful transfer as a security risk and dumps records. Refused = pass.

### HTTP / HTTPS (`--http`)
HEAD request to both `https://` and `http://`, manually follows the full redirect chain, prints each hop with status code.

### SSL / TLS (`--ssl`)
Connects to port 443 and inspects the certificate: expiry (colour-coded), issuer, SANs, domain match check, self-signed detection.

### Certificate chain (`--cert-chain`)
Verifies the full certificate chain (leaf + intermediates + root). Catches misconfigured servers that work in browsers but break on some mail clients or APIs. Uses `openssl` CLI if available, falls back to the Python `ssl` module.

### Blacklist / RBL (`--rbl`)
Checks the domain's A record IPs in parallel against 12 lists including Spamhaus ZEN, SpamCop, Barracuda, SORBS, and CBL.

### CDN / hosting detection (`--cdn`)
Identifies provider from NS, A, and CNAME patterns. Covers Cloudflare, AWS CloudFront, Azure, Fastly, Akamai, Google Cloud, Vercel, Netlify, GitHub Pages, Bunny CDN, and Sucuri.

### MX port check (`--mx-ports`)
Resolves each MX host and checks ports 25 (SMTP), 465 (SMTPS), and 587 (Submission) for connectivity.

### Port scan (`--portscan`)
Checks 20 common ports on each A record IP: 21/FTP, 22/SSH, 25/SMTP, 53/DNS, 80/HTTP, 443/HTTPS, 3306/MySQL, 3389/RDP, 5432/PostgreSQL, 6379/Redis, and more. Flags potentially exposed sensitive ports.

### Subdomain probe (`--subdomains`)
Probes 50+ common subdomains (`www`, `mail`, `api`, `vpn`, `admin`, `staging`, `git`, `grafana`, etc.) in parallel for A/AAAA/CNAME records.

### DNS timing (`--dns-timing`)
Measures A record query response time across 6 public resolvers plus authoritative nameservers. Displays an ASCII bar chart — green <100ms, yellow <250ms, red >250ms.

### Propagation check (`--propagation`)
Queries 6 public resolvers + authoritative NS in parallel, compares answers to consensus. Mismatches highlighted in red. Defaults to A/AAAA/MX/NS; use `-r` to specify types.

### DNSSEC validation (`--dnssec`)
Checks for DS record at parent zone, DNSKEY records (KSK/ZSK count), RRSIG coverage, and queries Google's validating resolver for the AD (Authenticated Data) flag to confirm the full chain of trust.

### Reverse DNS consistency (`--rdns`)
For each A record IP: looks up the PTR record, forward-confirms the PTR hostname resolves back to the same IP, and checks whether the PTR matches the queried domain. Mismatches are a common cause of mail rejection.

### IPv6 readiness (`--ipv6`)
Checks for AAAA records on the domain, AAAA records on each MX host, and PTR records for all IPv6 addresses.

### Bulk summary table (`--summary`)
After processing all domains, prints a compact one-line-per-domain table showing: A record, SSL days remaining, HTTP status, DMARC policy, RBL status, and CDN/hosting provider. Colour-coded for quick scanning. Most useful with `-f domains.txt`.

---

## Examples

```bash
# Standard DNS records
python3 dns_lookup.py example.com

# Multiple domains, mail records only
python3 dns_lookup.py example.com another.com -r MX TXT NS

# Bulk lookup with summary table
python3 dns_lookup.py -f domains.txt --summary --hide-empty

# Full audit, save to file
python3 dns_lookup.py example.com --all-checks --output report.txt

# Mail audit with a known DKIM selector
python3 dns_lookup.py example.com --mail-audit --dkim-selector selector1

# Analyse email headers (paste when prompted)
python3 dns_lookup.py example.com --mail-headers

# Check SSL cert and full chain
python3 dns_lookup.py example.com --ssl --cert-chain

# Check if IPs are blacklisted
python3 dns_lookup.py example.com --rbl

# Port scan
python3 dns_lookup.py example.com --portscan

# DNSSEC validation
python3 dns_lookup.py example.com --dnssec

# Reverse DNS check
python3 dns_lookup.py example.com --rdns

# IPv6 readiness
python3 dns_lookup.py example.com --ipv6

# Propagation check for A and MX only
python3 dns_lookup.py example.com --propagation -r A MX

# Use a named nameserver as resolver
python3 dns_lookup.py example.com --resolver ns1-37.azure-dns.com

# JSON output
python3 dns_lookup.py -f domains.txt --json | jq '.[].MX'

# No color (for logging)
python3 dns_lookup.py -f domains.txt --no-color > results.txt
```

---

## Notes

- If a domain does not exist (NXDOMAIN), remaining record type lookups are skipped since there is nothing to query.
- Propagation, RBL, subdomain, port scan, and timing checks run in parallel for speed.
- `--resolver` accepts both IPs and hostnames (e.g. `ns1-37.azure-dns.com`).
- `--mail-headers` reads from stdin — pipe a file or paste interactively.
- `--cert-chain` uses `openssl` CLI if installed; falls back to Python `ssl` module.

### Config file (`--init-config`)
Creates `~/.dns_lookup.conf` with commented defaults. Edit it to set a preferred resolver, default timeout, always-on checks, and extra RBL/subdomain lists. CLI flags always override config values.

```ini
[defaults]
resolver = 1.1.1.1
timeout = 5.0
hide_empty = false

[checks]
# Always run these checks without needing to pass the flag every time
always_run = whois,ssl,mail-audit

[rbl]
extra_lists =

[subdomains]
extra_subs = intranet,erp,crm
```

```bash
python3 dns_lookup.py --init-config
```

### Watch mode (`--watch N`)
Re-queries every N seconds and prints only what changed — added values in green, removed in red. First run shows full results; subsequent runs show diffs only. Hit Ctrl+C to stop.

```bash
python3 dns_lookup.py example.com --watch 30
python3 dns_lookup.py example.com --watch 60 -r A MX
```

### Compare mode (`--compare domain_a domain_b`)
Queries both domains and prints a side-by-side table of all record types. Identical values are dimmed; differences are highlighted with red (only in A) / green (only in B). A summary line shows which types differ.

```bash
python3 dns_lookup.py --compare example.com staging.example.com
python3 dns_lookup.py --compare old-domain.com new-domain.com -r A MX NS TXT
```
