# dns_lookup.py

Comprehensive DNS record lookup tool for single domains or bulk lists from a file.

Includes: WHOIS · Mail audit (SPF/DKIM/DMARC) · Zone transfer test · HTTP check · SSL/TLS cert · RBL/blacklist · CDN detection · MX port check · Subdomain probe · DNS timing · Propagation check · File output

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
| `--axfr` | Attempt zone transfer on all nameservers |
| `--http` | Check HTTP/HTTPS and follow redirect chain |
| `--ssl` | Check SSL/TLS certificate (expiry, issuer, SANs, match) |
| `--rbl` | Check IPs against 12 spam blacklists |
| `--cdn` | Detect CDN or hosting provider |
| `--mx-ports` | Check MX hosts for open ports 25/465/587 |
| `--subdomains` | Probe 50+ common subdomains for A/AAAA/CNAME |
| `--dns-timing` | Measure query response time across resolvers |
| `--propagation` | Check propagation across public + authoritative resolvers |
| `--all-checks` | Run all checks |

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

### Zone transfer (`--axfr`)
Attempts AXFR against every NS. Flags a successful transfer as a security risk and dumps records. Refused = pass.

### HTTP / HTTPS (`--http`)
HEAD request to both `https://` and `http://`, manually follows the full redirect chain, prints each hop with status code.

### SSL / TLS (`--ssl`)
Connects to port 443 and inspects the certificate: expiry (colour-coded), issuer, SANs, domain match check, self-signed detection.

### Blacklist / RBL (`--rbl`)
Checks the domain's A record IPs in parallel against 12 lists including Spamhaus ZEN, SpamCop, Barracuda, SORBS, and CBL.

### CDN / hosting detection (`--cdn`)
Identifies provider from NS, A, and CNAME patterns. Covers Cloudflare, AWS CloudFront, Azure, Fastly, Akamai, Google Cloud, Vercel, Netlify, GitHub Pages, Bunny CDN, and Sucuri.

### MX port check (`--mx-ports`)
Resolves each MX host and checks ports 25 (SMTP), 465 (SMTPS), and 587 (Submission) for connectivity.

### Subdomain probe (`--subdomains`)
Probes 50+ common subdomains (`www`, `mail`, `api`, `vpn`, `admin`, `staging`, `git`, `grafana`, etc.) in parallel for A/AAAA/CNAME records.

### DNS timing (`--dns-timing`)
Measures A record query response time across 6 public resolvers plus authoritative nameservers. Displays an ASCII bar chart — green <100ms, yellow <250ms, red >250ms.

### Propagation check (`--propagation`)
Queries 6 public resolvers + authoritative NS in parallel, compares answers to consensus. Mismatches highlighted in red. Defaults to A/AAAA/MX/NS; use `-r` to specify types.

---

## Examples

```bash
# Standard DNS records
python3 dns_lookup.py example.com

# Multiple domains, mail records only
python3 dns_lookup.py example.com another.com -r MX TXT NS

# Bulk lookup, hide empty types
python3 dns_lookup.py -f domains.txt --hide-empty

# Use a named nameserver as resolver
python3 dns_lookup.py example.com --resolver ns1-37.azure-dns.com

# Full audit, save to file
python3 dns_lookup.py example.com --all-checks --output report.txt

# Mail audit with a known DKIM selector
python3 dns_lookup.py example.com --mail-audit --dkim-selector selector1

# Check SSL cert
python3 dns_lookup.py example.com --ssl

# Check if IPs are blacklisted
python3 dns_lookup.py example.com --rbl

# Detect CDN/hosting
python3 dns_lookup.py example.com --cdn

# Check MX port availability
python3 dns_lookup.py example.com --mx-ports

# Probe for subdomains
python3 dns_lookup.py example.com --subdomains

# DNS response time across resolvers
python3 dns_lookup.py example.com --dns-timing

# Propagation check for A and MX only
python3 dns_lookup.py example.com --propagation -r A MX

# JSON output
python3 dns_lookup.py -f domains.txt --json | jq '.[].MX'

# No color (for logging)
python3 dns_lookup.py -f domains.txt --no-color > results.txt
```

---

## Notes

- NXDOMAIN stops further record lookups for that domain immediately.
- Propagation, RBL, subdomain, and timing checks run in parallel for speed.
- `--resolver` accepts both IPs and hostnames (e.g. `ns1-37.azure-dns.com`).
