# dns_lookup.py

Comprehensive DNS record lookup tool for single domains or bulk lists from a file.  
Includes WHOIS, mail security audit (SPF/DKIM/DMARC), zone transfer testing, HTTP checks, and propagation checking.

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

### Single domain

```bash
python3 dns_lookup.py example.com
```

### Multiple domains

```bash
python3 dns_lookup.py example.com another.com third.com
```

### From a text file

One domain per line. Lines starting with `#` are treated as comments and ignored.

```bash
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

### Mix file and CLI domains

```bash
python3 dns_lookup.py extra.com -f domains.txt
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
| `--whois` | Show WHOIS info (registrar, expiry, nameservers) |
| `--mail-audit` | Analyse SPF, DKIM, and DMARC records |
| `--dkim-selector SEL` | Extra DKIM selector to check alongside common ones |
| `--axfr` | Attempt zone transfer (AXFR) against all nameservers |
| `--http` | Check HTTP/HTTPS reachability and follow redirect chain |
| `--propagation` | Check DNS propagation across public resolvers + auth NS |
| `--all-checks` | Run all of the above checks in one go |

---

## Record types

All of the following are queried by default:

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

Query only specific types with `-r`:

```bash
python3 dns_lookup.py example.com -r A AAAA MX TXT
```

---

## Feature details

### WHOIS (`--whois`)

Shows registrar, creation date, expiry date, last updated, status flags, and nameservers.  
Expiry is colour-coded: green (>90 days), yellow (<90 days), red (<30 days).

```bash
python3 dns_lookup.py example.com --whois
```

Requires `pip3 install python-whois`.

---

### Mail audit (`--mail-audit`)

Parses and analyses SPF, DKIM, and DMARC records with actionable findings:

**SPF checks:**
- Detects dangerous `+all` (any server allowed), `~all` (softfail), `-all` (correct hard fail)
- Lists all `include:` and `redirect=` mechanisms
- Warns if DNS lookup count approaches the RFC limit of 10

**DMARC checks:**
- Reports enforcement policy (`none` / `quarantine` / `reject`)
- Flags missing or partial `pct=` coverage
- Warns if aggregate reporting (`rua=`) is not configured

**DKIM checks:**
- Probes ~15 common selectors automatically (`default`, `selector1`, `selector2`, `google`, `k1`, `mail`, etc.)
- Use `--dkim-selector` to add a known selector on top of the defaults

```bash
python3 dns_lookup.py example.com --mail-audit
python3 dns_lookup.py example.com --mail-audit --dkim-selector selector2
```

---

### Zone transfer (`--axfr`)

Attempts an AXFR zone transfer against every NS record for the domain.  
A successful transfer is a security misconfiguration — the script flags it clearly and dumps the returned records.  
A refused transfer reports as a pass.

```bash
python3 dns_lookup.py example.com --axfr
```

---

### HTTP / HTTPS check (`--http`)

Performs a HEAD request to both `https://` and `http://` and follows the full redirect chain manually.  
Each hop is printed with its status code. Final status is colour-coded (green=2xx, yellow=3xx, red=4xx/5xx/unreachable).

```bash
python3 dns_lookup.py example.com --http
```

---

### Propagation check (`--propagation`)

Queries the domain against 6 public resolvers (Cloudflare, Google, Quad9, OpenDNS, Comodo, Level3) plus all authoritative nameservers in parallel.  
Results are compared against the consensus answer — mismatches are highlighted in red.

By default checks `A`, `AAAA`, `MX`, `NS`. Use `-r` to specify other types:

```bash
python3 dns_lookup.py example.com --propagation
python3 dns_lookup.py example.com --propagation -r A MX TXT
```

---

### All checks (`--all-checks`)

Runs every feature in a single command:

```bash
python3 dns_lookup.py example.com --all-checks
python3 dns_lookup.py -f domains.txt --all-checks --hide-empty
```

---

## Examples

```bash
# Standard DNS records, system resolver
python3 dns_lookup.py example.com

# Multiple domains, mail records only
python3 dns_lookup.py example.com another.com -r MX TXT NS

# Bulk lookup from file, hide empty types
python3 dns_lookup.py -f domains.txt --hide-empty

# Use a named nameserver as resolver
python3 dns_lookup.py example.com --resolver ns1-37.azure-dns.com

# Use Cloudflare resolver
python3 dns_lookup.py example.com --resolver 1.1.1.1

# JSON output — pipe to jq
python3 dns_lookup.py example.com --json
python3 dns_lookup.py -f domains.txt --json | jq '.[].MX'

# No color (for logging to file)
python3 dns_lookup.py -f domains.txt --no-color > results.txt

# Full audit of a single domain
python3 dns_lookup.py example.com --all-checks

# Mail audit with a known DKIM selector
python3 dns_lookup.py example.com --mail-audit --dkim-selector selector1

# Propagation check for A and MX only
python3 dns_lookup.py example.com --propagation -r A MX

# Check zone transfer exposure
python3 dns_lookup.py example.com --axfr
```

---

## Output format

**Terminal output** shows a header per domain, then sections per record type with TTL:

```
┌──────────────────────────────────────────────────────────┐
│  [1/1] example.com                                       │
└──────────────────────────────────────────────────────────┘

  A        IPv4 address
  ────────────────────────────────────────────────────────
  [TTL    300]  93.184.216.34

  MX       Mail exchange
  ────────────────────────────────────────────────────────
  [TTL   3600]  [prio     0]  mail.protection.outlook.com.

  ── MAIL AUDIT (SPF / DKIM / DMARC) ─────────────────────

  SPF
    v=spf1 include:spf.protection.outlook.com -all
  ✔  '-all' hard fail — only listed servers may send
  ℹ  Includes: spf.protection.outlook.com

  DMARC
    v=DMARC1; p=reject; rua=mailto:dmarc@example.com
  ✔  p=reject — failing mail is rejected
  ℹ  Aggregate reports → mailto:dmarc@example.com
```

**JSON output** (`--json`) returns structured data (DNS records only, not extended checks):

```json
{
  "example.com": {
    "A": [
      { "ttl": 300, "value": "93.184.216.34" }
    ],
    "AAAA": { "error": "noanswer", "msg": "" }
  }
}
```

---

## Notes

- NXDOMAIN is detected and reported immediately — remaining record types are skipped for that domain.
- `--resolver` accepts both IP addresses and hostnames (e.g. `ns1-37.azure-dns.com`).
- Propagation check runs all resolvers in parallel for speed.
- DKIM probes ~15 common selectors; use `--dkim-selector` to add your own.
- The script is safe to run in a pipeline or as part of automation.
# dns_lookup.py

Comprehensive DNS record lookup tool for single domains or bulk lists from a file.  
Includes WHOIS, mail security audit (SPF/DKIM/DMARC), zone transfer testing, HTTP checks, and propagation checking.

---

## Requirements

Python 3.6+ and `dnspython`. For WHOIS support, also install `python-whois`.

```bash
pip3 install dnspython
pip3 install python-whois   # optional, needed for --whois
```

---

## Usage

```
python3 dns_lookup.py [domains ...] [options]
```

### Single domain

```bash
python3 dns_lookup.py example.com
```

### Multiple domains

```bash
python3 dns_lookup.py example.com another.com third.com
```

### From a text file

One domain per line. Lines starting with `#` are treated as comments and ignored.

```bash
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

### Mix file and CLI domains

```bash
python3 dns_lookup.py extra.com -f domains.txt
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
| `--whois` | Show WHOIS info (registrar, expiry, nameservers) |
| `--mail-audit` | Analyse SPF, DKIM, and DMARC records |
| `--dkim-selector SEL` | Extra DKIM selector to check alongside common ones |
| `--axfr` | Attempt zone transfer (AXFR) against all nameservers |
| `--http` | Check HTTP/HTTPS reachability and follow redirect chain |
| `--propagation` | Check DNS propagation across public resolvers + auth NS |
| `--all-checks` | Run all of the above checks in one go |

---

## Record types

All of the following are queried by default:

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

Query only specific types with `-r`:

```bash
python3 dns_lookup.py example.com -r A AAAA MX TXT
```

---

## Feature details

### WHOIS (`--whois`)

Shows registrar, creation date, expiry date, last updated, status flags, and nameservers.  
Expiry is colour-coded: green (>90 days), yellow (<90 days), red (<30 days).

```bash
python3 dns_lookup.py example.com --whois
```

Requires `pip3 install python-whois`.

---

### Mail audit (`--mail-audit`)

Parses and analyses SPF, DKIM, and DMARC records with actionable findings:

**SPF checks:**
- Detects dangerous `+all` (any server allowed), `~all` (softfail), `-all` (correct hard fail)
- Lists all `include:` and `redirect=` mechanisms
- Warns if DNS lookup count approaches the RFC limit of 10

**DMARC checks:**
- Reports enforcement policy (`none` / `quarantine` / `reject`)
- Flags missing or partial `pct=` coverage
- Warns if aggregate reporting (`rua=`) is not configured

**DKIM checks:**
- Probes ~15 common selectors automatically (`default`, `selector1`, `selector2`, `google`, `k1`, `mail`, etc.)
- Use `--dkim-selector` to add a known selector on top of the defaults

```bash
python3 dns_lookup.py example.com --mail-audit
python3 dns_lookup.py example.com --mail-audit --dkim-selector selector2
```

---

### Zone transfer (`--axfr`)

Attempts an AXFR zone transfer against every NS record for the domain.  
A successful transfer is a security misconfiguration — the script flags it clearly and dumps the returned records.  
A refused transfer reports as a pass.

```bash
python3 dns_lookup.py example.com --axfr
```

---

### HTTP / HTTPS check (`--http`)

Performs a HEAD request to both `https://` and `http://` and follows the full redirect chain manually.  
Each hop is printed with its status code. Final status is colour-coded (green=2xx, yellow=3xx, red=4xx/5xx/unreachable).

```bash
python3 dns_lookup.py example.com --http
```

---

### Propagation check (`--propagation`)

Queries the domain against 6 public resolvers (Cloudflare, Google, Quad9, OpenDNS, Comodo, Level3) plus all authoritative nameservers in parallel.  
Results are compared against the consensus answer — mismatches are highlighted in red.

By default checks `A`, `AAAA`, `MX`, `NS`. Use `-r` to specify other types:

```bash
python3 dns_lookup.py example.com --propagation
python3 dns_lookup.py example.com --propagation -r A MX TXT
```

---

### All checks (`--all-checks`)

Runs every feature in a single command:

```bash
python3 dns_lookup.py example.com --all-checks
python3 dns_lookup.py -f domains.txt --all-checks --hide-empty
```

---

## Examples

```bash
# Standard DNS records, system resolver
python3 dns_lookup.py example.com

# Multiple domains, mail records only
python3 dns_lookup.py example.com another.com -r MX TXT NS

# Bulk lookup from file, hide empty types
python3 dns_lookup.py -f domains.txt --hide-empty

# Use a named nameserver as resolver
python3 dns_lookup.py example.com --resolver ns1-37.azure-dns.com

# Use Cloudflare resolver
python3 dns_lookup.py example.com --resolver 1.1.1.1

# JSON output — pipe to jq
python3 dns_lookup.py example.com --json
python3 dns_lookup.py -f domains.txt --json | jq '.[].MX'

# No color (for logging to file)
python3 dns_lookup.py -f domains.txt --no-color > results.txt

# Full audit of a single domain
python3 dns_lookup.py example.com --all-checks

# Mail audit with a known DKIM selector
python3 dns_lookup.py example.com --mail-audit --dkim-selector selector1

# Propagation check for A and MX only
python3 dns_lookup.py example.com --propagation -r A MX

# Check zone transfer exposure
python3 dns_lookup.py example.com --axfr
```

---

## Output format

**Terminal output** shows a header per domain, then sections per record type with TTL:

```
┌──────────────────────────────────────────────────────────┐
│  [1/1] example.com                                       │
└──────────────────────────────────────────────────────────┘

  A        IPv4 address
  ────────────────────────────────────────────────────────
  [TTL    300]  93.184.216.34

  MX       Mail exchange
  ────────────────────────────────────────────────────────
  [TTL   3600]  [prio     0]  mail.protection.outlook.com.

  ── MAIL AUDIT (SPF / DKIM / DMARC) ─────────────────────

  SPF
    v=spf1 include:spf.protection.outlook.com -all
  ✔  '-all' hard fail — only listed servers may send
  ℹ  Includes: spf.protection.outlook.com

  DMARC
    v=DMARC1; p=reject; rua=mailto:dmarc@example.com
  ✔  p=reject — failing mail is rejected
  ℹ  Aggregate reports → mailto:dmarc@example.com
```

**JSON output** (`--json`) returns structured data (DNS records only, not extended checks):

```json
{
  "example.com": {
    "A": [
      { "ttl": 300, "value": "93.184.216.34" }
    ],
    "AAAA": { "error": "noanswer", "msg": "" }
  }
}
```

---

## Notes

- NXDOMAIN is detected and reported immediately — remaining record types are skipped for that domain.
- `--resolver` accepts both IP addresses and hostnames (e.g. `ns1-37.azure-dns.com`).
- Propagation check runs all resolvers in parallel for speed.
- DKIM probes ~15 common selectors; use `--dkim-selector` to add your own.
- The script is safe to run in a pipeline or as part of automation.
# dns_lookup.py

Comprehensive DNS record lookup tool for single domains or bulk lists from a file.

---

## Requirements

Python 3.6+ and the `dnspython` library.

```bash
pip3 install dnspython
```

---

## Usage

```
python3 dns_lookup.py [domains ...] [options]
```

### Single domain

```bash
python3 dns_lookup.py example.com
```

### Multiple domains

```bash
python3 dns_lookup.py example.com another.com third.com
```

### From a text file

One domain per line. Lines starting with `#` are treated as comments and ignored.

```bash
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

### Mix file and CLI domains

```bash
python3 dns_lookup.py extra.com -f domains.txt
```

---

## Options

| Flag | Description |
|------|-------------|
| `-f`, `--file FILE` | Text file with one domain per line |
| `-r`, `--records TYPE [TYPE ...]` | Record types to query (default: all) |
| `--resolver IP` | Use a specific DNS resolver IP instead of the system default |
| `--timeout SECONDS` | Query timeout in seconds (default: 5) |
| `--json` | Output results as JSON |
| `--hide-empty` | Skip record types that return no data |
| `--no-color` | Disable color output (useful for logging/piping) |

---

## Record types

All of the following are queried by default:

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
| `NAPTR` | Naming authority pointer (used in VoIP/SIP) |
| `SSHFP` | SSH fingerprint |

Query only specific types with `-r`:

```bash
python3 dns_lookup.py example.com -r A AAAA MX TXT
```

---

## Examples

```bash
# All records, system resolver
python3 dns_lookup.py example.com

# Multiple domains, only mail-related records
python3 dns_lookup.py example.com another.com -r MX TXT NS

# Bulk lookup from file, hide types with no data
python3 dns_lookup.py -f domains.txt --hide-empty

# Use Cloudflare resolver
python3 dns_lookup.py example.com --resolver 1.1.1.1

# Use Google resolver with longer timeout
python3 dns_lookup.py example.com --resolver 8.8.8.8 --timeout 10

# JSON output — pipe to jq for filtering
python3 dns_lookup.py example.com --json
python3 dns_lookup.py -f domains.txt --json | jq '.[].MX'

# No color (for logging to file)
python3 dns_lookup.py -f domains.txt --no-color > results.txt
```

---

## Output format

**Terminal output** shows a header per domain, then each record type with TTL and value:

```
┌──────────────────────────────────────────────────────────┐
│  [1/2] example.com                                       │
└──────────────────────────────────────────────────────────┘

  A        IPv4 address
  ────────────────────────────────────────────────────────
  [TTL     300]  93.184.216.34

  MX       Mail exchange
  ────────────────────────────────────────────────────────
  [TTL    3600]  [prio     0]  example-com.mail.protection.outlook.com.

  TXT      Text / SPF / DKIM / DMARC
  ────────────────────────────────────────────────────────
  [TTL    3600]  v=spf1 include:spf.protection.outlook.com -all
```

**JSON output** (`--json`) returns structured data per domain and record type:

```json
{
  "example.com": {
    "A": [
      { "ttl": 300, "value": "93.184.216.34" }
    ],
    "MX": [
      { "ttl": 3600, "value": "[prio     0]  mail.example.com." }
    ],
    "AAAA": { "error": "noanswer", "msg": "" }
  }
}
```

---

## Notes

- NXDOMAIN is detected and reported immediately — remaining record types are skipped for that domain.
- MX and SRV records include priority in the output.
- TXT records with multiple strings are automatically joined.
- SOA records are fully parsed (mname, rname, serial, refresh, retry, expire, minimum).
- The script is safe to run in parallel or as part of a pipeline.
