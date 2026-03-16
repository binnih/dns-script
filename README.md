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
