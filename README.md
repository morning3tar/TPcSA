# TLS/PKI Certificate Scanner and Analyzer

A terminal-based Python tool to scan and analyze TLS/PKI certificates for single or multiple hosts, providing detailed certificate and TLS configuration information.

## Features
- Scan single or multiple hosts (domain/IP, custom port)
- Extract certificate details: subject, issuer, validity, serial, signature algorithm, public key info, SANs
- Security analysis: expiration, weak algorithms, self-signed, hostname mismatch
- TLS configuration analysis: supported protocols, cipher suites, forward secrecy
- HTTP header checks: HSTS, HPKP
- Reporting: summary tables, export to CSV/JSON/HTML/Markdown, color-coded output
- Interactive or CLI-driven operation

## Usage

### 1. Install dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the scanner
#### Single host:
```bash
python main.py --target example.com:443
```
#### Bulk scan from file:
```bash
python main.py --file targets.txt
```
Where `targets.txt` contains one host per line, e.g.:
```
google.com:443
example.com:443
github.com:443
```

### 3. Export results
Add `--export <file>` and `--format csv|json|html|md` to export results:
```bash
python main.py --file targets.txt --export results.csv --format csv
python main.py --file targets.txt --export results.json --format json
python main.py --file targets.txt --export results.html --format html
python main.py --file targets.txt --export results.md --format md
```

## Command Line Usage

### Scan a single host
```bash
python main.py --target example.com:443
```

### Scan multiple hosts from a file
```bash
python main.py --file targets.txt
```
Where `targets.txt` contains one host per line, e.g.:
```
google.com:443
example.com:443
github.com:443
```

### Export results to CSV, JSON, HTML, or Markdown
```bash
python main.py --file targets.txt --export results.csv --format csv
python main.py --file targets.txt --export results.json --format json
python main.py --file targets.txt --export results.html --format html
python main.py --file targets.txt --export results.md --format md
```

### Interactive mode (menu-driven)
Just run:
```bash
python main.py
```
And follow the prompts.

## Requirements
- Python 3.7+
- See `requirements.txt` for dependencies

## Example Output
```
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Host            ┃ Expiry     ┃ Issuer                                 ┃ Algorithm ┃ Warnings ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ google.com:443  │ 2025-06-23 │ CN=WR2                                 │ sha256    │          │
│ example.com:443 │ 2026-01-15 │ CN=DigiCert Global G3 TLS ECC SHA38... │ sha384    │          │
│ github.com:443  │ 2026-02-05 │ CN=Sectigo ECC Domain Validation Se... │ sha256    │          │
└─────────────────┴────────────┴────────────────────────────────────────┴───────────┴──────────┘
google.com:443 details:
  OCSP: OCSP URL present
  CRL: CRL URL present
  Protocols: TLSv1_2
  Ciphers: ECDHE-ECDSA-CHACHA20-POLY1305
  Forward Secrecy: Yes
  HSTS: Not Set
  HPKP: Not Set
example.com:443 details:
  OCSP: OCSP URL present
  CRL: CRL URL present
  Protocols: TLSv1_2
  Ciphers: ECDHE-ECDSA-AES256-GCM-SHA384
  Forward Secrecy: Yes
  HSTS: Not Set
  HPKP: Not Set
github.com:443 details:
  OCSP: OCSP URL present
  CRL: No CRL info
  Protocols: TLSv1_2
  Ciphers: ECDHE-ECDSA-AES128-GCM-SHA256
  Forward Secrecy: Yes
  HSTS: max-age=31536000; includeSubdomains; preload
  HPKP: Not Set
```

## License
MIT 