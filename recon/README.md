# Recon Module — emR00T-toolkit

The `recon` module provides reconnaissance utilities for authorized security assessments, including DNS enumeration, subdomain discovery, TCP port scanning, and OSINT lookups.

## Contents

* [Modules](#modules)
* [Requirements](#requirements)
* [Usage](#usage)
* [Command-Line Options](#command-line-options)
* [Built-in Resources](#built-in-resources)
* [Output](#output)
* [Responsible Use](#responsible-use)

## Modules

| File                 | Description                                                                             |
| -------------------- | --------------------------------------------------------------------------------------- |
| `dns_enum.py`        | Queries A, AAAA, MX, NS, TXT, CNAME, and SOA DNS records.                               |
| `subdomain_brute.py` | Performs multithreaded subdomain discovery using a built-in or custom wordlist.         |
| `port_scan.py`       | Performs TCP connect scans, with optional banner grabbing and service lookup.           |
| `osint.py`           | Provides IP geolocation, username searches, WHOIS lookups, and Wayback Machine queries. |

## Requirements

* Python 3.10+
* `dnspython` — DNS enumeration
* `requests` — HTTP-based OSINT queries

The subdomain discovery and TCP scanning modules use Python's standard library.

Install the project's dependencies from the repository root:

```bash
pip install -r requirements.txt
```

## Usage

Run commands from the root directory of `emR00T-toolkit`.

### 1. DNS Enumeration

Query common DNS record types for a domain.

```bash
# Enumerate DNS records
python -m recon.dns_enum example.com

# Use a custom DNS resolver
python -m recon.dns_enum example.com -n 8.8.8.8

# Request JSON output
python -m recon.dns_enum example.com --json
```

### 2. Subdomain Discovery

Search for subdomains using the module's wordlist or a custom wordlist.

```bash
# Use the built-in wordlist
python -m recon.subdomain_brute example.com

# Specify a wordlist and thread count
python -m recon.subdomain_brute example.com -w wordlist.txt -t 50

# Request JSON output
python -m recon.subdomain_brute example.com --json
```

Use a reasonable thread count and timeout to avoid generating excessive DNS traffic.

### 3. TCP Port Scanning

Check selected TCP ports and optionally attempt to retrieve service banners.

```bash
# Scan the default port list
python -m recon.port_scan scanme.nmap.org

# Scan selected ports
python -m recon.port_scan scanme.nmap.org -p 22,80,443

# Scan a port range
python -m recon.port_scan scanme.nmap.org -p 1-1024 -t 100

# Skip banner grabbing and request JSON output
python -m recon.port_scan scanme.nmap.org --no-banner --json
```

Only scan systems for which you have explicit authorization. Large port ranges and high thread counts can generate substantial network traffic.

### 4. OSINT Utilities

Use the OSINT module to query publicly available information.

```bash
# IP geolocation
python -m recon.osint --ip 8.8.8.8

# Search for a username
python -m recon.osint --user torvalds

# Perform a WHOIS lookup
python -m recon.osint --whois example.com

# Retrieve archived URLs from the Wayback Machine
python -m recon.osint --wayback example.com

# Request JSON output
python -m recon.osint --ip 8.8.8.8 --json
```

Results depend on the availability, coverage, and response formats of external services. Username searches and archived URLs should not be treated as proof that an account or resource is currently active.

## Command-Line Options

### `dns_enum.py`

| Option               | Description                    |
| -------------------- | ------------------------------ |
| `domain`             | Target domain to query.        |
| `-n`, `--nameserver` | Custom DNS resolver.           |
| `-t`, `--timeout`    | DNS query timeout in seconds.  |
| `--json`             | Output results in JSON format. |

### `subdomain_brute.py`

| Option             | Description                              |
| ------------------ | ---------------------------------------- |
| `domain`           | Domain to investigate.                   |
| `-w`, `--wordlist` | Path to a custom wordlist.               |
| `-t`, `--threads`  | Number of worker threads; default: `30`. |
| `--timeout`        | Socket timeout in seconds.               |
| `--json`           | Output results in JSON format.           |

### `port_scan.py`

| Option            | Description                                    |
| ----------------- | ---------------------------------------------- |
| `host`            | Target hostname or IP address.                 |
| `-p`, `--ports`   | Ports or ranges, such as `80,443` or `1-1024`. |
| `-t`, `--threads` | Number of worker threads; default: `100`.      |
| `--timeout`       | Connection timeout in seconds.                 |
| `--no-banner`     | Skip banner grabbing.                          |
| `--json`          | Output results in JSON format.                 |

### `osint.py`

| Option      | Description                                   |
| ----------- | --------------------------------------------- |
| `--ip`      | Look up IP geolocation.                       |
| `--user`    | Search for a username on supported platforms. |
| `--whois`   | Look up domain registration information.      |
| `--wayback` | Retrieve archived URLs for a domain.          |
| `--json`    | Output results in JSON format.                |

For exact argument requirements and additional options, consult each module's help output:

```bash
python -m recon.dns_enum --help
python -m recon.subdomain_brute --help
python -m recon.port_scan --help
python -m recon.osint --help
```

## Built-in Resources

The module includes the following resources, according to the project configuration:

* **Subdomain discovery:** approximately 100 common subdomain names.
* **Port scanning:** approximately 40 common TCP ports and their associated service names.
* **Username searches:** support for 15 social platforms.

The actual results depend on the configured wordlists, network conditions, and external service availability.

## Output

Commands that implement the `--json` option can return machine-readable results for use in scripts and other tools.

For example:

```bash
python -m recon.dns_enum example.com --json
```

JSON support and the exact output schema may differ between modules. Check the relevant implementation before building automation around its output.

## Responsible Use

These tools are intended for authorized security testing, educational labs, and legitimate research.

* Obtain permission before scanning or enumerating systems you do not own.
* Respect applicable laws, service terms, and rate limits.
* Avoid excessive concurrency against production systems.
* Treat geolocation and OSINT results as potentially incomplete or outdated.
* Do not use collected information to harass, target, or gain unauthorized access to others.

Although the tools are designed for non-destructive information gathering, network requests can still trigger monitoring systems or affect remote services.

---

**Part of [emR00T-toolkit](https://github.com/emR00T/emR00T-toolkit)**
