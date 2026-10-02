# Web Module — emR00T-toolkit

The `web` module provides HTTP-based security assessment utilities for authorized web application testing. It includes scanners for SQL injection indicators, reflected cross-site scripting (XSS), local file inclusion (LFI), and directory or file discovery.

> **Scope:** These tools perform preliminary checks and may produce false positives or false negatives. Findings should be manually verified in an authorized test environment.

## Table of Contents

* [Modules](#modules)
* [Requirements](#requirements)
* [Installation](#installation)
* [Usage](#usage)
* [Command-Line Options](#command-line-options)
* [Detection Coverage](#detection-coverage)
* [Output and Limitations](#output-and-limitations)
* [Local Testing](#local-testing)
* [Responsible Use](#responsible-use)

## Modules

| File              | Description                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------------- |
| `sqli_scanner.py` | Checks URL parameters for database error signatures associated with SQL injection.                  |
| `xss_scanner.py`  | Checks whether test inputs are reflected in HTTP responses in ways that may indicate reflected XSS. |
| `lfi_scanner.py`  | Checks for file-inclusion indicators using path traversal and PHP filter-related test cases.        |
| `dir_brute.py`    | Performs multithreaded discovery of common web directories and files.                               |

## Requirements

* Python 3.10+
* `requests`

Install the project's dependencies from the repository root:

```bash
pip install -r requirements.txt
```

If you are developing or testing the module independently, install the dependency directly:

```bash
python -m pip install requests
```

## Usage

Run commands from the root directory of `emR00T-toolkit`.

Only use targets that you own or have explicit authorization to assess. The examples below use placeholder URLs; replace them with endpoints in your own test environment.

### 1. SQL Injection Scanner

The SQL injection scanner checks URL parameters for known database error signatures.

```bash
# Check a URL with a query parameter
python -m web.sqli_scanner "http://localhost:8000/page.php?id=1"

# Check a URL containing multiple parameters
python -m web.sqli_scanner "http://localhost:8000/item?id=1&cat=2" --json
```

An error-signature match is an indicator for further investigation, not conclusive proof of SQL injection.

### 2. Reflected XSS Scanner

The XSS scanner checks whether supplied test inputs are reflected in the HTTP response.

```bash
# Check a search parameter
python -m web.xss_scanner "http://localhost:8000/search?q=test"

# Check a URL containing multiple parameters
python -m web.xss_scanner "http://localhost:8000/page?name=test&lang=en"
```

Reflection alone does not establish exploitability. Context, output encoding, browser parsing, and the application's security controls affect whether a vulnerability exists.

### 3. Local File Inclusion Scanner

The LFI scanner checks URL parameters for file-inclusion indicators.

```bash
# Check a file parameter
python -m web.lfi_scanner "http://localhost:8000/page.php?file=home"

# Check a path parameter
python -m web.lfi_scanner "http://localhost:8000/view?path=index"
```

Use this scanner only in an authorized environment. Do not use it to access files or data outside your permitted test scope.

### 4. Directory and File Discovery

The directory discovery module checks common paths and optional file extensions.

```bash
# Discover common paths
python -m web.dir_brute "http://localhost:8000/"

# Use a custom wordlist
python -m web.dir_brute "http://localhost:8000/" -w wordlist.txt

# Check selected extensions
python -m web.dir_brute "http://localhost:8000/" -e php,html,json

# Configure concurrency and request timeout
python -m web.dir_brute "http://localhost:8000/" -t 20 --timeout 3

# Hide selected HTTP status codes
python -m web.dir_brute "http://localhost:8000/" --exclude 404,403

# Request JSON output
python -m web.dir_brute "http://localhost:8000/" --json
```

Use conservative concurrency when testing shared or production environments.

## Command-Line Options

### SQLi, XSS, and LFI scanners

| Option        | Description                                                   |
| ------------- | ------------------------------------------------------------- |
| `url`         | Target URL to check, including the relevant query parameters. |
| `--timeout N` | HTTP request timeout in seconds; default: `8`.                |
| `--json`      | Output results in JSON format.                                |

### `dir_brute.py`

| Option               | Description                                                |
| -------------------- | ---------------------------------------------------------- |
| `url`                | Base URL for path discovery.                               |
| `-w`, `--wordlist`   | Path to a custom wordlist.                                 |
| `-e`, `--extensions` | Comma-separated file extensions, such as `php,html,json`.  |
| `-t`, `--threads`    | Number of worker threads; default: `30`.                   |
| `--timeout N`        | HTTP request timeout in seconds; default: `5`.             |
| `--exclude`          | Comma-separated HTTP status codes to hide; default: `404`. |
| `--json`             | Output results in JSON format.                             |

Check the implementation for exact argument requirements and supported options:

```bash
python -m web.sqli_scanner --help
python -m web.xss_scanner --help
python -m web.lfi_scanner --help
python -m web.dir_brute --help
```

## Detection Coverage

The following describes the module's documented test coverage. Actual behavior depends on the payloads and signatures implemented in the checked-out source code.

### SQL Injection

* Error-signature checks for MySQL, PostgreSQL, Microsoft SQL Server, Oracle, and SQLite.
* Approximately 20 known database error signatures.

This approach primarily detects error-based indicators. It does not reliably detect every SQL injection vulnerability, particularly cases where the application suppresses database errors.

### Reflected XSS

* Approximately 10 test payloads.
* Categories include script elements, event handlers, SVG, iframe, JavaScript URI, and image error handlers.

A reflected string is not necessarily executable JavaScript. Results require contextual verification.

### Local File Inclusion

* Approximately 14 traversal-oriented test cases.
* Unix- and Windows-oriented file indicators.
* PHP filter-wrapper test cases.
* Detection signatures associated with files such as `/etc/passwd`, `win.ini`, and `boot.ini`.

Results depend on operating system, application behavior, PHP configuration, input filtering, and response handling.

### Directory and File Discovery

* Approximately 90 common paths in the built-in wordlist.
* 12 default file extensions.
* Records response status, response size, and the `Location` header.

A discovered path is not necessarily accessible or vulnerable. HTTP status codes and redirects must be interpreted in context.

## Output and Limitations

Modules that implement `--json` can provide machine-readable results suitable for scripts and further analysis.

Example:

```bash
python -m web.dir_brute "http://localhost:8000/" --json
```

The JSON schema may differ between modules. Check each implementation before depending on its output in automation.

All four modules are documented as using HTTP GET requests. However, GET requests are not guaranteed to be harmless: they can trigger application-side actions, generate logs, or place a load on the server.

Other limitations include:

* False positives and false negatives.
* Rate limiting, authentication, and session requirements.
* Redirects, proxies, and web application firewalls affecting responses.
* Differences between test environments and production systems.

## Local Testing

For basic HTTP testing, start a local server:

```bash
python -m http.server 8000
```

Then run directory discovery against it:

```bash
python -m web.dir_brute "http://127.0.0.1:8000/"
```

This is useful for checking basic HTTP requests and path discovery. The Python static HTTP server does **not** provide a realistic SQL database, PHP runtime, or vulnerable web application, so it is not sufficient to validate SQLi, XSS, or LFI detection.

For those tests, use an isolated lab application specifically designed for security training.

## Responsible Use

The `web` module is intended for authorized penetration testing, cybersecurity education, and defensive research.

* Obtain explicit permission before testing a website or application.
* Keep testing within the agreed scope.
* Use conservative request rates and thread counts.
* Avoid accessing sensitive files or data.
* Do not treat scanner output as a substitute for manual verification.
* Stop testing if the target behaves unexpectedly or becomes unstable.

Users are responsible for complying with applicable laws and the terms governing the systems they test.

---

**Part of [emR00T-toolkit](https://github.com/emR00T/emR00T-toolkit)**
