# emR00T-toolkit

**A Modular Python Toolkit for Authorized Security Testing and Cybersecurity Research**

`emR00T-toolkit` is a modular cybersecurity toolkit designed to support reconnaissance, web security assessment, cryptographic utilities, network analysis, and security research in authorized environments.

The project aims to bring commonly used security-testing utilities together under a consistent command-line interface, with an emphasis on modularity, readable code, and extensibility.

> **Project status:** Under development. Available commands and functionality depend on the modules implemented in the current version.

## Table of Contents

* [Features](#features)
* [Project Structure](#project-structure)
* [Requirements](#requirements)
* [Installation](#installation)
* [Usage](#usage)
* [Output Formats](#output-formats)
* [Development](#development)
* [Testing](#testing)
* [Roadmap](#roadmap)
* [Responsible Use](#responsible-use)
* [License](#license)

## Features

### Reconnaissance

Utilities for gathering information about authorized targets:

* DNS record enumeration
* Subdomain discovery
* TCP port scanning
* Publicly available information gathering
* Basic target information collection

### Web Security

Tools for assessing web applications in authorized test environments:

* SQL injection detection
* Cross-site scripting (XSS) testing
* Local file inclusion (LFI) checks
* Web directory discovery
* Basic HTTP response analysis

### Cryptography

Utilities for common cryptographic and password-related tasks:

* Hash generation and identification support
* Hash verification
* AES encryption and decryption utilities
* Password generation
* Password strength checks

### Payload Utilities

Encoding and security-testing utilities for controlled lab environments:

* Common data encoding and decoding
* Payload formatting helpers
* Test-input generation

Advanced payload execution, stealth, and evasion capabilities are not considered part of the stable feature set.

### Network Analysis

Planned and existing utilities for inspecting network activity in authorized environments:

* Basic packet inspection
* Protocol and connection analysis
* Structured output for supported analysis results

### OSINT

Utilities for organizing publicly available information:

* Domain-related information gathering
* Public DNS data collection
* Basic organization and target profiling

### Post-Exploitation Research

This area is reserved for future, controlled lab research. It is not represented as a currently implemented feature.

## Project Structure

```text
emR00T-toolkit/
├── recon/
│   ├── dns_enum.py
│   ├── subdomain_brute.py
│   ├── port_scan.py
│   └── osint.py
├── web/
│   ├── sqli_scanner.py
│   ├── xss_scanner.py
│   ├── lfi_scanner.py
│   └── dir_brute.py
├── crypto/
│   ├── hashes.py
│   ├── aes_tools.py
│   └── password.py
├── payload/
│   └── encoding.py
├── network/
│   └── sniffer.py
├── osint/
├── post/
├── docs/
├── tests/
├── scripts/
├── requirements.txt
├── .gitignore
└── README.md
```

*The tree describes the intended layout. Files may be added, renamed, or omitted as development progresses.*

## Requirements

* Python 3.10 or newer
* `pip`
* Git

Dependencies may include:

* `requests` — HTTP requests
* `dnspython` — DNS queries
* `cryptography` — cryptographic operations
* `colorama` — optional terminal formatting

The exact dependencies are defined in `requirements.txt`.

## Installation

Clone the repository:

```bash
git clone https://github.com/emR00T/emR00T-toolkit.git
cd emR00T-toolkit
```

Create and activate a virtual environment.

**Linux:**

```bash
python -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If a module or command is not present in the checked-out version, verify the repository contents before attempting to run it.

## Usage

Run modules from the repository root using Python's module syntax.

### DNS Enumeration

```bash
python -m recon.dns_enum --help
```

### Subdomain Discovery

```bash
python -m recon.subdomain_brute --help
```

### TCP Port Scanner

```bash
python -m recon.port_scan --help
```

### OSINT Utilities

```bash
python -m recon.osint --help
```

### Web Security Checks

```bash
python -m web.sqli_scanner --help
python -m web.xss_scanner --help
python -m web.lfi_scanner --help
python -m web.dir_brute --help
```

### Cryptographic Utilities

```bash
python -m crypto.hashes --help
python -m crypto.aes_tools --help
python -m crypto.password --help
```

### Network Analysis

```bash
python -m network.sniffer --help
```

These commands display each module's available options when the corresponding module and CLI entry point have been implemented.

**Only test systems you own or have explicit permission to assess.** Start with a local lab or intentionally vulnerable training application.

## Output Formats

Where supported, modules may provide structured JSON output for integration with other tools and scripts.

Example:

```bash
python -m recon.port_scan --help
```

Check the relevant module's help output for supported output flags. A `--json` option should only be used for modules that explicitly implement it.

## Development

The project is organized into independent Python modules to make individual utilities easier to maintain, test, and extend.

When adding a module:

1. Place it in the appropriate package.
2. Provide a clear command-line interface.
3. Validate user-supplied arguments.
4. Handle network errors and invalid input gracefully.
5. Document usage and limitations.
6. Add tests for expected behavior.
7. Update this README when functionality changes.

Follow standard Python conventions and keep dependencies limited to what the module actually needs.

## Testing

If the project includes a test suite, run it from the repository root:

```bash
python -m pytest
```

To verify that Python files compile:

```bash
python -m compileall -q recon web crypto payload network osint post
```

A successful compilation check does not guarantee that a module works correctly. Test functionality in an isolated environment before relying on it.

## Roadmap

Planned improvements may include:

* [ ] Consistent CLI argument handling across modules
* [ ] Shared configuration and logging
* [ ] Standardized JSON output
* [ ] Expanded unit and integration tests
* [ ] Improved error handling and input validation
* [ ] Documentation and usage examples for every module
* [ ] Reusable components for authorized security assessments
* [ ] Controlled lab exercises for advanced security research

Roadmap items are proposals, not claims about features available in the current release.

## Responsible Use

`emR00T-toolkit` is intended for **authorized security testing, education, and defensive research**.

Users are responsible for obtaining permission before scanning or testing systems they do not own. Unauthorized access, disruption, data collection, or other unlawful activity is not supported or encouraged.

The maintainers are not responsible for misuse of this software or for damage caused by unauthorized testing.

## License

Refer to the repository's `LICENSE` file for the applicable license terms.

---

**Developed by emR00T**
*Learn. Test. Understand. Secure.*
