"""
Subdomain brute-force module.

Multithreaded subdomain enumeration using a wordlist and DNS resolution.
Ships with a built-in common-subdomain list.
"""

from __future__ import annotations

import json
import socket
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


DEFAULT_WORDLIST: tuple[str, ...] = (
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
    "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m",
    "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum",
    "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support",
    "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo",
    "cp", "calendar", "wiki", "web", "media", "email", "images", "img",
    "www1", "intranet", "portal", "video", "sip", "dns2", "api", "cdn",
    "stats", "dns1", "ns4", "www3", "dns", "search", "staging", "server",
    "mx1", "chat", "wap", "my", "svn", "mail1", "sites", "proxy", "ads",
    "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info", "apps",
    "download", "remote", "db", "forums", "store", "relay", "files",
    "newsletter", "app", "live", "owa", "en", "start", "sms", "office",
    "exchange", "ipv4",
)


class SubdomainBrute:
    """
    Multithreaded subdomain brute forcer.

    Example:
        sb = SubdomainBrute("example.com", threads=50)
        found = sb.run()
    """

    def __init__(
        self,
        domain: str,
        wordlist: str | None = None,
        threads: int = 30,
        timeout: float = 2.0,
    ) -> None:
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.words = self._load_wordlist(wordlist) if wordlist else list(DEFAULT_WORDLIST)
        self.found: list[dict[str, str]] = []

    def _load_wordlist(self, path: str) -> list[str]:
        try:
            with open(path, "r", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] wordlist not found, using default: {path}")
            return list(DEFAULT_WORDLIST)

    def _check(self, sub: str) -> tuple[str, str] | None:
        host = f"{sub}.{self.domain}"
        try:
            socket.setdefaulttimeout(self.timeout)
            ip = socket.gethostbyname(host)
            return (host, ip)
        except (socket.gaierror, socket.timeout, OSError):
            return None

    def run(self) -> list[dict[str, str]]:
        """Run brute force. Prints hits as they're found."""
        self.found = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._check, w): w for w in self.words}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    host, ip = res
                    self.found.append({"host": host, "ip": ip})
                    print(f"[+] {host} -> {ip}")
        return self.found

    def pretty(self) -> str:
        bar = "=" * 56
        lines = [
            bar,
            f"  Subdomain Brute :: {self.domain}",
            f"  Found: {len(self.found)}",
            bar,
        ]
        for f in self.found:
            lines.append(f"  {f['host']}  ->  {f['ip']}")
        return "\n".join(lines)


def main() -> None:
    p = ArgumentParser(description="Subdomain brute force")
    p.add_argument("domain")
    p.add_argument("-w", "--wordlist", help="custom wordlist path")
    p.add_argument("-t", "--threads", type=int, default=30)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    sb = SubdomainBrute(
        args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
    )
    results = sb.run()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(sb.pretty())


if __name__ == "__main__":
    main()
