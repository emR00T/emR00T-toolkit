"""
DNS enumeration module.

Queries A, AAAA, MX, NS, TXT, CNAME, SOA records for a given domain.
Supports custom nameservers and JSON output.
"""

from __future__ import annotations

import json
from argparse import ArgumentParser
from typing import Any

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


class DNSEnum:
    """
    DNS record enumerator.

    Example:
        de = DNSEnum("example.com")
        results = de.run()
        print(de.pretty(results))
    """

    def __init__(
        self,
        domain: str,
        timeout: int = 5,
        nameserver: str | None = None,
    ) -> None:
        if not HAS_DNS:
            raise RuntimeError("dnspython not installed. run: pip install dnspython")

        self.domain = domain
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if nameserver:
            self.resolver.nameservers = [nameserver]

    def query(self, record_type: str) -> list[str]:
        """Query a single record type. Returns empty list on failure."""
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            return [str(r) for r in answers]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return []
        except Exception:
            return []

    def run(self) -> dict[str, Any]:
        """Run all record queries. Returns dict keyed by record type."""
        results: dict[str, Any] = {"domain": self.domain}
        for rt in RECORD_TYPES:
            results[rt] = self.query(rt)
        return results

    def pretty(self, results: dict[str, Any]) -> str:
        """Human-readable output."""
        lines: list[str] = []
        bar = "=" * 56
        lines.append(bar)
        lines.append(f"  DNS Enum :: {self.domain}")
        lines.append(bar)
        for rt in RECORD_TYPES:
            vals = results.get(rt, [])
            if vals:
                lines.append("")
                lines.append(f"[{rt}]")
                for v in vals:
                    lines.append(f"  {v}")
        return "\n".join(lines)


def main() -> None:
    p = ArgumentParser(description="DNS record enumeration")
    p.add_argument("domain", help="target domain")
    p.add_argument("-n", "--nameserver", help="custom DNS server (e.g. 8.8.8.8)")
    p.add_argument("-t", "--timeout", type=int, default=5, help="query timeout in seconds")
    p.add_argument("--json", action="store_true", help="emit JSON output")
    args = p.parse_args()

    de = DNSEnum(args.domain, timeout=args.timeout, nameserver=args.nameserver)
    results = de.run()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(de.pretty(results))


if __name__ == "__main__":
    main()
