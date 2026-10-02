"""
TCP port scanner module.

Socket-based multithreaded TCP connect scan with optional banner grabbing.
Ships with a common-ports dictionary covering typical services.
"""

from __future__ import annotations

import json
import socket
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp", 631: "ipp", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    5985: "winrm", 5986: "winrm-ssl", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


class PortScan:
    """
    TCP connect scanner.

    Example:
        ps = PortScan("scanme.nmap.org", ports="22,80,443")
        results = ps.run()
    """

    def __init__(
        self,
        target: str,
        ports: str | list[int] | None = None,
        threads: int = 100,
        timeout: float = 1.0,
        banner: bool = True,
    ) -> None:
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.banner = banner

        if ports is None:
            self.ports: list[int] = list(COMMON_PORTS.keys())
        elif isinstance(ports, str):
            self.ports = self._parse_ports(ports)
        else:
            self.ports = ports

        self.open_ports: list[dict[str, Any]] = []

    @staticmethod
    def _parse_ports(spec: str) -> list[int]:
        result: list[int] = []
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                result.extend(range(int(a), int(b) + 1))
            else:
                result.append(int(part))
        return result

    def _grab_banner(self, sock: socket.socket) -> str:
        try:
            sock.settimeout(2.0)
            data = sock.recv(1024)
            return data.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    def _scan(self, port: int) -> dict[str, Any] | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            if s.connect_ex((self.target, port)) == 0:
                banner = self._grab_banner(s) if self.banner else ""
                s.close()
                return {
                    "port": port,
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "banner": banner,
                }
            s.close()
        except Exception:
            pass
        return None

    def run(self) -> list[dict[str, Any]]:
        self.open_ports = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._scan, p): p for p in self.ports}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    self.open_ports.append(res)
                    line = f"[+] {res['port']}/tcp  {res['service']}"
                    if res["banner"]:
                        line += f"  ::  {res['banner'][:60]}"
                    print(line)
        self.open_ports.sort(key=lambda x: x["port"])
        return self.open_ports

    def pretty(self) -> str:
        bar = "=" * 56
        lines = [
            bar,
            f"  Port Scan :: {self.target}",
            f"  Open: {len(self.open_ports)}",
            bar,
        ]
        for p in self.open_ports:
            lines.append(f"  {p['port']}/tcp  {p['service']}")
            if p["banner"]:
                lines.append(f"      banner: {p['banner'][:100]}")
        return "\n".join(lines)


def main() -> None:
    p = ArgumentParser(description="TCP port scanner")
    p.add_argument("target")
    p.add_argument("-p", "--ports", help="port spec: 80,443,8000-8100")
    p.add_argument("-t", "--threads", type=int, default=100)
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    ps = PortScan(
        args.target,
        ports=args.ports,
        threads=args.threads,
        timeout=args.timeout,
        banner=not args.no_banner,
    )
    results = ps.run()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(ps.pretty())


if __name__ == "__main__":
    main()
