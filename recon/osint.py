"""
OSINT module.

IP geolocation, username enumeration across social platforms,
WHOIS lookup, and Wayback Machine URL harvesting.
"""

from __future__ import annotations

import json
from argparse import ArgumentParser
from typing import Any

import requests


SITES: dict[str, str] = {
    "github": "https://github.com/{}",
    "twitter": "https://twitter.com/{}",
    "reddit": "https://reddit.com/user/{}",
    "instagram": "https://instagram.com/{}",
    "tiktok": "https://tiktok.com/@{}",
    "telegram": "https://t.me/{}",
    "youtube": "https://youtube.com/@{}",
    "twitch": "https://twitch.tv/{}",
    "pinterest": "https://pinterest.com/{}",
    "medium": "https://medium.com/@{}",
    "gitlab": "https://gitlab.com/{}",
    "keybase": "https://keybase.io/{}",
    "steam": "https://steamcommunity.com/id/{}",
    "spotify": "https://open.spotify.com/user/{}",
    "soundcloud": "https://soundcloud.com/{}",
}


class OSINT:
    """
    OSINT aggregation helpers.

    Example:
        o = OSINT()
        print(o.ip_info("8.8.8.8"))
        print(o.username_enum("torvalds"))
    """

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            )
        })

    def ip_info(self, ip: str) -> dict[str, Any]:
        try:
            r = self.session.get(
                f"http://ip-api.com/json/{ip}",
                timeout=self.timeout,
            )
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    def username_enum(self, username: str) -> dict[str, str]:
        found: dict[str, str] = {}
        for site, tpl in SITES.items():
            url = tpl.format(username)
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code == 200:
                    found[site] = url
                    print(f"[+] {site}  {url}")
            except Exception:
                continue
        return found

    def whois_lookup(self, domain: str) -> dict[str, Any]:
        try:
            import whois
        except ImportError:
            return {"error": "pip install python-whois"}
        try:
            w = whois.whois(domain)
            return {k: str(v) for k, v in dict(w).items() if v}
        except Exception as e:
            return {"error": str(e)}

    def wayback(self, domain: str, limit: int = 100) -> list[str] | dict[str, str]:
        try:
            r = self.session.get(
                "http://web.archive.org/cdx/search/cdx"
                f"?url={domain}/*&output=json&limit={limit}",
                timeout=self.timeout,
            )
            data = r.json()
            return [row[2] for row in data[1:]] if len(data) > 1 else []
        except Exception as e:
            return {"error": str(e)}


def main() -> None:
    p = ArgumentParser(description="OSINT toolkit")
    p.add_argument("--ip", help="IP geolocation lookup")
    p.add_argument("--user", help="username enumeration")
    p.add_argument("--whois", help="WHOIS lookup for a domain")
    p.add_argument("--wayback", help="Wayback Machine URLs for a domain")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    o = OSINT()
    out: dict[str, Any] = {}

    if args.ip:
        out["ip"] = o.ip_info(args.ip)
    if args.user:
        out["username"] = o.username_enum(args.user)
    if args.whois:
        out["whois"] = o.whois_lookup(args.whois)
    if args.wayback:
        out["wayback"] = o.wayback(args.wayback)

    if args.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        for k, v in out.items():
            print(f"\n[{k.upper()}]")
            print(json.dumps(v, indent=2, default=str))


if __name__ == "__main__":
    main()
