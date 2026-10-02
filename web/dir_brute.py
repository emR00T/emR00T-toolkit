"""
Directory and file brute-force module.

Multithreaded discovery of directories and files with support for
custom wordlists, extension lists, status-code filters, and response-size
differences. Handles Ctrl+C gracefully, returning partial results.
"""

from __future__ import annotations

import json
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urljoin

import requests


DEFAULT_WORDLIST: tuple[str, ...] = (
    "admin", "administrator", "login", "logout", "register", "signup",
    "api", "v1", "v2", "v3", "docs", "swagger", "swagger.json", "openapi.json",
    "backup", "backups", "bak", "old", "temp", "tmp", "test", "tests",
    "config", "conf", "settings", ".env", ".git", ".git/config", ".svn",
    "wp-admin", "wp-content", "wp-includes", "wp-config.php.bak",
    "uploads", "upload", "files", "images", "img", "media", "static",
    "assets", "js", "css", "fonts", "download", "downloads",
    "private", "secret", "hidden", "internal", "staging", "dev", "beta",
    "db", "database", "sql", "mysql", "phpmyadmin", "adminer.php",
    "console", "shell", "cgi-bin", "server-status", "server-info",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "humans.txt",
    "phpinfo.php", "info.php", "test.php", "readme.md", "README.md",
    "CHANGELOG.md", "LICENSE", ".htaccess", "web.config",
)


DEFAULT_EXTENSIONS: tuple[str, ...] = (
    "", ".php", ".html", ".htm", ".txt", ".bak", ".old", ".zip", ".tar.gz",
    ".json", ".xml", ".js",
)


class DirBrute:
    """
    Directory / file brute forcer.

    Example:
        d = DirBrute("http://target/", wordlist="words.txt")
        results = d.run()
    """

    def __init__(
        self,
        base_url: str,
        wordlist: str | None = None,
        extensions: list[str] | None = None,
        threads: int = 30,
        timeout: float = 5.0,
        exclude_status: tuple[int, ...] = (404,),
    ) -> None:
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.threads = threads
        self.timeout = timeout
        self.exclude_status = exclude_status
        self.words = self._load_wordlist(wordlist) if wordlist else list(DEFAULT_WORDLIST)
        self.extensions = extensions if extensions is not None else list(DEFAULT_EXTENSIONS)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            )
        })
        self.found: list[dict[str, Any]] = []

    @staticmethod
    def _load_wordlist(path: str) -> list[str]:
        try:
            with open(path, "r", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] wordlist not found, using default: {path}")
            return list(DEFAULT_WORDLIST)

    def _check(self, path: str) -> dict[str, Any] | None:
        url = urljoin(self.base_url, path.lstrip("/"))
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except Exception:
            return None
        if r.status_code in self.exclude_status:
            return None
        return {
            "path": "/" + path.lstrip("/"),
            "url": url,
            "status": r.status_code,
            "size": len(r.content),
            "location": r.headers.get("Location", ""),
        }

    def run(self) -> list[dict[str, Any]]:
        self.found = []
        tasks: list[str] = []
        for w in self.words:
            for ext in self.extensions:
                tasks.append(w + ext)

        executor = ThreadPoolExecutor(max_workers=self.threads)
        try:
            futures = {executor.submit(self._check, t): t for t in tasks}
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                except Exception:
                    continue
                if res:
                    self.found.append(res)
                    line = f"[+] {res['status']}  {res['path']}  ({res['size']}b)"
                    if res["location"]:
                        line += f"  -> {res['location']}"
                    print(line)
        except KeyboardInterrupt:
            print("\n[!] interrupted — returning partial results")
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        self.found.sort(key=lambda x: (x["status"], x["path"]))
        return self.found

    def pretty(self) -> str:
        bar = "=" * 56
        lines = [bar, f"  Dir Brute :: {self.base_url}",
                 f"  Found: {len(self.found)}", bar]
        for f in self.found:
            line = f"  {f['status']}  {f['path']}  ({f['size']}b)"
            if f["location"]:
                line += f"  -> {f['location']}"
            lines.append(line)
        return "\n".join(lines)


def main() -> None:
    p = ArgumentParser(description="Directory / file brute forcer")
    p.add_argument("url", help="base URL, e.g. http://target/")
    p.add_argument("-w", "--wordlist", help="custom wordlist path")
    p.add_argument("-e", "--extensions", help="comma-separated extensions, e.g. .php,.html")
    p.add_argument("-t", "--threads", type=int, default=30)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--exclude", default="404",
                   help="comma-separated status codes to hide (default 404)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    extensions: list[str] | None = None
    if args.extensions:
        extensions = [
            e.strip() if (e.startswith(".") or e == "") else "." + e.strip()
            for e in args.extensions.split(",")
        ]

    exclude = tuple(int(s.strip()) for s in args.exclude.split(",") if s.strip())

    d = DirBrute(
        args.url,
        wordlist=args.wordlist,
        extensions=extensions,
        threads=args.threads,
        timeout=args.timeout,
        exclude_status=exclude,
    )
    results = d.run()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(d.pretty())


if __name__ == "__main__":
    main()
