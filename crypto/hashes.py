"""
Hashing module.

Compute MD5, SHA1, SHA256, SHA512, BLAKE2, and NTLM hashes.
Includes hash identification (by length / prefix) and wordlist cracking.
NTLM uses a pure-python MD4 implementation because OpenSSL 3.x
disabled md4 in hashlib.
"""

from __future__ import annotations

import hashlib
import json
import struct
from argparse import ArgumentParser
from typing import Any


SUPPORTED: tuple[str, ...] = ("md5", "sha1", "sha256", "sha512", "blake2b", "blake2s")


def _lrot(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _md4(data: bytes) -> bytes:
    """
    Pure-python MD4 implementation.
    Returns 16-byte digest.
    """
    h0, h1, h2, h3 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    orig_len = len(data)
    data = data + b"\x80"
    while len(data) % 64 != 56:
        data += b"\x00"
    data += struct.pack("<Q", (orig_len * 8) & 0xFFFFFFFFFFFFFFFF)

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    for off in range(0, len(data), 64):
        X = struct.unpack("<16I", data[off:off + 64])
        a, b, c, d = h0, h1, h2, h3

        # round 1
        for i in range(4):
            a = _lrot((a + F(b, c, d) + X[i * 4]) & 0xFFFFFFFF, 3)
            d = _lrot((d + F(a, b, c) + X[i * 4 + 1]) & 0xFFFFFFFF, 7)
            c = _lrot((c + F(d, a, b) + X[i * 4 + 2]) & 0xFFFFFFFF, 11)
            b = _lrot((b + F(c, d, a) + X[i * 4 + 3]) & 0xFFFFFFFF, 19)

        # round 2
        for i in range(4):
            a = _lrot((a + G(b, c, d) + X[i] + 0x5A827999) & 0xFFFFFFFF, 3)
            d = _lrot((d + G(a, b, c) + X[i + 4] + 0x5A827999) & 0xFFFFFFFF, 5)
            c = _lrot((c + G(d, a, b) + X[i + 8] + 0x5A827999) & 0xFFFFFFFF, 9)
            b = _lrot((b + G(c, d, a) + X[i + 12] + 0x5A827999) & 0xFFFFFFFF, 13)

        # round 3
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(4):
            a = _lrot((a + H(b, c, d) + X[order[i * 4]] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
            d = _lrot((d + H(a, b, c) + X[order[i * 4 + 1]] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
            c = _lrot((c + H(d, a, b) + X[order[i * 4 + 2]] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
            b = _lrot((b + H(c, d, a) + X[order[i * 4 + 3]] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF

    return struct.pack("<4I", h0, h1, h2, h3)


def _ntlm(text: str) -> str:
    return _md4(text.encode("utf-16-le")).hex()


class HashTools:
    """
    Multi-algorithm hashing utility.

    Example:
        ht = HashTools()
        print(ht.hash_all("password123"))
    """

    @staticmethod
    def hash_one(text: str, algo: str = "sha256") -> str:
        algo = algo.lower()
        if algo == "ntlm":
            return _ntlm(text)
        h = hashlib.new(algo)
        h.update(text.encode("utf-8"))
        return h.hexdigest()

    @staticmethod
    def hash_all(text: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for algo in SUPPORTED:
            try:
                out[algo] = HashTools.hash_one(text, algo)
            except Exception:
                out[algo] = ""
        try:
            out["ntlm"] = _ntlm(text)
        except Exception:
            out["ntlm"] = ""
        return out

    @staticmethod
    def hash_file(path: str, algo: str = "sha256", chunk_size: int = 65536) -> str:
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def identify(hash_val: str) -> list[str]:
        """Guess possible algorithms based on hash characteristics."""
        h = hash_val.strip()
        guesses: list[str] = []
        length = len(h)

        prefixes = {
            "$1$": "md5crypt",
            "$2a$": "bcrypt",
            "$2b$": "bcrypt",
            "$2y$": "bcrypt",
            "$5$": "sha256crypt",
            "$6$": "sha512crypt",
            "$argon2": "argon2",
            "$y$": "yescrypt",
            "$pbkdf2": "pbkdf2",
        }
        for p, name in prefixes.items():
            if h.startswith(p):
                guesses.append(name)

        is_hex = all(c in "0123456789abcdefABCDEF" for c in h)

        if length == 32 and is_hex:
            guesses.extend(["md5", "ntlm", "md4"])
        elif length == 40 and is_hex:
            guesses.extend(["sha1", "mysql41"])
        elif length == 56 and is_hex:
            guesses.append("sha224")
        elif length == 64 and is_hex:
            guesses.extend(["sha256", "sha3-256", "blake2s"])
        elif length == 96 and is_hex:
            guesses.append("sha384")
        elif length == 128 and is_hex:
            guesses.extend(["sha512", "sha3-512", "blake2b"])

        return list(dict.fromkeys(guesses))

    @staticmethod
    def crack(target: str, wordlist: str, algo: str = "md5") -> str | None:
        """Dictionary attack against a single hash."""
        target = target.strip().lower()
        algo = algo.lower()
        try:
            with open(wordlist, "r", errors="ignore") as f:
                for line in f:
                    word = line.rstrip("\r\n")
                    if not word:
                        continue
                    try:
                        if algo == "ntlm":
                            h = _ntlm(word)
                        else:
                            h = hashlib.new(algo, word.encode("utf-8")).hexdigest()
                    except Exception:
                        continue
                    if h == target:
                        return word
        except FileNotFoundError:
            return None
        return None


def main() -> None:
    p = ArgumentParser(description="Hashing utilities")
    sub = p.add_subparsers(dest="cmd")

    p_hash = sub.add_parser("hash", help="hash a string")
    p_hash.add_argument("text")
    p_hash.add_argument("-a", "--algo", default="all", help="algo name or 'all'")
    p_hash.add_argument("--json", action="store_true")

    p_file = sub.add_parser("hashfile", help="hash a file")
    p_file.add_argument("path")
    p_file.add_argument("-a", "--algo", default="sha256")

    p_id = sub.add_parser("identify", help="guess algorithm from hash")
    p_id.add_argument("hash")
    p_id.add_argument("--json", action="store_true")

    p_crack = sub.add_parser("crack", help="dictionary attack")
    p_crack.add_argument("hash")
    p_crack.add_argument("wordlist")
    p_crack.add_argument("-a", "--algo", default="md5")

    args = p.parse_args()

    if args.cmd == "hash":
        ht = HashTools()
        if args.algo == "all":
            result = ht.hash_all(args.text)
        else:
            result = {args.algo: ht.hash_one(args.text, args.algo)}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            for k, v in result.items():
                print(f"{k:<8} {v}")

    elif args.cmd == "hashfile":
        print(HashTools.hash_file(args.path, args.algo))

    elif args.cmd == "identify":
        guesses = HashTools.identify(args.hash)
        if args.json:
            print(json.dumps({"guesses": guesses}, indent=2))
        else:
            if not guesses:
                print("[!] unknown hash format")
            for g in guesses:
                print(f"[+] {g}")

    elif args.cmd == "crack":
        found = HashTools.crack(args.hash, args.wordlist, args.algo)
        if found:
            print(f"[+] cracked: {found}")
        else:
            print("[-] not found in wordlist")

    else:
        p.print_help()


if __name__ == "__main__":
    main()
