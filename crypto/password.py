"""
Password utilities module.

Secure password generation, entropy calculation, mutation-based wordlist
generation for dictionary attacks.
"""

from __future__ import annotations

import json
import math
import secrets
import string
from argparse import ArgumentParser
from typing import Any


class PasswordTools:
    """
    Password generation and analysis.

    Example:
        pt = PasswordTools()
        print(pt.generate(length=24))
        print(pt.entropy("Tr0ub4dor&3"))
    """

    @staticmethod
    def generate(
        length: int = 20,
        symbols: bool = True,
        digits: bool = True,
        upper: bool = True,
        lower: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        pool = ""
        if lower:
            pool += string.ascii_lowercase
        if upper:
            pool += string.ascii_uppercase
        if digits:
            pool += string.digits
        if symbols:
            pool += "!@#$%^&*()-_=+[]{};:,.<>/?"
        if exclude_ambiguous:
            for ch in "Il1O0":
                pool = pool.replace(ch, "")
        if not pool:
            raise ValueError("character pool empty")

        return "".join(secrets.choice(pool) for _ in range(length))

    @staticmethod
    def generate_passphrase(wordlist: str, words: int = 4, separator: str = "-") -> str:
        try:
            with open(wordlist, "r", errors="ignore") as f:
                pool = [w.strip() for w in f if w.strip()]
        except FileNotFoundError:
            pool = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
                    "golf", "hotel", "india", "juliet", "kilo", "lima"]
        picks = [secrets.choice(pool) for _ in range(words)]
        return separator.join(picks)

    @staticmethod
    def entropy(password: str) -> dict[str, Any]:
        pool = 0
        if any(c.islower() for c in password):
            pool += 26
        if any(c.isupper() for c in password):
            pool += 26
        if any(c.isdigit() for c in password):
            pool += 10
        if any(c in "!@#$%^&*()-_=+[]{};:,.<>/?" for c in password):
            pool += 28
        if any(ord(c) > 127 for c in password):
            pool += 100  # rough estimate for unicode

        if pool == 0 or not password:
            bits = 0.0
        else:
            bits = len(password) * math.log2(pool)

        if bits < 28:
            label = "very weak"
        elif bits < 36:
            label = "weak"
        elif bits < 60:
            label = "reasonable"
        elif bits < 80:
            label = "strong"
        else:
            label = "very strong"

        return {
            "length": len(password),
            "pool_size": pool,
            "entropy_bits": round(bits, 2),
            "rating": label,
        }

    @staticmethod
    def mutate(word: str) -> list[str]:
        """Common password mutations for a base word."""
        out = set()
        out.add(word)
        out.add(word.lower())
        out.add(word.upper())
        out.add(word.capitalize())
        out.add(word[::-1])

        suffixes = ["", "1", "12", "123", "1234", "!", "@", "#", "2024", "2025", "!"]
        for s in suffixes:
            out.add(word + s)
            out.add(word.capitalize() + s)

        # leet variants
        leet = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
        leet_word = "".join(leet.get(c.lower(), c) for c in word)
        out.add(leet_word)
        out.add(leet_word + "!")

        return sorted(out)

    @staticmethod
    def wordlist_from_bases(bases: list[str], mutate: bool = True) -> list[str]:
        result: set[str] = set()
        for b in bases:
            if mutate:
                result.update(PasswordTools.mutate(b))
            else:
                result.add(b)
        return sorted(result)


def main() -> None:
    p = ArgumentParser(description="Password tools")
    sub = p.add_subparsers(dest="cmd")

    p_gen = sub.add_parser("gen", help="generate a secure password")
    p_gen.add_argument("-l", "--length", type=int, default=20)
    p_gen.add_argument("--no-symbols", action="store_true")
    p_gen.add_argument("--no-digits", action="store_true")
    p_gen.add_argument("--no-upper", action="store_true")
    p_gen.add_argument("--no-lower", action="store_true")
    p_gen.add_argument("--no-ambiguous", action="store_true")

    p_pass = sub.add_parser("passphrase", help="generate a passphrase")
    p_pass.add_argument("--wordlist", default="/usr/share/dict/words")
    p_pass.add_argument("-w", "--words", type=int, default=4)

    p_ent = sub.add_parser("entropy", help="rate password strength")
    p_ent.add_argument("password")
    p_ent.add_argument("--json", action="store_true")

    p_mut = sub.add_parser("mutate", help="generate mutations of a word")
    p_mut.add_argument("word")
    p_mut.add_argument("--json", action="store_true")

    p_wl = sub.add_parser("wordlist", help="wordlist from base words")
    p_wl.add_argument("bases", nargs="+")
    p_wl.add_argument("-o", "--out", help="write to file")

    args = p.parse_args()
    pt = PasswordTools()

    if args.cmd == "gen":
        print(pt.generate(
            length=args.length,
            symbols=not args.no_symbols,
            digits=not args.no_digits,
            upper=not args.no_upper,
            lower=not args.no_lower,
            exclude_ambiguous=args.no_ambiguous,
        ))

    elif args.cmd == "passphrase":
        print(pt.generate_passphrase(args.wordlist, words=args.words))

    elif args.cmd == "entropy":
        info = pt.entropy(args.password)
        if args.json:
            print(json.dumps(info, indent=2))
        else:
            for k, v in info.items():
                print(f"{k:<14} {v}")

    elif args.cmd == "mutate":
        mutations = pt.mutate(args.word)
        if args.json:
            print(json.dumps(mutations, indent=2))
        else:
            for m in mutations:
                print(m)

    elif args.cmd == "wordlist":
        wl = pt.wordlist_from_bases(args.bases)
        if args.out:
            with open(args.out, "w") as f:
                f.write("\n".join(wl))
            print(f"[+] wrote {len(wl)} entries to {args.out}")
        else:
            print("\n".join(wl))

    else:
        p.print_help()


if __name__ == "__main__":
    main()
