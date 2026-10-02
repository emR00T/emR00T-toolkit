"""
AES encryption module.

AES-CBC and AES-GCM with raw key or passphrase-derived key.
Includes Fernet (AES-CBC + HMAC) convenience wrappers.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from argparse import ArgumentParser
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding as sympad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


KDF_ITERATIONS = 200_000
SALT_LEN = 16
IV_LEN = 16
GCM_NONCE_LEN = 12


class AESTools:
    """
    AES encryption helpers.

    Example:
        a = AESTools()
        token = a.encrypt_cbc(b"key"*8, "secret message")
        print(a.decrypt_cbc(b"key"*8, token))
    """

    # ---------- AES-CBC ----------
    @staticmethod
    def encrypt_cbc(key: bytes, plaintext: str | bytes) -> str:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        padder = sympad.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        iv = secrets.token_bytes(IV_LEN)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        return base64.b64encode(iv + ct).decode("ascii")

    @staticmethod
    def decrypt_cbc(key: bytes, token_b64: str) -> bytes:
        data = base64.b64decode(token_b64)
        iv, ct = data[:IV_LEN], data[IV_LEN:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = sympad.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    # ---------- AES-GCM ----------
    @staticmethod
    def encrypt_gcm(key: bytes, plaintext: str | bytes, aad: bytes = b"") -> str:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        nonce = secrets.token_bytes(GCM_NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, plaintext, aad)
        return base64.b64encode(nonce + ct).decode("ascii")

    @staticmethod
    def decrypt_gcm(key: bytes, token_b64: str, aad: bytes = b"") -> bytes:
        data = base64.b64decode(token_b64)
        nonce, ct = data[:GCM_NONCE_LEN], data[GCM_NONCE_LEN:]
        return AESGCM(key).decrypt(nonce, ct, aad)

    # ---------- Passphrase-based ----------
    @staticmethod
    def derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
        if salt is None:
            salt = secrets.token_bytes(SALT_LEN)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return kdf.derive(passphrase.encode("utf-8")), salt

    @staticmethod
    def encrypt_passphrase(passphrase: str, plaintext: str) -> str:
        key, salt = AESTools.derive_key(passphrase)
        ct_b64 = AESTools.encrypt_gcm(key, plaintext)
        bundle = {"salt": base64.b64encode(salt).decode(), "ct": ct_b64}
        return base64.b64encode(json.dumps(bundle).encode()).decode()

    @staticmethod
    def decrypt_passphrase(passphrase: str, token_b64: str) -> str:
        bundle = json.loads(base64.b64decode(token_b64).decode())
        salt = base64.b64decode(bundle["salt"])
        key, _ = AESTools.derive_key(passphrase, salt)
        return AESTools.decrypt_gcm(key, bundle["ct"]).decode("utf-8")

    # ---------- Key / Fernet ----------
    @staticmethod
    def gen_key_32() -> str:
        return base64.b64encode(secrets.token_bytes(32)).decode()

    @staticmethod
    def gen_fernet_key() -> str:
        return Fernet.generate_key().decode()

    @staticmethod
    def fernet_encrypt(key: str, text: str) -> str:
        return Fernet(key.encode()).encrypt(text.encode()).decode()

    @staticmethod
    def fernet_decrypt(key: str, token: str) -> str:
        return Fernet(key.encode()).decrypt(token.encode()).decode()


def main() -> None:
    p = ArgumentParser(description="AES / Fernet tools")
    sub = p.add_subparsers(dest="cmd")

    p_key = sub.add_parser("genkey", help="generate AES-256 key (base64)")
    p_key.add_argument("--fernet", action="store_true", help="generate Fernet key")

    p_enc = sub.add_parser("encrypt", help="encrypt a message")
    p_enc.add_argument("text")
    p_enc.add_argument("--key", help="base64 AES key or Fernet key")
    p_enc.add_argument("--passphrase", help="derive key from passphrase")
    p_enc.add_argument("--mode", choices=["gcm", "cbc", "fernet"], default="gcm")

    p_dec = sub.add_parser("decrypt", help="decrypt a token")
    p_dec.add_argument("token")
    p_dec.add_argument("--key")
    p_dec.add_argument("--passphrase")
    p_dec.add_argument("--mode", choices=["gcm", "cbc", "fernet"], default="gcm")

    args = p.parse_args()

    a = AESTools()

    if args.cmd == "genkey":
        if args.fernet:
            print(a.gen_fernet_key())
        else:
            print(a.gen_key_32())

    elif args.cmd == "encrypt":
        if args.passphrase:
            print(a.encrypt_passphrase(args.passphrase, args.text))
        elif args.key:
            if args.mode == "fernet":
                print(a.fernet_encrypt(args.key, args.text))
            elif args.mode == "gcm":
                print(a.encrypt_gcm(base64.b64decode(args.key), args.text))
            else:
                print(a.encrypt_cbc(base64.b64decode(args.key), args.text))
        else:
            print("[!] need --key or --passphrase")

    elif args.cmd == "decrypt":
        if args.passphrase:
            print(a.decrypt_passphrase(args.passphrase, args.token))
        elif args.key:
            if args.mode == "fernet":
                print(a.fernet_decrypt(args.key, args.token))
            elif args.mode == "gcm":
                print(a.decrypt_gcm(base64.b64decode(args.key), args.token).decode())
            else:
                print(a.decrypt_cbc(base64.b64decode(args.key), args.token).decode())
        else:
            print("[!] need --key or --passphrase")

    else:
        p.print_help()


if __name__ == "__main__":
    main()
