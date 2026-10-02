# Crypto Module — emR00T-toolkit

The `crypto` module provides cryptographic utilities for hashing, hash identification, dictionary-based password auditing, symmetric encryption, secure password generation, and password entropy analysis.

It brings together common cryptographic operations in a modular command-line interface for cybersecurity education, software development, and authorized security auditing.

## Table of Contents

* [Modules](#modules)
* [Requirements](#requirements)
* [Installation](#installation)
* [Usage](#usage)
* [Command-Line Options](#command-line-options)
* [Supported Algorithms](#supported-algorithms)
* [Encryption Details](#encryption-details)
* [Password Security](#password-security)
* [NTLM Compatibility](#ntlm-compatibility)
* [Limitations](#limitations)
* [Responsible Use](#responsible-use)

## Modules

| File           | Description                                                                                             |
| -------------- | ------------------------------------------------------------------------------------------------------- |
| `hashes.py`    | Text and file hashing, hash identification, and dictionary-based hash auditing.                         |
| `aes_tools.py` | AES-CBC and AES-GCM encryption, PBKDF2 key derivation, and Fernet operations.                           |
| `password.py`  | Secure password generation, passphrase generation, entropy estimation, and wordlist mutation utilities. |

## Requirements

* Python 3.10+
* `cryptography`

Install the project's dependencies from the repository root:

```bash
pip install -r requirements.txt
```

To install the cryptographic dependency independently:

```bash
python -m pip install cryptography
```

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/emR00T/emR00T-toolkit.git
cd emR00T-toolkit
```

Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The activation command above is for Linux and other POSIX-compatible shells.

## Usage

Run commands from the repository root using Python's module syntax.

### 1. Hashing and File Integrity

Calculate hashes for text or files:

```bash
# Calculate supported hashes
python -m crypto.hashes hash "password123"

# Select an algorithm
python -m crypto.hashes hash "password123" -a sha256

# Request JSON output
python -m crypto.hashes hash "password123" --json

# Hash a file using streaming reads
python -m crypto.hashes hashfile ./large.bin -a sha256
```

File hashing is useful for integrity checks and comparing file contents without loading an entire large file into memory.

### 2. Hash Identification

Attempt to identify possible hash algorithms from a supplied hash:

```bash
python -m crypto.hashes identify 5f4dcc3b5aa765d61d8327deb882cf99
```

Hash identification is heuristic. Different algorithms can produce digests with the same length or format, so the result is not necessarily unique.

### 3. Dictionary-Based Hash Auditing

The module supports checking candidate passwords from a wordlist against a supplied hash.

```bash
python -m crypto.hashes crack HASH_VALUE wordlist.txt -a md5
```

Use only hashes you own or are explicitly authorized to audit. This operation should not be used to access other people's accounts or credentials.

### 4. Key Generation

Generate an AES key or a Fernet-compatible key:

```bash
# Generate an AES-256 key
python -m crypto.aes_tools genkey

# Generate a Fernet key
python -m crypto.aes_tools genkey --fernet
```

Store generated keys securely. Anyone who obtains a key may be able to decrypt data protected by it.

### 5. AES Encryption and Decryption

Encrypt text using a passphrase:

```bash
python -m crypto.aes_tools encrypt "secret message" --passphrase "YOUR_STRONG_PASSPHRASE"
```

Encrypt using an existing Base64-encoded key and AES-GCM:

```bash
python -m crypto.aes_tools encrypt "data" --key "BASE64_ENCODED_KEY" --mode gcm
```

AES-CBC mode is also supported:

```bash
python -m crypto.aes_tools encrypt "data" --key "BASE64_ENCODED_KEY" --mode cbc
```

Fernet operations:

```bash
python -m crypto.aes_tools encrypt "data" --key "FERNET_KEY" --mode fernet
```

Decrypt data using the matching passphrase or key:

```bash
python -m crypto.aes_tools decrypt "ENCRYPTED_TOKEN" --passphrase "YOUR_STRONG_PASSPHRASE"
```

For AES-GCM:

```bash
python -m crypto.aes_tools decrypt "ENCRYPTED_TOKEN" --key "BASE64_ENCODED_KEY" --mode gcm
```

The decryption mode and key material must match the encryption operation. Preserve the complete encrypted token, including any encoded nonce, IV, salt, or authentication tag required by the implementation.

Avoid placing real secrets directly in shell history or shared terminal logs.

### 6. Secure Password Generation

Generate a password using the module's defaults:

```bash
python -m crypto.password gen
```

Specify a length:

```bash
python -m crypto.password gen -l 24
```

Exclude selected character categories:

```bash
python -m crypto.password gen --no-symbols --no-ambiguous
```

Other supported character controls include:

* `--no-digits`
* `--no-upper`
* `--no-lower`

The `--no-ambiguous` option removes commonly confused characters such as `I`, `l`, `1`, `O`, and `0` from the character pool.

### 7. Passphrase Generation

Generate a word-based passphrase:

```bash
python -m crypto.password passphrase --words 5
```

The number of words and the source wordlist affect the passphrase's security. A larger word count generally increases the search space when words are selected independently and uniformly.

### 8. Password Entropy Estimation

Estimate the entropy of a password:

```bash
python -m crypto.password entropy "Tr0ub4dor&3"
```

Request JSON output:

```bash
python -m crypto.password entropy "YOUR_TEST_PASSWORD" --json
```

Entropy estimates depend on assumptions about how a password was created. They should not be treated as definitive measurements of real-world password strength.

### 9. Wordlist Mutation

Generate common mutations of a base word:

```bash
python -m crypto.password mutate "summer"
```

Generate a wordlist from multiple base words and save it to a file:

```bash
python -m crypto.password wordlist alice bob carol -o words.txt
```

These utilities are intended for controlled password-auditing exercises using authorized test data.

## Command-Line Options

### `hashes.py`

| Command                       | Description                                        |
| ----------------------------- | -------------------------------------------------- |
| `hash TEXT`                   | Calculate supported hash digests.                  |
| `hash TEXT -a ALGO`           | Calculate a digest using a selected algorithm.     |
| `hashfile PATH -a ALGO`       | Hash a file using streaming reads.                 |
| `identify HASH`               | Suggest possible algorithms based on hash format.  |
| `crack HASH WORDLIST -a ALGO` | Check wordlist candidates against a supplied hash. |
| `--json`                      | Request JSON output where supported.               |

The file hashing implementation is documented as using 64 KB chunks.

### `aes_tools.py`

| Option or command   | Description                                         |
| ------------------- | --------------------------------------------------- |
| `genkey`            | Generate an AES key.                                |
| `genkey --fernet`   | Generate a Fernet-compatible key.                   |
| `encrypt TEXT`      | Encrypt text using a key or passphrase.             |
| `decrypt TOKEN`     | Decrypt a token using a matching key or passphrase. |
| `--key KEY`         | Supply the relevant encoded key.                    |
| `--passphrase TEXT` | Supply a passphrase for key derivation.             |
| `--mode gcm`        | Use AES-GCM; documented default.                    |
| `--mode cbc`        | Use AES-CBC.                                        |
| `--mode fernet`     | Use Fernet.                                         |

### `password.py`

| Command or option      | Description                            |
| ---------------------- | -------------------------------------- |
| `gen`                  | Generate a random password.            |
| `-l N`                 | Set password length; default: `20`.    |
| `--no-symbols`         | Exclude symbols.                       |
| `--no-digits`          | Exclude digits.                        |
| `--no-upper`           | Exclude uppercase letters.             |
| `--no-lower`           | Exclude lowercase letters.             |
| `--no-ambiguous`       | Exclude visually ambiguous characters. |
| `passphrase --words N` | Generate a word-based passphrase.      |
| `entropy PASSWORD`     | Estimate password entropy.             |
| `mutate WORD`          | Generate common mutations of a word.   |
| `wordlist BASES...`    | Generate mutations from base words.    |
| `-o FILE`              | Write wordlist output to a file.       |

Check the implemented CLI options with:

```bash
python -m crypto.hashes --help
python -m crypto.aes_tools --help
python -m crypto.password --help
```

## Supported Algorithms

### Hashing

The module documents support for:

* MD5
* SHA-1
* SHA-256
* SHA-512
* BLAKE2b
* BLAKE2s
* NTLM-compatible hashing

**Security note:** MD5, SHA-1, and NTLM are not suitable for storing new application passwords. For application password storage, use a dedicated password-hashing scheme such as Argon2id, scrypt, or appropriately configured bcrypt.

### Symmetric Encryption

* AES-256 in supported modes
* AES-GCM
* AES-CBC
* Fernet

The actual key sizes, accepted encodings, token format, and mode defaults should be confirmed against the implementation.

## Encryption Details

The module documents the following encryption parameters:

| Feature               | Documented behavior                                                   |
| --------------------- | --------------------------------------------------------------------- |
| AES-CBC IV            | Random 16-byte IV prepended to the ciphertext before Base64 encoding. |
| AES-GCM nonce         | Random 12-byte nonce prepended to the ciphertext.                     |
| Passphrase derivation | PBKDF2-HMAC-SHA256 with 200,000 iterations.                           |
| Passphrase salt       | 16-byte salt.                                                         |
| Fernet                | Compatible with the standard `cryptography.Fernet` token format.      |

Important implementation considerations:

* **AES-GCM:** The nonce must never be reused with the same key. Authentication-tag verification must succeed before decrypted data is trusted.
* **AES-CBC:** CBC does not provide authentication by itself. Use a secure authenticated construction when integrity is required; do not treat successful decryption as proof that the ciphertext is authentic.
* **Passphrases:** A salt is not secret, but it should be unique for each encryption operation.
* **Key management:** Keep keys separate from encrypted data and store them in a secure location.
* **Fernet:** Use the same key to decrypt a token that was used to create it.

Do not modify the encryption format without updating the corresponding decryption logic and tests.

## NTLM Compatibility

Some OpenSSL 3.x configurations restrict access to MD4 through standard `hashlib` interfaces. The project documents a pure-Python MD4 implementation for NTLM compatibility.

NTLM is a legacy authentication-related hash format. It should be handled only for compatibility testing and authorized password audits, not used as a modern password-storage mechanism.

## Limitations

* Hash identification is based on format and heuristics, not guaranteed algorithm detection.
* Dictionary auditing can only find candidates present in the supplied wordlist.
* Entropy scores are estimates and depend on assumptions about password generation.
* Encryption security depends on correct implementation, key management, and parameter handling.
* CLI examples and options must match the current source code.

## Responsible Use

The `crypto` module is intended for cryptographic education, data protection, integrity verification, and authorized security auditing.

Use password-auditing and wordlist utilities only with credentials or hashes you are permitted to test. Never use these features to obtain unauthorized access to accounts or systems.

---

**Part of [emR00T-toolkit](https://github.com/emR00T/emR00T-toolkit)**
