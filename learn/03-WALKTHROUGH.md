# 03 - Codebase Walkthrough & Learning Guide

This guide walks through every module in **PASS VAULT**, explaining the code mechanics, cryptographic APIs, and design choices.

---

## 1. Project Layout Tour

```
Password Manager/
├── passvault/
│   ├── __init__.py        # Package version and export definitions
│   ├── config.py          # Cryptographic parameters and OWASP constants
│   ├── exceptions.py      # Typed error boundary hierarchy
│   ├── generator.py       # CSPRNG password generation with Fisher-Yates shuffle
│   ├── crypto.py          # Low-level Argon2id and AES-256-GCM primitives
│   ├── vault.py           # Atomic writes, fcntl locking, and Vault data model
│   ├── ui.py              # Rich panels and formatted terminal tables
│   └── cli.py             # CLI parser and command handlers
├── tests/
│   ├── test_crypto.py     # 27+ cryptographic primitive unit tests
│   ├── test_generator.py  # 12+ entropy, diversity, and shuffle tests
│   ├── test_vault.py      # 19+ persistence, permissions, and locking tests
│   └── test_cli.py        # 13+ CLI dispatch and security guard tests
├── bin/
│   └── pv                 # Executable wrapper script
├── install.sh             # Automated setup script
├── justfile               # Developer command recipes (test, lint, format)
└── README.md              # Project documentation
```

---

## 2. Cryptographic Engine (`passvault/crypto.py`)

### Argon2id Derivation
We invoke `argon2.low_level.hash_secret_raw`:
```python
key = argon2.low_level.hash_secret_raw(
    secret=master_password.encode("utf-8"),
    salt=salt,
    time_cost=time_cost,
    memory_cost=memory_cost,
    parallelism=parallelism,
    hash_len=hash_len,
    type=Type.ID,
)
```
- We specify `Type.ID` to get the hybrid Argon2id variant.
- Output is a raw 32-byte byte-string (`bytes`), directly usable as an AES-256 key.

### AES-256-GCM AEAD
We use cryptography's `AESGCM`:
```python
aesgcm = AESGCM(key)
nonce = secrets.token_bytes(12)
ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
```
When decrypting, if the tag validation fails, `cryptography.exceptions.InvalidTag` is raised. We catch it and raise:
```python
raise WrongPasswordError("Invalid master password or corrupted vault file")
```

---

## 3. Password Generator (`passvault/generator.py`)

### Eliminating Bias with Fisher-Yates:
```python
# 1. Guarantee 1 char from each pool
chosen_chars = [secrets.choice(pool) for pool in pools]

# 2. Fill the remainder
for _ in range(length - len(chosen_chars)):
    chosen_chars.append(secrets.choice(unified_pool))

# 3. Fisher-Yates (Knuth) in-place shuffle
for i in range(len(chosen_chars) - 1, 0, -1):
    j = secrets.randbelow(i + 1)
    chosen_chars[i], chosen_chars[j] = chosen_chars[j], chosen_chars[i]
```
`secrets.randbelow(i + 1)` selects an integer uniformly from $[0, i]$, avoiding the modulo bias that occurs with `random() % n`.

---

## 4. Vault Persistence & Concurrency (`passvault/vault.py`)

### Preventing the Chmod Race Window:
In naive code, developers often do:
```python
# UNSAFE PATTERN:
with open("tmp.txt", "w") as f:
    f.write(data)
os.chmod("tmp.txt", 0o600)  # RACE WINDOW: File was world-readable between open and chmod!
```
In PASS VAULT, we specify the mode directly in the syscall:
```python
# SAFE PATTERN:
fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, content)
os.fsync(fd)
os.close(fd)
```
The file is created private from the exact moment of inode allocation.

---

## 5. Security Guardrails in CLI (`passvault/cli.py`)

Passwords must **never** be accepted via flags:
```bash
# REJECTED BY DESIGN:
pv add github -p mypassword
```
If an adversary runs `history` or `ps aux`, command-line arguments are visible in plain text.
PASS VAULT intercepts `-p` or `--password` and cleanly refuses with an educational message, ensuring that all passwords pass exclusively through non-echoing `getpass.getpass()` prompts.
