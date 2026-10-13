# 01 - Cryptographic Concepts & Security Model

Welcome to the architectural and cryptographic theory behind **PASS VAULT (`pv`)**. This guide covers the mathematical, cryptographic, and architectural principles required to build a zero-knowledge password manager.

---

## Table of Contents
1. [The Password Manager Problem](#1-the-password-manager-problem)
2. [Cryptographic Primitives: Hashing vs. Ciphers](#2-cryptographic-primitives-hashing-vs-ciphers)
3. [The Zero-Knowledge Principle](#3-the-zero-knowledge-principle)
4. [Key Derivation Functions (KDF): Why Not SHA-256?](#4-key-derivation-functions-kdf-why-not-sha-256)
5. [Argon2id: The Memory-Hard Gold Standard](#5-argon2id-the-memory-hard-gold-standard)
6. [Authenticated Encryption (AEAD): Confidentiality + Integrity](#6-authenticated-encryption-aead-confidentiality--integrity)
7. [AES-256-GCM Deep Dive](#7-aes-256-gcm-deep-dive)
8. [The Anti-Oracle Principle: Why "Wrong Password" and "Tampered File" Are Indistinguishable](#8-the-anti-oracle-principle-why-wrong-password-and-tampered-file-are-indistinguishable)
9. [Cryptographically Secure Randomness](#9-cryptographically-secure-randomness)
10. [Storage Durability: fsync, Atomic Replace, and Locking](#10-storage-durability-fsync-atomic-replace-and-locking)
11. [KDF Aging and Password Rotation](#11-kdf-aging-and-password-rotation)
12. [What This Project Does NOT Defend Against — And Why](#12-what-this-project-does-not-defend-against--and-why)

---

## 1. The Password Manager Problem
Humans are notoriously bad at remembering unique high-entropy strings across hundreds of online services. Consequently, users tend to reuse passwords or select predictable passwords vulnerable to dictionary attacks and credential stuffing.

A password manager solves this by requiring the user to memorize exactly **one** master password, offloading the generation, storage, and retrieval of distinct 128+ bit entropy passwords to an encrypted local database.

---

## 2. Cryptographic Primitives: Hashing vs. Ciphers

A common novice misconception is confusing **hashing** with **encryption**:
- **Cryptographic Hash (One-Way):** $H(m) \to h$. Given $h$, it is computationally infeasible to invert $h$ back to $m$. Hashes are used for integrity verification and password checking.
- **Symmetric Cipher (Two-Way):** $E_k(m) \to c$ and $D_k(c) \to m$. With the key $k$, ciphertext $c$ can be decrypted back to plaintext $m$.

A password manager stores credentials that must be recovered, so it requires **symmetric encryption**, not just hashing.

---

## 3. The Zero-Knowledge Principle
The master password is **never written to disk**, never cached in logs, and never stored alongside the ciphertext. The derived key is computed strictly on-demand in volatile RAM and discarded when the process exits.

Even if an attacker gains complete read access to the encrypted vault file `vault.json`, they learn nothing about your stored secrets without recovering the master password.

---

## 4. Key Derivation Functions (KDF): Why Not SHA-256?
Why can't we just take `SHA-256(master_password)` and use the resulting 32-byte digest as our AES key?

Fast cryptographic hash functions like SHA-256 or MD5 were designed to be **fast** (processing gigabytes per second). A modern GPU cluster can compute upwards of **100 billion SHA-256 hashes per second**.
If an attacker steals your vault file, a master password with 40 bits of entropy would be cracked in less than a second!

A **Key Derivation Function (KDF)** solves this by being intentionally **slow and resource-intensive**, forcing attackers to spend substantial computing time and hardware memory on every single guess.

---

## 5. Argon2id: The Memory-Hard Gold Standard
Winner of the Password Hashing Competition (PHC) and codified in **RFC 9106**, **Argon2** is the modern standard for password-based key derivation.

Argon2 comes in three variants:
- **Argon2d:** Maximizes resistance to GPU-based cracking by utilizing data-dependent memory access. (Susceptible to side-channel cache-timing attacks).
- **Argon2i:** Uses data-independent memory access to prevent side-channel timing attacks.
- **Argon2id (Used in PASS VAULT):** A hybrid approach. It uses Argon2i passes over the first half of memory to defeat side-channels, followed by Argon2d passes over the remainder to maximize GPU/ASIC cracking resistance.

### Parameters Used in PASS VAULT (OWASP Recommended):
- **Memory Cost ($m$):** `65,536 KiB` (64 MiB of RAM). An attacker trying to run millions of parallel cracking instances on GPUs quickly runs out of VRAM.
- **Time Cost ($t$):** `3` iterations.
- **Parallelism ($p$):** `4` concurrent execution lanes.
- **Salt Length:** `16 bytes` (128 bits) of cryptographic entropy from the OS CSPRNG.
- **Derivation Time:** ~0.5 seconds on modern CPUs. At ~0.5s per guess, a billion guesses would take ~15 years!

---

## 6. Authenticated Encryption (AEAD): Confidentiality + Integrity
Traditional encryption modes (such as AES-CBC without HMAC) provide **confidentiality** but not **integrity**. Attackers who can modify the ciphertext on disk can execute bit-flipping attacks, padding oracle attacks, or truncate records without being detected.

**Authenticated Encryption with Associated Data (AEAD)** solves this by computing an unforgeable cryptographic authentication tag over the ciphertext and nonce. If even a single bit of the file is flipped or deleted, decryption fails immediately.

---

## 7. AES-256-GCM Deep Dive
PASS VAULT uses **AES-256-GCM** (Galois/Counter Mode):
- **AES-256:** Uses a 256-bit symmetric key derived via Argon2id.
- **Counter Mode (CTR):** Encrypts a counter value with AES and XORs it with plaintext, turning a block cipher into a stream cipher.
- **Galois Message Authentication Code (GMAC):** Evaluates polynomial operations over the Galois Field $\text{GF}(2^{128})$ to produce a 128-bit authentication tag.
- **Nonce Rule:** A fresh 96-bit (12-byte) nonce is generated via `secrets.token_bytes(12)` on **every single write**. Reusing a nonce with the same key under GCM destroys authentication security and can leak plaintext.

---

## 8. The Anti-Oracle Principle: Why "Wrong Password" and "Tampered File" Are Indistinguishable
In PASS VAULT, if you provide an incorrect master password or if an adversary modifies the vault file on disk, the system raises the exact same typed exception:

```
WrongPasswordError("Invalid master password or corrupted vault file")
```

### Why?
If a software tool differentiates between:
1. "The password you entered is incorrect"
2. "The password was right, but byte 42 was corrupted"

...the application acts as an **oracle**! An attacker with partial key knowledge or who modified specific bytes could query the system to test hypotheses about the file structure. Cryptographically, both events represent a mismatch of the AES-GCM 128-bit authentication tag. Refusing to distinguish them eliminates side-channel leakage.

---

## 9. Cryptographically Secure Randomness
Python provides two random number generators:
- `random`: Uses the Mersenne Twister (MT19937). It is **not** cryptographically secure. After observing 624 32-bit outputs, an adversary can predict all future outputs!
- `secrets`: Wraps OS-level CSPRNGs (`/dev/urandom` on POSIX or `CryptGenRandom`/`BCryptGenRandom` on Windows).

PASS VAULT uses `secrets` exclusively:
- For 16-byte Argon2id salts
- For 12-byte AES-GCM nonces
- For password generation characters and the Fisher-Yates shuffle

---

## 10. Storage Durability: fsync, Atomic Replace, and Locking
Data corruption during power loss or concurrent execution is a major risk in credential storage. PASS VAULT implements a strict write pipeline:

1. **Permission at Syscall:** Temporary file is created with mode `0o600` directly in `os.open` (no race condition between creation and `os.chmod`).
2. **Buffer Flush (`fsync`):** `os.fsync(fd)` flushes OS page cache buffers to physical non-volatile storage.
3. **Atomic Rename (`os.replace`):** Uses POSIX atomic rename semantics. The vault is always 100% the old version or 100% the new version—never partially written.
4. **Parent Directory Flush:** `os.fsync(dir_fd)` commits the updated directory entry on POSIX filesystems.
5. **Process Serialization:** Uses `fcntl.flock(fd, fcntl.LOCK_EX)` on a sidecar `.lock` file to prevent racing write operations from concurrent CLI invocations.

---

## 11. KDF Aging and Password Rotation
Over time, hardware capabilities increase (Moore's law, ASIC advances). A KDF parameter tuned in 2020 might be weak in 2030.

PASS VAULT stores its KDF parameters directly in the vault envelope:
- Older vaults can be unlocked using the parameters they were created with.
- Parameter minimum floors are strictly validated on load to prevent malicious downgrade attacks.
- Running `pv change-password` automatically upgrades the vault to the latest OWASP parameters under a fresh salt and key.

---

## 12. What This Project Does NOT Defend Against — And Why

A credible security system must be transparent about its threat model boundaries. PASS VAULT defends against an offline attacker who steals or copies your `vault.json` file. It does **not** defend against the following threat vectors:

### §12.1 Compromised Endpoints (Rootkits & Keyloggers)
If an adversary has kernel access, root privileges, or an active keylogger on your machine, no software password manager can save you. When you type your master password into the terminal, a keylogger captures the keystrokes before PASS VAULT receives them.

### §12.2 Memory Scraping While Unlocked
While the vault is unlocked in RAM, the plaintext secrets and derived key reside in process memory. An attacker with `ptrace` capabilities, root access, or physical DMA (Direct Memory Access) devices could dump the process memory. While Python's garbage collection eventually reclaims memory, Python strings are immutable and cannot be reliably zeroized in user-space without custom C extensions.

### §12.3 Clipboard Snooping
If you copy a generated or retrieved password to your system clipboard (`pbcopy` / `xclip`), any background application with clipboard read permissions can inspect it. We recommend using clipboard managers with auto-clear timers.

### §12.4 File Size & Metadata Leakage
The encrypted vault file is a JSON envelope. While the plaintext contents are encrypted, an observer can infer:
- The approximate size of your vault (number of credentials).
- The file modification timestamp.
- The KDF parameters stored in the plaintext envelope header.

### §12.5 Master Password Weakness & Coercion
If the user selects `password123` as their master password, even Argon2id's 64 MiB memory hardness will only delay a dictionary attack by seconds. Cryptography cannot compensate for insufficient human entropy. Furthermore, software cannot defend against rubber-hose cryptanalysis (coercion).
