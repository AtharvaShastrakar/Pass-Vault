# 02 - System Architecture & File Format

This document details the architectural layout, serialization envelopes, and POSIX concurrency guarantees implemented in **PASS VAULT (`pv`)**.

---

## 1. High-Level System Architecture

```mermaid
flowchart TD
    User([User Master Password]) --> Argon2id["Argon2id KDF\n(64 MiB, 3 passes, 4 lanes)"]
    Salt[(16-byte Random Salt)] --> Argon2id
    Argon2id --> AESKey["32-Byte AES Key\n(Volatile RAM Only)"]

    Plaintext[(Credentials JSON\nusername, password, url, notes)] --> AESGCM["AES-256-GCM AEAD"]
    Nonce[(12-byte Random Nonce)] --> AESGCM
    AESKey --> AESGCM

    AESGCM --> Ciphertext["Ciphertext + 16-byte Tag"]
    
    subgraph OnDisk ["Durable On-Disk File: ~/.password-vault/vault.json (mode 0600)"]
        Envelope["JSON Envelope\n- version: 1\n- kdf: {algorithm, memory, passes, parallelism, salt}\n- nonce: base64\n- ciphertext: base64"]
    end

    Ciphertext --> Envelope
    Nonce --> Envelope
    Salt --> Envelope
```

---

## 2. On-Disk Vault Envelope Schema

The vault is persisted as an ASCII-encoded JSON envelope with strict permission `0o600`.
Notice that no credential plaintext, master password, or derived key is stored here.

```json
{
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "salt": "base64_encoded_16_bytes_salt==",
    "memory_cost": 65536,
    "time_cost": 3,
    "parallelism": 4,
    "hash_len": 32
  },
  "nonce": "base64_encoded_12_bytes_nonce==",
  "ciphertext": "base64_encoded_ciphertext_and_16_byte_auth_tag=="
}
```

### Decrypted Internal Payload
Once authenticated and decrypted with the derived key, the payload contains:

```json
{
  "entries": {
    "github": {
      "username": "dev_user",
      "password": "k9#V!mP8$xL2@qZ4",
      "url": "https://github.com",
      "notes": "Primary development account",
      "created": "2026-10-13T10:00:00+00:00",
      "updated": "2026-10-13T10:00:00+00:00"
    }
  }
}
```

---

## 3. Atomic, Durable Write Pipeline

To ensure the vault file is never left in a corrupted or half-written state during sudden power loss or process crashes, `passvault.vault._atomic_write_file` implements this exact sequence:

```mermaid
sequenceDiagram
    participant App as PASS VAULT
    participant OS as Kernel / VFS
    participant Disk as Physical Storage

    App->>OS: os.open(tmp_file, O_CREAT|O_WRONLY, 0600)
    Note over App,OS: Mode 0600 set at syscall (no chmod race)
    App->>OS: os.write(fd, ciphertext_bytes)
    App->>Disk: os.fsync(fd) [Flush buffers to hardware]
    App->>OS: os.close(fd)
    App->>OS: os.replace(tmp_file, vault.json) [Atomic inode swap]
    App->>Disk: os.fsync(parent_dir_fd) [Commit directory entry]
    App->>OS: os.close(parent_dir_fd)
```

---

## 4. Advisory File Locking

Concurrent invocations of `pv` (e.g. background automation or multiple open terminal windows) could race to update `vault.json`.

PASS VAULT handles this using POSIX advisory locking on a sidecar file:
`~/.password-vault/vault.json.lock`.

```python
with acquire_vault_lock(vault_path):
    # Lock is held exclusively via fcntl.flock(lock_fd, fcntl.LOCK_EX)
    # Perform read -> decrypt -> modify -> encrypt -> atomic_write
    # Lock is safely released in finally block via fcntl.flock(lock_fd, fcntl.LOCK_UN)
```

---

## 5. Typed Exception Hierarchy

```mermaid
classDiagram
    class PassVaultError {
        <<Base Exception>>
    }
    class WrongPasswordError {
        Invalid password OR tampered file
    }
    class VaultFormatError {
        Corrupted JSON or floor violation
    }
    class VaultNotFoundError {
        Vault file does not exist
    }
    class VaultAlreadyExistsError {
        Vault file exists during init
    }
    class EntryNotFoundError {
        Credential name not in vault
    }
    class EntryAlreadyExistsError {
        Credential name duplicate
    }
    class LockError {
        Unable to acquire file lock
    }

    PassVaultError <|-- WrongPasswordError
    PassVaultError <|-- VaultFormatError
    PassVaultError <|-- VaultNotFoundError
    PassVaultError <|-- VaultAlreadyExistsError
    PassVaultError <|-- EntryNotFoundError
    PassVaultError <|-- EntryAlreadyExistsError
    PassVaultError <|-- LockError
```
