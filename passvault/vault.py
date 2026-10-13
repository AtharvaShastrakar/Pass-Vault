"""Core Vault engine for PASS VAULT.

Handles:
1. Vault data serialization and schema management.
2. Atomic, durable file persistence (tmp file -> fsync -> os.replace -> dir fsync).
3. First-syscall permissions enforcement (mode 0o600 with zero chmod race window).
4. Advisory process serialization via fcntl.flock on sidecar .lock files.
5. Entry CRUD operations and master password rotation.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from passvault.config import (
    DEFAULT_ARGON2_MEMORY_KIB,
    DEFAULT_ARGON2_TIME_COST,
    DEFAULT_ARGON2_PARALLELISM,
    DEFAULT_SALT_LENGTH_BYTES,
    DERIVED_KEY_LENGTH_BYTES,
    VAULT_FORMAT_VERSION,
    get_default_vault_path,
)
from passvault.crypto import (
    derive_key,
    encrypt_data,
    decrypt_data,
    generate_salt,
    validate_kdf_params,
)
from passvault.exceptions import (
    VaultNotFoundError,
    VaultAlreadyExistsError,
    VaultFormatError,
    EntryNotFoundError,
    EntryAlreadyExistsError,
    LockError,
)


def _get_lock_path(vault_path: Path) -> Path:
    """Return the sidecar lock file path for a given vault file."""
    return vault_path.with_name(vault_path.name + ".lock")


@contextlib.contextmanager
def acquire_vault_lock(vault_path: Path) -> Iterator[None]:
    """Acquire an exclusive advisory lock to serialize concurrent access to the vault.

    Uses POSIX fcntl.flock(LOCK_EX) on a sidecar .lock file.
    """
    lock_file = _get_lock_path(vault_path)
    # Ensure parent directory exists for the lock file
    lock_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    try:
        # Open lock file with 0o600 mode
        lock_fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as err:
        raise LockError(f"Could not open lock file {lock_file}: {err}") from err

    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    except OSError as err:
        raise LockError(f"Failed to acquire advisory lock on {lock_file}: {err}") from err
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)


def _atomic_write_file(target_path: Path, content_bytes: bytes) -> None:
    """Durable, atomic write to disk.

    Guarantee chain:
    1. Parent directory created with secure mode 0o700 if missing.
    2. Write to sibling temporary file in the same directory (guaranteeing same filesystem for os.replace).
    3. os.open sets mode 0o600 at the very first syscall — eliminates chmod race window.
    4. os.fsync flushes file buffers from OS cache to physical disk.
    5. os.replace atomically switches the temp file into target_path.
    6. Directory fsync forces parent directory metadata to commit to physical disk.
    """
    parent_dir = target_path.parent
    parent_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Temporary file in the same directory
    tmp_path = parent_dir / f".{target_path.name}.tmp.{os.getpid()}_{os.urandom(4).hex()}"

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(tmp_path), flags, 0o600)
    try:
        os.write(fd, content_bytes)
        os.fsync(fd)
    finally:
        os.close(fd)

    # Atomic rename / replace
    os.replace(tmp_path, target_path)

    # Directory fsync to ensure the directory entry is durable on POSIX filesystems
    if sys.platform != "win32":
        try:
            dir_fd = os.open(str(parent_dir), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            # Some platforms / network mounts do not allow fsync on directory descriptors
            pass


class Vault:
    """In-memory representation of an unlocked credential vault."""

    def __init__(
        self,
        entries: dict[str, dict[str, Any]] | None = None,
        kdf_params: dict[str, Any] | None = None,
    ) -> None:
        self.entries: dict[str, dict[str, Any]] = entries if entries is not None else {}
        self.kdf_params: dict[str, Any] = kdf_params if kdf_params is not None else {}

    @classmethod
    def create_new(cls) -> Vault:
        """Create a fresh in-memory vault."""
        return cls(entries={}, kdf_params={})

    @classmethod
    def load(cls, path: Path | str, master_password: str) -> Vault:
        """Load, authenticate, and decrypt a vault file from disk.

        Args:
            path: Path to the vault JSON file.
            master_password: Master password for key derivation and decryption.

        Returns:
            Decrypted Vault instance.

        Raises:
            VaultNotFoundError: If the file does not exist.
            VaultFormatError: If the file is malformed or parameters violate algorithmic floors.
            WrongPasswordError: If the password is wrong or ciphertext is tampered.
        """
        vault_path = Path(path).expanduser().resolve()
        if not vault_path.exists():
            raise VaultNotFoundError(f"Vault file not found at: {vault_path}")

        with acquire_vault_lock(vault_path):
            try:
                raw_text = vault_path.read_text(encoding="utf-8")
                envelope = json.loads(raw_text)
            except json.JSONDecodeError as err:
                raise VaultFormatError(f"Vault file contains invalid JSON: {err}") from err
            except OSError as err:
                raise VaultFormatError(f"Could not read vault file: {err}") from err

            if not isinstance(envelope, dict):
                raise VaultFormatError("Malformed vault structure: root must be a JSON object.")

            version = envelope.get("version")
            if version != VAULT_FORMAT_VERSION:
                raise VaultFormatError(
                    f"Unsupported vault format version {version}. Expected version {VAULT_FORMAT_VERSION}."
                )

            kdf_meta = envelope.get("kdf")
            if not isinstance(kdf_meta, dict):
                raise VaultFormatError("Missing or malformed 'kdf' section in vault envelope.")

            # Validate parameters against algorithmic floors
            validate_kdf_params(kdf_meta)

            salt_bytes = base64.b64decode(kdf_meta["salt"].encode("ascii"))
            memory_cost = int(kdf_meta["memory_cost"])
            time_cost = int(kdf_meta["time_cost"])
            parallelism = int(kdf_meta["parallelism"])
            hash_len = int(kdf_meta.get("hash_len", DERIVED_KEY_LENGTH_BYTES))

            nonce_b64 = envelope.get("nonce")
            ciphertext_b64 = envelope.get("ciphertext")
            if not nonce_b64 or not ciphertext_b64:
                raise VaultFormatError("Vault envelope is missing 'nonce' or 'ciphertext'.")

            try:
                nonce_bytes = base64.b64decode(nonce_b64.encode("ascii"), validate=True)
                ciphertext_bytes = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
            except Exception as err:
                raise VaultFormatError(f"Invalid base64 payload in vault: {err}") from err

            # Derive key using stored Argon2id parameters
            derived_key = derive_key(
                master_password=master_password,
                salt=salt_bytes,
                memory_cost=memory_cost,
                time_cost=time_cost,
                parallelism=parallelism,
                hash_len=hash_len,
            )

            # Decrypt with AES-256-GCM (raises WrongPasswordError on authentication tag failure)
            decrypted_bytes = decrypt_data(ciphertext_bytes, nonce_bytes, derived_key)

            try:
                payload = json.loads(decrypted_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as err:
                raise VaultFormatError(f"Corrupted vault payload after decryption: {err}") from err

            if not isinstance(payload, dict) or "entries" not in payload:
                raise VaultFormatError("Decrypted payload missing 'entries' map.")

            entries = payload.get("entries", {})
            if not isinstance(entries, dict):
                raise VaultFormatError("'entries' section in decrypted payload must be a map.")

            return cls(entries=entries, kdf_params=kdf_meta)

    def save(
        self,
        path: Path | str,
        master_password: str,
        upgrade_kdf: bool = False,
    ) -> None:
        """Encrypt and atomically save vault to disk.

        Args:
            path: Destination file path.
            master_password: Master password used to derive the encryption key.
            upgrade_kdf: If True, replace parameters with the latest OWASP defaults.
        """
        vault_path = Path(path).expanduser().resolve()

        with acquire_vault_lock(vault_path):
            if upgrade_kdf or not self.kdf_params:
                # Use current default parameters and generate fresh salt
                salt = generate_salt(DEFAULT_SALT_LENGTH_BYTES)
                memory_cost = DEFAULT_ARGON2_MEMORY_KIB
                time_cost = DEFAULT_ARGON2_TIME_COST
                parallelism = DEFAULT_ARGON2_PARALLELISM
                hash_len = DERIVED_KEY_LENGTH_BYTES
            else:
                salt = base64.b64decode(self.kdf_params["salt"].encode("ascii"))
                memory_cost = int(self.kdf_params["memory_cost"])
                time_cost = int(self.kdf_params["time_cost"])
                parallelism = int(self.kdf_params["parallelism"])
                hash_len = int(self.kdf_params.get("hash_len", DERIVED_KEY_LENGTH_BYTES))

            # Derive key with Argon2id
            key = derive_key(
                master_password=master_password,
                salt=salt,
                memory_cost=memory_cost,
                time_cost=time_cost,
                parallelism=parallelism,
                hash_len=hash_len,
            )

            # Serialize entries payload to JSON bytes
            payload = {"entries": self.entries}
            payload_bytes = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")

            # Encrypt with AES-256-GCM using a freshly generated nonce
            nonce_bytes, ciphertext_bytes = encrypt_data(payload_bytes, key)

            # Assemble encrypted vault envelope
            envelope = {
                "version": VAULT_FORMAT_VERSION,
                "kdf": {
                    "algorithm": "argon2id",
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "memory_cost": memory_cost,
                    "time_cost": time_cost,
                    "parallelism": parallelism,
                    "hash_len": hash_len,
                },
                "nonce": base64.b64encode(nonce_bytes).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext_bytes).decode("ascii"),
            }

            self.kdf_params = envelope["kdf"]
            content = json.dumps(envelope, indent=2).encode("utf-8")

            # Perform atomic, durable write with mode 0o600
            _atomic_write_file(vault_path, content)

    # --- Entry CRUD Operations ---

    def add_entry(
        self,
        name: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Add a credential entry to the vault."""
        now_iso = datetime.now(timezone.utc).isoformat()
        if name in self.entries and not overwrite:
            raise EntryAlreadyExistsError(f"Entry '{name}' already exists in vault.")

        created_time = self.entries[name].get("created", now_iso) if name in self.entries else now_iso

        entry_data = {
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "created": created_time,
            "updated": now_iso,
        }
        self.entries[name] = entry_data
        return entry_data

    def get_entry(self, name: str) -> dict[str, Any]:
        """Retrieve an entry by name."""
        if name not in self.entries:
            raise EntryNotFoundError(f"Entry '{name}' not found.")
        return self.entries[name]

    def delete_entry(self, name: str) -> None:
        """Delete an entry by name."""
        if name not in self.entries:
            raise EntryNotFoundError(f"Entry '{name}' not found.")
        del self.entries[name]

    def list_entries(self) -> list[tuple[str, dict[str, Any]]]:
        """Return list of (name, entry) tuples sorted alphabetically."""
        return sorted(self.entries.items(), key=lambda item: item[0])

    def change_password(
        self,
        path: Path | str,
        current_password: str,
        new_password: str,
    ) -> None:
        """Rotate the master password, re-encrypting under fresh salt, key, and nonce."""
        vault_path = Path(path).expanduser().resolve()
        # Verify current password and decrypt existing data
        loaded_vault = Vault.load(vault_path, current_password)
        self.entries = loaded_vault.entries

        # Generate fresh salt and upgrade KDF parameters
        self.kdf_params = {}  # Trigger fresh salt generation and latest OWASP parameters
        self.save(vault_path, new_password, upgrade_kdf=True)
