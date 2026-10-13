"""Cryptographic engine for PASS VAULT.

Implements:
1. Argon2id Key Derivation Function (KDF):
   - Derives a 32-byte AES key from the master password.
   - Memory-hard to resist GPU and ASIC hardware-accelerated attacks.
   - Algorithmic floors are verified to prevent library crashes or parameter downgrade attacks.
2. AES-256-GCM Authenticated Encryption:
   - Provides both confidentiality and tamper detection (AEAD).
   - Generates fresh 12-byte cryptographically secure random nonces per encryption.
   - Unifies invalid authentication tag and wrong key errors into WrongPasswordError
     to avoid exposing an authentication oracle.
"""

import base64
import secrets
from typing import Any

import argon2.low_level
from argon2.low_level import Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from passvault.config import (
    DEFAULT_ARGON2_MEMORY_KIB,
    DEFAULT_ARGON2_TIME_COST,
    DEFAULT_ARGON2_PARALLELISM,
    DEFAULT_SALT_LENGTH_BYTES,
    DERIVED_KEY_LENGTH_BYTES,
    MIN_ARGON2_MEMORY_KIB,
    MIN_ARGON2_TIME_COST,
    MIN_ARGON2_PARALLELISM,
    MIN_SALT_LENGTH_BYTES,
    MIN_DERIVED_KEY_LENGTH_BYTES,
    AES_GCM_NONCE_LENGTH_BYTES,
)
from passvault.exceptions import WrongPasswordError, VaultFormatError


def generate_salt(length: int = DEFAULT_SALT_LENGTH_BYTES) -> bytes:
    """Generate a cryptographically secure random salt."""
    return secrets.token_bytes(length)


def generate_nonce(length: int = AES_GCM_NONCE_LENGTH_BYTES) -> bytes:
    """Generate a cryptographically secure random nonce for AES-GCM."""
    return secrets.token_bytes(length)


def validate_kdf_params(kdf_meta: dict[str, Any]) -> None:
    """Validate Argon2id parameters against algorithmic minimum floors.

    Corrupted, tampered, or maliciously downgraded parameters raise
    VaultFormatError rather than causing unhandled crashes or insecure execution.
    """
    if not isinstance(kdf_meta, dict):
        raise VaultFormatError("Invalid KDF metadata: expected a dictionary.")

    algorithm = kdf_meta.get("algorithm")
    if algorithm != "argon2id":
        raise VaultFormatError(f"Unsupported KDF algorithm: '{algorithm}'. Expected 'argon2id'.")

    try:
        memory_cost = int(kdf_meta["memory_cost"])
        time_cost = int(kdf_meta["time_cost"])
        parallelism = int(kdf_meta["parallelism"])
        hash_len = int(kdf_meta.get("hash_len", DERIVED_KEY_LENGTH_BYTES))
        salt_b64 = str(kdf_meta["salt"])
        salt_bytes = base64.b64decode(salt_b64.encode("ascii"))
    except (KeyError, ValueError, TypeError) as err:
        raise VaultFormatError(f"Malformed KDF parameters in vault file: {err}") from err

    if parallelism < MIN_ARGON2_PARALLELISM:
        raise VaultFormatError(
            f"KDF parallelism {parallelism} is below algorithmic floor ({MIN_ARGON2_PARALLELISM})."
        )

    if time_cost < MIN_ARGON2_TIME_COST:
        raise VaultFormatError(
            f"KDF time_cost {time_cost} is below algorithmic floor ({MIN_ARGON2_TIME_COST})."
        )

    # Argon2 RFC 9106 specifies memory must be at least 8 * parallelism and at least 8 KiB
    min_mem = max(MIN_ARGON2_MEMORY_KIB, 8 * parallelism)
    if memory_cost < min_mem:
        raise VaultFormatError(
            f"KDF memory_cost {memory_cost} KiB is below algorithmic floor ({min_mem} KiB)."
        )

    if len(salt_bytes) < MIN_SALT_LENGTH_BYTES:
        raise VaultFormatError(
            f"KDF salt length ({len(salt_bytes)} bytes) is below minimum floor ({MIN_SALT_LENGTH_BYTES} bytes)."
        )

    if hash_len < MIN_DERIVED_KEY_LENGTH_BYTES:
        raise VaultFormatError(
            f"KDF hash_len ({hash_len} bytes) is below minimum floor ({MIN_DERIVED_KEY_LENGTH_BYTES} bytes)."
        )


def derive_key(
    master_password: str,
    salt: bytes,
    memory_cost: int = DEFAULT_ARGON2_MEMORY_KIB,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    hash_len: int = DERIVED_KEY_LENGTH_BYTES,
) -> bytes:
    """Derive a 256-bit symmetric encryption key from a master password using Argon2id.

    Args:
        master_password: User master password in plaintext.
        salt: Random salt bytes.
        memory_cost: Memory hardness in KiB.
        time_cost: Number of passes/iterations.
        parallelism: Number of parallel computing lanes.
        hash_len: Output key length in bytes (32 for AES-256).

    Returns:
        32-byte derived key.
    """
    try:
        return argon2.low_level.hash_secret_raw(
            secret=master_password.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=Type.ID,
        )
    except Exception as err:
        raise VaultFormatError(f"Argon2id key derivation error: {err}") from err


def encrypt_data(plaintext_bytes: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM.

    Args:
        plaintext_bytes: Raw bytes to encrypt.
        key: 32-byte symmetric AES key.

    Returns:
        tuple of (nonce_bytes, ciphertext_with_tag_bytes).
    """
    if len(key) != DERIVED_KEY_LENGTH_BYTES:
        raise ValueError(f"AES-256 key must be {DERIVED_KEY_LENGTH_BYTES} bytes, got {len(key)}")

    nonce = generate_nonce(AES_GCM_NONCE_LENGTH_BYTES)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce, ciphertext


def decrypt_data(ciphertext_bytes: bytes, nonce: bytes, key: bytes) -> bytes:
    """Decrypt ciphertext using AES-256-GCM and verify authenticity tag.

    Args:
        ciphertext_bytes: Ciphertext containing the 16-byte authentication tag.
        nonce: 12-byte initialization vector / nonce used during encryption.
        key: 32-byte symmetric AES key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        WrongPasswordError: If the authentication tag fails (wrong password OR corrupted/tampered file).
    """
    if len(key) != DERIVED_KEY_LENGTH_BYTES:
        raise ValueError(f"AES-256 key must be {DERIVED_KEY_LENGTH_BYTES} bytes, got {len(key)}")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_bytes, None)
    except InvalidTag as err:
        # Refuse to distinguish "wrong password" from "tampered file"
        raise WrongPasswordError("Invalid master password or corrupted vault file") from err
