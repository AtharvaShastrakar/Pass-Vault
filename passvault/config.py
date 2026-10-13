"""Configuration defaults and cryptographic constants for PASS VAULT (pv).

This module defines standard file paths, OWASP-recommended Argon2id parameters,
and algorithmic floor limits used for integrity validation.
"""

from pathlib import Path
import os

# Default vault path: ~/.password-vault/vault.json
# Can be overridden via PV_VAULT environment variable or --vault CLI flag.
DEFAULT_VAULT_DIR = Path.home() / ".password-vault"
DEFAULT_VAULT_FILE = DEFAULT_VAULT_DIR / "vault.json"

ENV_VAULT_PATH = "PV_VAULT"

def get_default_vault_path() -> Path:
    """Return default vault path, honoring $PV_VAULT if set."""
    env_path = os.environ.get(ENV_VAULT_PATH)
    if env_path:
        return Path(env_path).expanduser().resolve()
    return DEFAULT_VAULT_FILE


# Format version for the vault envelope
VAULT_FORMAT_VERSION = 1

# --- Cryptographic Parameters ---

# Argon2id Key Derivation Function (KDF)
# OWASP recommendations for password storage / derivation:
# - memory_cost: 65536 KiB (64 MiB)
# - time_cost: 3 iterations (passes)
# - parallelism: 4 lanes / threads
# - salt_len: 16 bytes (128 bits)
# - hash_len: 32 bytes (256 bits, matching AES-256 key size)
# Derivation target: ~0.5s per derivation to frustrate brute-force attacks.
DEFAULT_KDF_ALGORITHM = "argon2id"
DEFAULT_ARGON2_MEMORY_KIB = 65536  # 64 MiB
DEFAULT_ARGON2_TIME_COST = 3       # 3 passes
DEFAULT_ARGON2_PARALLELISM = 4     # 4 lanes
DEFAULT_SALT_LENGTH_BYTES = 16    # 16 bytes
DERIVED_KEY_LENGTH_BYTES = 32     # 32 bytes (256-bit AES key)

# Algorithmic floors for Argon2 parameter validation:
# Prevents corrupted/malicious parameters from crashing the engine or weakening security
MIN_ARGON2_PARALLELISM = 1
MIN_ARGON2_TIME_COST = 1
MIN_ARGON2_MEMORY_KIB = 8          # Absolute minimum RFC 9106 floor
MIN_SALT_LENGTH_BYTES = 8
MIN_DERIVED_KEY_LENGTH_BYTES = 16

# AES-256-GCM Authenticated Encryption with Associated Data (AEAD)
AES_KEY_LENGTH_BYTES = 32          # 256 bits
AES_GCM_NONCE_LENGTH_BYTES = 12    # 96 bits (standard recommended GCM nonce size)
AES_GCM_TAG_LENGTH_BYTES = 16      # 128 bits authentication tag

# Password Generator Defaults
DEFAULT_GENERATED_PASSWORD_LEN = 20
SAFE_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"
