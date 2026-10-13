"""Typed exception hierarchy for PASS VAULT.

Clean, intentional exceptions ensure that cryptographic failures are securely handled,
file formatting corruptions are clearly distinguished from authentication errors,
and callers receive predictable, typed error boundaries.
"""

class PassVaultError(Exception):
    """Base exception for all PASS VAULT errors."""
    pass


class WrongPasswordError(PassVaultError):
    """Raised when the master password is incorrect OR the vault file has been tampered with.

    Security Note:
    In authenticated encryption (AES-256-GCM), an invalid password (which produces
    an incorrect derived key) and an altered ciphertext/tag produce the exact same
    cryptographic failure (authentication tag verification fails).
    Refusing to distinguish between 'wrong password' and 'tampered file' prevents
    attackers from using the application as an oracle to test file modifications
    or key candidates separately.
    """
    def __init__(self, message: str = "Invalid master password or corrupted vault file") -> None:
        super().__init__(message)


class VaultFormatError(PassVaultError):
    """Raised when the vault file envelope is malformed or parameters violate algorithmic floors."""
    pass


class VaultNotFoundError(PassVaultError):
    """Raised when an operation requires an existing vault file, but none was found."""
    pass


class VaultAlreadyExistsError(PassVaultError):
    """Raised when attempting to initialize a vault at an existing file path without overwrite."""
    pass


class EntryNotFoundError(PassVaultError):
    """Raised when attempting to query or delete a non-existent credential entry."""
    pass


class EntryAlreadyExistsError(PassVaultError):
    """Raised when attempting to add an entry name that already exists."""
    pass


class LockError(PassVaultError):
    """Raised when unable to acquire the advisory lock to serialize vault access."""
    pass
