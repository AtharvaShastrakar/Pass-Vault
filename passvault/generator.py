"""Cryptographically secure password generator using Python's secrets module.

Key cryptographic guarantees:
1. CSPRNG Entropy: Uses `secrets` (backed by the OS cryptographically secure pseudorandom
   number generator, e.g. /dev/urandom or getrandom(2)), never the predictable `random` module.
2. Character Diversity: Guarantees at least one character from each active character class.
3. Unbiased Shuffling: Uses an in-place Fisher-Yates (Knuth) shuffle driven by
   `secrets.randbelow` to eliminate positional predictability without modulo bias.
"""

import secrets
import string
from passvault.config import SAFE_SYMBOLS, DEFAULT_GENERATED_PASSWORD_LEN


def generate_password(
    length: int = DEFAULT_GENERATED_PASSWORD_LEN,
    include_symbols: bool = True,
    include_digits: bool = True,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
) -> str:
    """Generate a high-entropy, cryptographically secure random password.

    Args:
        length: Desired length of the password (must be >= count of enabled character sets).
        include_symbols: Whether to include special symbols.
        include_digits: Whether to include decimal numbers 0-9.
        include_uppercase: Whether to include ASCII uppercase letters A-Z.
        include_lowercase: Whether to include ASCII lowercase letters a-z.

    Returns:
        A high-entropy password string.

    Raises:
        ValueError: If length is insufficient or no character classes are enabled.
    """
    pools: list[str] = []
    if include_lowercase:
        pools.append(string.ascii_lowercase)
    if include_uppercase:
        pools.append(string.ascii_uppercase)
    if include_digits:
        pools.append(string.digits)
    if include_symbols:
        pools.append(SAFE_SYMBOLS)

    if not pools:
        raise ValueError("At least one character set must be enabled.")

    if length < len(pools):
        raise ValueError(
            f"Password length ({length}) must be at least {len(pools)} to guarantee "
            f"at least one character from each enabled character set."
        )

    # 1. Guarantee at least one character from each selected pool
    # secrets.choice ensures cryptographically secure selection
    chosen_chars: list[str] = [secrets.choice(pool) for pool in pools]

    # 2. Fill the remaining length from the unified pool of all active characters
    unified_pool = "".join(pools)
    remaining_count = length - len(chosen_chars)
    for _ in range(remaining_count):
        chosen_chars.append(secrets.choice(unified_pool))

    # 3. Fisher-Yates (Knuth) shuffle using secrets.randbelow
    # This prevents the guaranteed characters from always appearing at the beginning
    # while ensuring every permutation is equally likely (unbiased).
    for i in range(len(chosen_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chosen_chars[i], chosen_chars[j] = chosen_chars[j], chosen_chars[i]

    return "".join(chosen_chars)
