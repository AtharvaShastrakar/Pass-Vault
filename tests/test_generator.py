"""Unit tests for the password generator in passvault.generator."""

import string
import pytest
from passvault.config import SAFE_SYMBOLS
from passvault.generator import generate_password


class TestPasswordGenerator:
    def test_default_generation(self):
        pw = generate_password()
        assert len(pw) == 20
        # Should contain lowercase, uppercase, digits, symbols
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SAFE_SYMBOLS for c in pw)

    def test_custom_lengths(self):
        for length in [4, 8, 16, 32, 64, 128]:
            pw = generate_password(length=length)
            assert len(pw) == length

    def test_no_symbols(self):
        pw = generate_password(length=24, include_symbols=False)
        assert len(pw) == 24
        assert not any(c in SAFE_SYMBOLS for c in pw)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)

    def test_no_digits(self):
        pw = generate_password(length=24, include_digits=False)
        assert len(pw) == 24
        assert not any(c in string.digits for c in pw)
        assert any(c in SAFE_SYMBOLS for c in pw)

    def test_only_letters(self):
        pw = generate_password(length=20, include_symbols=False, include_digits=False)
        assert len(pw) == 20
        for char in pw:
            assert char in string.ascii_letters

    def test_only_digits(self):
        pw = generate_password(
            length=12,
            include_symbols=False,
            include_digits=True,
            include_uppercase=False,
            include_lowercase=False,
        )
        assert len(pw) == 12
        assert pw.isdigit()

    def test_only_symbols(self):
        pw = generate_password(
            length=15,
            include_symbols=True,
            include_digits=False,
            include_uppercase=False,
            include_lowercase=False,
        )
        assert len(pw) == 15
        assert all(c in SAFE_SYMBOLS for c in pw)

    def test_large_length(self):
        pw = generate_password(length=512)
        assert len(pw) == 512

    def test_length_too_short_for_active_pools_raises_error(self):
        # 4 pools active (lower, upper, digit, symbol), length 3 cannot guarantee all 4
        with pytest.raises(ValueError, match="must be at least 4"):
            generate_password(length=3)

    def test_no_character_set_enabled_raises_error(self):
        with pytest.raises(ValueError, match="At least one character set must be enabled"):
            generate_password(
                include_lowercase=False,
                include_uppercase=False,
                include_digits=False,
                include_symbols=False,
            )

    def test_diversity_over_multiple_runs(self):
        # Ensure random outputs are distinct (high entropy)
        passwords = {generate_password(length=32) for _ in range(50)}
        assert len(passwords) == 50

    def test_shuffle_prevents_fixed_prefix(self):
        # Even though first 4 chars are picked one from each pool,
        # Fisher-Yates must shuffle them throughout the entire string.
        # Run 30 times and verify the first character is not always from the same pool.
        first_chars = [generate_password(length=16)[0] for _ in range(30)]
        has_lower = any(c in string.ascii_lowercase for c in first_chars)
        has_upper = any(c in string.ascii_uppercase for c in first_chars)
        has_digit = any(c in string.digits for c in first_chars)
        has_sym = any(c in SAFE_SYMBOLS for c in first_chars)
        # At least 3 different pools should have appeared in the 0-th position
        assert sum([has_lower, has_upper, has_digit, has_sym]) >= 3
