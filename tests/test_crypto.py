"""Unit tests for cryptographic engine in passvault.crypto."""

import base64
import pytest
from cryptography.exceptions import InvalidTag

from passvault.config import (
    DEFAULT_ARGON2_MEMORY_KIB,
    DEFAULT_ARGON2_TIME_COST,
    DEFAULT_ARGON2_PARALLELISM,
    DEFAULT_SALT_LENGTH_BYTES,
    DERIVED_KEY_LENGTH_BYTES,
    AES_GCM_NONCE_LENGTH_BYTES,
)
from passvault.crypto import (
    derive_key,
    encrypt_data,
    decrypt_data,
    generate_salt,
    generate_nonce,
    validate_kdf_params,
)
from passvault.exceptions import WrongPasswordError, VaultFormatError


class TestArgon2KeyDerivation:
    def test_derive_key_length(self):
        salt = generate_salt(16)
        key = derive_key("master-password-123", salt, memory_cost=8192, time_cost=1, parallelism=1)
        assert len(key) == DERIVED_KEY_LENGTH_BYTES
        assert isinstance(key, bytes)

    def test_deterministic_for_same_inputs(self):
        salt = b"\x01" * 16
        k1 = derive_key("test-pw", salt, memory_cost=8192, time_cost=1, parallelism=1)
        k2 = derive_key("test-pw", salt, memory_cost=8192, time_cost=1, parallelism=1)
        assert k1 == k2

    def test_different_passwords_produce_different_keys(self):
        salt = b"\x01" * 16
        k1 = derive_key("password-A", salt, memory_cost=8192, time_cost=1, parallelism=1)
        k2 = derive_key("password-B", salt, memory_cost=8192, time_cost=1, parallelism=1)
        assert k1 != k2

    def test_different_salts_produce_different_keys(self):
        s1 = b"\x01" * 16
        s2 = b"\x02" * 16
        k1 = derive_key("password", s1, memory_cost=8192, time_cost=1, parallelism=1)
        k2 = derive_key("password", s2, memory_cost=8192, time_cost=1, parallelism=1)
        assert k1 != k2

    def test_salt_generation_length(self):
        s1 = generate_salt(16)
        s2 = generate_salt(16)
        assert len(s1) == 16
        assert len(s2) == 16
        assert s1 != s2  # High entropy random generation

    def test_nonce_generation_length(self):
        n1 = generate_nonce(12)
        n2 = generate_nonce(12)
        assert len(n1) == 12
        assert len(n2) == 12
        assert n1 != n2


class TestAESGCMEncryption:
    @pytest.fixture
    def test_key(self):
        return b"K" * 32

    def test_encrypt_decrypt_roundtrip(self, test_key):
        plaintext = b"Super sensitive secret payload."
        nonce, ciphertext = encrypt_data(plaintext, test_key)

        assert len(nonce) == AES_GCM_NONCE_LENGTH_BYTES
        # Ciphertext must contain ciphertext + 16 byte authentication tag
        assert len(ciphertext) == len(plaintext) + 16

        decrypted = decrypt_data(ciphertext, nonce, test_key)
        assert decrypted == plaintext

    def test_unique_nonce_per_encryption(self, test_key):
        plaintext = b"Same data"
        nonce1, ct1 = encrypt_data(plaintext, test_key)
        nonce2, ct2 = encrypt_data(plaintext, test_key)

        assert nonce1 != nonce2
        assert ct1 != ct2

    def test_wrong_key_fails_with_unified_error(self, test_key):
        plaintext = b"Sensitive data"
        nonce, ciphertext = encrypt_data(plaintext, test_key)

        wrong_key = b"W" * 32
        with pytest.raises(WrongPasswordError) as exc_info:
            decrypt_data(ciphertext, nonce, wrong_key)
        assert "Invalid master password or corrupted vault file" in str(exc_info.value)

    def test_tampered_ciphertext_fails_with_unified_error(self, test_key):
        plaintext = b"Secret text"
        nonce, ciphertext = encrypt_data(plaintext, test_key)

        # Flip the first bit of the ciphertext
        corrupted_ct = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]

        with pytest.raises(WrongPasswordError) as exc_info:
            decrypt_data(corrupted_ct, nonce, test_key)
        assert "Invalid master password or corrupted vault file" in str(exc_info.value)

    def test_tampered_nonce_fails_with_unified_error(self, test_key):
        plaintext = b"Secret text"
        nonce, ciphertext = encrypt_data(plaintext, test_key)

        corrupted_nonce = bytes([nonce[0] ^ 0xFF]) + nonce[1:]
        with pytest.raises(WrongPasswordError):
            decrypt_data(ciphertext, corrupted_nonce, test_key)

    def test_invalid_key_length_raises_value_error(self):
        with pytest.raises(ValueError, match="AES-256 key must be 32 bytes"):
            encrypt_data(b"data", b"too-short")

        with pytest.raises(ValueError, match="AES-256 key must be 32 bytes"):
            decrypt_data(b"data", b"\x00" * 12, b"too-short")


    def test_encrypt_empty_bytes(self, test_key):
        plaintext = b""
        nonce, ciphertext = encrypt_data(plaintext, test_key)
        decrypted = decrypt_data(ciphertext, nonce, test_key)
        assert decrypted == b""

    def test_encrypt_large_payload(self, test_key):
        plaintext = b"A" * 65536  # 64 KB payload
        nonce, ciphertext = encrypt_data(plaintext, test_key)
        decrypted = decrypt_data(ciphertext, nonce, test_key)
        assert decrypted == plaintext

    def test_unicode_passwords_and_data(self):
        salt = generate_salt(16)
        pw = "P@sswørd-🔑-日本語"
        key = derive_key(pw, salt, memory_cost=8192, time_cost=1, parallelism=1)
        data = "Secrets with unicode: 🔐 日本語 €100".encode("utf-8")
        nonce, ct = encrypt_data(data, key)
        pt = decrypt_data(ct, nonce, key)
        assert pt == data


class TestKDFParameterFloors:
    def valid_meta(self):
        return {
            "algorithm": "argon2id",
            "salt": base64.b64encode(b"0123456789abcdef").decode("ascii"),
            "memory_cost": 65536,
            "time_cost": 3,
            "parallelism": 4,
            "hash_len": 32,
        }

    def test_valid_meta_passes(self):
        meta = self.valid_meta()
        validate_kdf_params(meta)  # Should not raise

    def test_non_base64_salt_raises_vault_format_error(self):
        meta = self.valid_meta()
        meta["salt"] = "!!!not-valid-base64!!!"
        with pytest.raises(VaultFormatError, match="Malformed KDF parameters"):
            validate_kdf_params(meta)

    def test_non_integer_parameter_raises_vault_format_error(self):
        meta = self.valid_meta()
        meta["memory_cost"] = "not-a-number"
        with pytest.raises(VaultFormatError, match="Malformed KDF parameters"):
            validate_kdf_params(meta)

    def test_unsupported_algorithm(self):
        meta = self.valid_meta()
        meta["algorithm"] = "pbkdf2"
        with pytest.raises(VaultFormatError, match="Unsupported KDF algorithm"):
            validate_kdf_params(meta)

    def test_parallelism_below_floor(self):
        meta = self.valid_meta()
        meta["parallelism"] = 0
        with pytest.raises(VaultFormatError, match="below algorithmic floor"):
            validate_kdf_params(meta)

    def test_time_cost_below_floor(self):
        meta = self.valid_meta()
        meta["time_cost"] = 0
        with pytest.raises(VaultFormatError, match="below algorithmic floor"):
            validate_kdf_params(meta)

    def test_memory_below_floor(self):
        meta = self.valid_meta()
        meta["memory_cost"] = 4  # Below 8 KiB floor
        with pytest.raises(VaultFormatError, match="below algorithmic floor"):
            validate_kdf_params(meta)

    def test_memory_below_parallelism_floor(self):
        meta = self.valid_meta()
        meta["parallelism"] = 8
        meta["memory_cost"] = 32  # Must be at least 8 * parallelism = 64
        with pytest.raises(VaultFormatError, match="below algorithmic floor"):
            validate_kdf_params(meta)

    def test_salt_below_minimum_length(self):
        meta = self.valid_meta()
        meta["salt"] = base64.b64encode(b"short").decode("ascii")  # 5 bytes < 8
        with pytest.raises(VaultFormatError, match="below minimum floor"):
            validate_kdf_params(meta)

    def test_hash_len_below_minimum(self):
        meta = self.valid_meta()
        meta["hash_len"] = 8  # Below 16 bytes minimum
        with pytest.raises(VaultFormatError, match="below minimum floor"):
            validate_kdf_params(meta)

    def test_malformed_non_dict_metadata(self):
        with pytest.raises(VaultFormatError, match="expected a dictionary"):
            validate_kdf_params("not a dict")  # type: ignore

    def test_missing_parameter_raises_vault_format_error(self):
        meta = self.valid_meta()
        del meta["memory_cost"]
        with pytest.raises(VaultFormatError, match="Malformed KDF parameters"):
            validate_kdf_params(meta)
