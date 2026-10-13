"""Unit tests for vault persistence, atomic writes, locking, and CRUD in passvault.vault."""

import json
import os
import stat
from pathlib import Path
import pytest

from passvault.exceptions import (
    VaultNotFoundError,
    VaultFormatError,
    WrongPasswordError,
    EntryNotFoundError,
    EntryAlreadyExistsError,
)
from passvault.vault import Vault, acquire_vault_lock


class TestVaultLifecycleAndPermissions:
    def test_create_and_save_sets_mode_0600(self, tmp_path: Path):
        vault_file = tmp_path / "sub" / "vault.json"
        vault = Vault.create_new()
        vault.save(vault_file, "master123")

        assert vault_file.exists()
        file_mode = stat.S_IMODE(os.stat(vault_file).st_mode)
        # Check that file mode is strictly 0o600 (read/write for owner only)
        assert file_mode == 0o600

        parent_mode = stat.S_IMODE(os.stat(vault_file.parent).st_mode)
        # Parent directory mode should be 0o700 (owner only)
        assert parent_mode == 0o700

    def test_load_non_existent_vault_raises_not_found(self, tmp_path: Path):
        missing = tmp_path / "nonexistent.json"
        with pytest.raises(VaultNotFoundError):
            Vault.load(missing, "any-password")

    def test_load_with_wrong_password_raises_wrong_password_error(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault = Vault.create_new()
        vault.add_entry("gh", "test_user", "p1")
        vault.save(vault_file, "correct-password")

        with pytest.raises(WrongPasswordError) as exc_info:
            Vault.load(vault_file, "wrong-password")
        assert "Invalid master password or corrupted vault file" in str(exc_info.value)

    def test_load_tampered_ciphertext_raises_wrong_password_error(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault = Vault.create_new()
        vault.add_entry("gh", "test_user", "secret123")
        vault.save(vault_file, "correct-password")

        # Corrupt one character in the ciphertext
        data = json.loads(vault_file.read_text())
        ct = list(data["ciphertext"])
        ct[0] = "A" if ct[0] != "A" else "B"
        data["ciphertext"] = "".join(ct)
        vault_file.write_text(json.dumps(data))

        with pytest.raises(WrongPasswordError):
            Vault.load(vault_file, "correct-password")

    def test_load_corrupted_json_raises_vault_format_error(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault_file.write_text("{malformed: json...[")

        with pytest.raises(VaultFormatError, match="invalid JSON"):
            Vault.load(vault_file, "password")

    def test_load_invalid_version_raises_vault_format_error(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault = Vault.create_new()
        vault.save(vault_file, "pass")

        data = json.loads(vault_file.read_text())
        data["version"] = 99
        vault_file.write_text(json.dumps(data))

        with pytest.raises(VaultFormatError, match="Unsupported vault format version"):
            Vault.load(vault_file, "pass")

    def test_load_violating_kdf_floors_raises_vault_format_error(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault = Vault.create_new()
        vault.save(vault_file, "pass")

        data = json.loads(vault_file.read_text())
        data["kdf"]["memory_cost"] = 2  # Violates floor
        vault_file.write_text(json.dumps(data))

        with pytest.raises(VaultFormatError, match="below algorithmic floor"):
            Vault.load(vault_file, "pass")

    def test_load_missing_nonce_or_ciphertext_raises_vault_format_error(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault = Vault.create_new()
        vault.save(vault_file, "pass")

        data = json.loads(vault_file.read_text())
        del data["nonce"]
        vault_file.write_text(json.dumps(data))

        with pytest.raises(VaultFormatError, match="missing 'nonce' or 'ciphertext'"):
            Vault.load(vault_file, "pass")

    def test_load_corrupted_base64_raises_vault_format_error(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault = Vault.create_new()
        vault.save(vault_file, "pass")

        data = json.loads(vault_file.read_text())
        data["ciphertext"] = "===not-valid-b64==="
        vault_file.write_text(json.dumps(data))

        with pytest.raises(VaultFormatError, match="Invalid base64 payload"):
            Vault.load(vault_file, "pass")

    def test_unicode_entries_roundtrip(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault = Vault.create_new()
        vault.add_entry(
            name="東京_銀行",
            username="ユーザー名123",
            password="パスワード🔑!@#",
            url="https://銀行.jp",
            notes="セキュリティノート 🛡️",
        )
        vault.save(vault_file, "マスターキー🔑")

        loaded = Vault.load(vault_file, "マスターキー🔑")
        entry = loaded.get_entry("東京_銀行")
        assert entry["username"] == "ユーザー名123"
        assert entry["password"] == "パスワード🔑!@#"
        assert entry["notes"] == "セキュリティノート 🛡️"


class TestVaultCRUD:
    def test_add_get_entry(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault = Vault.create_new()
        added = vault.add_entry(
            name="github",
            username="dev_user",
            password="secure-pass-456",
            url="https://github.com",
            notes="Personal account",
        )
        assert added["username"] == "dev_user"
        assert added["url"] == "https://github.com"
        assert "created" in added
        assert "updated" in added

        vault.save(vault_file, "master123")

        # Load back
        loaded = Vault.load(vault_file, "master123")
        entry = loaded.get_entry("github")
        assert entry["username"] == "dev_user"
        assert entry["password"] == "secure-pass-456"
        assert entry["url"] == "https://github.com"
        assert entry["notes"] == "Personal account"

    def test_add_duplicate_without_overwrite_raises_error(self):
        vault = Vault.create_new()
        vault.add_entry("email", "bob", "p1")
        with pytest.raises(EntryAlreadyExistsError):
            vault.add_entry("email", "bob", "p2", overwrite=False)

    def test_add_duplicate_with_overwrite_preserves_created_timestamp(self):
        vault = Vault.create_new()
        e1 = vault.add_entry("email", "bob", "p1")
        created_ts = e1["created"]

        e2 = vault.add_entry("email", "bob-updated", "p2", overwrite=True)
        assert e2["created"] == created_ts
        assert e2["username"] == "bob-updated"

    def test_get_nonexistent_entry_raises_not_found(self):
        vault = Vault.create_new()
        with pytest.raises(EntryNotFoundError):
            vault.get_entry("nonexistent")

    def test_delete_entry(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault = Vault.create_new()
        vault.add_entry("entry1", "user1", "p1")
        vault.add_entry("entry2", "user2", "p2")
        vault.save(vault_file, "master")

        loaded = Vault.load(vault_file, "master")
        loaded.delete_entry("entry1")
        loaded.save(vault_file, "master")

        reloaded = Vault.load(vault_file, "master")
        with pytest.raises(EntryNotFoundError):
            reloaded.get_entry("entry1")
        assert reloaded.get_entry("entry2")["username"] == "user2"

    def test_delete_nonexistent_entry_raises_not_found(self):
        vault = Vault.create_new()
        with pytest.raises(EntryNotFoundError):
            vault.delete_entry("nonexistent")

    def test_list_entries_sorted(self):
        vault = Vault.create_new()
        vault.add_entry("zebra", "u1", "p1")
        vault.add_entry("apple", "u2", "p2")
        vault.add_entry("mango", "u3", "p3")

        listing = vault.list_entries()
        names = [item[0] for item in listing]
        assert names == ["apple", "mango", "zebra"]


class TestPasswordRotationAndLocking:
    def test_change_password_rotates_salt_and_key(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        vault = Vault.create_new()
        vault.add_entry("service", "dev_user", "secret")
        vault.save(vault_file, "old-master")

        data_before = json.loads(vault_file.read_text())
        salt_before = data_before["kdf"]["salt"]

        # Rotate password
        rotator = Vault()
        rotator.change_password(vault_file, "old-master", "new-master")

        data_after = json.loads(vault_file.read_text())
        salt_after = data_after["kdf"]["salt"]

        # Fresh salt must be generated
        assert salt_before != salt_after

        # Old password must now fail
        with pytest.raises(WrongPasswordError):
            Vault.load(vault_file, "old-master")

        # New password succeeds and retains data
        unlocked = Vault.load(vault_file, "new-master")
        assert unlocked.get_entry("service")["password"] == "secret"

    def test_advisory_file_locking(self, tmp_path: Path):
        vault_file = tmp_path / "vault.json"
        with acquire_vault_lock(vault_file):
            lock_path = vault_file.with_name(vault_file.name + ".lock")
            assert lock_path.exists()
            assert stat.S_IMODE(os.stat(lock_path).st_mode) == 0o600
