"""Unit tests for the command-line interface in passvault.cli."""

from pathlib import Path
from unittest.mock import patch
import pytest

from passvault.cli import main


class TestCLISecurityGuards:
    def test_rejection_of_password_flag(self, capsys):
        rc = main(["add", "github", "-p", "secret"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "never accepts passwords as CLI flags" in captured.err

    def test_rejection_of_long_password_flag(self, capsys):
        rc = main(["init", "--password", "secret"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "never accepts passwords as CLI flags" in captured.err


class TestCLIGenerator:
    def test_cli_gen_default_pipe_friendly(self, capsys):
        rc = main(["gen"])
        assert rc == 0
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert len(lines) == 1
        assert len(lines[0]) == 20

    def test_cli_gen_custom_length(self, capsys):
        rc = main(["gen", "32"])
        assert rc == 0
        captured = capsys.readouterr()
        assert len(captured.out.strip()) == 32

    def test_cli_gen_no_symbols(self, capsys):
        rc = main(["gen", "24", "--no-symbols"])
        assert rc == 0
        pw = captured = capsys.readouterr().out.strip()
        assert len(pw) == 24
        assert pw.isalnum()


class TestCLIWorkflow:
    def test_cli_init_add_get_list_delete_lifecycle(self, tmp_path: Path, capsys):
        vault_file = tmp_path / "test_vault.json"
        vault_arg = ["--vault", str(vault_file)]

        # 1. Init
        with patch("getpass.getpass", side_effect=["masterkey123", "masterkey123"]):
            rc = main(["init"] + vault_arg)
            assert rc == 0

        assert vault_file.exists()

        # 2. Add entry with --generate flag
        with patch("getpass.getpass", side_effect=["masterkey123"]), \
             patch("builtins.input", side_effect=["dev_user", "https://github.com", "my dev account"]):
            rc = main(["add", "github", "-g"] + vault_arg)
            assert rc == 0

        captured = capsys.readouterr()
        assert "Added entry: github" in captured.out

        # 3. Get entry
        with patch("getpass.getpass", side_effect=["masterkey123"]):
            rc = main(["get", "github"] + vault_arg)
            assert rc == 0

        captured = capsys.readouterr()
        assert "github" in captured.out
        assert "dev_user" in captured.out
        assert "https://github.com" in captured.out

        # 4. List entries
        with patch("getpass.getpass", side_effect=["masterkey123"]):
            rc = main(["list"] + vault_arg)
            assert rc == 0

        captured = capsys.readouterr()
        assert "github" in captured.out

        # 5. Add second entry manually
        with patch("getpass.getpass", side_effect=["masterkey123", "sample_pass_123"]):
            with patch("builtins.input", side_effect=["test_admin", "", ""]):
                rc = main(["add", "gitlab"] + vault_arg)
                assert rc == 0

        # 6. Delete entry
        with patch("getpass.getpass", side_effect=["masterkey123"]):
            rc = main(["delete", "github"] + vault_arg)
            assert rc == 0

        captured = capsys.readouterr()
        assert "Deleted entry: github" in captured.out

        # 7. Verify deleted entry can no longer be retrieved
        with patch("getpass.getpass", side_effect=["masterkey123"]):
            rc = main(["get", "github"] + vault_arg)
            assert rc == 1

        captured = capsys.readouterr()
        assert "Entry 'github' not found" in captured.err

    def test_cli_init_mismatch_password(self, tmp_path: Path, capsys):
        vault_file = tmp_path / "mismatch.json"
        with patch("getpass.getpass", side_effect=["pw1", "pw2"]):
            rc = main(["init", "--vault", str(vault_file)])
            assert rc == 1
        captured = capsys.readouterr()
        assert "Passwords do not match" in captured.err

    def test_cli_change_password(self, tmp_path: Path, capsys):
        vault_file = tmp_path / "rot.json"
        vault_arg = ["--vault", str(vault_file)]

        # Init
        with patch("getpass.getpass", side_effect=["oldpass", "oldpass"]):
            assert main(["init"] + vault_arg) == 0

        # Add item
        with patch("getpass.getpass", side_effect=["oldpass", "itempass"]):
            with patch("builtins.input", side_effect=["admin", "", ""]):
                assert main(["add", "server"] + vault_arg) == 0

        # Rotate password
        with patch("getpass.getpass", side_effect=["oldpass", "newpass", "newpass"]):
            rc = main(["change-password"] + vault_arg)
            assert rc == 0

        # Check with new password
        with patch("getpass.getpass", side_effect=["newpass"]):
            rc = main(["get", "server"] + vault_arg)
            assert rc == 0
        captured = capsys.readouterr()
        assert "server" in captured.out
        assert "admin" in captured.out

    def test_cli_list_empty_vault(self, tmp_path: Path, capsys):
        vault_file = tmp_path / "empty_vault.json"
        with patch("getpass.getpass", side_effect=["pass", "pass"]):
            main(["init", "--vault", str(vault_file)])

        with patch("getpass.getpass", side_effect=["pass"]):
            rc = main(["list", "--vault", str(vault_file)])
            assert rc == 0
        captured = capsys.readouterr()
        assert "Vault is empty" in captured.out

    def test_cli_get_nonexistent_entry(self, tmp_path: Path, capsys):
        vault_file = tmp_path / "vault.json"
        with patch("getpass.getpass", side_effect=["pass", "pass"]):
            main(["init", "--vault", str(vault_file)])

        with patch("getpass.getpass", side_effect=["pass"]):
            rc = main(["get", "missing", "--vault", str(vault_file)])
            assert rc == 1
        captured = capsys.readouterr()
        assert "Entry 'missing' not found" in captured.err

    def test_cli_delete_nonexistent_entry(self, tmp_path: Path, capsys):
        vault_file = tmp_path / "vault.json"
        with patch("getpass.getpass", side_effect=["pass", "pass"]):
            main(["init", "--vault", str(vault_file)])

        with patch("getpass.getpass", side_effect=["pass"]):
            rc = main(["delete", "missing", "--vault", str(vault_file)])
            assert rc == 1
        captured = capsys.readouterr()
        assert "Entry 'missing' not found" in captured.err

    def test_cli_empty_password_aborts(self, tmp_path: Path, capsys):
        vault_file = tmp_path / "vault.json"
        with patch("getpass.getpass", side_effect=[""]):
            rc = main(["init", "--vault", str(vault_file)])
            assert rc == 1
        captured = capsys.readouterr()
        assert "Password cannot be empty" in captured.err or "Master password cannot be empty" in captured.err

    def test_cli_no_args_prints_help(self, capsys):
        rc = main([])
        assert rc == 0
        captured = capsys.readouterr()
        assert "PASS VAULT" in captured.out
