"""Command Line Interface (CLI) for PASS VAULT (pv).

Design Principles:
1. No passwords in CLI flags: Master passwords are NEVER accepted via command-line arguments,
   as CLI flags leak into shell histories (e.g. ~/.bash_history) and system process tables (ps aux).
   Instead, all sensitive inputs use getpass.getpass().
2. Pipe-friendly stdout/stderr separation: Output designed for piping (like `pv gen 32 | pbcopy`)
   writes clean raw text to stdout, while interactive logs and warnings write to stderr.
3. Informative, typed error exits: Exceptions map to clean, readable terminal alerts.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from passvault.config import (
    DEFAULT_GENERATED_PASSWORD_LEN,
    get_default_vault_path,
)
from passvault.exceptions import (
    PassVaultError,
    WrongPasswordError,
    VaultNotFoundError,
    VaultAlreadyExistsError,
    EntryNotFoundError,
    EntryAlreadyExistsError,
    VaultFormatError,
    LockError,
)
from passvault.generator import generate_password
from passvault.ui import (
    console,
    err_console,
    print_error,
    print_success,
    render_entry_panel,
    render_entries_table,
)
from passvault.vault import Vault


def _secure_input(prompt_text: str, is_password: bool = True) -> str:
    """Prompt user securely without echoing password to terminal."""
    if is_password:
        return getpass.getpass(prompt_text)
    return input(prompt_text)


def _prompt_master_password(prompt_text: str = "Master password: ") -> str:
    """Prompt for master password without echoing to terminal."""
    try:
        pw = _secure_input(prompt_text, is_password=True)
    except (KeyboardInterrupt, EOFError):
        err_console.print("\nAborted.")
        sys.exit(130)

    if not pw:
        err_console.print("[red]Password cannot be empty.[/red]")
        sys.exit(1)
    return pw


def handle_init(args: argparse.Namespace) -> int:
    """Create a new empty vault. Prompts for the master password twice."""
    vault_path: Path = args.vault

    if vault_path.exists() and not getattr(args, "force", False):
        print_error(
            f"Vault already exists at {vault_path}. "
            "Specify another path with --vault or remove the existing file."
        )
        return 1

    try:
        pw1 = _secure_input("New master password: ", is_password=True)
        if not pw1:
            print_error("Master password cannot be empty.")
            return 1
        pw2 = _secure_input("Confirm master password: ", is_password=True)
    except (KeyboardInterrupt, EOFError):
        err_console.print("\nAborted.")
        return 130

    if pw1 != pw2:
        print_error("Passwords do not match.")
        return 1

    vault = Vault.create_new()
    vault.save(vault_path, pw1, upgrade_kdf=True)
    console.print(f"Vault created at {vault_path}")
    return 0


def handle_add(args: argparse.Namespace) -> int:
    """Add an entry to the vault."""
    vault_path: Path = args.vault
    name: str = args.name

    master_pw = _prompt_master_password()
    try:
        vault = Vault.load(vault_path, master_pw)
    except PassVaultError as err:
        print_error(str(err))
        return 1

    if name in vault.entries and not getattr(args, "overwrite", False):
        print_error(f"Entry '{name}' already exists. Use another name or delete it first.")
        return 1

    try:
        username = input(f"Username for {name}: ")
        if args.generate:
            password = generate_password(DEFAULT_GENERATED_PASSWORD_LEN)
            err_console.print(f"[dim]Generated strong random password for {name}[/dim]")
        else:
            password = _secure_input(f"Password for {name} (hidden): ", is_password=True)
            if not password:
                print_error("Password cannot be empty.")
                return 1

        url = input("URL (optional, press Enter to skip): ").strip()
        notes = input("Notes (optional, press Enter to skip): ").strip()
    except (KeyboardInterrupt, EOFError):
        err_console.print("\nAborted.")
        return 130

    vault.add_entry(
        name=name,
        username=username,
        password=password,
        url=url,
        notes=notes,
        overwrite=getattr(args, "overwrite", False),
    )
    vault.save(vault_path, master_pw)
    console.print(f"Added entry: {name}")
    return 0


def handle_get(args: argparse.Namespace) -> int:
    """Retrieve and display an entry."""
    vault_path: Path = args.vault
    name: str = args.name

    master_pw = _prompt_master_password()
    try:
        vault = Vault.load(vault_path, master_pw)
        entry = vault.get_entry(name)
        render_entry_panel(name, entry)
        return 0
    except PassVaultError as err:
        print_error(str(err))
        return 1


def handle_list(args: argparse.Namespace) -> int:
    """List all entry names as a table (passwords are omitted)."""
    vault_path: Path = args.vault

    master_pw = _prompt_master_password()
    try:
        vault = Vault.load(vault_path, master_pw)
        entries = vault.list_entries()
        if not entries:
            console.print("[dim]Vault is empty. Add entries with 'pv add <name>'.[/dim]")
            return 0
        render_entries_table(entries)
        return 0
    except PassVaultError as err:
        print_error(str(err))
        return 1


def handle_delete(args: argparse.Namespace) -> int:
    """Remove an entry by name."""
    vault_path: Path = args.vault
    name: str = args.name

    master_pw = _prompt_master_password()
    try:
        vault = Vault.load(vault_path, master_pw)
        vault.delete_entry(name)
        vault.save(vault_path, master_pw)
        console.print(f"Deleted entry: {name}")
        return 0
    except PassVaultError as err:
        print_error(str(err))
        return 1


def handle_gen(args: argparse.Namespace) -> int:
    """Generate a strong random password and print to stdout."""
    length = args.length
    include_symbols = not args.no_symbols
    include_digits = not args.no_digits

    try:
        pw = generate_password(
            length=length,
            include_symbols=include_symbols,
            include_digits=include_digits,
        )
        # Directly print raw password without formatting for piping support
        sys.stdout.write(pw + "\n")
        sys.stdout.flush()
        return 0
    except ValueError as err:
        print_error(str(err))
        return 1


def handle_change_password(args: argparse.Namespace) -> int:
    """Rotate the master password, re-encrypting the entire vault under a fresh salt and key."""
    vault_path: Path = args.vault

    try:
        current_pw = _secure_input("Current master password: ", is_password=True)
        new_pw1 = _secure_input("New master password: ", is_password=True)
        if not new_pw1:
            print_error("New master password cannot be empty.")
            return 1
        new_pw2 = _secure_input("Confirm new master password: ", is_password=True)
    except (KeyboardInterrupt, EOFError):
        err_console.print("\nAborted.")
        return 130

    if new_pw1 != new_pw2:
        print_error("New passwords do not match.")
        return 1

    try:
        vault = Vault()
        vault.change_password(vault_path, current_pw, new_pw1)
        console.print("[bold green]✓[/bold green] Master password rotated successfully.")
        return 0
    except PassVaultError as err:
        print_error(str(err))
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--vault",
        type=Path,
        default=get_default_vault_path(),
        help="Path to the vault file (defaults to ~/.password-vault/vault.json or $PV_VAULT)",
    )

    parser = argparse.ArgumentParser(
        prog="pv",
        parents=[common_parser],
        description="PASS VAULT: Encrypted command-line password manager using Argon2id and AES-256-GCM.",
    )

    # Educational guard: reject any attempt to pass password as flag
    parser.add_argument(
        "-p", "--password",
        action="store_true",
        help=argparse.SUPPRESS,  # Hidden flag to catch unsafe habit
    )

    subparsers = parser.add_subparsers(dest="subcommand", title="Commands")

    # init
    p_init = subparsers.add_parser(
        "init",
        parents=[common_parser],
        help="Create a new empty vault. Prompts for master password twice.",
    )
    p_init.add_argument("--force", action="store_true", help="Overwrite existing vault if present")

    # add
    p_add = subparsers.add_parser(
        "add",
        parents=[common_parser],
        help="Add an entry. Prompts for username, password, optional URL and notes.",
    )
    p_add.add_argument("name", help="Name of the entry (e.g. github, email)")
    p_add.add_argument(
        "-g", "--generate",
        action="store_true",
        help="Automatically generate a cryptographically strong random password",
    )
    p_add.add_argument("--overwrite", action="store_true", help="Overwrite existing entry if present")

    # get
    p_get = subparsers.add_parser(
        "get",
        parents=[common_parser],
        help="Show every field of one entry in a colored panel.",
    )
    p_get.add_argument("name", help="Name of the entry to retrieve")

    # list
    subparsers.add_parser(
        "list",
        parents=[common_parser],
        help="Print every entry name as a table (no passwords shown).",
    )

    # delete
    p_del = subparsers.add_parser(
        "delete",
        parents=[common_parser],
        help="Remove an entry by name.",
    )
    p_del.add_argument("name", help="Name of the entry to remove")

    # gen
    p_gen = subparsers.add_parser(
        "gen",
        parents=[common_parser],
        help="Generate a strong random password and print it to stdout.",
    )
    p_gen.add_argument(
        "length",
        nargs="?",
        type=int,
        default=DEFAULT_GENERATED_PASSWORD_LEN,
        help=f"Length of password (default: {DEFAULT_GENERATED_PASSWORD_LEN})",
    )
    p_gen.add_argument("--no-symbols", action="store_true", help="Omit special symbols (letters + digits only)")
    p_gen.add_argument("--no-digits", action="store_true", help="Omit numbers")

    # change-password
    subparsers.add_parser(
        "change-password",
        parents=[common_parser],
        help="Rotate the master password — re-encrypts the entire vault under a fresh salt and key.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    if argv is None:
        argv = sys.argv[1:]

    # Check for insecure flag usage before parsing
    if any(arg in argv for arg in ("-p", "--password")):
        print_error(
            "Security Notice: 'pv' never accepts passwords as CLI flags!\n"
            "Passwords in flags leak into shell history (~/.bash_history) and process tables ('ps aux').\n"
            "Passwords must be entered interactively via secure prompts."
        )
        return 2

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 0

    command_handlers = {
        "init": handle_init,
        "add": handle_add,
        "get": handle_get,
        "list": handle_list,
        "delete": handle_delete,
        "gen": handle_gen,
        "change-password": handle_change_password,
    }

    handler = command_handlers.get(args.subcommand)
    if not handler:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
