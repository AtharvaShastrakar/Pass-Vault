"""Rich UI rendering components for PASS VAULT.

Provides:
- Colored panels for entry display (matching specification).
- Tables for listing credentials without exposing passwords.
- Pipe-friendly stdout and dedicated stderr consoles.
"""

from typing import Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Stdout console (detects whether redirected/piped)
console = Console()

# Stderr console for prompts, logs, and error messages
err_console = Console(stderr=True)


def print_error(message: str) -> None:
    """Print an error message to stderr in red text."""
    err_console.print(f"[bold red]Error:[/bold red] {message}")


def print_success(message: str) -> None:
    """Print a success message to stderr or stdout."""
    console.print(f"[bold green]✓[/bold green] {message}")


def render_entry_panel(name: str, entry: dict[str, Any]) -> None:
    """Render a credential entry in a clean, colored Rich panel.

    Example layout:
    ┌───────────── name ─────────────┐
    │ username dev_user              │
    │ password k9#V!mP8$xL2@qZ4      │
    │ url      https://github.com    │
    │ created  2026-10-13T10:00:00...│
    │ updated  2026-10-13T10:00:00...│
    └────────────────────────────────┘
    """
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="left")
    grid.add_column(style="white", justify="left")

    grid.add_row("username", entry.get("username", ""))
    grid.add_row("password", entry.get("password", ""))

    url = entry.get("url")
    if url:
        grid.add_row("url", url)

    notes = entry.get("notes")
    if notes:
        grid.add_row("notes", notes)

    grid.add_row("created", entry.get("created", ""))
    grid.add_row("updated", entry.get("updated", ""))

    panel = Panel(
        grid,
        title=f"[bold yellow]{name}[/bold yellow]",
        border_style="cyan",
        expand=False,
    )
    console.print(panel)


def render_entries_table(entries: list[tuple[str, dict[str, Any]]]) -> None:
    """Render the list of entries as a formatted table without showing passwords."""
    table = Table(
        title="Vault Entries",
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
    )
    table.add_column("Name", style="bold cyan")
    table.add_column("Username", style="white")
    table.add_column("URL", style="blue")
    table.add_column("Last Updated", style="dim")

    for name, data in entries:
        table.add_row(
            name,
            data.get("username", ""),
            data.get("url", "") or "-",
            data.get("updated", "")[:19].replace("T", " ") if data.get("updated") else "-",
        )

    console.print(table)
