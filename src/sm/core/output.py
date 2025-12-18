"""Output and logging utilities using Rich for beautiful console output.

Provides:
- Colored, formatted console output
- Verbosity level control
- Dry-run mode indicators
- Progress indicators
- Structured summaries
"""

from enum import IntEnum
from typing import Any

from rich import box
from rich.console import Console as RichConsole
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table


class Verbosity(IntEnum):
    """Output verbosity levels."""
    QUIET = 0    # Errors only
    NORMAL = 1   # Standard output
    VERBOSE = 2  # Additional details
    DEBUG = 3    # Everything


class Console:
    """Centralized console output with Rich integration.

    Features:
    - Color-coded log levels
    - Verbosity control
    - Dry-run mode awareness
    - Beautiful tables and panels
    - Progress spinners
    """

    def __init__(self) -> None:
        self._console = RichConsole(highlight=False)
        self._err_console = RichConsole(stderr=True, highlight=False)
        self.verbosity = Verbosity.NORMAL
        self.dry_run = False
        self.no_color = False

    def configure(
        self,
        verbosity: int = 1,
        dry_run: bool = False,
        no_color: bool = False,
    ) -> None:
        """Configure console output settings."""
        self.verbosity = Verbosity(min(verbosity, Verbosity.DEBUG))
        self.dry_run = dry_run
        self.no_color = no_color
        if no_color:
            self._console = RichConsole(highlight=False, no_color=True)
            self._err_console = RichConsole(stderr=True, highlight=False, no_color=True)

    # Basic output methods
    def info(self, message: str) -> None:
        """Print info message (green)."""
        if self.verbosity >= Verbosity.NORMAL:
            self._console.print(f"[green][INFO][/green] {message}")

    def success(self, message: str) -> None:
        """Print success message (green checkmark)."""
        if self.verbosity >= Verbosity.NORMAL:
            self._console.print(f"[green][OK][/green] {message}")

    def warn(self, message: str) -> None:
        """Print warning message (yellow) to stderr."""
        self._err_console.print(f"[yellow][WARN][/yellow] {message}")

    def error(self, message: str) -> None:
        """Print error message (red) to stderr."""
        self._err_console.print(f"[red][ERROR][/red] {message}")

    def debug(self, message: str) -> None:
        """Print debug message (cyan) - only in debug mode."""
        if self.verbosity >= Verbosity.DEBUG:
            self._console.print(f"[cyan][DEBUG][/cyan] {message}")

    def verbose(self, message: str) -> None:
        """Print verbose message (dim) - only in verbose mode."""
        if self.verbosity >= Verbosity.VERBOSE:
            self._console.print(f"[dim]{message}[/dim]")

    def step(self, message: str) -> None:
        """Print a step indicator (blue arrow)."""
        if self.verbosity >= Verbosity.NORMAL:
            self._console.print(f"[blue]->[/blue] {message}")

    def dry_run_msg(self, message: str) -> None:
        """Print dry-run indicator (blue)."""
        if self.dry_run:
            self._console.print(f"[blue][DRY-RUN][/blue] Would: {message}")

    def hint(self, message: str) -> None:
        """Print a helpful hint (cyan)."""
        self._console.print(f"[cyan]Hint:[/cyan] {message}")

    # Structured output
    def print(self, message: Any = "", **kwargs: Any) -> None:
        """Print raw message or Rich renderable with formatting."""
        self._console.print(message, **kwargs)

    def rule(self, title: str = "") -> None:
        """Print a horizontal rule."""
        self._console.rule(title)

    def panel(
        self,
        content: str,
        title: str | None = None,
        border_style: str = "blue",
    ) -> None:
        """Print content in a panel."""
        self._console.print(Panel(content, title=title, border_style=border_style))

    def table(
        self,
        title: str,
        columns: list[str],
        rows: list[list[str]],
        box_style: box.Box = box.ROUNDED,
    ) -> None:
        """Print a formatted table."""
        table = Table(title=title, box=box_style)
        for col in columns:
            table.add_column(col)
        for row in rows:
            table.add_row(*row)
        self._console.print(table)

    def sql(self, sql: str, title: str = "SQL") -> None:
        """Print formatted SQL code."""
        syntax = Syntax(sql, "sql", theme="monokai", line_numbers=False)
        self._console.print(Panel(syntax, title=title, border_style="green"))

    def diff(self, diff_text: str, title: str = "Changes") -> None:
        """Print formatted diff output."""
        syntax = Syntax(diff_text, "diff", theme="monokai", line_numbers=False)
        self._console.print(Panel(syntax, title=title, border_style="yellow"))

    def yaml(self, yaml_text: str, title: str = "Configuration") -> None:
        """Print formatted YAML."""
        syntax = Syntax(yaml_text, "yaml", theme="monokai", line_numbers=False)
        self._console.print(Panel(syntax, title=title, border_style="cyan"))

    # Summary output
    def summary(self, title: str, items: dict[str, Any]) -> None:
        """Print a summary panel with key-value pairs."""
        content_lines = []
        for key, value in items.items():
            if isinstance(value, bool):
                value_str = "[green]Yes[/green]" if value else "[red]No[/red]"
            else:
                value_str = str(value)
            content_lines.append(f"[bold]{key}:[/bold] {value_str}")

        content = "\n".join(content_lines)
        self._console.print(Panel(content, title=title, border_style="blue"))

    def operation_summary(
        self,
        operation: str,
        success: bool,
        details: dict[str, Any],
    ) -> None:
        """Print operation result summary."""
        status = "[green]SUCCESS[/green]" if success else "[red]FAILED[/red]"
        title = f"{operation} - {status}"
        border = "green" if success else "red"

        content_lines = []
        for key, value in details.items():
            content_lines.append(f"[bold]{key}:[/bold] {value}")

        content = "\n".join(content_lines)
        self._console.print(Panel(content, title=title, border_style=border))

    # Progress indicators
    def progress(self) -> Progress:
        """Get a progress context manager."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self._console,
        )

    def status(self, message: str, spinner: str = "dots") -> Any:
        """Get a status context manager with spinner.

        Args:
            message: Status message to display
            spinner: Spinner animation name (default: dots)

        Returns:
            Rich Status context manager
        """
        return self._console.status(message, spinner=spinner)

    # User input
    def input(self, prompt: str) -> str:
        """Get text input from user.

        Args:
            prompt: Prompt to display (supports Rich markup)

        Returns:
            User's input string

        Raises:
            EOFError: If input stream is closed
            KeyboardInterrupt: If user presses Ctrl+C
        """
        return self._console.input(prompt)

    # Confirmation prompts
    def confirm(
        self,
        message: str,
        default: bool = False,
        skip_confirm: bool = False,
    ) -> bool:
        """Ask for confirmation.

        Args:
            message: Question to ask
            default: Default answer if user just presses Enter
            skip_confirm: If True, return True without prompting

        Returns:
            True if confirmed, False otherwise
        """
        if skip_confirm:
            return True

        suffix = "[Y/n]" if default else "[y/N]"
        try:
            response = self._console.input(f"{message} {suffix}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False

        if not response:
            return default
        return response in ("y", "yes")

    def confirm_critical(
        self,
        operation: str,
        resource_name: str,
        skip_confirm: bool = False,
    ) -> bool:
        """Ask for critical operation confirmation.

        Requires typing the resource name to confirm.
        """
        if skip_confirm:
            return True

        self._console.print(
            f"\n[bold red]WARNING:[/bold red] You are about to {operation}.\n"
            f"This action [bold]cannot be undone[/bold].\n"
        )

        try:
            response = self._console.input(
                f"Type [bold]{resource_name}[/bold] to confirm: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return False

        return response == resource_name


# Global console instance
console = Console()
