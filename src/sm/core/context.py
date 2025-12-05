"""Execution context for commands.

The ExecutionContext holds the current state and flags that affect
how commands are executed. It is passed to all commands and used by
the safety framework, executor, and output systems.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any

from sm.core.config import AppConfig, DEFAULT_CONFIG_PATH
from sm.core.output import Console, console, Verbosity


@dataclass
class ExecutionContext:
    """Execution context passed to all commands.

    This contains:
    - Runtime flags (dry_run, force, etc.)
    - Configuration
    - Console for output
    - Any command-specific context

    Attributes:
        dry_run: If True, show what would happen without executing
        force: If True, allow dangerous operations
        yes: If True, skip confirmation prompts
        verbosity: Output verbosity level (0-3)
        no_color: If True, disable colored output
        config_path: Path to configuration file
        confirm_name: Name for critical operation confirmation
    """

    # Runtime flags
    dry_run: bool = False
    force: bool = False
    yes: bool = False
    verbosity: int = 1
    no_color: bool = False

    # Configuration
    config_path: Path = field(default_factory=lambda: DEFAULT_CONFIG_PATH)

    # Critical operation confirmation
    confirm_name: Optional[str] = None

    # Internal state (initialized lazily)
    _config: Optional[AppConfig] = field(default=None, repr=False)
    _console: Console = field(default_factory=lambda: console, repr=False)

    # Command-specific context
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Configure console after initialization."""
        self._console.configure(
            verbosity=self.verbosity,
            dry_run=self.dry_run,
            no_color=self.no_color,
        )

    @property
    def config(self) -> AppConfig:
        """Get application configuration (lazy loaded)."""
        if self._config is None:
            self._config = AppConfig(config_path=self.config_path)
        return self._config

    @property
    def console(self) -> Console:
        """Get console for output."""
        return self._console

    @property
    def is_verbose(self) -> bool:
        """Check if verbose output is enabled."""
        return self.verbosity >= Verbosity.VERBOSE

    @property
    def is_debug(self) -> bool:
        """Check if debug output is enabled."""
        return self.verbosity >= Verbosity.DEBUG

    @property
    def is_quiet(self) -> bool:
        """Check if quiet mode is enabled."""
        return self.verbosity <= Verbosity.QUIET

    @property
    def should_confirm(self) -> bool:
        """Check if confirmations should be shown."""
        return not self.yes

    def with_config(self, config: AppConfig) -> "ExecutionContext":
        """Create a new context with different config."""
        return ExecutionContext(
            dry_run=self.dry_run,
            force=self.force,
            yes=self.yes,
            verbosity=self.verbosity,
            no_color=self.no_color,
            config_path=self.config_path,
            confirm_name=self.confirm_name,
            _config=config,
            _console=self._console,
            extra=self.extra.copy(),
        )

    def with_extra(self, **kwargs: Any) -> "ExecutionContext":
        """Create a new context with additional extra data."""
        new_extra = {**self.extra, **kwargs}
        return ExecutionContext(
            dry_run=self.dry_run,
            force=self.force,
            yes=self.yes,
            verbosity=self.verbosity,
            no_color=self.no_color,
            config_path=self.config_path,
            confirm_name=self.confirm_name,
            _config=self._config,
            _console=self._console,
            extra=new_extra,
        )


def create_context(
    dry_run: bool = False,
    force: bool = False,
    yes: bool = False,
    verbose: int = 0,
    quiet: bool = False,
    no_color: bool = False,
    config: Optional[Path] = None,
    confirm_name: Optional[str] = None,
) -> ExecutionContext:
    """Create an execution context from CLI options.

    Args:
        dry_run: Preview changes without executing
        force: Allow dangerous operations
        yes: Skip confirmation prompts
        verbose: Increase verbosity (can be repeated)
        quiet: Suppress non-essential output
        no_color: Disable colored output
        config: Path to configuration file
        confirm_name: Name for critical operation confirmation

    Returns:
        Configured execution context
    """
    # Calculate verbosity level
    if quiet:
        verbosity = Verbosity.QUIET
    else:
        verbosity = min(Verbosity.NORMAL + verbose, Verbosity.DEBUG)

    return ExecutionContext(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbosity=verbosity,
        no_color=no_color,
        config_path=config or DEFAULT_CONFIG_PATH,
        confirm_name=confirm_name,
    )
