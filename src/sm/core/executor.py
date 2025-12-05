"""Command execution with rollback support.

Provides:
- Safe command execution with output capture
- SQL execution via psql
- Rollback stack for transaction-like behavior
- Dry-run mode support
"""

import shlex
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Generator, Optional, Any

from sm.core.context import ExecutionContext
from sm.core.exceptions import ExecutionError, RollbackError
from sm.core.output import console


@dataclass
class RollbackAction:
    """A single rollback action."""
    description: str
    action: Callable[[], None]
    critical: bool = False  # If True, failure stops rollback


class RollbackStack:
    """Stack of rollback actions for transaction-like behavior.

    Usage:
        with executor.transaction() as rollback:
            create_user(name)
            rollback.add("Delete user", lambda: delete_user(name))

            create_database(name)
            rollback.add("Drop database", lambda: drop_database(name))

            # If anything fails, rollback is triggered automatically
    """

    def __init__(self) -> None:
        self.actions: list[RollbackAction] = []
        self.committed = False

    def add(
        self,
        description: str,
        action: Callable[[], None],
        critical: bool = False,
    ) -> None:
        """Add a rollback action to the stack.

        Args:
            description: Human-readable description
            action: Callable to execute for rollback
            critical: If True, rollback stops on failure
        """
        self.actions.append(RollbackAction(description, action, critical))

    def commit(self) -> None:
        """Mark transaction as successful - rollback won't run."""
        self.committed = True
        self.actions.clear()

    def rollback(self) -> None:
        """Execute all rollback actions in reverse order."""
        if self.committed:
            return

        console.warn("Rolling back changes...")

        for action in reversed(self.actions):
            try:
                console.step(f"Rollback: {action.description}")
                action.action()
            except Exception as e:
                console.error(f"Rollback failed: {action.description}: {e}")
                if action.critical:
                    raise RollbackError(
                        f"Critical rollback action failed: {action.description}",
                        details=[str(e)],
                    )


@dataclass
class CommandResult:
    """Result of a command execution."""
    command: list[str]
    return_code: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        """Check if command succeeded."""
        return self.return_code == 0


class CommandExecutor:
    """Safe command execution with dry-run support and output capture.

    Features:
    - Dry-run mode shows what would happen
    - Output capture for processing
    - Timeout support
    - User switching (sudo -u)
    - Sensitive command masking
    """

    def __init__(self, ctx: ExecutionContext) -> None:
        """Initialize executor with context.

        Args:
            ctx: Execution context with flags
        """
        self.ctx = ctx
        self._rollback_stack: Optional[RollbackStack] = None

    def run(
        self,
        command: list[str],
        *,
        description: Optional[str] = None,
        check: bool = True,
        capture: bool = True,
        as_user: Optional[str] = None,
        sensitive: bool = False,
        timeout: Optional[int] = None,
        env: Optional[dict[str, str]] = None,
        cwd: Optional[Path] = None,
    ) -> CommandResult:
        """Execute a shell command safely.

        Args:
            command: Command as list of strings
            description: Human-readable description for logging
            check: Raise exception on non-zero exit
            capture: Capture stdout/stderr
            as_user: Run as different user (via sudo -u)
            sensitive: Don't log the actual command
            timeout: Command timeout in seconds
            env: Additional environment variables
            cwd: Working directory

        Returns:
            CommandResult with output

        Raises:
            ExecutionError: If command fails and check=True
        """
        # Prepend sudo if running as different user
        if as_user:
            command = ["sudo", "-u", as_user] + command

        # Log what we're doing
        if description:
            self.ctx.console.step(description)

        cmd_display = "<sensitive command>" if sensitive else shlex.join(command)
        self.ctx.console.debug(f"Running: {cmd_display}")

        # Dry-run mode
        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Run: {cmd_display}")
            return CommandResult(
                command=command,
                return_code=0,
                stdout="",
                stderr="",
            )

        # Prepare environment
        run_env = None
        if env:
            import os
            run_env = os.environ.copy()
            run_env.update(env)

        # Execute
        try:
            result = subprocess.run(
                command,
                capture_output=capture,
                text=True,
                timeout=timeout,
                env=run_env,
                cwd=cwd,
            )

            cmd_result = CommandResult(
                command=command,
                return_code=result.returncode,
                stdout=result.stdout if capture else "",
                stderr=result.stderr if capture else "",
            )

            # Check for errors
            if check and result.returncode != 0:
                raise ExecutionError(
                    f"Command failed: {description or cmd_display}",
                    command=cmd_display,
                    return_code=result.returncode,
                    stderr=result.stderr if capture else None,
                )

            return cmd_result

        except subprocess.TimeoutExpired:
            raise ExecutionError(
                f"Command timed out after {timeout}s: {description or cmd_display}",
                command=cmd_display,
            )

    def run_sql(
        self,
        sql: str,
        *,
        database: str = "postgres",
        as_user: str = "postgres",
        description: Optional[str] = None,
        variables: Optional[dict[str, str]] = None,
        check: bool = True,
    ) -> str:
        """Execute SQL via psql safely.

        Uses psql variables (-v) to avoid SQL injection.

        Args:
            sql: SQL statement(s) to execute
            database: Database to connect to
            as_user: PostgreSQL user to run as
            description: Human-readable description
            variables: psql variables to set (safe from injection)
            check: Raise exception on error

        Returns:
            Query output

        Raises:
            ExecutionError: If query fails and check=True
        """
        command = [
            "psql",
            "-v", "ON_ERROR_STOP=1",
            "-d", database,
            "-t",  # Tuples only (no headers)
            "-A",  # Unaligned output
            "-c", sql,
        ]

        # Add variables safely
        if variables:
            for key, value in variables.items():
                command.extend(["-v", f"{key}={value}"])

        if description:
            self.ctx.console.step(description)

        # Show SQL in dry-run and debug modes
        if self.ctx.dry_run or self.ctx.is_debug:
            # Truncate long SQL for display
            sql_display = sql[:200] + "..." if len(sql) > 200 else sql
            if self.ctx.dry_run:
                self.ctx.console.dry_run_msg(f"Execute SQL: {sql_display}")
                if self.ctx.is_verbose:
                    self.ctx.console.sql(sql)
                return ""
            else:
                self.ctx.console.debug(f"SQL: {sql_display}")

        result = self.run(
            command,
            as_user=as_user,
            check=check,
            sensitive=True,  # SQL might contain sensitive data
        )

        return result.stdout.strip()

    def run_sql_format(
        self,
        sql_template: str,
        *,
        database: str = "postgres",
        as_user: str = "postgres",
        description: Optional[str] = None,
        check: bool = True,
        **format_args: Any,
    ) -> str:
        """Execute SQL using PostgreSQL format() for safe interpolation.

        This is the safest way to include dynamic values in SQL.
        Use %I for identifiers and %L for literals.

        Args:
            sql_template: SQL with format() placeholders
            database: Database to connect to
            as_user: PostgreSQL user
            description: Human-readable description
            check: Raise exception on error
            **format_args: Arguments for format()

        Returns:
            Query output

        Example:
            executor.run_sql_format(
                "CREATE DATABASE %I OWNER %I",
                db_name="mydb",
                owner="myuser",
            )
        """
        # Build format() call with proper quoting
        # format_args are passed as psql variables
        args_list = list(format_args.values())
        format_placeholders = ", ".join(f":{k}" for k in format_args.keys())

        if format_placeholders:
            sql = f"SELECT format($${sql_template}$$, {format_placeholders})"
            result = self.run_sql(
                sql,
                database=database,
                as_user=as_user,
                description=None,  # We'll describe the actual operation
                variables=format_args,
                check=check,
            )
            # Execute the formatted SQL
            if result and not self.ctx.dry_run:
                return self.run_sql(
                    result,
                    database=database,
                    as_user=as_user,
                    description=description,
                    check=check,
                )
            return result
        else:
            return self.run_sql(
                sql_template,
                database=database,
                as_user=as_user,
                description=description,
                check=check,
            )

    def check_sql(
        self,
        sql: str,
        *,
        database: str = "postgres",
        as_user: str = "postgres",
    ) -> bool:
        """Check if SQL returns any rows (for existence checks).

        Args:
            sql: SQL query that returns rows
            database: Database to connect to
            as_user: PostgreSQL user

        Returns:
            True if query returns at least one row
        """
        if self.ctx.dry_run:
            return False

        result = self.run_sql(
            sql,
            database=database,
            as_user=as_user,
            check=False,
        )
        return bool(result.strip())

    @contextmanager
    def transaction(self) -> Generator[RollbackStack, None, None]:
        """Context manager for transaction-like behavior with rollback.

        Usage:
            with executor.transaction() as rollback:
                do_something()
                rollback.add("Undo something", undo_something)
                # If exception occurs, rollback is triggered
        """
        stack = RollbackStack()
        self._rollback_stack = stack

        try:
            yield stack
            stack.commit()
        except Exception:
            stack.rollback()
            raise
        finally:
            self._rollback_stack = None

    def systemctl(
        self,
        action: str,
        service: str,
        *,
        description: Optional[str] = None,
        check: bool = True,
    ) -> CommandResult:
        """Execute systemctl command.

        Args:
            action: systemctl action (start, stop, restart, reload, status)
            service: Service name
            description: Human-readable description
            check: Raise exception on error

        Returns:
            CommandResult
        """
        desc = description or f"{action.title()} {service}"
        return self.run(
            ["systemctl", action, service],
            description=desc,
            check=check,
        )

    def apt_install(
        self,
        packages: list[str],
        *,
        description: Optional[str] = None,
    ) -> CommandResult:
        """Install packages via apt.

        Args:
            packages: List of package names
            description: Human-readable description

        Returns:
            CommandResult
        """
        desc = description or f"Install {', '.join(packages)}"
        return self.run(
            ["apt-get", "install", "-y"] + packages,
            description=desc,
            env={"DEBIAN_FRONTEND": "noninteractive"},
        )

    def file_exists(self, path: Path) -> bool:
        """Check if a file exists.

        Args:
            path: Path to check

        Returns:
            True if file exists
        """
        return path.exists()

    def write_file(
        self,
        path: Path,
        content: str,
        *,
        description: Optional[str] = None,
        permissions: int = 0o644,
        owner: Optional[str] = None,
        group: Optional[str] = None,
    ) -> None:
        """Write content to a file atomically.

        Args:
            path: Destination path
            content: File content
            description: Human-readable description
            permissions: File permissions
            owner: File owner
            group: File group
        """
        desc = description or f"Write {path}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Write {len(content)} bytes to {path}")
            if self.ctx.is_verbose:
                # Show content preview
                preview = content[:500] + "..." if len(content) > 500 else content
                self.ctx.console.print(f"[dim]{preview}[/dim]")
            return

        # Create parent directory if needed
        path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write
        from sm.core.credentials import AtomicFileWriter

        with AtomicFileWriter(path, permissions=permissions).open() as f:
            f.write(content)

        # Set ownership if specified
        if owner or group:
            import pwd
            import grp

            uid = pwd.getpwnam(owner).pw_uid if owner else -1
            gid = grp.getgrnam(group).gr_gid if group else -1

            import os
            os.chown(path, uid, gid)

    def backup_file(
        self,
        path: Path,
        *,
        suffix: str = ".bak",
    ) -> Optional[Path]:
        """Create a backup of a file.

        Args:
            path: File to backup
            suffix: Backup file suffix

        Returns:
            Path to backup file, or None if original doesn't exist
        """
        if not path.exists():
            return None

        import shutil
        import time

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_path = path.with_suffix(f"{path.suffix}.{timestamp}{suffix}")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Backup {path} to {backup_path}")
            return backup_path

        shutil.copy2(path, backup_path)
        self.ctx.console.debug(f"Backed up {path} to {backup_path}")
        return backup_path
