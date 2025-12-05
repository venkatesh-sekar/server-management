"""PgBouncer service abstraction.

Provides safe interface for managing PgBouncer configuration.
"""

import re
from pathlib import Path
from typing import Optional

from sm.core.context import ExecutionContext
from sm.core.executor import CommandExecutor
from sm.core.exceptions import PgBouncerError
from sm.core.credentials import AtomicFileWriter
from sm.services.systemd import SystemdService


# Default paths
DEFAULT_USERLIST_PATH = Path("/etc/pgbouncer/userlist.txt")
DEFAULT_INI_PATH = Path("/etc/pgbouncer/pgbouncer.ini")
DEFAULT_SERVICE_NAME = "pgbouncer.service"


class PgBouncerService:
    """Safe interface for PgBouncer operations.

    All operations:
    - Respect dry-run mode
    - Use atomic file writes
    - Preserve file ownership
    - Support rollback
    """

    def __init__(
        self,
        ctx: ExecutionContext,
        executor: CommandExecutor,
        systemd: SystemdService,
        *,
        userlist_path: Optional[Path] = None,
        ini_path: Optional[Path] = None,
        pg_host: str = "127.0.0.1",
        pg_port: int = 5432,
    ) -> None:
        """Initialize PgBouncer service.

        Args:
            ctx: Execution context
            executor: Command executor
            systemd: Systemd service manager
            userlist_path: Path to userlist.txt
            ini_path: Path to pgbouncer.ini
            pg_host: PostgreSQL host
            pg_port: PostgreSQL port
        """
        self.ctx = ctx
        self.executor = executor
        self.systemd = systemd
        self.userlist_path = userlist_path or DEFAULT_USERLIST_PATH
        self.ini_path = ini_path or DEFAULT_INI_PATH
        self.pg_host = pg_host
        self.pg_port = pg_port
        self._service_user: Optional[tuple[str, str]] = None

    @property
    def service_user(self) -> tuple[str, str]:
        """Get PgBouncer service user and group."""
        if self._service_user is None:
            self._service_user = self.systemd.get_service_user(DEFAULT_SERVICE_NAME)
        return self._service_user

    def is_installed(self) -> bool:
        """Check if PgBouncer is installed.

        Returns:
            True if installed
        """
        return self.ini_path.exists() or self.systemd.exists(DEFAULT_SERVICE_NAME)

    def is_running(self) -> bool:
        """Check if PgBouncer is running.

        Returns:
            True if running
        """
        return self.systemd.is_active(DEFAULT_SERVICE_NAME)

    def update_userlist(
        self,
        username: str,
        scram_hash: str,
        *,
        backup: bool = True,
    ) -> None:
        """Update PgBouncer userlist with a SCRAM-SHA-256 hash.

        Args:
            username: PostgreSQL username
            scram_hash: SCRAM-SHA-256 password hash
            backup: Create backup before modifying

        Raises:
            PgBouncerError: If update fails
        """
        if not self.userlist_path.exists():
            self.ctx.console.warn(f"PgBouncer userlist not found: {self.userlist_path}")
            return

        if not scram_hash.startswith("SCRAM-SHA-256$"):
            raise PgBouncerError(
                f"Invalid SCRAM hash for '{username}'",
                hint="Password must be stored as SCRAM-SHA-256 in PostgreSQL",
            )

        self.ctx.console.step(f"Updating PgBouncer userlist for '{username}'")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Update userlist entry for {username}")
            return

        # Read current content
        current_content = self.userlist_path.read_text()
        lines = current_content.splitlines()

        # Create new entry
        new_entry = f'"{username}" "{scram_hash}"'

        # Find and replace or append
        username_pattern = re.compile(rf'^"{re.escape(username)}"')
        updated = False
        new_lines = []

        for line in lines:
            if username_pattern.match(line):
                new_lines.append(new_entry)
                updated = True
            else:
                new_lines.append(line)

        if not updated:
            new_lines.append(new_entry)

        # Write atomically
        user, group = self.service_user
        self._write_config_file(
            self.userlist_path,
            "\n".join(new_lines) + "\n",
            user,
            group,
            permissions=0o640,
            backup=backup,
        )

        self.ctx.console.success(f"PgBouncer userlist updated for '{username}'")

    def remove_from_userlist(self, username: str) -> None:
        """Remove a user from the PgBouncer userlist.

        Args:
            username: Username to remove
        """
        if not self.userlist_path.exists():
            return

        self.ctx.console.step(f"Removing '{username}' from PgBouncer userlist")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Remove userlist entry for {username}")
            return

        current_content = self.userlist_path.read_text()
        lines = current_content.splitlines()

        username_pattern = re.compile(rf'^"{re.escape(username)}"')
        new_lines = [line for line in lines if not username_pattern.match(line)]

        if len(new_lines) != len(lines):
            user, group = self.service_user
            self._write_config_file(
                self.userlist_path,
                "\n".join(new_lines) + "\n",
                user,
                group,
                permissions=0o640,
            )
            self.ctx.console.success(f"Removed '{username}' from userlist")
        else:
            self.ctx.console.info(f"'{username}' not found in userlist")

    def add_database(
        self,
        name: str,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        backup: bool = True,
    ) -> None:
        """Add or update a database mapping in pgbouncer.ini.

        Args:
            name: Database name
            host: PostgreSQL host (default: self.pg_host)
            port: PostgreSQL port (default: self.pg_port)
            backup: Create backup before modifying

        Raises:
            PgBouncerError: If update fails
        """
        if not self.ini_path.exists():
            self.ctx.console.warn(f"PgBouncer config not found: {self.ini_path}")
            return

        host = host or self.pg_host
        port = port or self.pg_port

        self.ctx.console.step(f"Adding database '{name}' to PgBouncer")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(
                f"Add database mapping: {name} = host={host} port={port} dbname={name}"
            )
            return

        # Read current content
        current_content = self.ini_path.read_text()
        lines = current_content.splitlines()

        # Build database entry
        db_entry = f"{name} = host={host} port={port} dbname={name}"

        # Find [databases] section and update
        db_pattern = re.compile(rf'^{re.escape(name)}\s*=')
        section_pattern = re.compile(r'^\[databases\]', re.IGNORECASE)

        new_lines = []
        in_databases_section = False
        updated = False
        section_found = False

        for i, line in enumerate(lines):
            if section_pattern.match(line):
                in_databases_section = True
                section_found = True
                new_lines.append(line)
                continue

            if in_databases_section:
                if line.startswith("[") and not section_pattern.match(line):
                    # End of databases section
                    if not updated:
                        new_lines.append(db_entry)
                        updated = True
                    in_databases_section = False
                elif db_pattern.match(line):
                    new_lines.append(db_entry)
                    updated = True
                    continue

            new_lines.append(line)

        # If databases section exists but we haven't updated, add at end of section
        if section_found and not updated:
            # Find the section and insert after it
            for i, line in enumerate(new_lines):
                if section_pattern.match(line):
                    new_lines.insert(i + 1, db_entry)
                    updated = True
                    break

        # If no databases section, create one at the beginning
        if not section_found:
            new_lines.insert(0, "[databases]")
            new_lines.insert(1, db_entry)
            new_lines.insert(2, "")

        # Write atomically
        user, group = self.service_user
        self._write_config_file(
            self.ini_path,
            "\n".join(new_lines) + "\n",
            user,
            group,
            permissions=0o640,
            backup=backup,
        )

        self.ctx.console.success(f"Database '{name}' added to PgBouncer")

    def remove_database(self, name: str) -> None:
        """Remove a database mapping from pgbouncer.ini.

        Args:
            name: Database name
        """
        if not self.ini_path.exists():
            return

        self.ctx.console.step(f"Removing database '{name}' from PgBouncer")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Remove database mapping for {name}")
            return

        current_content = self.ini_path.read_text()
        lines = current_content.splitlines()

        db_pattern = re.compile(rf'^{re.escape(name)}\s*=')
        new_lines = [line for line in lines if not db_pattern.match(line)]

        if len(new_lines) != len(lines):
            user, group = self.service_user
            self._write_config_file(
                self.ini_path,
                "\n".join(new_lines) + "\n",
                user,
                group,
                permissions=0o640,
            )
            self.ctx.console.success(f"Removed '{name}' from PgBouncer config")
        else:
            self.ctx.console.info(f"Database '{name}' not found in PgBouncer config")

    def reload(self) -> None:
        """Reload PgBouncer configuration.

        Uses SIGHUP via systemctl reload.
        """
        if not self.is_installed():
            self.ctx.console.debug("PgBouncer not installed, skipping reload")
            return

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Reload PgBouncer")
            return

        if not self.is_running():
            self.ctx.console.warn("PgBouncer is not running, skipping reload")
            return

        try:
            self.systemd.reload(DEFAULT_SERVICE_NAME)
        except Exception:
            # Try restart as fallback
            self.ctx.console.warn("PgBouncer reload failed, trying restart...")
            self.systemd.restart(DEFAULT_SERVICE_NAME)

        # Verify it's still running
        if not self.is_running():
            raise PgBouncerError(
                "PgBouncer stopped after reload",
                hint=f"Check logs: journalctl -xeu {DEFAULT_SERVICE_NAME}",
            )

    def _write_config_file(
        self,
        path: Path,
        content: str,
        owner: str,
        group: str,
        *,
        permissions: int = 0o640,
        backup: bool = False,
    ) -> None:
        """Write a config file atomically with proper ownership.

        Args:
            path: File path
            content: File content
            owner: File owner
            group: File group
            permissions: File permissions
            backup: Create backup first
        """
        import grp
        import pwd

        # Backup if requested
        if backup and path.exists():
            self.executor.backup_file(path)

        # Get UID/GID
        try:
            uid = pwd.getpwnam(owner).pw_uid
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            uid = -1
            gid = -1

        # Atomic write
        writer = AtomicFileWriter(
            path,
            permissions=permissions,
            owner_uid=uid if uid >= 0 else None,
            owner_gid=gid if gid >= 0 else None,
        )

        with writer.open() as f:
            f.write(content)
