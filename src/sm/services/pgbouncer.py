"""PgBouncer service abstraction.

Provides safe interface for managing PgBouncer configuration.
"""

import configparser
import re
from pathlib import Path
from typing import TYPE_CHECKING

from sm.core.context import ExecutionContext
from sm.core.credentials import AtomicFileWriter
from sm.core.exceptions import PgBouncerError
from sm.core.executor import CommandExecutor
from sm.services.systemd import SystemdService
from sm.services.tuning import (
    IDLE_TIMEOUT_SECONDS,
    MULTIPLEX_RATIO,
    POOL_UTILIZATION_PCT,
    RESERVED_FOR_ADMIN,
)

if TYPE_CHECKING:
    from sm.services.tuning import PgBouncerParameter, WorkloadProfile


# PgBouncer tunable parameters we track
PGBOUNCER_TUNABLE_PARAMETERS = [
    "default_pool_size",
    "min_pool_size",
    "reserve_pool_size",
    "max_client_conn",
    "pool_mode",
    "server_idle_timeout",
    "server_connect_timeout",
    "query_timeout",
]


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
        userlist_path: Path | None = None,
        ini_path: Path | None = None,
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
        self._service_user: tuple[str, str] | None = None

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
        host: str | None = None,
        port: int | None = None,
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

        for line in lines:
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

    def read_current_config(self) -> dict[str, str]:
        """Read current PgBouncer settings from pgbouncer.ini.

        Parses the [pgbouncer] section to get current pool settings.

        Note: This is a read-only operation, so it runs even in dry-run mode.
        This ensures the preview shows accurate current vs recommended comparisons.

        Returns:
            Dict of parameter name -> current value
        """
        if not self.ini_path.exists():
            return {}

        # Note: We intentionally DO NOT skip in dry_run mode.
        # Reading current config is non-destructive and needed for accurate previews.

        settings: dict[str, str] = {}
        try:
            content = self.ini_path.read_text()

            # PgBouncer uses INI format but may have comments with semicolons
            # Use configparser with inline_comment_prefixes
            config = configparser.ConfigParser(
                inline_comment_prefixes=(";", "#"),
                comment_prefixes=(";", "#"),
            )
            config.read_string(content)

            # Read from [pgbouncer] section
            if config.has_section("pgbouncer"):
                for param in PGBOUNCER_TUNABLE_PARAMETERS:
                    if config.has_option("pgbouncer", param):
                        settings[param] = config.get("pgbouncer", param)

        except Exception:
            # Fallback: simple line parsing
            try:
                in_pgbouncer_section = False
                for line in content.splitlines():
                    line = line.strip()
                    if line.lower() == "[pgbouncer]":
                        in_pgbouncer_section = True
                        continue
                    if line.startswith("[") and in_pgbouncer_section:
                        break
                    if in_pgbouncer_section and "=" in line:
                        # Remove comments
                        if ";" in line:
                            line = line.split(";")[0].strip()
                        if "#" in line:
                            line = line.split("#")[0].strip()
                        key, _, value = line.partition("=")
                        key = key.strip().lower()
                        value = value.strip()
                        if key in PGBOUNCER_TUNABLE_PARAMETERS:
                            settings[key] = value
            except Exception:
                pass

        return settings

    def calculate_pool_recommendations(
        self,
        pg_max_connections: int,
        workload: "WorkloadProfile",
        current_config: dict[str, str],
        expected_connections: int | None = None,
    ) -> list["PgBouncerParameter"]:
        """Calculate PgBouncer tuning recommendations.

        Coordinates PgBouncer settings with PostgreSQL max_connections to
        eliminate connection bottlenecks.

        Args:
            pg_max_connections: PostgreSQL max_connections value
            workload: Target workload profile
            current_config: Current PgBouncer settings
            expected_connections: Expected number of app connections

        Returns:
            List of PgBouncerParameter recommendations
        """
        from sm.services.tuning import PgBouncerParameter

        params: list[PgBouncerParameter] = []

        # Use shared constants from tuning module
        available = pg_max_connections - RESERVED_FOR_ADMIN
        pool_pct = POOL_UTILIZATION_PCT[workload.value]
        default_pool_size = max(20, int(available * pool_pct))

        params.append(PgBouncerParameter(
            name="default_pool_size",
            current_value=current_config.get("default_pool_size"),
            recommended_value=str(default_pool_size),
            reason=f"{int(pool_pct * 100)}% of PostgreSQL capacity ({available} available)",
        ))

        # min_pool_size: 25% of pool ready
        min_pool_size = max(5, default_pool_size // 4)
        params.append(PgBouncerParameter(
            name="min_pool_size",
            current_value=current_config.get("min_pool_size"),
            recommended_value=str(min_pool_size),
            reason="25% of pool kept ready for fast response",
        ))

        # reserve_pool_size: 20% emergency overflow
        reserve_pool_size = max(5, default_pool_size // 5)
        params.append(PgBouncerParameter(
            name="reserve_pool_size",
            current_value=current_config.get("reserve_pool_size"),
            recommended_value=str(reserve_pool_size),
            reason="20% emergency overflow for burst traffic",
        ))

        # max_client_conn: use shared multiplex ratio constants
        multiplex = MULTIPLEX_RATIO[workload.value]
        max_client_conn = default_pool_size * multiplex

        # Adjust for expected connections
        if expected_connections:
            max_client_conn = max(max_client_conn, int(expected_connections * 1.5))

        params.append(PgBouncerParameter(
            name="max_client_conn",
            current_value=current_config.get("max_client_conn"),
            recommended_value=str(max_client_conn),
            reason=f"{multiplex}x multiplex ratio for {workload.value.upper()}",
        ))

        # server_idle_timeout: use shared constants
        idle_timeout = IDLE_TIMEOUT_SECONDS[workload.value]
        params.append(PgBouncerParameter(
            name="server_idle_timeout",
            current_value=current_config.get("server_idle_timeout"),
            recommended_value=str(idle_timeout),
            reason="Connection recycling timeout",
        ))

        return params

    def generate_optimized_config(
        self,
        recommendations: list["PgBouncerParameter"],
        current_config: dict[str, str] | None = None,
    ) -> str:
        """Generate optimized pgbouncer.ini section content.

        Updates only the pool-related settings in the [pgbouncer] section.
        This is designed to be merged with existing config.

        Args:
            recommendations: List of PgBouncerParameter recommendations
            current_config: Current config for reference

        Returns:
            Config section content as string
        """
        lines = [
            "; Pool settings (optimized by sm postgres optimize)",
        ]

        for param in recommendations:
            if param.changed:
                lines.append(f"; Reason: {param.reason}")
            lines.append(f"{param.name} = {param.recommended_value}")

        return "\n".join(lines)

    def apply_optimized_config(
        self,
        recommendations: list["PgBouncerParameter"],
    ) -> None:
        """Apply optimized PgBouncer configuration.

        Updates pgbouncer.ini with new pool settings and reloads.

        Args:
            recommendations: List of PgBouncerParameter recommendations

        Raises:
            PgBouncerError: If update fails
        """
        if not self.ini_path.exists():
            raise PgBouncerError(
                f"PgBouncer config not found: {self.ini_path}",
                hint="Run 'sm postgres setup' to install PgBouncer",
            )

        self.ctx.console.step("Updating PgBouncer configuration...")

        if self.ctx.dry_run:
            for param in recommendations:
                if param.changed:
                    self.ctx.console.dry_run_msg(
                        f"Set {param.name} = {param.recommended_value}"
                    )
            return

        # Read current content
        current_content = self.ini_path.read_text()
        lines = current_content.splitlines()

        # Create mapping of recommendations
        rec_map = {p.name: p.recommended_value for p in recommendations if p.changed}

        # Update lines in [pgbouncer] section
        new_lines = []
        in_pgbouncer_section = False
        params_updated = set()

        for line in lines:
            stripped = line.strip()

            # Check for section headers
            if stripped.lower() == "[pgbouncer]":
                in_pgbouncer_section = True
                new_lines.append(line)
                continue
            elif stripped.startswith("["):
                # Leaving pgbouncer section - add any params we haven't updated yet
                if in_pgbouncer_section:
                    for param_name, value in rec_map.items():
                        if param_name not in params_updated:
                            new_lines.append(f"{param_name} = {value}")
                            params_updated.add(param_name)
                in_pgbouncer_section = False
                new_lines.append(line)
                continue

            # Process lines in pgbouncer section
            if in_pgbouncer_section and "=" in stripped:
                # Extract key (handle comments)
                key_part = stripped.split("=")[0].strip().lower()
                if key_part in rec_map:
                    new_lines.append(f"{key_part} = {rec_map[key_part]}")
                    params_updated.add(key_part)
                    continue

            new_lines.append(line)

        # If we're still in pgbouncer section at end of file, add remaining params
        if in_pgbouncer_section:
            for param_name, value in rec_map.items():
                if param_name not in params_updated:
                    new_lines.append(f"{param_name} = {value}")

        # Write atomically
        user, group = self.service_user
        self._write_config_file(
            self.ini_path,
            "\n".join(new_lines) + "\n",
            user,
            group,
            permissions=0o640,
            backup=True,
        )

        self.ctx.console.success("PgBouncer configuration updated")

        # Reload to apply changes
        self.reload()
        self.ctx.console.success("PgBouncer reloaded with new settings")
