"""pgBackRest service for backup info and restore operations.

Wraps pgBackRest commands for listing backups and performing PITR restores.
This service uses the existing pgBackRest configuration set up during
PostgreSQL installation.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sm.core.context import ExecutionContext
from sm.core.exceptions import BackupError
from sm.core.executor import CommandExecutor
from sm.core.output import console


@dataclass
class BackupInfo:
    """Information about a pgBackRest backup."""

    label: str
    backup_type: str  # "full", "diff", "incr"
    start_time: datetime
    stop_time: datetime
    size: int  # Backup size in bytes
    database_size: int  # Original database size in bytes
    repo_size: int  # Size in repository (compressed)
    wal_start: str
    wal_stop: str

    @property
    def duration_seconds(self) -> int:
        """Get backup duration in seconds."""
        return int((self.stop_time - self.start_time).total_seconds())

    @property
    def type_display(self) -> str:
        """Get display-friendly backup type."""
        return {
            "full": "Full",
            "diff": "Differential",
            "incr": "Incremental",
        }.get(self.backup_type, self.backup_type)


@dataclass
class RecoveryPoint:
    """Point-in-time recovery target."""

    timestamp: datetime | None = None
    xid: str | None = None
    lsn: str | None = None
    name: str | None = None  # Restore point name
    target_action: str = "promote"  # "pause", "shutdown", "promote"

    def validate(self) -> None:
        """Validate that at least one target is set.

        Raises:
            BackupError: If no target specified
        """
        if not any([self.timestamp, self.xid, self.lsn, self.name]):
            raise BackupError(
                "Recovery point requires at least one target: timestamp, xid, lsn, or name",
            )


@dataclass
class RecoveryWindow:
    """Available recovery time window."""

    earliest: datetime
    latest: datetime

    @property
    def duration_days(self) -> int:
        """Get window duration in days."""
        return (self.latest - self.earliest).days


class PgBackRestService:
    """Service for pgBackRest operations.

    Provides interfaces for:
    - Listing available backups
    - Getting backup details
    - Point-in-time recovery
    - Backup verification

    Uses the existing pgBackRest configuration created during
    PostgreSQL setup (stanza: "main").
    """

    DEFAULT_STANZA = "main"
    CONFIG_PATH = Path("/etc/pgbackrest/pgbackrest.conf")
    PGDATA_PATH = Path("/var/lib/postgresql/{version}/main")

    def __init__(
        self,
        ctx: ExecutionContext,
        executor: CommandExecutor,
        *,
        stanza: str = DEFAULT_STANZA,
        pg_version: str | None = None,
    ) -> None:
        """Initialize pgBackRest service.

        Args:
            ctx: Execution context
            executor: Command executor
            stanza: pgBackRest stanza name
            pg_version: PostgreSQL version (for data directory)
        """
        self.ctx = ctx
        self.executor = executor
        self.stanza = stanza
        self.pg_version = pg_version

    def is_configured(self) -> bool:
        """Check if pgBackRest is configured.

        Returns:
            True if pgBackRest config exists
        """
        return self.CONFIG_PATH.exists()

    def check_available(self) -> bool:
        """Check if pgbackrest command is available.

        Returns:
            True if pgbackrest command is in PATH
        """
        result = self.executor.run(
            ["which", "pgbackrest"],
            description="Check pgbackrest installed",
            check=False,
        )
        return result.return_code == 0

    def stanza_exists(self) -> bool:
        """Check if stanza exists and is valid.

        Returns:
            True if stanza is valid
        """
        if self.ctx.dry_run:
            return True

        if not self.is_configured():
            return False

        result = self.executor.run(
            ["pgbackrest", "--stanza", self.stanza, "check"],
            description="Check stanza",
            check=False,
            as_user="postgres",
        )
        return result.return_code == 0

    def list_backups(self) -> list[BackupInfo]:
        """List all available backups.

        Returns:
            List of BackupInfo objects sorted by time (newest first)

        Raises:
            BackupError: If listing fails
        """
        if self.ctx.dry_run:
            console.dry_run("Would list pgBackRest backups")
            return []

        if not self.is_configured():
            raise BackupError(
                "pgBackRest is not configured",
                hint="Run 'sm postgres setup' first",
            )

        try:
            result = self.executor.run(
                ["pgbackrest", "--stanza", self.stanza, "info", "--output=json"],
                description="List backups",
                check=True,
                as_user="postgres",
            )

            data = json.loads(result.stdout)

            backups = []
            for stanza in data:
                if stanza["name"] != self.stanza:
                    continue

                for backup in stanza.get("backup", []):
                    # Parse timestamps
                    start_time = datetime.fromtimestamp(backup["timestamp"]["start"])
                    stop_time = datetime.fromtimestamp(backup["timestamp"]["stop"])

                    backups.append(BackupInfo(
                        label=backup["label"],
                        backup_type=backup["type"],
                        start_time=start_time,
                        stop_time=stop_time,
                        size=backup["info"]["size"],
                        database_size=backup["info"]["delta"],
                        repo_size=backup["info"]["repository"]["size"],
                        wal_start=backup.get("lsn", {}).get("start", ""),
                        wal_stop=backup.get("lsn", {}).get("stop", ""),
                    ))

            # Sort by time (newest first)
            backups.sort(key=lambda x: x.stop_time, reverse=True)
            return backups

        except json.JSONDecodeError as e:
            raise BackupError(
                "Failed to parse pgBackRest info output",
                details=[str(e)],
            ) from e
        except Exception as e:
            raise BackupError(
                "Failed to list backups",
                details=[str(e)],
            ) from e

    def get_backup_info(self, label: str | None = None) -> BackupInfo | None:
        """Get info about a specific backup.

        Args:
            label: Backup label (None for latest)

        Returns:
            BackupInfo or None if not found
        """
        backups = self.list_backups()

        if not backups:
            return None

        if label is None:
            return backups[0]  # Latest

        for backup in backups:
            if backup.label == label:
                return backup

        return None

    def get_recovery_window(self) -> RecoveryWindow | None:
        """Get the time window available for PITR.

        Returns:
            RecoveryWindow or None if no backups exist
        """
        if self.ctx.dry_run:
            return None

        if not self.is_configured():
            return None

        try:
            result = self.executor.run(
                ["pgbackrest", "--stanza", self.stanza, "info", "--output=json"],
                description="Get recovery window",
                check=True,
                as_user="postgres",
            )

            data = json.loads(result.stdout)

            for stanza in data:
                if stanza["name"] != self.stanza:
                    continue

                archive = stanza.get("archive", [])
                if not archive:
                    return None

                # Get earliest and latest from archive info
                archive_info = archive[0]
                db_info = archive_info.get("database", {})

                if "repo-key" in db_info:
                    # Get timestamps from WAL archive
                    backups = stanza.get("backup", [])
                    if not backups:
                        return None

                    earliest = datetime.fromtimestamp(backups[-1]["timestamp"]["start"])
                    latest = datetime.now()  # Can restore up to current WAL

                    return RecoveryWindow(earliest=earliest, latest=latest)

            return None

        except Exception:
            return None

    def verify_backup(self, label: str | None = None) -> bool:
        """Verify backup integrity.

        Args:
            label: Backup label to verify (None for all)

        Returns:
            True if verification passes

        Raises:
            BackupError: If verification fails
        """
        if self.ctx.dry_run:
            console.dry_run("Would verify backup")
            return True

        cmd = ["pgbackrest", "--stanza", self.stanza, "verify"]

        console.step("Verifying backup integrity...")

        try:
            self.executor.run(
                cmd,
                description="Verify backup",
                check=True,
                as_user="postgres",
            )
            console.success("Backup verification passed")
            return True

        except Exception as e:
            raise BackupError(
                "Backup verification failed",
                details=[str(e)],
            ) from e

    def trigger_backup(
        self,
        backup_type: str = "full",
    ) -> None:
        """Trigger a manual backup.

        Args:
            backup_type: "full", "diff", or "incr"

        Raises:
            BackupError: If backup fails
        """
        if backup_type not in ("full", "diff", "incr"):
            raise BackupError(f"Invalid backup type: {backup_type}")

        if self.ctx.dry_run:
            console.dry_run(f"Would trigger {backup_type} backup")
            return

        console.step(f"Starting {backup_type} backup...")

        try:
            self.executor.run(
                [
                    "pgbackrest",
                    "--stanza", self.stanza,
                    "--type", backup_type,
                    "backup",
                ],
                description=f"Run {backup_type} backup",
                check=True,
                as_user="postgres",
                timeout=7200,  # 2 hours max
            )
            console.success(f"{backup_type.capitalize()} backup completed")

        except Exception as e:
            raise BackupError(
                f"Backup failed: {backup_type}",
                details=[str(e)],
            ) from e

    def restore(
        self,
        *,
        recovery_target: RecoveryPoint | None = None,
        target_dir: Path | None = None,
        delta: bool = False,
        force: bool = False,
    ) -> None:
        """Perform restore operation.

        This restores the ENTIRE PostgreSQL cluster. PostgreSQL must be
        stopped before running this.

        Args:
            recovery_target: PITR target (timestamp, xid, lsn, or name)
            target_dir: Custom PGDATA directory (default: auto-detected)
            delta: Use delta restore (faster for minor recovery)
            force: Overwrite existing data directory

        Raises:
            BackupError: If restore fails
        """
        if self.ctx.dry_run:
            console.dry_run("Would perform pgBackRest restore")
            if recovery_target:
                if recovery_target.timestamp:
                    console.dry_run(f"  Recovery target: {recovery_target.timestamp}")
                elif recovery_target.lsn:
                    console.dry_run(f"  Recovery target LSN: {recovery_target.lsn}")
            return

        # Validate recovery target if provided
        if recovery_target:
            recovery_target.validate()

        # Build restore command
        cmd = ["pgbackrest", "--stanza", self.stanza]

        # Add PITR options
        if recovery_target:
            if recovery_target.timestamp:
                cmd.extend(["--target", recovery_target.timestamp.strftime("%Y-%m-%d %H:%M:%S")])
                cmd.append("--type=time")
            elif recovery_target.lsn:
                cmd.extend(["--target", recovery_target.lsn])
                cmd.append("--type=lsn")
            elif recovery_target.xid:
                cmd.extend(["--target", recovery_target.xid])
                cmd.append("--type=xid")
            elif recovery_target.name:
                cmd.extend(["--target", recovery_target.name])
                cmd.append("--type=name")

            cmd.extend(["--target-action", recovery_target.target_action])

        # Add target directory if specified
        if target_dir:
            cmd.extend(["--pg1-path", str(target_dir)])

        # Add delta restore option
        if delta:
            cmd.append("--delta")

        cmd.append("restore")

        console.step("Starting pgBackRest restore...")
        console.warn("This will replace the PostgreSQL data directory")

        try:
            self.executor.run(
                cmd,
                description="pgBackRest restore",
                check=True,
                as_user="postgres",
                timeout=7200,  # 2 hours max
            )
            console.success("Restore completed successfully")

        except Exception as e:
            raise BackupError(
                "Restore failed",
                details=[str(e)],
                hint="Check pgBackRest logs at /var/log/pgbackrest/",
            ) from e

    def create_restore_script(
        self,
        output_path: Path,
        recovery_target: RecoveryPoint | None = None,
    ) -> Path:
        """Generate a restore script for manual execution.

        This creates a shell script that can be reviewed and executed
        manually for more control over the restore process.

        Args:
            output_path: Where to write the script
            recovery_target: PITR target

        Returns:
            Path to generated script
        """
        script_lines = [
            "#!/bin/bash",
            "# pgBackRest Restore Script",
            f"# Generated: {datetime.now().isoformat()}",
            "#",
            "# IMPORTANT: Review this script before execution!",
            "#",
            "set -e  # Exit on error",
            "",
            "# Step 1: Stop PostgreSQL",
            "echo 'Stopping PostgreSQL...'",
            "sudo systemctl stop postgresql",
            "",
            "# Step 2: Run pgBackRest restore",
            "echo 'Running restore...'",
        ]

        # Build restore command
        cmd = f"sudo -u postgres pgbackrest --stanza={self.stanza}"

        if recovery_target:
            if recovery_target.timestamp:
                cmd += f" --target='{recovery_target.timestamp.strftime('%Y-%m-%d %H:%M:%S')}'"
                cmd += " --type=time"
            elif recovery_target.lsn:
                cmd += f" --target='{recovery_target.lsn}'"
                cmd += " --type=lsn"

            cmd += f" --target-action={recovery_target.target_action}"

        cmd += " restore"

        script_lines.append(cmd)
        script_lines.extend([
            "",
            "# Step 3: Start PostgreSQL",
            "echo 'Starting PostgreSQL...'",
            "sudo systemctl start postgresql",
            "",
            "# Step 4: Verify",
            "echo 'Verifying...'",
            "sudo -u postgres psql -c 'SELECT version();'",
            "",
            "echo 'Restore completed!'",
        ])

        # Write script
        output_path.write_text("\n".join(script_lines))
        output_path.chmod(0o755)

        return output_path

    def get_stanza_status(self) -> dict:
        """Get detailed stanza status.

        Returns:
            Dictionary with status information
        """
        if self.ctx.dry_run:
            return {"status": "dry-run"}

        if not self.is_configured():
            return {"status": "not-configured"}

        try:
            result = self.executor.run(
                ["pgbackrest", "--stanza", self.stanza, "info", "--output=json"],
                description="Get stanza status",
                check=True,
                as_user="postgres",
            )

            data = json.loads(result.stdout)

            for stanza in data:
                if stanza["name"] == self.stanza:
                    return {
                        "status": stanza.get("status", {}).get("message", "unknown"),
                        "backup_count": len(stanza.get("backup", [])),
                        "archive": stanza.get("archive", []),
                    }

            return {"status": "stanza-not-found"}

        except Exception as e:
            return {"status": "error", "error": str(e)}


def format_backup_size(size_bytes: int) -> str:
    """Format backup size for display.

    Args:
        size_bytes: Size in bytes

    Returns:
        Human-readable size string
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"
