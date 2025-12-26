"""pg_dump and pg_restore service wrappers.

Provides safe wrappers around pg_dump and pg_restore for database
export/import operations with progress reporting and verification.
"""

import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sm.core.context import ExecutionContext
from sm.core.exceptions import BackupError
from sm.core.executor import CommandExecutor
from sm.core.output import console
from sm.services.s3 import calculate_file_checksum


@dataclass
class DumpInfo:
    """Information about a pg_dump output file."""

    database: str
    file_path: Path
    size_bytes: int
    checksum: str  # SHA256 with prefix
    format: str  # "custom" for -Fc
    pg_version: str
    dump_time: datetime


@dataclass
class DatabaseSize:
    """Database size information."""

    name: str
    size_bytes: int
    size_pretty: str


class PgDumpService:
    """Service for pg_dump and pg_restore operations.

    Features:
    - Uses custom format (-Fc) for portability and compression
    - Parallel restore with --jobs (pg_restore only)
    - Progress reporting via verbose mode
    - Checksum calculation for verification
    - Proper error handling with fail-fast behavior
    """

    # Default excluded databases (system databases)
    DEFAULT_EXCLUDE_DATABASES = {"template0", "template1"}

    def __init__(
        self,
        ctx: ExecutionContext,
        executor: CommandExecutor,
        *,
        pg_host: str = "127.0.0.1",
        pg_port: int = 5432,
        pg_user: str = "postgres",
        pg_admin_db: str = "postgres",
    ) -> None:
        """Initialize pg_dump service.

        Args:
            ctx: Execution context
            executor: Command executor
            pg_host: PostgreSQL host
            pg_port: PostgreSQL port
            pg_user: PostgreSQL user for connections
            pg_admin_db: Database to connect to for admin operations
        """
        self.ctx = ctx
        self.executor = executor
        self.pg_host = pg_host
        self.pg_port = pg_port
        self.pg_user = pg_user
        self.pg_admin_db = pg_admin_db
        self._use_peer_auth = self._is_local_host(pg_host)

    @staticmethod
    def _is_local_host(host: str | None) -> bool:
        """Return True if host refers to the local server or a socket path."""
        if not host:
            return True
        host = host.strip()
        return host in {"127.0.0.1", "localhost", "::1"} or host.startswith("/")

    def _connection_args(
        self,
        *,
        include_database: bool = False,
        database: str | None = None,
    ) -> tuple[list[str], str | None]:
        """Build connection args and determine if sudo is required for peer auth."""
        args: list[str] = []
        as_user: str | None = None

        if self._use_peer_auth:
            as_user = self.pg_user
            args.extend(["-p", str(self.pg_port)])
        else:
            args.extend(
                ["-h", self.pg_host, "-p", str(self.pg_port), "-U", self.pg_user]
            )

        if include_database and database:
            args.extend(["-d", database])

        return args, as_user

    def check_commands_available(self) -> tuple[bool, list[str]]:
        """Check if pg_dump and pg_restore are available.

        Returns:
            Tuple of (all_available, list of missing commands)
        """
        missing = []

        for cmd in ["pg_dump", "pg_restore", "pg_dumpall", "psql"]:
            if not shutil.which(cmd):
                missing.append(cmd)

        return len(missing) == 0, missing

    def get_pg_version(self) -> str:
        """Get PostgreSQL version string.

        Returns:
            Version string (e.g., "18.1")
        """
        if self.ctx.dry_run:
            return "18.0"

        cmd = ["psql"]
        conn_args, as_user = self._connection_args(
            include_database=True, database=self.pg_admin_db
        )
        cmd.extend(conn_args)
        cmd.extend(["-t", "-c", "SHOW server_version;"])
        result = self.executor.run(
            cmd,
            description="Get PostgreSQL version",
            check=True,
            as_user=as_user,
        )
        return result.stdout.strip()

    def list_databases(self, exclude_system: bool = True) -> list[DatabaseSize]:
        """List all databases with sizes.

        Args:
            exclude_system: Exclude template0, template1, postgres

        Returns:
            List of DatabaseSize objects
        """
        if self.ctx.dry_run:
            console.dry_run_msg("Would list databases")
            return []

        # Query to get database names and sizes
        sql = """
        SELECT datname, pg_database_size(datname) as size_bytes,
               pg_size_pretty(pg_database_size(datname)) as size_pretty
        FROM pg_database
        WHERE datistemplate = false
        ORDER BY datname;
        """

        cmd = ["psql"]
        conn_args, as_user = self._connection_args(
            include_database=True, database=self.pg_admin_db
        )
        cmd.extend(conn_args)
        cmd.extend(["-t", "-A", "-F", "|", "-c", sql])
        result = self.executor.run(
            cmd,
            description="List databases",
            check=True,
            as_user=as_user,
        )

        databases = []
        for line in result.stdout.strip().split("\n"):
            if line and "|" in line:
                parts = line.split("|")
                if len(parts) >= 3:
                    name = parts[0]
                    if exclude_system and name in ("template0", "template1", "postgres"):
                        continue
                    try:
                        size_bytes = int(parts[1])
                    except ValueError:
                        size_bytes = 0
                    databases.append(DatabaseSize(
                        name=name,
                        size_bytes=size_bytes,
                        size_pretty=parts[2],
                    ))

        return databases

    def database_exists(self, database: str) -> bool:
        """Check if a database exists.

        Args:
            database: Database name

        Returns:
            True if database exists
        """
        if self.ctx.dry_run:
            return True

        # Use Unix socket auth (peer) to avoid password prompts
        result = self.executor.run_sql_format(
            "SELECT 1 FROM pg_database WHERE datname = %L",
            database=self.pg_admin_db,
            as_user=self.pg_user,
            check=False,
            db_name=database,
        )
        return bool(result.strip())

    def dump_database(
        self,
        database: str,
        output_path: Path,
        *,
        compression_level: int = 6,
        jobs: int = 4,
        exclude_tables: list[str] | None = None,
    ) -> DumpInfo:
        """Dump a single database to custom format.

        Args:
            database: Database name
            output_path: Output file path
            compression_level: Compression level (0-9, 0=none)
            jobs: Number of parallel jobs
            exclude_tables: Tables to exclude

        Returns:
            DumpInfo with dump metadata

        Raises:
            BackupError: If dump fails
        """
        if self.ctx.dry_run:
            console.dry_run_msg(f"Would dump database '{database}' to {output_path}")
            return DumpInfo(
                database=database,
                file_path=output_path,
                size_bytes=0,
                checksum="sha256:dry-run",
                format="custom",
                pg_version="dry-run",
                dump_time=datetime.now(),
            )

        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Build pg_dump command
        cmd = ["pg_dump"]
        conn_args, as_user = self._connection_args(
            include_database=True, database=database
        )
        cmd.extend(conn_args)
        cmd.extend([
            "-Fc",
            f"-Z{compression_level}",
            "-f",
            str(output_path),
        ])

        # Note: pg_dump -j only works with directory format (-Fd), not custom format (-Fc)
        # Parallel restore is supported via pg_restore -j

        # Add table exclusions
        if exclude_tables:
            for table in exclude_tables:
                cmd.extend(["-T", table])

        # Add verbose if needed
        if self.ctx.is_verbose:
            cmd.append("-v")

        console.step(f"Dumping database '{database}'...")

        try:
            self.executor.run(
                cmd,
                description=f"Dump database {database}",
                check=True,
                as_user=as_user,
            )

            # Calculate checksum
            checksum = calculate_file_checksum(output_path)

            # Get file size
            size_bytes = output_path.stat().st_size

            return DumpInfo(
                database=database,
                file_path=output_path,
                size_bytes=size_bytes,
                checksum=checksum,
                format="custom",
                pg_version=self.get_pg_version(),
                dump_time=datetime.now(),
            )

        except Exception as e:
            # Clean up partial dump file
            if output_path.exists():
                output_path.unlink()
            raise BackupError(
                f"Failed to dump database '{database}'",
                details=[str(e)],
            ) from e

    def dump_globals(self, output_path: Path) -> Path:
        """Dump global objects (roles, tablespaces) using pg_dumpall -g.

        Args:
            output_path: Output SQL file path

        Returns:
            Path to the output file

        Raises:
            BackupError: If dump fails
        """
        if self.ctx.dry_run:
            console.dry_run_msg(f"Would dump globals to {output_path}")
            return output_path

        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = ["pg_dumpall"]
        conn_args, as_user = self._connection_args()
        cmd.extend(conn_args)
        cmd.extend([
            "-g",
            "-f",
            str(output_path),
        ])

        console.step("Dumping global objects (roles, tablespaces)...")

        try:
            self.executor.run(
                cmd,
                description="Dump globals",
                check=True,
                as_user=as_user,
            )
            return output_path

        except Exception as e:
            if output_path.exists():
                output_path.unlink()
            raise BackupError(
                "Failed to dump global objects",
                details=[str(e)],
            ) from e

    def dump_all_databases(
        self,
        output_dir: Path,
        *,
        exclude_databases: set[str] | None = None,
        compression_level: int = 6,
        jobs: int = 4,
    ) -> list[DumpInfo]:
        """Dump all databases to individual files.

        Args:
            output_dir: Output directory
            exclude_databases: Databases to exclude (defaults include template0, template1)
            compression_level: Compression level (0-9)
            jobs: Parallel jobs per database

        Returns:
            List of DumpInfo for each database

        Raises:
            BackupError: If any dump fails
        """
        # Build exclude set
        exclude = self.DEFAULT_EXCLUDE_DATABASES.copy()
        if exclude_databases:
            exclude.update(exclude_databases)

        # Get list of databases
        databases = self.list_databases(exclude_system=True)

        # Filter out excluded
        databases = [db for db in databases if db.name not in exclude]

        if not databases:
            console.warn("No databases to dump")
            return []

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        dump_infos = []
        for db in databases:
            output_path = output_dir / f"{db.name}.dump"
            dump_info = self.dump_database(
                db.name,
                output_path,
                compression_level=compression_level,
                jobs=jobs,
            )
            dump_infos.append(dump_info)

        return dump_infos

    def restore_database(
        self,
        dump_path: Path,
        target_database: str,
        *,
        create: bool = True,
        clean: bool = False,
        jobs: int = 4,
        no_owner: bool = False,
        owner: str | None = None,
    ) -> None:
        """Restore a database from custom format dump.

        Args:
            dump_path: Path to dump file
            target_database: Target database name
            create: Create database if not exists
            clean: Drop and recreate objects (use with caution)
            jobs: Parallel restore jobs
            no_owner: Skip ownership commands
            owner: Set owner for all objects (implies no_owner)

        Raises:
            BackupError: If restore fails
        """
        if not dump_path.exists():
            raise BackupError(f"Dump file not found: {dump_path}")

        if self.ctx.dry_run:
            console.dry_run_msg(f"Would restore {dump_path} to database '{target_database}'")
            return

        # Create database if needed
        if create and not self.database_exists(target_database):
            console.step(f"Creating database '{target_database}'...")
            create_sql = (
                "CREATE DATABASE %I OWNER %I"
                if owner
                else "CREATE DATABASE %I"
            )
            format_args: dict[str, Any] = {"db_name": target_database}
            if owner:
                format_args["owner"] = owner
            self.executor.run_sql_format(
                create_sql,
                database=self.pg_admin_db,
                as_user=self.pg_user,
                **format_args,
            )

        # Build pg_restore command
        cmd = ["pg_restore"]
        conn_args, restore_as_user = self._connection_args(
            include_database=True, database=target_database
        )
        cmd.extend(conn_args)

        # Add parallel jobs
        if jobs > 1:
            cmd.extend(["-j", str(jobs)])

        # Add options
        if clean:
            cmd.append("--clean")

        if no_owner or owner:
            cmd.append("--no-owner")

        if owner:
            cmd.extend(["--role", owner])

        if self.ctx.is_verbose:
            cmd.append("-v")

        # Add dump file
        cmd.append(str(dump_path))

        console.step(f"Restoring to database '{target_database}'...")

        try:
            # pg_restore returns non-zero for warnings too, so we handle it specially
            result = self.executor.run(
                cmd,
                description=f"Restore to {target_database}",
                check=False,
                as_user=restore_as_user,
            )

            # Check for actual errors (not just warnings)
            if result.return_code != 0:
                # Some warnings are OK, real errors should fail
                stderr_lower = result.stderr.lower()
                is_fatal = any(x in stderr_lower for x in ["error:", "fatal:"])
                if is_fatal:
                    raise BackupError(
                        f"Failed to restore to '{target_database}'",
                        details=[result.stderr] if result.stderr else None,
                    )
                else:
                    console.warn("Restore completed with warnings")
                    if self.ctx.is_verbose and result.stderr:
                        console.verbose(result.stderr)

            # Set owner if specified
            if owner:
                alter_cmd = ["psql"]
                conn_args, as_user = self._connection_args(
                    include_database=True, database=self.pg_admin_db
                )
                alter_cmd.extend(conn_args)
                alter_cmd.extend(
                    ["-c", f'ALTER DATABASE "{target_database}" OWNER TO "{owner}";']
                )
                self.executor.run(
                    alter_cmd,
                    description=f"Set owner for {target_database}",
                    check=True,
                    as_user=as_user,
                )

            console.success(f"Restored database '{target_database}'")

        except BackupError:
            raise
        except Exception as e:
            raise BackupError(
                f"Failed to restore to '{target_database}'",
                details=[str(e)],
            ) from e

    def restore_globals(self, sql_path: Path) -> None:
        """Restore global objects from pg_dumpall -g output.

        Args:
            sql_path: Path to globals SQL file

        Raises:
            BackupError: If restore fails
        """
        if not sql_path.exists():
            raise BackupError(f"Globals file not found: {sql_path}")

        if self.ctx.dry_run:
            console.dry_run_msg(f"Would restore globals from {sql_path}")
            return

        console.step("Restoring global objects...")

        try:
            cmd = ["psql"]
            conn_args, as_user = self._connection_args(
                include_database=True, database=self.pg_admin_db
            )
            cmd.extend(conn_args)
            cmd.extend(["-f", str(sql_path)])
            self.executor.run(
                cmd,
                description="Restore globals",
                check=True,
                as_user=as_user,
            )
            console.success("Restored global objects")

        except Exception as e:
            raise BackupError(
                "Failed to restore global objects",
                details=[str(e)],
            ) from e

    def get_dump_info(self, dump_path: Path) -> dict:
        """Get metadata from a dump file using pg_restore -l.

        Args:
            dump_path: Path to dump file

        Returns:
            Dictionary with dump metadata

        Raises:
            BackupError: If read fails
        """
        if not dump_path.exists():
            raise BackupError(f"Dump file not found: {dump_path}")

        if self.ctx.dry_run:
            return {"tables": [], "schemas": [], "format": "unknown"}

        try:
            result = self.executor.run(
                ["pg_restore", "-l", str(dump_path)],
                description="Read dump metadata",
                check=True,
            )

            # Parse the TOC output
            lines = result.stdout.strip().split("\n")
            tables = []
            schemas = set()

            for line in lines:
                if " TABLE " in line:
                    # Extract table name from TOC line
                    parts = line.split()
                    if len(parts) >= 5:
                        tables.append(parts[4])
                if "SCHEMA" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        schemas.add(parts[-1])

            return {
                "tables": tables,
                "schemas": list(schemas),
                "format": "custom",
            }

        except Exception as e:
            raise BackupError(
                f"Failed to read dump metadata: {dump_path}",
                details=[str(e)],
            ) from e

    def drop_database(self, database: str, force: bool = False) -> None:
        """Drop a database.

        Args:
            database: Database name
            force: Terminate connections and drop

        Raises:
            BackupError: If drop fails
        """
        if self.ctx.dry_run:
            console.dry_run_msg(f"Would drop database '{database}'")
            return

        if force:
            # Terminate connections first
            console.step(f"Terminating connections to '{database}'...")
            # Database name validated by caller via validate_identifier
            terminate_sql = (
                f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "  # noqa: S608
                f"WHERE datname = '{database}' AND pid <> pg_backend_pid();"
            )
            term_cmd = ["psql"]
            conn_args, as_user = self._connection_args(
                include_database=True, database=self.pg_admin_db
            )
            term_cmd.extend(conn_args)
            term_cmd.extend(["-c", terminate_sql])
            self.executor.run(
                term_cmd,
                description=f"Terminate connections to {database}",
                check=False,
                as_user=as_user,
            )

        console.step(f"Dropping database '{database}'...")

        try:
            drop_cmd = ["psql"]
            conn_args, as_user = self._connection_args(
                include_database=True, database=self.pg_admin_db
            )
            drop_cmd.extend(conn_args)
            drop_cmd.extend(["-c", f'DROP DATABASE IF EXISTS "{database}";'])
            self.executor.run(
                drop_cmd,
                description=f"Drop database {database}",
                check=True,
                as_user=as_user,
            )

        except Exception as e:
            raise BackupError(
                f"Failed to drop database '{database}'",
                details=[str(e)],
                hint="Use --force to terminate active connections",
            ) from e


def check_disk_space(path: Path, required_bytes: int) -> tuple[bool, int]:
    """Check if sufficient disk space is available.

    Args:
        path: Path to check (will check the filesystem containing this path)
        required_bytes: Required space in bytes

    Returns:
        Tuple of (sufficient, available_bytes)
    """
    # Get the filesystem stats for the path
    stat = os.statvfs(path if path.exists() else path.parent)
    available = stat.f_bavail * stat.f_frsize
    return available >= required_bytes, available


def format_bytes(size_bytes: int) -> str:
    """Format bytes as human-readable string.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 GB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"
