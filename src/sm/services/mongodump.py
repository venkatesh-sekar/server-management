"""mongodump and mongorestore service wrappers.

Provides safe wrappers around mongodump and mongorestore for database
export/import operations with S3 upload support.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import quote_plus

from sm.core.context import ExecutionContext
from sm.core.exceptions import BackupError
from sm.core.executor import CommandExecutor
from sm.core.output import console
from sm.services.s3 import calculate_file_checksum


@dataclass
class DumpInfo:
    """Information about a mongodump output."""

    database: str
    dump_path: Path
    size_bytes: int
    checksum: str
    mongo_version: str
    dump_time: datetime


@dataclass
class DatabaseSize:
    """Database size information."""

    name: str
    size_bytes: int
    size_pretty: str


def format_bytes(size_bytes: int) -> str:
    """Format bytes as human-readable string.

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


class MongoDumpService:
    """Service for mongodump and mongorestore operations.

    Features:
    - GZIP compression by default
    - Oplog support for consistent snapshots
    - Progress reporting
    - Checksum calculation for verification
    """

    # Default excluded databases (system databases)
    DEFAULT_EXCLUDE_DATABASES = {"admin", "config", "local"}

    def __init__(
        self,
        ctx: ExecutionContext,
        executor: CommandExecutor,
        *,
        mongo_host: str = "127.0.0.1",
        mongo_port: int = 27017,
        auth_database: str = "admin",
    ) -> None:
        """Initialize mongodump service.

        Args:
            ctx: Execution context
            executor: Command executor
            mongo_host: MongoDB host
            mongo_port: MongoDB port
            auth_database: Authentication database
        """
        self.ctx = ctx
        self.executor = executor
        self.mongo_host = mongo_host
        self.mongo_port = mongo_port
        self.auth_database = auth_database
        self._credentials: Optional[tuple[str, str]] = None

    def set_credentials(self, username: str, password: str) -> None:
        """Set authentication credentials.

        Args:
            username: MongoDB username
            password: MongoDB password
        """
        self._credentials = (username, password)

    def check_commands_available(self) -> tuple[bool, list[str]]:
        """Check if mongodump and mongorestore are available.

        Returns:
            Tuple of (all_available, list of missing commands)
        """
        missing = []
        for cmd in ["mongodump", "mongorestore", "mongosh"]:
            if not shutil.which(cmd):
                missing.append(cmd)
        return len(missing) == 0, missing

    def get_mongo_version(self) -> str:
        """Get MongoDB version string.

        Returns:
            Version string (e.g., "7.0.14")
        """
        if self.ctx.dry_run:
            return "7.0.0"

        result = self.executor.run(
            ["mongod", "--version"],
            check=False,
        )
        if result.success:
            for line in result.stdout.splitlines():
                if "db version" in line:
                    return line.split("v")[-1].split()[0]
        return "unknown"

    def _build_connection_args(
        self,
        include_auth: bool = True,
    ) -> list[str]:
        """Build common connection arguments for mongodump/mongorestore.

        Args:
            include_auth: Include authentication arguments

        Returns:
            List of command-line arguments
        """
        args = [
            "--host", self.mongo_host,
            "--port", str(self.mongo_port),
        ]

        if include_auth and self._credentials:
            user, password = self._credentials
            args.extend([
                "--username", user,
                "--password", password,
                "--authenticationDatabase", self.auth_database,
            ])

        return args

    def list_databases(self, exclude_system: bool = True) -> list[DatabaseSize]:
        """List all databases with sizes.

        Args:
            exclude_system: Exclude admin, config, local databases

        Returns:
            List of DatabaseSize objects
        """
        if self.ctx.dry_run:
            console.dry_run("Would list databases")
            return []

        # Build mongosh command
        cmd = ["mongosh"]

        if self._credentials:
            user, password = self._credentials
            encoded_pass = quote_plus(password)
            uri = f"mongodb://{user}:{encoded_pass}@{self.mongo_host}:{self.mongo_port}/admin?authSource={self.auth_database}"
            cmd.append(uri)
        else:
            cmd.append(f"mongodb://{self.mongo_host}:{self.mongo_port}/admin")

        cmd.extend([
            "--quiet",
            "--eval", "JSON.stringify(db.adminCommand('listDatabases').databases)",
        ])

        result = self.executor.run(cmd, check=False, sensitive=True)

        if not result.success:
            return []

        try:
            databases = []
            for db in json.loads(result.stdout.strip()):
                name = db["name"]
                if exclude_system and name in self.DEFAULT_EXCLUDE_DATABASES:
                    continue
                size_bytes = db.get("sizeOnDisk", 0)
                databases.append(DatabaseSize(
                    name=name,
                    size_bytes=size_bytes,
                    size_pretty=format_bytes(size_bytes),
                ))
            return databases
        except json.JSONDecodeError:
            return []

    def dump_database(
        self,
        database: str,
        output_dir: Path,
        *,
        gzip: bool = True,
        oplog: bool = False,
    ) -> DumpInfo:
        """Dump a single database.

        Args:
            database: Database name
            output_dir: Output directory
            gzip: Enable GZIP compression
            oplog: Include oplog for point-in-time consistency

        Returns:
            DumpInfo with dump metadata

        Raises:
            BackupError: If dump fails
        """
        if self.ctx.dry_run:
            console.dry_run(f"Would dump database '{database}' to {output_dir}")
            return DumpInfo(
                database=database,
                dump_path=output_dir / f"{database}.tar.gz",
                size_bytes=0,
                checksum="sha256:dry-run",
                mongo_version="dry-run",
                dump_time=datetime.now(),
            )

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build mongodump command
        cmd = ["mongodump"]
        cmd.extend(self._build_connection_args())
        cmd.extend([
            "--db", database,
            "--out", str(output_dir),
        ])

        if gzip:
            cmd.append("--gzip")

        if oplog:
            cmd.append("--oplog")

        console.step(f"Dumping database '{database}'...")

        try:
            self.executor.run(
                cmd,
                description=f"Dump database {database}",
                check=True,
                sensitive=True,
            )

            # Calculate total size of dump directory
            dump_path = output_dir / database
            total_size = sum(
                f.stat().st_size for f in dump_path.rglob("*") if f.is_file()
            )

            # Create archive for easier S3 upload
            archive_path = output_dir / f"{database}.tar.gz"
            self.executor.run(
                ["tar", "-czf", str(archive_path), "-C", str(output_dir), database],
                description=f"Archive {database} dump",
            )

            # Clean up the unarchived dump directory
            shutil.rmtree(dump_path)

            checksum = calculate_file_checksum(archive_path)

            return DumpInfo(
                database=database,
                dump_path=archive_path,
                size_bytes=archive_path.stat().st_size,
                checksum=checksum,
                mongo_version=self.get_mongo_version(),
                dump_time=datetime.now(),
            )

        except Exception as e:
            raise BackupError(
                f"Failed to dump database '{database}'",
                details=[str(e)],
            ) from e

    def restore_database(
        self,
        dump_path: Path,
        target_database: str,
        *,
        drop: bool = False,
        gzip: bool = True,
    ) -> None:
        """Restore a database from dump.

        Args:
            dump_path: Path to dump archive or directory
            target_database: Target database name
            drop: Drop existing collections before restore
            gzip: Dump was compressed with gzip

        Raises:
            BackupError: If restore fails
        """
        if not dump_path.exists():
            raise BackupError(f"Dump file not found: {dump_path}")

        if self.ctx.dry_run:
            console.dry_run(f"Would restore {dump_path} to database '{target_database}'")
            return

        # Extract if archive
        restore_path = dump_path
        extract_dir: Optional[Path] = None

        if dump_path.suffix == ".gz" or str(dump_path).endswith(".tar.gz"):
            extract_dir = dump_path.parent / "extracted"
            extract_dir.mkdir(exist_ok=True)
            self.executor.run(
                ["tar", "-xzf", str(dump_path), "-C", str(extract_dir)],
                description="Extract dump archive",
            )
            # Find the database directory
            for item in extract_dir.iterdir():
                if item.is_dir():
                    restore_path = item
                    break

        try:
            # Build mongorestore command
            cmd = ["mongorestore"]
            cmd.extend(self._build_connection_args())
            cmd.extend([
                "--db", target_database,
                str(restore_path),
            ])

            if drop:
                cmd.append("--drop")

            if gzip:
                cmd.append("--gzip")

            console.step(f"Restoring database '{target_database}'...")

            self.executor.run(
                cmd,
                description=f"Restore {target_database}",
                check=True,
                sensitive=True,
            )
            console.success(f"Restored database '{target_database}'")

        except Exception as e:
            raise BackupError(
                f"Failed to restore database '{target_database}'",
                details=[str(e)],
            ) from e

        finally:
            # Clean up extracted files
            if extract_dir and extract_dir.exists():
                shutil.rmtree(extract_dir)

    def dump_all_databases(
        self,
        output_dir: Path,
        *,
        gzip: bool = True,
        exclude: Optional[list[str]] = None,
    ) -> list[DumpInfo]:
        """Dump all user databases.

        Args:
            output_dir: Output directory
            gzip: Enable GZIP compression
            exclude: List of database names to exclude

        Returns:
            List of DumpInfo for each database

        Raises:
            BackupError: If any dump fails
        """
        exclude_set = set(exclude or [])
        exclude_set.update(self.DEFAULT_EXCLUDE_DATABASES)

        databases = self.list_databases(exclude_system=True)
        databases = [db for db in databases if db.name not in exclude_set]

        if not databases:
            console.warn("No databases to dump")
            return []

        dump_infos = []
        for db in databases:
            console.step(f"Dumping '{db.name}'...")
            dump_info = self.dump_database(db.name, output_dir, gzip=gzip)
            dump_infos.append(dump_info)
            if not self.ctx.dry_run:
                console.success(f"  Dumped {db.name}: {format_bytes(dump_info.size_bytes)}")

        return dump_infos
