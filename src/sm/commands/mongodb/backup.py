"""MongoDB backup commands.

Commands:
- sm mongodb backup export     # Export database(s) to S3
- sm mongodb backup list       # List available exports
- sm mongodb backup delete     # Delete an export
"""

from __future__ import annotations

import json
import socket
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table

from sm.core import (
    AppConfig,
    AuditEventType,
    BackupError,
    CommandExecutor,
    ConfigurationError,
    PrerequisiteError,
    console,
    create_context,
    get_audit_logger,
    get_credential_manager,
    require_force,
    require_root,
    run_preflight_checks,
    ValidationError,
)
from sm.core.validation import validate_identifier
from sm.services.mongodump import MongoDumpService, format_bytes
from sm.services.s3 import S3Config, S3Service


app = typer.Typer(
    name="backup",
    help="MongoDB backup operations (mongodump to S3).",
    no_args_is_help=True,
)


def _get_s3_config(app_config: AppConfig) -> S3Config:
    """Create S3 config from app config.

    Args:
        app_config: Application configuration

    Returns:
        S3Config instance

    Raises:
        ConfigurationError: If credentials missing
    """
    if not app_config.has_backup_credentials():
        raise ConfigurationError(
            "S3 credentials not configured",
            hint="Set SM_B2_KEY, SM_B2_SECRET, and SM_BACKUP_PASSPHRASE environment variables",
        )

    return S3Config(
        endpoint=app_config.backup.s3_endpoint or "",
        region=app_config.backup.s3_region or "",
        bucket=app_config.backup.s3_bucket or "",
        access_key=app_config.secrets.sm_b2_key or "",
        secret_key=app_config.secrets.sm_b2_secret or "",
    )


def _get_hostname() -> str:
    """Get current hostname for export paths."""
    return socket.gethostname()


def _get_timestamp() -> str:
    """Get timestamp for export paths."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


@app.command("export")
@require_root
def export_database(
    database: Optional[str] = typer.Option(
        None, "--database", "-d",
        help="Database name (omit for all databases)",
    ),
    exclude: Optional[list[str]] = typer.Option(
        None, "--exclude", "-e",
        help="Databases to exclude (can be specified multiple times)",
    ),
    gzip: bool = typer.Option(
        True, "--gzip/--no-gzip",
        help="Enable gzip compression",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Export database(s) to S3 using mongodump.

    Creates compressed dumps and uploads to S3.

    Use this for:
    - Manual point-in-time snapshots
    - Cross-cluster migration prep
    - Development environment seeding

    Examples:

        # Export single database
        sm mongodb backup export -d myapp

        # Export all databases
        sm mongodb backup export

        # Export all except specific databases
        sm mongodb backup export --exclude analytics --exclude logs

        # Preview what would happen
        sm mongodb backup export -d myapp --dry-run
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    app_config = AppConfig()
    creds = get_credential_manager()

    # Validate database name if provided
    if database:
        try:
            validate_identifier(database, "database")
        except ValidationError as e:
            console.error(str(e))
            raise typer.Exit(3)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor = CommandExecutor(ctx)
    mongodump = MongoDumpService(
        ctx, executor,
        mongo_host=app_config.mongodb.host,
        mongo_port=app_config.mongodb.port,
        auth_database=app_config.mongodb.auth_database,
    )

    # Set credentials
    admin_pass = creds.get_password("admin", "_mongodb")
    if admin_pass:
        mongodump.set_credentials("admin", admin_pass)

    # Check commands available
    available, missing = mongodump.check_commands_available()
    if not available:
        raise PrerequisiteError(
            f"Required commands not found: {', '.join(missing)}",
            hint="Install mongodb-database-tools package",
        )

    # Get S3 config
    try:
        s3_config = _get_s3_config(app_config)
        s3 = S3Service(ctx, s3_config)
        console.step("Testing S3 connectivity...")
        s3.test_connectivity()
        console.success("S3 connection OK")
    except (ConfigurationError, BackupError) as e:
        console.error(str(e))
        raise typer.Exit(2)

    # Determine databases to export
    if database:
        databases_to_export = [database]
    else:
        db_list = mongodump.list_databases(exclude_system=True)
        databases_to_export = [db.name for db in db_list]
        if exclude:
            databases_to_export = [db for db in databases_to_export if db not in exclude]

    if not databases_to_export:
        console.warn("No databases to export")
        raise typer.Exit(0)

    # Build export path
    hostname = _get_hostname()
    timestamp = _get_timestamp()
    export_prefix = f"{app_config.mongo_export.export_path.lstrip('/')}/{hostname}/{timestamp}"

    # Display configuration
    console.print()
    console.print("[bold]Export Configuration[/bold]")
    console.print(f"  Databases:  {', '.join(databases_to_export)}")
    console.print(f"  Compress:   {'Yes (gzip)' if gzip else 'No'}")
    console.print(f"  S3 Path:    s3://{s3_config.bucket}/{export_prefix}/")
    console.print()

    if not yes and not dry_run:
        if not console.confirm("Proceed with export?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    with tempfile.TemporaryDirectory(prefix="sm-mongo-export-") as temp_dir:
        temp_path = Path(temp_dir)

        try:
            dump_infos = []
            for db_name in databases_to_export:
                console.step(f"Exporting '{db_name}'...")
                dump_info = mongodump.dump_database(
                    db_name,
                    temp_path,
                    gzip=gzip,
                )
                dump_infos.append(dump_info)
                if not dry_run:
                    console.success(f"  Exported {db_name}: {format_bytes(dump_info.size_bytes)}")

            # Create manifest
            manifest = {
                "version": "1.0",
                "type": "mongodb",
                "hostname": hostname,
                "timestamp": datetime.now().isoformat(),
                "mongo_version": mongodump.get_mongo_version() if not dry_run else "dry-run",
                "databases": [
                    {
                        "name": info.database,
                        "size_bytes": info.size_bytes,
                        "file": f"{info.database}.tar.gz",
                        "checksum": info.checksum,
                    }
                    for info in dump_infos
                ],
                "compression": gzip,
            }

            # Upload to S3
            console.step("Uploading to S3...")

            if not dry_run:
                s3.upload_json(f"{export_prefix}/manifest.json", manifest)

                for info in dump_infos:
                    remote_key = f"{export_prefix}/{info.database}.tar.gz"
                    s3.upload_file(info.dump_path, remote_key)
                    console.verbose(f"  Uploaded {info.database}.tar.gz")

            s3_uri = f"s3://{s3_config.bucket}/{export_prefix}/"
            console.print()
            console.success(f"Export completed: {s3_uri}")

            audit.log_success(
                AuditEventType.BACKUP_EXPORT,
                target_type="export",
                target_name=export_prefix,
                message=f"Exported {len(dump_infos)} database(s) to {s3_uri}",
            )

        except BackupError as e:
            audit.log_failure(
                AuditEventType.BACKUP_EXPORT,
                target_type="export",
                target_name=export_prefix,
                error=str(e),
            )
            console.error(str(e))
            raise typer.Exit(12)


@app.command("list")
@require_root
def list_exports(
    hostname: Optional[str] = typer.Option(
        None, "--hostname",
        help="Filter by hostname (default: current host)",
    ),
    all_hosts: bool = typer.Option(
        False, "--all",
        help="Show exports from all hosts",
    ),
    limit: int = typer.Option(
        20, "--limit", "-n",
        help="Maximum number of exports to show",
    ),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """List available MongoDB exports in S3.

    Shows exports for the current host by default.

    Examples:

        sm mongodb backup list

        sm mongodb backup list --all

        sm mongodb backup list --hostname db-prod-01
    """
    ctx = create_context(verbose=verbose)
    app_config = AppConfig()

    try:
        s3_config = _get_s3_config(app_config)
        s3 = S3Service(ctx, s3_config)
    except (ConfigurationError, BackupError) as e:
        console.error(str(e))
        raise typer.Exit(2)

    export_base = app_config.mongo_export.export_path.lstrip("/")

    if all_hosts:
        prefix = f"{export_base}/"
    else:
        host = hostname or _get_hostname()
        prefix = f"{export_base}/{host}/"

    console.step(f"Listing exports in s3://{s3_config.bucket}/{prefix}")

    try:
        exports = []

        # List objects and find manifests
        objects = s3.list_objects(prefix)

        for obj in objects:
            if obj["Key"].endswith("manifest.json"):
                manifest_key = obj["Key"]
                try:
                    manifest = s3.download_json(manifest_key)
                    # Extract path (remove manifest.json)
                    path = manifest_key.rsplit("/", 1)[0]
                    exports.append({"path": path, "manifest": manifest})
                except Exception as e:
                    console.warn(f"Skipping invalid manifest {manifest_key}: {e}")
                    continue

        if not exports:
            console.warn("No MongoDB exports found")
            raise typer.Exit(0)

        # Sort by timestamp (newest first)
        exports.sort(key=lambda x: x["manifest"].get("timestamp", ""), reverse=True)
        exports = exports[:limit]

        table = Table(title="Available MongoDB Exports")
        table.add_column("Path", style="cyan")
        table.add_column("Timestamp", style="green")
        table.add_column("Databases")
        table.add_column("MongoDB Version")

        for export in exports:
            manifest = export["manifest"]
            path = export["path"]
            display_path = path.replace(f"{export_base}/", "")
            timestamp = manifest.get("timestamp", "unknown")[:19]
            databases = ", ".join(db["name"] for db in manifest.get("databases", []))
            mongo_version = manifest.get("mongo_version", "?")

            table.add_row(display_path, timestamp, databases, mongo_version)

        console.print(table)

    except BackupError as e:
        console.error(str(e))
        raise typer.Exit(12)


@app.command("delete")
@require_root
@require_force("Deleting exports permanently removes backup data")
def delete_export(
    path: str = typer.Argument(
        ...,
        help="Export path (e.g., hostname/20240115_103000)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow dangerous operation"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Delete a MongoDB export from S3.

    WARNING: This permanently deletes the export data!

    Requires --force flag for safety.

    Examples:

        sm mongodb backup delete db-prod-01/20240115_103000 --force
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    app_config = AppConfig()

    try:
        s3_config = _get_s3_config(app_config)
        s3 = S3Service(ctx, s3_config)
    except (ConfigurationError, BackupError) as e:
        console.error(str(e))
        raise typer.Exit(2)

    export_base = app_config.mongo_export.export_path.lstrip("/")
    full_prefix = f"{export_base}/{path}"

    # Check if export exists
    manifest_key = f"{full_prefix}/manifest.json"
    if not s3.object_exists(manifest_key):
        console.error(f"Export not found: {path}")
        raise typer.Exit(3)

    # Get manifest for info
    manifest = s3.download_json(manifest_key)
    databases = ", ".join(db["name"] for db in manifest.get("databases", []))
    timestamp = manifest.get("timestamp", "unknown")[:19]

    # Display warning
    console.print()
    console.print("[bold red]DANGER: Export Deletion[/bold red]")
    console.print(f"  Path:      {path}")
    console.print(f"  Timestamp: {timestamp}")
    console.print(f"  Databases: {databases}")
    console.print("[red]This will PERMANENTLY DELETE the export data![/red]")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"[red]Delete export '{path}'?[/red]", default=False):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        # List all objects with this prefix
        objects = s3.list_objects(f"{full_prefix}/")

        if not objects:
            console.error(f"No objects found at {path}")
            raise typer.Exit(3)

        console.step(f"Deleting {len(objects)} objects...")

        if not dry_run:
            for obj in objects:
                s3.delete_object(obj["Key"])
                console.verbose(f"  Deleted {obj['Key']}")

        console.success(f"Export '{path}' deleted")

        audit.log_success(
            AuditEventType.BACKUP_DELETE,
            target_type="export",
            target_name=path,
            message=f"Deleted export with {len(objects)} objects",
        )

    except BackupError as e:
        audit.log_failure(
            AuditEventType.BACKUP_DELETE,
            target_type="export",
            target_name=path,
            error=str(e),
        )
        console.error(str(e))
        raise typer.Exit(12)
