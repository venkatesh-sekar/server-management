"""MongoDB restore commands.

Commands:
- sm mongodb restore from-export     # Restore from S3 export
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

import typer

from sm.core import (
    AppConfig,
    AuditEventType,
    BackupError,
    CommandExecutor,
    ConfigurationError,
    PrerequisiteError,
    SafetyError,
    console,
    create_context,
    get_audit_logger,
    get_credential_manager,
    require_force,
    require_root,
    run_preflight_checks,
)
from sm.core.validation import validate_identifier
from sm.services.mongodump import MongoDumpService, format_bytes
from sm.services.s3 import S3Config, S3Service, verify_file_checksum


app = typer.Typer(
    name="restore",
    help="MongoDB restore operations.",
    no_args_is_help=True,
)


def _get_s3_config(app_config: AppConfig) -> S3Config:
    """Create S3 config from app config."""
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


@app.command("from-export")
@require_root
def restore_from_export(
    source: str = typer.Argument(
        ...,
        help="Export path (e.g., hostname/20240115_103000/mydb.tar.gz or hostname/20240115_103000)",
    ),
    database: Optional[str] = typer.Option(
        None, "--database", "-d",
        help="Database to restore (if export contains multiple)",
    ),
    target: Optional[str] = typer.Option(
        None, "--target", "-t",
        help="Target database name (defaults to source database name)",
    ),
    drop: bool = typer.Option(
        False, "--drop",
        help="Drop existing collections before restore",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", "-f", help="Allow dangerous operations"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Restore a database from S3 export.

    Downloads the dump file from S3 and restores it using mongorestore.

    Examples:

        # Restore specific database from export
        sm mongodb restore from-export hostname/20240115_103000/mydb.tar.gz

        # Restore to a different database name
        sm mongodb restore from-export hostname/20240115_103000/mydb.tar.gz --target newdb

        # Drop existing collections before restore
        sm mongodb restore from-export hostname/20240115_103000/mydb.tar.gz --drop --force
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    app_config = AppConfig()
    creds = get_credential_manager()

    # --drop requires --force
    if drop and not force:
        raise SafetyError(
            "--drop requires --force flag",
            required_flags=["--force"],
        )

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
    except (ConfigurationError, BackupError) as e:
        console.error(str(e))
        raise typer.Exit(2)

    export_base = app_config.mongo_export.export_path.lstrip("/")

    # Parse source path
    if source.endswith(".tar.gz"):
        # Full path to specific dump file
        parts = source.rsplit("/", 1)
        export_dir = parts[0]
        dump_file = parts[1]
        db_name = dump_file.replace(".tar.gz", "")
    else:
        # Path to export directory
        export_dir = source
        if database:
            db_name = database
            dump_file = f"{database}.tar.gz"
        else:
            # Check manifest to see what databases are available
            manifest_key = f"{export_base}/{export_dir}/manifest.json"
            if not s3.object_exists(manifest_key):
                console.error(f"Export not found: {source}")
                raise typer.Exit(3)

            manifest = s3.download_json(manifest_key)
            databases = [db["name"] for db in manifest.get("databases", [])]

            if len(databases) == 1:
                db_name = databases[0]
                dump_file = f"{db_name}.tar.gz"
            else:
                console.error(f"Export contains multiple databases: {', '.join(databases)}")
                console.print("  Use --database to specify which one to restore")
                raise typer.Exit(3)

    target_db = target or db_name

    # Validate target
    try:
        validate_identifier(target_db, "database")
    except Exception as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Build full S3 paths
    dump_key = f"{export_base}/{export_dir}/{dump_file}"
    manifest_key = f"{export_base}/{export_dir}/manifest.json"

    # Check dump file exists
    if not s3.object_exists(dump_key):
        console.error(f"Dump file not found: {dump_key}")
        raise typer.Exit(3)

    # Get manifest for checksum and info
    manifest = s3.download_json(manifest_key)
    db_info = next(
        (db for db in manifest.get("databases", []) if db["name"] == db_name),
        None
    )
    expected_checksum = db_info.get("checksum") if db_info else None
    dump_size = db_info.get("size_bytes", 0) if db_info else 0

    # Display configuration
    console.print()
    console.print("[bold]Restore Configuration[/bold]")
    console.print(f"  Source:   s3://{s3_config.bucket}/{dump_key}")
    console.print(f"  Database: {db_name}")
    console.print(f"  Target:   {target_db}")
    console.print(f"  Size:     {format_bytes(dump_size)}")
    console.print(f"  Drop:     {'Yes (will delete existing data!)' if drop else 'No'}")
    console.print()

    if drop:
        console.warn("WARNING: --drop will delete all existing data in the target database!")
        console.print()

    if not yes and not dry_run:
        if not console.confirm("Proceed with restore?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    with tempfile.TemporaryDirectory(prefix="sm-mongo-restore-") as temp_dir:
        temp_path = Path(temp_dir)

        try:
            local_dump = temp_path / dump_file

            # Download dump file
            console.step("Downloading dump file...")
            s3.download_file(dump_key, local_dump)

            # Verify checksum
            if expected_checksum:
                console.step("Verifying checksum...")
                if not verify_file_checksum(local_dump, expected_checksum):
                    raise BackupError(
                        "Checksum verification failed",
                        hint="The dump file may be corrupted. Try downloading again.",
                    )
                console.success("Checksum OK")

            # Restore database
            console.step(f"Restoring database '{target_db}'...")
            mongodump.restore_database(
                local_dump,
                target_db,
                drop=drop,
            )

            console.print()
            console.success(f"Database '{target_db}' restored successfully")

            audit.log_success(
                AuditEventType.RESTORE_FROM_EXPORT,
                target_type="database",
                target_name=target_db,
                message=f"Restored from {export_dir}/{dump_file}",
            )

        except BackupError as e:
            audit.log_failure(
                AuditEventType.RESTORE_FROM_EXPORT,
                target_type="database",
                target_name=target_db,
                error=str(e),
            )
            console.error(str(e))
            raise typer.Exit(12)
