"""PostgreSQL backup commands.

Commands:
- sm postgres backup export     # Export database(s) to S3
- sm postgres backup list       # List available exports
- sm postgres backup delete     # Delete an export
"""

import socket
import tempfile
from datetime import datetime
from pathlib import Path

import typer
from rich.table import Table

from sm.core import (
    AppConfig,
    AuditEventType,
    BackupError,
    CommandExecutor,
    ConfigurationError,
    PrerequisiteError,
    ValidationError,
    console,
    create_context,
    get_audit_logger,
    require_force,
    require_root,
    run_preflight_checks,
)
from sm.core.validation import validate_identifier
from sm.services.pgdump import PgDumpService, check_disk_space, format_bytes
from sm.services.s3 import S3Config, S3Service, calculate_file_checksum

app = typer.Typer(
    name="backup",
    help="PostgreSQL backup and export operations (pg_dump to S3).",
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


def _confirm_pg_credentials(
    app_config: AppConfig,
    skip_confirm: bool = False,
) -> tuple[str, int, str]:
    """Confirm PostgreSQL connection credentials with auto-filled defaults.

    Args:
        app_config: Application configuration
        skip_confirm: If True, return defaults without prompting

    Returns:
        Tuple of (host, port, pg_user)
    """
    # Auto-fill from config (which reads env vars)
    default_host = app_config.postgres.host
    default_port = app_config.postgres.port
    default_user = app_config.postgres.pg_user

    if skip_confirm:
        return default_host, default_port, default_user

    console.print("-> Confirm database connection:")

    # Interactive prompts with defaults
    host_input = console.input(f"  Host [[cyan]{default_host}[/cyan]]: ").strip()
    host = host_input if host_input else default_host

    port_input = console.input(f"  Port [[cyan]{default_port}[/cyan]]: ").strip()
    try:
        port = int(port_input) if port_input else default_port
    except ValueError:
        console.warn(f"Invalid port '{port_input}', using default {default_port}")
        port = default_port

    user_input = console.input(f"  Username [[cyan]{default_user}[/cyan]]: ").strip()
    user = user_input if user_input else default_user

    return host, port, user


@app.command("export")
@require_root
def export_database(
    database: str | None = typer.Option(
        None, "--database", "-d",
        help="Database name (omit for all databases)",
    ),
    exclude: list[str] | None = typer.Option(
        None, "--exclude", "-e",
        help="Databases to exclude (can be specified multiple times)",
    ),
    compression: int = typer.Option(
        6, "--compression", "-z",
        help="Compression level (0-9, 0=none)",
        min=0, max=9,
    ),
    jobs: int = typer.Option(
        4, "--jobs", "-j",
        help="Parallel jobs for pg_dump",
        min=1, max=16,
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Export database(s) to S3 using pg_dump.

    Creates portable custom-format dumps and uploads to S3.
    This is SEPARATE from pgBackRest continuous backups.

    Use this for:
    - Manual point-in-time snapshots
    - Cross-cluster migration prep
    - Development environment seeding

    Examples:

        # Export single database
        sm postgres backup export -d myapp

        # Export all databases
        sm postgres backup export

        # Export all except specific databases
        sm postgres backup export --exclude analytics --exclude logs

        # Preview what would happen
        sm postgres backup export -d myapp --dry-run
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    app_config = AppConfig()

    # Validate database name if provided
    if database:
        try:
            validate_identifier(database, "database")
        except ValidationError as e:
            console.error(str(e))
            raise typer.Exit(3) from None

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Confirm database credentials (auto-filled, user can override)
    pg_host, pg_port, pg_user = _confirm_pg_credentials(app_config, skip_confirm=yes)

    # Get services
    executor = CommandExecutor(ctx)
    pgdump = PgDumpService(
        ctx, executor,
        pg_host=pg_host,
        pg_port=pg_port,
        pg_user=pg_user,
    )

    # Check pg_dump is available
    available, missing = pgdump.check_commands_available()
    if not available:
        raise PrerequisiteError(
            f"Required commands not found: {', '.join(missing)}",
            hint="Install postgresql-client package",
        )

    # Get S3 config and test connectivity
    try:
        s3_config = _get_s3_config(app_config)
        s3 = S3Service(ctx, s3_config)
        console.step("Testing S3 connectivity...")
        s3.test_connectivity()
        console.success("S3 connection OK")
    except (ConfigurationError, BackupError) as e:
        console.error(str(e))
        raise typer.Exit(2) from None

    # Determine databases to export
    if database:
        # Single database
        if not pgdump.database_exists(database):
            console.error(f"Database '{database}' does not exist")
            raise typer.Exit(3)
        databases_to_export = [database]
    else:
        # All databases
        db_list = pgdump.list_databases(exclude_system=True)
        databases_to_export = [db.name for db in db_list]

        # Apply exclusions
        if exclude:
            databases_to_export = [db for db in databases_to_export if db not in exclude]

        if not databases_to_export:
            console.warn("No databases to export")
            raise typer.Exit(0)

    # Build export path
    hostname = _get_hostname()
    timestamp = _get_timestamp()
    export_prefix = f"{app_config.export.export_path.lstrip('/')}/{hostname}/{timestamp}"

    # Show confirmation
    console.print()
    console.print("[bold]Export Configuration[/bold]")
    console.print(f"  Databases:    {', '.join(databases_to_export)}")
    console.print(f"  Compression:  {compression}")
    console.print(f"  Jobs:         {jobs}")
    console.print(f"  S3 Path:      s3://{s3_config.bucket}/{export_prefix}/")
    console.print()

    if not yes and not dry_run:
        if not console.confirm("Proceed with export?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    # Create temp directory for dumps
    with tempfile.TemporaryDirectory(prefix="sm-export-") as temp_dir:
        temp_path = Path(temp_dir)

        try:
            # Check disk space (estimate 2x database size for safety)
            if database:
                db_info = next((db for db in pgdump.list_databases() if db.name == database), None)
                required_space = (db_info.size_bytes * 2) if db_info else 1024 * 1024 * 100
            else:
                total_size = sum(db.size_bytes for db in pgdump.list_databases())
                required_space = total_size * 2

            sufficient, available = check_disk_space(temp_path, required_space)
            if not sufficient:
                msg = (
                    f"Insufficient disk space: need {format_bytes(required_space)}, "
                    f"have {format_bytes(available)}"
                )
                raise PrerequisiteError(
                    msg,
                    hint="Free up disk space or export databases individually",
                )

            # Dump databases
            dump_infos = []
            for db_name in databases_to_export:
                console.step(f"Exporting '{db_name}'...")
                dump_path = temp_path / f"{db_name}.dump"
                dump_info = pgdump.dump_database(
                    db_name,
                    dump_path,
                    compression_level=compression,
                    jobs=jobs,
                )
                dump_infos.append(dump_info)
                if not dry_run:
                    console.success(f"  Exported {db_name}: {format_bytes(dump_info.size_bytes)}")

            # Dump globals (roles, tablespaces)
            globals_path = temp_path / "globals.sql"
            pgdump.dump_globals(globals_path)

            # Create manifest
            manifest = {
                "version": "1.0",
                "hostname": hostname,
                "timestamp": datetime.now().isoformat(),
                "pg_version": pgdump.get_pg_version() if not dry_run else "dry-run",
                "databases": [
                    {
                        "name": info.database,
                        "size_bytes": info.size_bytes,
                        "file": f"{info.database}.dump",
                        "checksum": info.checksum,
                    }
                    for info in dump_infos
                ],
                "globals_file": "globals.sql",
                "globals_checksum": (
                    calculate_file_checksum(globals_path) if globals_path.exists() else None
                ),
                "compression": compression,
            }

            # Upload to S3
            console.step("Uploading to S3...")

            if not dry_run:
                # Upload manifest first
                s3.upload_json(f"{export_prefix}/manifest.json", manifest)

                # Upload each dump file
                for info in dump_infos:
                    remote_key = f"{export_prefix}/{info.database}.dump"
                    s3.upload_file(info.file_path, remote_key)
                    console.verbose(f"  Uploaded {info.database}.dump")

                # Upload globals
                s3.upload_file(globals_path, f"{export_prefix}/globals.sql")

            # Success
            s3_uri = f"s3://{s3_config.bucket}/{export_prefix}/"
            console.print()
            console.success(f"Export completed: {s3_uri}")

            # Log audit event
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
            raise typer.Exit(12) from None
        except Exception as e:
            audit.log_failure(
                AuditEventType.BACKUP_EXPORT,
                target_type="export",
                target_name=export_prefix,
                error=str(e),
            )
            console.error(f"Export failed: {e}")
            raise typer.Exit(12) from None


@app.command("list")
@require_root
def list_exports(
    hostname: str | None = typer.Option(
        None, "--hostname",
        help="Filter by hostname (default: current host)",
    ),
    all_hosts: bool = typer.Option(
        False, "--all",
        help="Show exports from all hosts",
    ),
    limit: int = typer.Option(
        20, "--limit", "-n",
        help="Maximum exports to show",
    ),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """List available pg_dump exports in S3.

    Shows exports created with 'sm postgres backup export'.

    Examples:

        sm postgres backup list
        sm postgres backup list --hostname db-prod-01
        sm postgres backup list --all
    """
    ctx = create_context(verbose=verbose)
    app_config = AppConfig()

    # Get S3 config
    try:
        s3_config = _get_s3_config(app_config)
        s3 = S3Service(ctx, s3_config)
    except (ConfigurationError, BackupError) as e:
        console.error(str(e))
        raise typer.Exit(2) from None

    # Determine prefix to list
    export_base = app_config.export.export_path.lstrip("/")

    if all_hosts:
        prefix = f"{export_base}/"
    else:
        host = hostname or _get_hostname()
        prefix = f"{export_base}/{host}/"

    console.step(f"Listing exports in s3://{s3_config.bucket}/{prefix}")

    try:
        # List host directories if showing all
        exports = []

        if all_hosts:
            # List all host directories
            for host_prefix in s3.list_prefixes(prefix):
                # List timestamp directories under each host
                for ts_prefix in s3.list_prefixes(host_prefix):
                    # Try to read manifest
                    manifest_key = f"{ts_prefix}manifest.json"
                    if s3.object_exists(manifest_key):
                        manifest = s3.download_json(manifest_key)
                        exports.append({
                            "path": ts_prefix.rstrip("/"),
                            "manifest": manifest,
                        })
        else:
            # List timestamp directories for specific host
            for ts_prefix in s3.list_prefixes(prefix):
                manifest_key = f"{ts_prefix}manifest.json"
                if s3.object_exists(manifest_key):
                    manifest = s3.download_json(manifest_key)
                    exports.append({
                        "path": ts_prefix.rstrip("/"),
                        "manifest": manifest,
                    })

        if not exports:
            console.warn("No exports found")
            raise typer.Exit(0)

        # Sort by timestamp (newest first) and limit
        exports.sort(key=lambda x: x["manifest"].get("timestamp", ""), reverse=True)
        exports = exports[:limit]

        # Display table
        table = Table(title="Available Exports")
        table.add_column("Path", style="cyan")
        table.add_column("Timestamp", style="green")
        table.add_column("Databases")
        table.add_column("PG Version")

        for export in exports:
            manifest = export["manifest"]
            path = export["path"]
            # Extract relative path for display
            display_path = path.replace(f"{export_base}/", "")
            timestamp = manifest.get("timestamp", "unknown")[:19]  # Truncate to seconds
            databases = ", ".join(db["name"] for db in manifest.get("databases", []))
            pg_version = manifest.get("pg_version", "?")

            table.add_row(display_path, timestamp, databases, pg_version)

        console.print(table)

    except BackupError as e:
        console.error(str(e))
        raise typer.Exit(12) from None


@app.command("delete")
@require_root
@require_force("Deleting backups is irreversible")
def delete_export(
    path: str = typer.Argument(
        ...,
        help="Export path (e.g., db-prod-01/20240115_103000)",
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Required for deletion"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    confirm_name: str | None = typer.Option(
        None, "--confirm-name",
        help="Type the export path to confirm deletion (required without --yes)",
    ),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Delete an export from S3.

    IRREVERSIBLE: Use with caution. This permanently deletes the backup.

    For safety, you must either:
    - Provide --confirm-name with the exact export path, OR
    - Use --yes to skip confirmation (for scripting)

    Examples:

        sm postgres backup delete db-prod-01/20240115_103000 --force --confirm-name db-prod-01/20240115_103000
        sm postgres backup delete db-prod-01/20240115_103000 --force -y
    """
    ctx = create_context(force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    app_config = AppConfig()

    # Get S3 config
    try:
        s3_config = _get_s3_config(app_config)
        s3 = S3Service(ctx, s3_config)
    except (ConfigurationError, BackupError) as e:
        console.error(str(e))
        raise typer.Exit(2) from None

    # Build full S3 prefix
    export_base = app_config.export.export_path.lstrip("/")
    full_prefix = f"{export_base}/{path}/"

    # Check export exists
    manifest_key = f"{full_prefix}manifest.json"
    if not s3.object_exists(manifest_key):
        console.error(f"Export not found: {path}")
        console.print(f"  Looked for: s3://{s3_config.bucket}/{manifest_key}")
        raise typer.Exit(3)

    # Get manifest for display
    manifest = s3.download_json(manifest_key)
    databases = [db["name"] for db in manifest.get("databases", [])]

    # Confirm
    console.print()
    console.print("[bold red]╔═══════════════════════════════════════════════════════════════╗[/bold red]")
    console.print("[bold red]║  ⚠️  WARNING: THIS OPERATION IS IRREVERSIBLE!                  ║[/bold red]")
    console.print("[bold red]║  The backup will be PERMANENTLY DELETED from S3.              ║[/bold red]")
    console.print("[bold red]╚═══════════════════════════════════════════════════════════════╝[/bold red]")
    console.print()
    console.print(f"  Export:     {path}")
    console.print(f"  Databases:  {', '.join(databases)}")
    console.print(f"  Timestamp:  {manifest.get('timestamp', 'unknown')}")
    console.print()

    if not yes:
        # Check confirm_name if provided
        if confirm_name:
            if confirm_name != path:
                console.error(f"Confirmation name does not match!")
                console.print(f"  Expected: {path}")
                console.print(f"  Got:      {confirm_name}")
                raise typer.Exit(3)
        else:
            # Interactive confirmation - ask user to type the name
            console.print("To confirm deletion, type the export path exactly as shown above:")
            console.print(f"  [bold cyan]{path}[/bold cyan]")
            console.print()
            user_input = typer.prompt("Export path")
            if user_input != path:
                console.error("Confirmation failed - export path did not match")
                console.print("  Deletion cancelled for safety.")
                raise typer.Exit(0)

    try:
        # Delete all objects under the prefix
        deleted_count = s3.delete_prefix(full_prefix)

        console.success(f"Deleted export: {path} ({deleted_count} objects)")

        # Log audit event
        audit.log_success(
            AuditEventType.BACKUP_EXPORT_DELETE,
            target_type="export",
            target_name=path,
            message=f"Deleted {deleted_count} objects",
        )

    except BackupError as e:
        audit.log_failure(
            AuditEventType.BACKUP_EXPORT_DELETE,
            target_type="export",
            target_name=path,
            error=str(e),
        )
        console.error(str(e))
        raise typer.Exit(12) from None
