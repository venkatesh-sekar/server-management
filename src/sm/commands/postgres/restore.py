"""PostgreSQL restore commands.

Commands:
- sm postgres restore from-export   # Restore from pg_dump export
- sm postgres restore from-backup   # Restore from pgBackRest
- sm postgres restore list-backups  # List pgBackRest backups
"""

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
    SafetyError,
    ValidationError,
    console,
    create_context,
    get_audit_logger,
    require_force,
    require_root,
    run_preflight_checks,
)
from sm.core.validation import validate_identifier
from sm.services.pgbackrest import (
    PgBackRestService,
    RecoveryPoint,
    format_backup_size,
)
from sm.services.pgdump import PgDumpService, check_disk_space, format_bytes
from sm.services.postgresql import PostgreSQLService
from sm.services.s3 import S3Config, S3Service, verify_file_checksum
from sm.services.systemd import SystemdService

app = typer.Typer(
    name="restore",
    help="PostgreSQL restore operations.",
    no_args_is_help=True,
)


def _get_s3_config(app_config: AppConfig) -> S3Config:
    """Create S3 config from app config."""
    if not app_config.has_backup_credentials():
        raise ConfigurationError(
            "S3 credentials not configured",
            hint="Set SM_B2_KEY, SM_B2_SECRET environment variables",
        )

    return S3Config(
        endpoint=app_config.backup.s3_endpoint or "",
        region=app_config.backup.s3_region or "",
        bucket=app_config.backup.s3_bucket or "",
        access_key=app_config.secrets.sm_b2_key or "",
        secret_key=app_config.secrets.sm_b2_secret or "",
    )


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


@app.command("from-export")
@require_root
def restore_from_export(
    source: str = typer.Argument(
        ...,
        help="Export path (e.g., db-prod-01/20240115_103000/myapp.dump)",
    ),
    database: str | None = typer.Option(
        None, "--database", "-d",
        help="Specific database to restore (if export contains multiple)",
    ),
    target: str | None = typer.Option(
        None, "--target", "-t",
        help="Target database name (default: same as source)",
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite",
        help="Drop and recreate if exists (DANGEROUS: creates safety backup first)",
    ),
    no_owner: bool = typer.Option(
        False, "--no-owner",
        help="Skip ownership commands (useful for different user setup)",
    ),
    owner: str | None = typer.Option(
        None, "--owner", "-o",
        help="Set owner for restored database",
    ),
    jobs: int = typer.Option(
        4, "--jobs", "-j",
        help="Parallel jobs for pg_restore",
        min=1, max=16,
    ),
    restore_globals: bool = typer.Option(
        False, "--restore-globals",
        help="Also restore global objects (roles, tablespaces)",
    ),
    skip_safety_backup: bool = typer.Option(
        False, "--skip-safety-backup",
        help="Skip creating safety backup before overwrite (NOT recommended)",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", "-f", help="Required if --overwrite"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Restore a database from a pg_dump export in S3.

    Downloads the dump file and restores using pg_restore.

    Examples:

        # Restore from export (specify database)
        sm postgres restore from-export db-prod-01/20240115_103000 -d myapp

        # Restore single database from path with dump file
        sm postgres restore from-export db-prod-01/20240115_103000/myapp.dump

        # Restore to different database name (for testing)
        sm postgres restore from-export db-prod-01/20240115_103000/myapp.dump -t myapp_test

        # Overwrite existing database
        sm postgres restore from-export db-prod-01/20240115_103000/myapp.dump --overwrite --force
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    app_config = AppConfig()

    # Validate target name if provided
    if target:
        try:
            validate_identifier(target, "target database")
        except ValidationError as e:
            console.error(str(e))
            raise typer.Exit(3) from None

    # Check overwrite requires force
    if overwrite and not force:
        raise SafetyError(
            "Overwrite requires --force flag",
            required_flags=["--force"],
        )

    # Warn about skip_safety_backup
    if skip_safety_backup and not force:
        raise SafetyError(
            "--skip-safety-backup requires --force flag",
            required_flags=["--force"],
        )

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

    # Check pg_restore is available
    available, missing = pgdump.check_commands_available()
    if not available:
        raise PrerequisiteError(
            f"Required commands not found: {', '.join(missing)}",
            hint="Install postgresql-client package",
        )

    # Check PostgreSQL is running
    pg = PostgreSQLService(ctx, executor)
    if not dry_run and not pg.is_running():
        raise PrerequisiteError(
            "PostgreSQL is not running",
            hint="Start PostgreSQL with: systemctl start postgresql",
        )

    # Get S3 config
    try:
        s3_config = _get_s3_config(app_config)
        s3 = S3Service(ctx, s3_config)
    except (ConfigurationError, BackupError) as e:
        console.error(str(e))
        raise typer.Exit(2) from None

    # Parse source path
    export_base = app_config.export.export_path.lstrip("/")

    # Check if source includes .dump file or is just the export directory
    if source.endswith(".dump"):
        # Direct path to dump file
        parts = source.rsplit("/", 1)
        export_dir = parts[0]
        dump_file = parts[1]
        db_name = dump_file.replace(".dump", "")
    else:
        # Path to export directory - need to specify database
        export_dir = source
        if database:
            db_name = database
            dump_file = f"{database}.dump"
        else:
            # Check manifest for available databases
            manifest_key = f"{export_base}/{export_dir}/manifest.json"
            if not s3.object_exists(manifest_key):
                console.error(f"Export not found: {source}")
                raise typer.Exit(3)

            manifest = s3.download_json(manifest_key)
            databases = [db["name"] for db in manifest.get("databases", [])]

            if len(databases) == 1:
                db_name = databases[0]
                dump_file = f"{db_name}.dump"
            else:
                console.error(f"Export contains multiple databases: {', '.join(databases)}")
                console.print("  Use --database to specify which one to restore")
                raise typer.Exit(3)

    # Target database name
    target_db = target or db_name

    # Build S3 keys
    dump_key = f"{export_base}/{export_dir}/{dump_file}"
    manifest_key = f"{export_base}/{export_dir}/manifest.json"
    globals_key = f"{export_base}/{export_dir}/globals.sql"

    # Check dump file exists
    if not s3.object_exists(dump_key):
        console.error(f"Dump file not found: {dump_key}")
        raise typer.Exit(3)

    # Get manifest for checksum verification
    manifest = s3.download_json(manifest_key)
    db_info = next((db for db in manifest.get("databases", []) if db["name"] == db_name), None)
    expected_checksum = db_info.get("checksum") if db_info else None
    dump_size = db_info.get("size_bytes", 0) if db_info else 0

    # Check if target exists and warn appropriately
    target_exists = not dry_run and pgdump.database_exists(target_db)
    target_size_info = None
    if target_exists:
        # Get size of existing database for user info
        existing_dbs = pgdump.list_databases(exclude_system=False)
        target_size_info = next((db for db in existing_dbs if db.name == target_db), None)

    # Show configuration
    console.print()
    console.print("[bold]Restore Configuration[/bold]")
    console.print(f"  Source:       s3://{s3_config.bucket}/{dump_key}")
    console.print(f"  Database:     {db_name}")
    console.print(f"  Target:       {target_db}")
    console.print(f"  Size:         {format_bytes(dump_size)}")
    console.print(f"  Overwrite:    {'Yes' if overwrite else 'No'}")
    console.print(f"  Globals:      {'Yes' if restore_globals else 'No'}")

    # Show warning if target exists
    if target_exists:
        console.print()
        if overwrite:
            console.print("[bold yellow]⚠️  WARNING: Target database exists and will be REPLACED![/bold yellow]")
            if target_size_info:
                console.print(f"  Existing database size: {target_size_info.size_pretty}")
            if not skip_safety_backup:
                console.print("  A safety backup will be created before dropping.")
            else:
                console.print("[bold red]  ⚠️  Safety backup is DISABLED - data cannot be recovered![/bold red]")
        else:
            console.print(f"[bold red]ERROR: Database '{target_db}' already exists![/bold red]")
            console.print()
            console.print("Options:")
            console.print(f"  1. Use --overwrite --force to replace it (creates safety backup)")
            console.print(f"  2. Use --target to restore to a different database name")
            console.print(f"     Example: --target {target_db}_restored")
            raise typer.Exit(4)
    console.print()

    if not yes and not dry_run:
        if not console.confirm("Proceed with restore?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    # Create temp directory for download
    with tempfile.TemporaryDirectory(prefix="sm-restore-") as temp_dir:
        temp_path = Path(temp_dir)

        safety_backup_path = None
        try:
            # Check disk space (use 5x multiplier - compressed dumps expand significantly)
            required_space = dump_size * 5
            # Add extra space for safety backup if needed
            if target_exists and overwrite and not skip_safety_backup and target_size_info:
                required_space += target_size_info.size_bytes
            sufficient, available = check_disk_space(temp_path, required_space)
            if not sufficient:
                msg = (
                    f"Insufficient disk space: need {format_bytes(required_space)}, "
                    f"have {format_bytes(available)}"
                )
                raise PrerequisiteError(
                    msg,
                    hint="Free up disk space or use --skip-safety-backup (not recommended)",
                )

            # Download dump file
            local_dump = temp_path / dump_file
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

            # Download globals if requested
            local_globals = None
            if restore_globals and s3.object_exists(globals_key):
                local_globals = temp_path / "globals.sql"
                console.step("Downloading globals file...")
                s3.download_file(globals_key, local_globals)

            # Create safety backup before overwrite
            if target_exists and overwrite and not skip_safety_backup:
                from datetime import datetime as dt
                safety_backup_path = temp_path / f"safety_backup_{target_db}_{dt.now():%Y%m%d_%H%M%S}.dump"
                console.step(f"Creating safety backup of '{target_db}'...")
                console.print(f"  Safety backup: {safety_backup_path}")
                try:
                    pgdump.dump_database(target_db, safety_backup_path, compression_level=6, jobs=jobs)
                    console.success(f"Safety backup created: {format_bytes(safety_backup_path.stat().st_size)}")
                except BackupError as e:
                    console.error(f"Failed to create safety backup: {e}")
                    console.print()
                    console.print("[bold red]Cannot proceed without safety backup.[/bold red]")
                    console.print("Options:")
                    console.print("  1. Fix the issue and try again")
                    console.print("  2. Use --skip-safety-backup --force (DANGEROUS)")
                    raise typer.Exit(12) from None

            # Drop existing database if overwrite
            if overwrite and pgdump.database_exists(target_db):
                console.step(f"Dropping existing database '{target_db}'...")
                pgdump.drop_database(target_db, force=True)

            # Restore globals first (roles need to exist before database)
            if local_globals and local_globals.exists():
                console.step("Restoring global objects...")
                pgdump.restore_globals(local_globals)

            # Restore database
            console.step(f"Restoring database '{target_db}'...")
            pgdump.restore_database(
                local_dump,
                target_db,
                create=True,
                clean=False,
                jobs=jobs,
                no_owner=no_owner,
                owner=owner,
            )

            console.print()
            console.success(f"Database '{target_db}' restored successfully")

            # Log audit event
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
            # Show recovery instructions if we have a safety backup
            if safety_backup_path and safety_backup_path.exists():
                console.print()
                console.print("[bold yellow]Recovery Instructions:[/bold yellow]")
                console.print(f"  A safety backup exists at: {safety_backup_path}")
                console.print(f"  To restore it, run:")
                console.print(f"    pg_restore -h {app_config.postgres.host} -p {app_config.postgres.port} \\")
                console.print(f"      -U postgres -d postgres -C {safety_backup_path}")
                console.print()
                console.print("[bold]⚠️  The safety backup will be deleted when this command exits![/bold]")
                console.print("  Copy it to a safe location NOW if you need it.")
            raise typer.Exit(12) from None
        except Exception as e:
            audit.log_failure(
                AuditEventType.RESTORE_FROM_EXPORT,
                target_type="database",
                target_name=target_db,
                error=str(e),
            )
            console.error(f"Restore failed: {e}")
            # Show recovery instructions if we have a safety backup
            if safety_backup_path and safety_backup_path.exists():
                console.print()
                console.print("[bold yellow]Recovery Instructions:[/bold yellow]")
                console.print(f"  A safety backup exists at: {safety_backup_path}")
                console.print(f"  To restore it, run:")
                console.print(f"    pg_restore -h {app_config.postgres.host} -p {app_config.postgres.port} \\")
                console.print(f"      -U postgres -d postgres -C {safety_backup_path}")
                console.print()
                console.print("[bold]⚠️  The safety backup will be deleted when this command exits![/bold]")
                console.print("  Copy it to a safe location NOW if you need it.")
            raise typer.Exit(12) from None


@app.command("from-backup")
@require_root
@require_force("Cluster restore is a major operation that will stop PostgreSQL")
def restore_from_backup(
    target_time: str | None = typer.Option(
        None, "--target-time",
        help="PITR target timestamp (ISO format, e.g., 2024-01-15T10:30:00)",
    ),
    target_lsn: str | None = typer.Option(
        None, "--target-lsn",
        help="PITR target LSN",
    ),
    backup_label: str | None = typer.Option(
        None, "--backup",
        help="Specific backup label (default: latest)",
    ),
    delta: bool = typer.Option(
        False, "--delta",
        help="Use delta restore (faster for minor recovery)",
    ),
    generate_script: bool = typer.Option(
        False, "--generate-script",
        help="Generate restore script instead of executing",
    ),
    script_path: Path | None = typer.Option(
        None, "--script-output",
        help="Path for generated script (default: ./restore.sh)",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", "-f", help="Required for this operation"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Restore PostgreSQL cluster from pgBackRest backup.

    This restores the ENTIRE cluster using pgBackRest.
    Supports point-in-time recovery (PITR).

    WARNING: This stops PostgreSQL and replaces the data directory.

    Examples:

        # Restore to latest point
        sm postgres restore from-backup --force

        # Point-in-time recovery
        sm postgres restore from-backup --target-time "2024-01-15T10:30:00" --force

        # Generate script for manual execution
        sm postgres restore from-backup --generate-script --force
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    app_config = AppConfig()

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    pgbackrest = PgBackRestService(
        ctx, executor,
        pg_version=app_config.postgres.version,
    )

    # Check pgBackRest is configured
    if not pgbackrest.is_configured():
        raise ConfigurationError(
            "pgBackRest is not configured",
            hint="Run 'sm postgres setup' first to configure backups",
        )

    # Check stanza is valid
    if not pgbackrest.stanza_exists():
        raise BackupError(
            "pgBackRest stanza is not valid",
            hint="Check pgBackRest configuration with: pgbackrest --stanza=main check",
        )

    # Build recovery target
    recovery_target = None
    if target_time or target_lsn:
        recovery_target = RecoveryPoint()
        if target_time:
            try:
                recovery_target.timestamp = datetime.fromisoformat(target_time)
            except ValueError as e:
                console.error(f"Invalid timestamp format: {target_time}")
                console.print("  Expected ISO format: YYYY-MM-DDTHH:MM:SS")
                raise typer.Exit(3) from e
        if target_lsn:
            recovery_target.lsn = target_lsn

    # Get backup info
    backup_info = pgbackrest.get_backup_info(backup_label)
    if not backup_info:
        console.error("No backups available")
        raise typer.Exit(3)

    # Get recovery window
    recovery_window = pgbackrest.get_recovery_window()

    # Show configuration
    console.print()
    console.print("[bold]Restore Configuration[/bold]")
    console.print(f"  Backup:         {backup_info.label} ({backup_info.type_display})")
    console.print(f"  Backup Time:    {backup_info.stop_time}")
    console.print(f"  Database Size:  {format_backup_size(backup_info.database_size)}")
    if recovery_target and recovery_target.timestamp:
        console.print(f"  Recovery To:    {recovery_target.timestamp}")
    elif recovery_target and recovery_target.lsn:
        console.print(f"  Recovery LSN:   {recovery_target.lsn}")
    else:
        console.print("  Recovery To:    Latest available")
    if recovery_window:
        console.print(f"  Recovery Window: {recovery_window.earliest} to {recovery_window.latest}")
    console.print(f"  Delta Restore:  {'Yes' if delta else 'No'}")
    console.print()

    # Generate script mode
    if generate_script:
        output_path = script_path or Path("./restore.sh")
        pgbackrest.create_restore_script(output_path, recovery_target)
        console.success(f"Restore script generated: {output_path}")
        console.print()
        console.print("Review the script and run it manually:")
        console.print(f"  chmod +x {output_path}")
        console.print(f"  ./{output_path}")
        return

    # Final confirmation
    console.print(
        "[bold red]WARNING: This will stop PostgreSQL and "
        "replace the data directory![/bold red]"
    )
    console.print()

    if not yes and not dry_run:
        if not console.confirm("Are you absolutely sure you want to proceed?", default=False):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        # Stop PostgreSQL
        console.step("Stopping PostgreSQL...")
        systemd.stop("postgresql")

        # Perform restore
        console.step("Running pgBackRest restore...")
        pgbackrest.restore(
            recovery_target=recovery_target,
            delta=delta,
            force=True,
        )

        # Start PostgreSQL
        console.step("Starting PostgreSQL...")
        systemd.start("postgresql")

        # Verify
        console.step("Verifying cluster health...")
        pg = PostgreSQLService(ctx, executor)
        if pg.is_running():
            console.success("PostgreSQL is running")
        else:
            console.warn("PostgreSQL may not have started correctly")

        console.print()
        console.success("Cluster restore completed successfully")

        # Log audit event
        audit.log_success(
            AuditEventType.RESTORE_FROM_BACKUP,
            target_type="cluster",
            target_name="main",
            message=f"Restored from backup {backup_info.label}",
        )

    except BackupError as e:
        # Try to restart PostgreSQL
        console.warn("Restore failed, attempting to restart PostgreSQL...")
        try:
            systemd.start("postgresql")
        except Exception:
            pass

        audit.log_failure(
            AuditEventType.RESTORE_FROM_BACKUP,
            target_type="cluster",
            target_name="main",
            error=str(e),
        )
        console.error(str(e))
        raise typer.Exit(12) from None


@app.command("list-backups")
@require_root
def list_backups(
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """List available pgBackRest backups.

    Shows full, differential, and incremental backups with recovery windows.

    Example:

        sm postgres restore list-backups
    """
    ctx = create_context(verbose=verbose)
    app_config = AppConfig()

    # Get services
    executor = CommandExecutor(ctx)
    pgbackrest = PgBackRestService(
        ctx, executor,
        pg_version=app_config.postgres.version,
    )

    # Check pgBackRest is configured
    if not pgbackrest.is_configured():
        console.error("pgBackRest is not configured")
        console.print("  Run 'sm postgres setup' first to configure backups")
        raise typer.Exit(2)

    # Get backups
    backups = pgbackrest.list_backups()

    if not backups:
        console.warn("No backups available")
        raise typer.Exit(0)

    # Get recovery window
    recovery_window = pgbackrest.get_recovery_window()

    # Display table
    table = Table(title="Available pgBackRest Backups")
    table.add_column("Label", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Stop Time")
    table.add_column("Duration")
    table.add_column("DB Size")
    table.add_column("Repo Size")

    for backup in backups:
        duration = f"{backup.duration_seconds}s"
        if backup.duration_seconds > 60:
            duration = f"{backup.duration_seconds // 60}m {backup.duration_seconds % 60}s"

        table.add_row(
            backup.label,
            backup.type_display,
            backup.stop_time.strftime("%Y-%m-%d %H:%M:%S"),
            duration,
            format_backup_size(backup.database_size),
            format_backup_size(backup.repo_size),
        )

    console.print(table)

    # Show recovery window
    if recovery_window:
        console.print()
        console.print("[bold]Recovery Window[/bold]")
        console.print(f"  Earliest: {recovery_window.earliest}")
        console.print(f"  Latest:   {recovery_window.latest}")
        console.print(f"  Duration: {recovery_window.duration_days} days")
