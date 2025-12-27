"""PostgreSQL pgBackRest commands for continuous backup management.

Commands:
- sm postgres backrest list       # List available backups
- sm postgres backrest restore    # Restore from pgBackRest backup
- sm postgres backrest info       # Show backup status and info
"""

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
    console,
    create_context,
    get_audit_logger,
    require_force,
    require_root,
    run_preflight_checks,
)
from sm.services.pgbackrest import (
    PgBackRestService,
    RecoveryPoint,
    format_backup_size,
)
from sm.services.postgresql import PostgreSQLService
from sm.services.systemd import SystemdService

app = typer.Typer(
    name="backrest",
    help="PostgreSQL pgBackRest operations (continuous backup management).",
    no_args_is_help=True,
)


@app.command("list")
@require_root
def list_backups(
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """List available pgBackRest backups.

    Shows full, differential, and incremental backups with recovery windows.

    Example:

        sm postgres backrest list
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


@app.command("restore")
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
        sm postgres backrest restore --force

        # Point-in-time recovery
        sm postgres backrest restore --target-time "2024-01-15T10:30:00" --force

        # Generate script for manual execution
        sm postgres backrest restore --generate-script --force
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


@app.command("info")
@require_root
def backup_info(
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Show pgBackRest backup status and configuration info.

    Displays the current backup configuration, stanza status,
    and repository information.

    Example:

        sm postgres backrest info
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

    # Get stanza status
    stanza_ok = pgbackrest.stanza_exists()

    # Get backup summary
    backups = pgbackrest.list_backups()
    recovery_window = pgbackrest.get_recovery_window()

    # Display info
    console.print()
    console.print("[bold]pgBackRest Configuration[/bold]")
    console.print("  Stanza:     main")
    console.print(f"  Status:     {'[green]OK[/green]' if stanza_ok else '[red]NOT VALID[/red]'}")
    console.print(f"  PG Version: {app_config.postgres.version}")
    console.print()

    if not stanza_ok:
        console.warn("Stanza is not valid. Run: pgbackrest --stanza=main stanza-check")
        raise typer.Exit(2)

    # Backup summary
    console.print("[bold]Backup Summary[/bold]")
    if backups:
        full_count = sum(1 for b in backups if b.backup_type == "full")
        diff_count = sum(1 for b in backups if b.backup_type == "diff")
        incr_count = sum(1 for b in backups if b.backup_type == "incr")
        total_repo_size = sum(b.repo_size for b in backups)

        console.print(f"  Total Backups:  {len(backups)}")
        console.print(f"    Full:         {full_count}")
        console.print(f"    Differential: {diff_count}")
        console.print(f"    Incremental:  {incr_count}")
        console.print(f"  Repo Size:      {format_backup_size(total_repo_size)}")

        if backups:
            latest = backups[0]  # Assuming sorted newest first
            console.print(f"  Latest Backup:  {latest.label}")
            console.print(f"    Type:         {latest.type_display}")
            console.print(f"    Time:         {latest.stop_time}")
    else:
        console.print("  No backups available")
    console.print()

    # Recovery window
    if recovery_window:
        console.print("[bold]Recovery Window[/bold]")
        console.print(f"  Earliest:  {recovery_window.earliest}")
        console.print(f"  Latest:    {recovery_window.latest}")
        console.print(f"  Duration:  {recovery_window.duration_days} days")
        console.print()

    # Hint for next steps
    if not backups:
        console.print("[dim]Hint: Wait for the scheduled backup or run manually:[/dim]")
        console.print("[dim]  pgbackrest --stanza=main backup --type=full[/dim]")
