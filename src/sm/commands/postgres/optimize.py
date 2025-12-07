"""PostgreSQL performance optimization command.

Analyzes system resources and provides workload-based tuning recommendations.

Commands:
- sm postgres optimize (preview recommendations)
- sm postgres optimize --apply (apply changes)
"""

from enum import Enum
from pathlib import Path

import typer
from rich import box
from rich.table import Table

from sm.core import (
    AuditEventType,
    CommandExecutor,
    PostgresError,
    console,
    create_context,
    get_audit_logger,
    require_root,
    run_preflight_checks,
)
from sm.services.postgresql import PostgreSQLService
from sm.services.systemd import SystemdService
from sm.services.tuning import (
    PostgresTuningService,
    SystemInfo,
    TuningRecommendation,
    WorkloadProfile,
)


class WorkloadChoice(str, Enum):
    """CLI workload choices."""

    OLTP = "oltp"
    OLAP = "olap"
    MIXED = "mixed"


app = typer.Typer(
    name="optimize",
    help="PostgreSQL performance optimization.",
    no_args_is_help=False,  # Allow running without args
)


def _display_system_info(system_info: SystemInfo, profile: WorkloadProfile) -> None:
    """Display detected system information."""
    console.print()
    console.print("[bold]System Detection[/bold]")
    console.print(f"  RAM:           {system_info.memory_mb} MB")
    console.print(f"  CPU Cores:     {system_info.cpu_count}")
    console.print(f"  Disk Type:     {system_info.disk_type.upper()} (detected)")
    console.print(f"  PostgreSQL:    {system_info.pg_version}")
    console.print()
    console.print(f"[bold]Workload Profile:[/bold] {profile.value.upper()}")
    console.print(f"  {profile.description}")


def _display_recommendations(recommendation: TuningRecommendation) -> None:
    """Display recommendation comparison table."""
    console.print()

    table = Table(
        title="Tuning Recommendations",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
    )
    table.add_column("Parameter", style="cyan", no_wrap=True)
    table.add_column("Current", style="yellow")
    table.add_column("Recommended", style="green")
    table.add_column("Reasoning", style="dim")
    table.add_column("", width=1, justify="center")  # Restart indicator

    for param in recommendation.parameters:
        restart_marker = "*" if param.requires_restart else ""
        style = "bold" if param.changed else "dim"

        table.add_row(
            param.name,
            param.current_value or "(not set)",
            param.recommended_value,
            param.reason,
            restart_marker,
            style=style,
        )

    console.print(table)

    if recommendation.has_restart_required:
        console.print()
        console.print("[dim]* = Requires PostgreSQL restart to take effect[/dim]")

    changed_count = len(recommendation.changed_parameters)
    if changed_count > 0:
        console.print()
        console.info(f"{changed_count} parameter(s) will be changed.")
    else:
        console.print()
        console.success("All parameters are already optimal!")


def _run_safety_checks(
    ctx,
    executor: CommandExecutor,
    pg_service: PostgreSQLService,
    recommendation: TuningRecommendation,
) -> list[str]:
    """Run safety checks before applying changes.

    Returns:
        List of warning messages (empty if all checks pass)
    """
    warnings: list[str] = []

    if ctx.dry_run:
        return warnings

    # Check 1: Active connections vs proposed max_connections
    max_conn_param = next(
        (p for p in recommendation.changed_parameters if p.name == "max_connections"),
        None,
    )
    if max_conn_param:
        try:
            result = executor.run_sql(
                "SELECT count(*) FROM pg_stat_activity WHERE state IS NOT NULL",
                as_user="postgres",
                check=False,
            )
            active_connections = int(result.strip()) if result.strip() else 0
            proposed_max = int(max_conn_param.recommended_value)

            if active_connections > proposed_max - 5:  # Leave 5 for superuser
                warnings.append(
                    f"Active connections ({active_connections}) close to or exceeds "
                    f"proposed max_connections ({proposed_max}). "
                    "Consider keeping higher max_connections or reducing connections first."
                )
        except (ValueError, TypeError):
            pass

    # Check 2: Shared buffers safety (shouldn't exceed 40% of RAM)
    shared_param = next(
        (p for p in recommendation.changed_parameters if p.name == "shared_buffers"),
        None,
    )
    if shared_param:
        total_ram = recommendation.system_info.memory_mb
        try:
            # Parse value like "8192MB"
            value = shared_param.recommended_value.upper()
            if value.endswith("MB"):
                shared_mb = int(value[:-2])
            elif value.endswith("GB"):
                shared_mb = int(value[:-2]) * 1024
            else:
                shared_mb = int(value)

            if shared_mb > total_ram * 0.5:
                warnings.append(
                    f"shared_buffers ({shared_mb}MB) exceeds 50% of RAM ({total_ram}MB). "
                    "This may cause memory pressure. Consider a lower value."
                )
        except ValueError:
            pass

    # Check 3: pgBackRest/backup compatibility
    try:
        result = executor.run_sql(
            "SHOW archive_mode",
            as_user="postgres",
            check=False,
        )
        archive_mode = result.strip().lower() if result else ""
        if archive_mode == "on":
            # Backups are configured - inform user
            console.info("Note: WAL archiving (pgBackRest) is enabled. "
                        "Tuning changes will NOT affect backup configuration.")
    except Exception:
        pass

    return warnings


def _apply_changes(
    ctx,
    executor: CommandExecutor,
    systemd: SystemdService,
    pg_version: str,
    recommendation: TuningRecommendation,
    tuning: PostgresTuningService,
    audit,
) -> None:
    """Apply recommended changes with backup."""
    config_path = Path(f"/etc/postgresql/{pg_version}/main/conf.d/99-tuning.conf")

    # Ensure conf.d directory exists
    conf_d = config_path.parent
    if not ctx.dry_run and not conf_d.exists():
        console.step(f"Creating directory: {conf_d}")
        conf_d.mkdir(parents=True, exist_ok=True)

    # Backup existing config
    console.step("Backing up current configuration...")
    backup_path = executor.backup_file(config_path)

    if backup_path:
        console.success(f"Backup created: {backup_path}")
        console.print(f"  [dim]To restore: cp {backup_path} {config_path}[/dim]")
    elif config_path.exists():
        console.warn("Could not create backup - proceeding anyway")

    # Generate and write new config
    console.step("Writing optimized configuration...")
    config_content = tuning.generate_config(recommendation)

    executor.write_file(
        config_path,
        config_content,
        description="Write optimized PostgreSQL config",
        owner="postgres",
        group="postgres",
        permissions=0o640,
    )

    console.success(f"Configuration written to: {config_path}")

    # Log audit
    audit.log_success(
        AuditEventType.CONFIG_MODIFY,
        "postgresql",
        f"postgresql-{pg_version}",
        message=f"Applied {recommendation.workload_profile.value.upper()} tuning profile "
        f"({len(recommendation.changed_parameters)} parameters changed)",
    )

    # Reload/restart decision
    console.print()
    if recommendation.has_restart_required:
        console.warn("Some changes require a PostgreSQL restart to take effect:")
        for param in recommendation.changed_parameters:
            if param.requires_restart:
                console.print(f"  - {param.name}")
        console.print()

        if ctx.yes or console.confirm("Restart PostgreSQL now?", default=False):
            console.step(f"Restarting PostgreSQL {pg_version}...")
            systemd.restart(f"postgresql@{pg_version}-main.service")
            console.success("PostgreSQL restarted")
        else:
            console.info(f"Restart later with: sudo systemctl restart postgresql@{pg_version}-main")
    else:
        if ctx.yes or console.confirm("Reload PostgreSQL now?", default=True):
            console.step(f"Reloading PostgreSQL {pg_version}...")
            systemd.reload(f"postgresql@{pg_version}-main.service")
            console.success("PostgreSQL configuration reloaded")

    # Final summary
    console.print()
    console.summary(
        "Optimization Complete",
        {
            "Workload Profile": recommendation.workload_profile.value.upper(),
            "Parameters Changed": len(recommendation.changed_parameters),
            "Config File": str(config_path),
            "Backup File": str(backup_path) if backup_path else "N/A",
        },
    )


@app.callback(invoke_without_command=True)
@require_root
def optimize(
    workload: WorkloadChoice = typer.Option(
        WorkloadChoice.MIXED,
        "--workload", "-w",
        help="Workload profile: oltp (web apps), olap (analytics), mixed (balanced)",
        case_sensitive=False,
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Apply the recommended changes (default: preview only)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview changes without executing",
    ),
    yes: bool = typer.Option(
        False,
        "--yes", "-y",
        help="Skip confirmation prompts",
    ),
    verbose: int = typer.Option(
        0,
        "--verbose", "-v",
        count=True,
        help="Increase verbosity",
    ),
) -> None:
    """Analyze and optimize PostgreSQL configuration.

    Detects system resources (CPU, RAM, disk type) and generates
    tuning recommendations based on the selected workload profile.

    Workload Profiles:

    - OLTP: High concurrency, fast transactions (web applications, APIs)
    - OLAP: Complex queries, large datasets (analytics, reporting)
    - MIXED: Balanced workload (general purpose, default)

    Examples:

        # Preview recommendations (default)
        sm postgres optimize

        # Preview with OLTP profile
        sm postgres optimize --workload oltp

        # Apply OLTP-optimized settings
        sm postgres optimize --workload oltp --apply

        # Dry-run (preview without any changes)
        sm postgres optimize --dry-run

    The command will:
    1. Detect system resources (RAM, CPU, disk type)
    2. Read current PostgreSQL configuration
    3. Calculate optimal settings for the workload
    4. Show comparison table with reasoning
    5. Apply changes (if --apply) with automatic backup

    Safety Considerations:

    - Backup: A backup is automatically created before applying changes
    - Connections: Warns if reducing max_connections below active connections
    - Memory: Warns if shared_buffers exceeds 50% of available RAM
    - Backups: Tuning changes do NOT affect pgBackRest/WAL archiving config
    - Restart: Some parameters require PostgreSQL restart; command prompts
    - Reload: Runtime parameters are applied via pg_reload without downtime

    For production systems, consider:

    - Apply during low-traffic periods
    - Monitor performance after changes
    - Use --dry-run first to preview changes
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
    audit = get_audit_logger()

    # Preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Initialize services
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    pg_service = PostgreSQLService(ctx, executor)
    tuning = PostgresTuningService(ctx, executor)

    # Detect PostgreSQL version
    console.step("Detecting PostgreSQL installation...")
    pg_version = pg_service.detect_version()
    if not pg_version:
        console.error("PostgreSQL is not installed")
        console.hint("Run: sm postgres setup")
        raise typer.Exit(1)

    console.verbose(f"Found PostgreSQL {pg_version}")

    # Check if PostgreSQL is running (needed to read current config)
    if not pg_service.is_running():
        console.error("PostgreSQL is not running")
        console.hint(f"Start with: sudo systemctl start postgresql@{pg_version}-main")
        raise typer.Exit(1)

    # Detect system info
    console.step("Detecting system resources...")
    system_info = tuning.detect_system_info(pg_version)

    # Read current config
    console.step("Reading current PostgreSQL configuration...")
    current_config = tuning.read_current_config(pg_version)

    # Calculate recommendations
    console.step("Calculating recommendations...")
    profile = WorkloadProfile(workload.value)
    recommendation = tuning.calculate_recommendations(
        system_info, profile, current_config
    )

    # Display system info and recommendations
    _display_system_info(system_info, profile)
    _display_recommendations(recommendation)

    # If not applying, just preview
    if not apply:
        console.print()
        console.info("Preview only. Use --apply to make changes.")
        console.hint(f"sm postgres optimize --workload {workload.value} --apply")
        return

    # Check if changes needed
    if not recommendation.changed_parameters:
        console.print()
        console.success("Configuration is already optimal! No changes needed.")
        return

    # Run safety checks
    console.print()
    console.step("Running safety checks...")
    safety_warnings = _run_safety_checks(ctx, executor, pg_service, recommendation)

    if safety_warnings:
        console.print()
        console.warn("Safety check warnings:")
        for warning in safety_warnings:
            console.print(f"  [yellow]![/yellow] {warning}")
        console.print()

    # Confirm
    if not yes and not dry_run:
        console.print()
        confirm_msg = f"Apply {len(recommendation.changed_parameters)} changes?"
        if safety_warnings:
            confirm_msg += " (warnings above)"
        if not console.confirm(confirm_msg, default=False):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    # Apply changes
    try:
        _apply_changes(
            ctx, executor, systemd, pg_version,
            recommendation, tuning, audit
        )
    except PostgresError as e:
        audit.log_failure(
            AuditEventType.CONFIG_MODIFY,
            "postgresql",
            f"postgresql-{pg_version}",
            error=str(e),
        )
        console.error(str(e))
        raise typer.Exit(10) from None
