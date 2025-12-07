"""PostgreSQL performance optimization command.

Analyzes system resources and provides workload-based tuning recommendations.
Now includes unified PgBouncer optimization for coordinated connection settings.

Commands:
- sm postgres optimize (preview recommendations)
- sm postgres optimize --apply (apply changes)
- sm postgres optimize --expected-connections 200 (specify expected connections)
"""

from enum import Enum
from pathlib import Path

import typer
from rich import box
from rich.panel import Panel
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
from sm.services.pgbouncer import PgBouncerService
from sm.services.postgresql import PostgreSQLService
from sm.services.systemd import SystemdService
from sm.services.tuning import (
    ConnectionStackRecommendation,
    PgBouncerParameter,
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


def _display_pgbouncer_recommendations(
    params: list[PgBouncerParameter],
) -> None:
    """Display PgBouncer recommendation comparison table."""
    console.print()

    table = Table(
        title="PgBouncer Tuning Recommendations",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
    )
    table.add_column("Parameter", style="cyan", no_wrap=True)
    table.add_column("Current", style="yellow")
    table.add_column("Recommended", style="green")
    table.add_column("Reasoning", style="dim")

    for param in params:
        style = "bold" if param.changed else "dim"
        table.add_row(
            param.name,
            param.current_value or "(not set)",
            param.recommended_value,
            param.reason,
            style=style,
        )

    console.print(table)

    changed_count = len([p for p in params if p.changed])
    if changed_count > 0:
        console.print()
        console.print("[dim]All PgBouncer changes require reload (no downtime)[/dim]")
        console.info(f"{changed_count} PgBouncer parameter(s) will be changed.")
    else:
        console.print()
        console.success("PgBouncer parameters are already optimal!")


def _display_connection_stack(
    stack: ConnectionStackRecommendation,
    current_pg_max: int | None = None,
    current_pgb_pool: int | None = None,
    current_pgb_max_client: int | None = None,
) -> None:
    """Display connection stack visualization."""
    console.print()

    # Build the visualization
    lines = []

    # Expected connections
    if stack.expected_connections:
        lines.append(f"  [bold]Expected App Connections:[/bold] {stack.expected_connections}")
    else:
        lines.append(f"  [bold]Max Client Connections:[/bold] {stack.pgb_max_client_conn}")

    lines.append("")

    # PgBouncer section
    lines.append("  [bold cyan]PgBouncer (Connection Pooler)[/bold cyan]")

    # Show changes for pool_size
    if current_pgb_pool and current_pgb_pool != stack.pgb_default_pool_size:
        diff = stack.pgb_default_pool_size - current_pgb_pool
        sign = "+" if diff > 0 else ""
        lines.append(
            f"    default_pool_size: {current_pgb_pool} "
            f"[green]→ {stack.pgb_default_pool_size}[/green] "
            f"({sign}{diff}, to PostgreSQL)"
        )
    else:
        lines.append(
            f"    default_pool_size: {stack.pgb_default_pool_size} (to PostgreSQL)"
        )

    # Show changes for max_client_conn
    if current_pgb_max_client and current_pgb_max_client != stack.pgb_max_client_conn:
        diff = stack.pgb_max_client_conn - current_pgb_max_client
        sign = "+" if diff > 0 else ""
        lines.append(
            f"    max_client_conn:   {current_pgb_max_client} "
            f"[green]→ {stack.pgb_max_client_conn}[/green] "
            f"({sign}{diff}, from apps)"
        )
    else:
        lines.append(
            f"    max_client_conn:   {stack.pgb_max_client_conn} (from apps)"
        )

    lines.append(f"    min_pool_size:     {stack.pgb_min_pool_size} (kept ready)")
    lines.append(f"    reserve_pool_size: {stack.pgb_reserve_pool_size} (emergency overflow)")

    # Contention ratio
    if stack.expected_connections:
        old_ratio = stack.expected_connections / (current_pgb_pool or 20)
        new_ratio = stack.contention_ratio
        if old_ratio > 5 and new_ratio < 5:
            lines.append(
                f"    [green]Contention: {old_ratio:.1f}:1 → {new_ratio:.1f}:1 ✓[/green]"
            )
        else:
            lines.append(f"    Contention ratio: {new_ratio:.1f}:1")

    lines.append("")

    # PostgreSQL section
    lines.append("  [bold cyan]PostgreSQL[/bold cyan]")

    if current_pg_max and current_pg_max != stack.pg_max_connections:
        diff = stack.pg_max_connections - current_pg_max
        sign = "+" if diff > 0 else ""
        lines.append(
            f"    max_connections:   {current_pg_max} [green]→ {stack.pg_max_connections}[/green] "
            f"({sign}{diff}, capacity for pool)"
        )
    else:
        lines.append(f"    max_connections:   {stack.pg_max_connections} (capacity for pool)")

    lines.append(
        f"    superuser_reserved: {stack.pg_superuser_reserved} (for admin)"
    )
    lines.append(f"    available_for_pool: {stack.effective_pg_connections}")
    lines.append(
        f"    Pool utilization:   {stack.utilization_ratio:.0%} of PostgreSQL"
    )

    # Add explanatory note when expected_connections is set
    if stack.expected_connections:
        lines.append("")
        lines.append(
            f"  [dim]Note: {stack.expected_connections} app connections multiplexed "
            f"through {stack.pgb_default_pool_size} server connections.[/dim]"
        )
        lines.append(
            "  [dim]PgBouncer handles the multiplexing, so PostgreSQL doesn't need[/dim]"
        )
        lines.append(
            f"  [dim]{stack.expected_connections} max_connections.[/dim]"
        )

    content = "\n".join(lines)

    panel = Panel(
        content,
        title="Connection Stack Analysis",
        border_style="blue",
        padding=(1, 2),
    )
    console.print(panel)


def _check_existing_tuning_files(pg_version: str) -> list[Path]:
    """Check for existing tuning configuration files that might conflict.

    Returns:
        List of conflicting config file paths
    """
    conf_d = Path(f"/etc/postgresql/{pg_version}/main/conf.d")
    if not conf_d.exists():
        return []

    # Our file that we'll create/update
    our_file = conf_d / "99-tuning.conf"

    # Look for other tuning-related files that might conflict
    patterns = ["*tuning*", "*custom*", "*performance*", "*optimize*"]
    conflicting: list[Path] = []

    for pattern in patterns:
        for path in conf_d.glob(pattern):
            # Skip our own file
            if path != our_file and path.is_file():
                conflicting.append(path)

    return conflicting


def _display_changes_summary(
    pg_changed: list,
    pgb_changed: list,
    pg_version: str,
    has_restart_required: bool,
    backup_will_be_created: bool = True,
) -> None:
    """Display a summary of all changes before confirmation.

    This gives the user a clear picture of what will happen if they proceed.
    """
    console.print()

    lines = []

    # PostgreSQL section
    if pg_changed:
        lines.append("[bold cyan]PostgreSQL:[/bold cyan]")
        lines.append(f"  • {len(pg_changed)} parameter(s) will be changed")
        lines.append(f"  • Config: /etc/postgresql/{pg_version}/main/conf.d/99-tuning.conf")
        if backup_will_be_created:
            lines.append("  • Backup will be created automatically")

        if has_restart_required:
            restart_params = [p.name for p in pg_changed if p.requires_restart]
            restart_list = ", ".join(restart_params)
            lines.append(f"  • [bold red]⚠️ RESTART REQUIRED[/bold red] ({restart_list})")
            lines.append("  • [dim]Active connections will be terminated[/dim]")
        else:
            lines.append("  • [green]Reload only (no downtime)[/green]")

    # PgBouncer section
    if pgb_changed:
        if pg_changed:
            lines.append("")
        lines.append("[bold cyan]PgBouncer:[/bold cyan]")
        lines.append(f"  • {len(pgb_changed)} parameter(s) will be changed")
        lines.append("  • Config: /etc/pgbouncer/pgbouncer.ini")
        lines.append("  • Backup will be created automatically")
        lines.append("  • [green]Reload only (no downtime)[/green]")

    content = "\n".join(lines)

    panel = Panel(
        content,
        title="Changes Summary",
        border_style="yellow",
        padding=(1, 2),
    )
    console.print(panel)


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
        console.print()
        console.print("[bold red]⚠️  DOWNTIME WARNING[/bold red]")
        console.print()
        console.print("The following changes require a PostgreSQL [bold]restart[/bold]:")
        for param in recommendation.changed_parameters:
            if param.requires_restart:
                current = param.current_value or "(not set)"
                recommended = param.recommended_value
                console.print(f"  • {param.name}: {current} → [green]{recommended}[/green]")
        console.print()
        console.print("[bold]All active database connections will be terminated.[/bold]")
        console.print(
            "[dim]Typical restart time: 5-30 seconds depending on shared_buffers size.[/dim]"
        )
        console.print()

        if ctx.yes:
            console.warn("Auto-restarting PostgreSQL (--yes flag was used)")

        if ctx.yes or console.confirm("Restart PostgreSQL now?", default=False):
            console.step(f"Restarting PostgreSQL {pg_version}...")
            systemd.restart(f"postgresql@{pg_version}-main.service")
            console.success("PostgreSQL restarted successfully")
        else:
            console.print()
            console.info("Changes written but [bold]not yet active[/bold].")
            console.print("  To apply later, run:")
            console.print(f"    [cyan]sudo systemctl restart postgresql@{pg_version}-main[/cyan]")
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
    skip_pgbouncer: bool = typer.Option(
        False,
        "--skip-pgbouncer",
        help="Skip PgBouncer optimization (PostgreSQL only)",
    ),
    expected_connections: int | None = typer.Option(
        None,
        "--expected-connections", "-c",
        help="Expected app connections (e.g., 20 containers x 10 = 200)",
    ),
) -> None:
    """Analyze and optimize PostgreSQL + PgBouncer configuration.

    Detects system resources (CPU, RAM, disk type) and generates
    tuning recommendations based on the selected workload profile.
    If PgBouncer is installed, also optimizes connection pooling settings.

    Workload Profiles:

    - OLTP: High concurrency, fast transactions (web applications, APIs)
    - OLAP: Complex queries, large datasets (analytics, reporting)
    - MIXED: Balanced workload (general purpose, default)

    Examples:

        # Preview recommendations (default)
        sm postgres optimize

        # Preview with OLTP profile
        sm postgres optimize --workload oltp

        # Specify expected app connections for better pool sizing
        sm postgres optimize --workload oltp --expected-connections 200

        # Apply OLTP-optimized settings
        sm postgres optimize --workload oltp --apply

        # Skip PgBouncer optimization (PostgreSQL only)
        sm postgres optimize --skip-pgbouncer --apply

        # Dry-run (preview without any changes)
        sm postgres optimize --dry-run

    The command will:
    1. Detect system resources (RAM, CPU, disk type)
    2. Read current PostgreSQL configuration
    3. Read current PgBouncer configuration (if installed)
    4. Calculate optimal settings for the workload
    5. Calculate coordinated connection pool settings
    6. Show connection stack visualization
    7. Show comparison tables with reasoning
    8. Apply changes (if --apply) with automatic backup

    Connection Stack Optimization:

    The --expected-connections flag helps size the connection pool correctly.
    For example, if you have 20 app containers with 10 connections each:

        sm postgres optimize --expected-connections 200 --apply

    This ensures PgBouncer's pool size is coordinated with PostgreSQL's
    max_connections to eliminate connection bottlenecks.

    Safety Considerations:

    - Backup: Backups are created for both PostgreSQL and PgBouncer configs
    - Connections: Warns if reducing max_connections below active connections
    - Memory: Warns if shared_buffers exceeds 50% of available RAM
    - Backups: Tuning changes do NOT affect pgBackRest/WAL archiving config
    - Restart: PostgreSQL restart may be needed; PgBouncer only needs reload
    - Reload: Runtime parameters are applied without downtime

    For production systems, consider:

    - Apply during low-traffic periods
    - Monitor performance after changes
    - Use --dry-run first to preview changes
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
    audit = get_audit_logger()

    # Preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Validate input parameters
    if expected_connections is not None:
        if expected_connections < 1:
            console.error("--expected-connections must be a positive number")
            raise typer.Exit(1)
        if expected_connections > 10000:
            console.warn(
                f"Very high expected connections ({expected_connections}). "
                "This may result in aggressive pool sizing."
            )
            if not yes and not console.confirm("Continue anyway?", default=False):
                raise typer.Exit(0)

    # Initialize services
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    pg_service = PostgreSQLService(ctx, executor)
    tuning = PostgresTuningService(ctx, executor)
    pgb_service = PgBouncerService(ctx, executor, systemd)

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

    # Check for existing tuning files that might conflict
    conflicting_files = _check_existing_tuning_files(pg_version)
    if conflicting_files:
        console.print()
        console.warn("Existing tuning configuration files detected:")
        for f in conflicting_files:
            console.print(f"  • {f}")
        console.print()
        console.print("[dim]These files may override or conflict with the new settings.[/dim]")
        console.print("[dim]PostgreSQL loads conf.d files in alphabetical order.[/dim]")
        console.print("Our settings will be written to: [cyan]99-tuning.conf[/cyan] (loaded last)")
        console.print()

    # Detect system info
    console.step("Detecting system resources...")
    system_info = tuning.detect_system_info(pg_version)

    # Read current config
    console.step("Reading current PostgreSQL configuration...")
    current_config = tuning.read_current_config(pg_version)

    # Check if PgBouncer is available
    pgb_installed = pgb_service.is_installed() and not skip_pgbouncer
    pgb_current_config: dict[str, str] = {}
    pgb_recommendations: list[PgBouncerParameter] = []
    connection_stack: ConnectionStackRecommendation | None = None

    if pgb_installed:
        console.step("Reading current PgBouncer configuration...")
        pgb_current_config = pgb_service.read_current_config()
        if pgb_current_config:
            pool_size = pgb_current_config.get("default_pool_size", "unknown")
            console.verbose(f"Found PgBouncer with pool_size={pool_size}")
    elif not skip_pgbouncer:
        console.info("PgBouncer not installed, skipping pool optimization")

    # Calculate recommendations
    console.step("Calculating recommendations...")
    profile = WorkloadProfile(workload.value)
    recommendation = tuning.calculate_recommendations(
        system_info, profile, current_config
    )

    # Calculate connection stack if PgBouncer is available
    if pgb_installed:
        console.step("Calculating connection stack optimization...")
        connection_stack = tuning.calculate_connection_stack(
            system_info.memory_mb,
            profile,
            expected_connections,
        )

        # Get the recommended max_connections value from PostgreSQL recommendations
        pg_max_conn_param = next(
            (p for p in recommendation.parameters if p.name == "max_connections"),
            None,
        )
        pg_max_conn = int(pg_max_conn_param.recommended_value) if pg_max_conn_param else 100

        # Calculate PgBouncer recommendations
        pgb_recommendations = pgb_service.calculate_pool_recommendations(
            pg_max_conn,
            profile,
            pgb_current_config,
            expected_connections,
        )

    # Display system info and recommendations
    _display_system_info(system_info, profile)

    # Display connection stack visualization if PgBouncer is available
    if connection_stack and pgb_installed:
        current_pg_max = int(current_config.get("max_connections", 100))
        current_pgb_pool = None
        current_pgb_max_client = None
        if pgb_current_config:
            current_pgb_pool = int(pgb_current_config.get("default_pool_size", 20))
            current_pgb_max_client = int(
                pgb_current_config.get("max_client_conn", 1000)
            )

        _display_connection_stack(
            connection_stack,
            current_pg_max=current_pg_max,
            current_pgb_pool=current_pgb_pool,
            current_pgb_max_client=current_pgb_max_client,
        )

    _display_recommendations(recommendation)

    # Display PgBouncer recommendations if available
    if pgb_recommendations:
        _display_pgbouncer_recommendations(pgb_recommendations)

    # Calculate total changes
    pg_changed = recommendation.changed_parameters
    pgb_changed = [p for p in pgb_recommendations if p.changed]
    total_changes = len(pg_changed) + len(pgb_changed)

    # If not applying, just preview
    if not apply:
        console.print()
        console.info("Preview only. Use --apply to make changes.")
        hint_cmd = f"sm postgres optimize --workload {workload.value}"
        if expected_connections:
            hint_cmd += f" --expected-connections {expected_connections}"
        hint_cmd += " --apply"
        console.hint(hint_cmd)
        return

    # Check if changes needed
    if total_changes == 0:
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

    # Display summary before confirmation
    _display_changes_summary(
        pg_changed,
        pgb_changed,
        pg_version,
        has_restart_required=recommendation.has_restart_required,
    )

    # Confirm
    if not yes and not dry_run:
        console.print()
        confirm_parts = []
        if pg_changed:
            confirm_parts.append(f"{len(pg_changed)} PostgreSQL")
        if pgb_changed:
            confirm_parts.append(f"{len(pgb_changed)} PgBouncer")
        confirm_msg = f"Apply {' + '.join(confirm_parts)} changes?"
        if safety_warnings:
            confirm_msg += " (warnings above)"
        if not console.confirm(confirm_msg, default=False):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    # Apply PostgreSQL changes
    pg_config_path = f"/etc/postgresql/{pg_version}/main/conf.d/99-tuning.conf"

    if pg_changed:
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
            console.print()
            console.print("[bold]To rollback PostgreSQL changes:[/bold]")
            console.print("  1. Remove the config file:")
            console.print(f"     [cyan]sudo rm {pg_config_path}[/cyan]")
            console.print("  2. Or restore from backup (check /var/backups/sm/)")
            console.print("  3. Reload PostgreSQL:")
            console.print(f"     [cyan]sudo systemctl reload postgresql@{pg_version}-main[/cyan]")
            raise typer.Exit(10) from None

    # Apply PgBouncer changes
    if pgb_changed and pgb_installed:
        try:
            pgb_service.apply_optimized_config(pgb_recommendations)
            audit.log_success(
                AuditEventType.CONFIG_MODIFY,
                "pgbouncer",
                "pgbouncer",
                message=f"Applied {len(pgb_changed)} PgBouncer tuning parameters",
            )
        except Exception as e:
            audit.log_failure(
                AuditEventType.CONFIG_MODIFY,
                "pgbouncer",
                "pgbouncer",
                error=str(e),
            )
            console.error(f"Failed to apply PgBouncer changes: {e}")
            console.print()
            console.print("[bold]To rollback PgBouncer changes:[/bold]")
            console.print("  1. Restore from backup (check /var/backups/sm/):")
            console.print(
                "     [cyan]sudo cp /var/backups/sm/pgbouncer.ini.* "
                "/etc/pgbouncer/pgbouncer.ini[/cyan]"
            )
            console.print("  2. Reload PgBouncer:")
            console.print("     [cyan]sudo systemctl reload pgbouncer[/cyan]")
            raise typer.Exit(11) from None

    # Final summary
    if pg_changed or pgb_changed:
        console.print()
        summary_data = {
            "Workload Profile": profile.value.upper(),
        }
        if pg_changed:
            summary_data["PostgreSQL Changes"] = len(pg_changed)
        if pgb_changed:
            summary_data["PgBouncer Changes"] = len(pgb_changed)
        if expected_connections:
            summary_data["Expected Connections"] = expected_connections
        if connection_stack:
            summary_data["Contention Ratio"] = f"{connection_stack.contention_ratio:.1f}:1"

        console.summary("Optimization Complete", summary_data)
