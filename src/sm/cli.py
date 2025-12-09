"""Main CLI entry point using Typer.

This module defines the root CLI application and global options.
Command groups are registered from submodules.
"""

from pathlib import Path
from typing import Optional, Annotated

import typer
from rich.console import Console

from sm import __version__
from sm.core.context import ExecutionContext, create_context
from sm.core.output import console as app_console
from sm.core.config import (
    DEFAULT_CONFIG_PATH,
    AppConfig,
    get_example_config,
    init_config,
)
from sm.core.exceptions import SMError


# Create the main Typer app
app = typer.Typer(
    name="sm",
    help="Server Management CLI - Secure server administration tool.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
)

# Create command group apps
postgres_app = typer.Typer(
    name="postgres",
    help="PostgreSQL management commands.",
    no_args_is_help=True,
)

security_app = typer.Typer(
    name="security",
    help="Security hardening commands.",
    no_args_is_help=True,
)

observability_app = typer.Typer(
    name="observability",
    help="Observability and monitoring setup.",
    no_args_is_help=True,
)

config_app = typer.Typer(
    name="config",
    help="Configuration management.",
    no_args_is_help=True,
)

docker_app = typer.Typer(
    name="docker",
    help="Docker management and fixes.",
    no_args_is_help=True,
)

mongodb_app = typer.Typer(
    name="mongodb",
    help="MongoDB management commands.",
    no_args_is_help=True,
)

# Import sub-commands
from sm.commands.postgres.user import app as postgres_user_app
from sm.commands.postgres.db import app as postgres_db_app
from sm.commands.postgres.optimize import app as postgres_optimize_app
from sm.commands.postgres.backup import app as postgres_backup_app
from sm.commands.postgres.restore import app as postgres_restore_app
from sm.commands.postgres.migrate import app as postgres_migrate_app
from sm.commands.postgres.extension import app as postgres_extension_app
from sm.commands.docker import app as docker_commands_app
from sm.commands.firewall import app as firewall_app
from sm.commands.mongodb.user import app as mongodb_user_app
from sm.commands.mongodb.db import app as mongodb_db_app
from sm.commands.mongodb.backup import app as mongodb_backup_app
from sm.commands.mongodb.restore import app as mongodb_restore_app

# Register postgres sub-commands
postgres_app.add_typer(postgres_user_app, name="user")
postgres_app.add_typer(postgres_db_app, name="db")
postgres_app.add_typer(postgres_optimize_app, name="optimize")
postgres_app.add_typer(postgres_backup_app, name="backup")
postgres_app.add_typer(postgres_restore_app, name="restore")
postgres_app.add_typer(postgres_migrate_app, name="migrate")
postgres_app.add_typer(postgres_extension_app, name="extension")

# Register mongodb sub-commands
mongodb_app.add_typer(mongodb_user_app, name="user")
mongodb_app.add_typer(mongodb_db_app, name="db")
mongodb_app.add_typer(mongodb_backup_app, name="backup")
mongodb_app.add_typer(mongodb_restore_app, name="restore")

# Register command groups
app.add_typer(postgres_app, name="postgres")
app.add_typer(mongodb_app, name="mongodb")
app.add_typer(security_app, name="security")
app.add_typer(observability_app, name="observability")
app.add_typer(config_app, name="config")
app.add_typer(docker_commands_app, name="docker")
app.add_typer(firewall_app, name="firewall")


# Type aliases for common options
DryRunOption = Annotated[
    bool,
    typer.Option(
        "--dry-run",
        help="Preview changes without executing. Shows what would happen.",
        is_flag=True,
    ),
]

ForceOption = Annotated[
    bool,
    typer.Option(
        "--force",
        "-f",
        help="Allow dangerous operations. Required for destructive actions.",
        is_flag=True,
    ),
]

YesOption = Annotated[
    bool,
    typer.Option(
        "--yes",
        "-y",
        help="Skip confirmation prompts. Still requires --force for dangerous ops.",
        is_flag=True,
    ),
]

VerboseOption = Annotated[
    int,
    typer.Option(
        "--verbose",
        "-v",
        count=True,
        help="Increase output verbosity. Can be repeated (-v, -vv, -vvv).",
    ),
]

QuietOption = Annotated[
    bool,
    typer.Option(
        "--quiet",
        "-q",
        help="Suppress non-essential output. Only show errors.",
        is_flag=True,
    ),
]

NoColorOption = Annotated[
    bool,
    typer.Option(
        "--no-color",
        help="Disable colored output.",
        is_flag=True,
    ),
]

ConfigOption = Annotated[
    Optional[Path],
    typer.Option(
        "--config",
        "-c",
        help=f"Path to configuration file. Default: {DEFAULT_CONFIG_PATH}",
        exists=False,
        file_okay=True,
        dir_okay=False,
    ),
]

ConfirmNameOption = Annotated[
    Optional[str],
    typer.Option(
        "--confirm-name",
        help="Confirm resource name for critical operations.",
    ),
]


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console = Console()
        console.print(f"sm version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
) -> None:
    """Server Management CLI - Secure server administration tool.

    A production-ready CLI for managing PostgreSQL, MongoDB, security hardening,
    and observability on Debian/Ubuntu servers.

    [bold]Features:[/bold]
    - Strict safety checks to prevent mistakes
    - Dry-run mode to preview changes
    - Comprehensive input validation
    - Audit logging of all operations

    [bold]Examples:[/bold]
        sm postgres setup --dry-run
        sm postgres user create -d myapp -u myapp_user
        sm mongodb setup --dry-run
        sm mongodb db create-with-user -d myapp
        sm security harden
        sm config show
    """
    pass


def get_context(
    dry_run: bool = False,
    force: bool = False,
    yes: bool = False,
    verbose: int = 0,
    quiet: bool = False,
    no_color: bool = False,
    config: Optional[Path] = None,
    confirm_name: Optional[str] = None,
) -> ExecutionContext:
    """Create execution context from CLI options.

    This is a helper for commands to create a context from global options.
    """
    return create_context(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
        quiet=quiet,
        no_color=no_color,
        config=config,
        confirm_name=confirm_name,
    )


def handle_error(error: SMError) -> None:
    """Handle an SMError by printing formatted error and exiting."""
    app_console.error(error.message)

    if error.details:
        for detail in error.details:
            app_console.print(f"  [dim]{detail}[/dim]")

    if error.hint:
        app_console.hint(error.hint)

    raise typer.Exit(error.exit_code)


# ============================================================================
# Config commands
# ============================================================================

@config_app.command("show")
def config_show(
    config: ConfigOption = None,
    verbose: VerboseOption = 0,
    no_color: NoColorOption = False,
) -> None:
    """Show current configuration.

    Displays the loaded configuration from the config file.
    Secrets are not shown.
    """
    ctx = get_context(verbose=verbose, no_color=no_color, config=config)

    try:
        app_config = ctx.config

        ctx.console.print()
        ctx.console.print(f"[bold]Configuration file:[/bold] {ctx.config_path}")
        ctx.console.print(f"[bold]File exists:[/bold] {ctx.config_path.exists()}")
        ctx.console.print()

        ctx.console.yaml(app_config.config.to_yaml(), title="Configuration")

        # Show secrets status (not values)
        ctx.console.summary("Secrets (from environment)", {
            "SM_B2_KEY": "Set" if app_config.secrets.sm_b2_key else "Not set",
            "SM_B2_SECRET": "Set" if app_config.secrets.sm_b2_secret else "Not set",
            "SM_BACKUP_PASSPHRASE": "Set" if app_config.secrets.sm_backup_passphrase else "Not set",
            "SM_PG_SUPERUSER_PASS": "Set" if app_config.secrets.sm_pg_superuser_pass else "Not set",
        })

    except SMError as e:
        handle_error(e)


@config_app.command("init")
def config_init(
    config: ConfigOption = None,
    force: ForceOption = False,
    no_color: NoColorOption = False,
) -> None:
    """Initialize a new configuration file.

    Creates a configuration file with sensible defaults and comments.
    """
    ctx = get_context(force=force, no_color=no_color, config=config)
    config_path = ctx.config_path

    try:
        if config_path.exists() and not force:
            ctx.console.error(f"Configuration file already exists: {config_path}")
            ctx.console.hint("Use --force to overwrite")
            raise typer.Exit(1)

        init_config(config_path, force=force)
        ctx.console.success(f"Configuration file created: {config_path}")
        ctx.console.info("Edit the file to customize settings, then run commands.")
        ctx.console.hint("Set secrets via environment variables (SM_B2_KEY, etc.)")

    except SMError as e:
        handle_error(e)


@config_app.command("validate")
def config_validate(
    config: ConfigOption = None,
    verbose: VerboseOption = 0,
    no_color: NoColorOption = False,
) -> None:
    """Validate configuration file.

    Checks that the configuration file exists, is valid YAML,
    and all values pass validation.
    """
    ctx = get_context(verbose=verbose, no_color=no_color, config=config)

    try:
        # This will raise ConfigurationError if invalid
        app_config = AppConfig(config_path=ctx.config_path)

        ctx.console.success(f"Configuration is valid: {ctx.config_path}")

        if ctx.is_verbose:
            ctx.console.yaml(app_config.config.to_yaml())

        # Check for missing recommended settings
        warnings = []

        if app_config.backup.enabled and not app_config.has_backup_credentials():
            warnings.append("Backup is enabled but credentials not set (SM_B2_KEY, etc.)")

        if app_config.observability.enabled and not app_config.observability.otlp_endpoint:
            warnings.append("Observability enabled but otlp_endpoint not set")

        if warnings:
            ctx.console.print()
            for warning in warnings:
                ctx.console.warn(warning)

    except SMError as e:
        handle_error(e)


@config_app.command("example")
def config_example(no_color: NoColorOption = False) -> None:
    """Print example configuration file.

    Outputs a complete example configuration with comments.
    Useful as a starting point for creating your own config.
    """
    ctx = get_context(no_color=no_color)
    example = get_example_config()
    ctx.console.print(example)


# ============================================================================
# MongoDB setup command
# ============================================================================

@mongodb_app.command("setup")
def mongodb_setup_cmd(
    dry_run: DryRunOption = False,
    yes: YesOption = False,
    verbose: VerboseOption = 0,
    config: ConfigOption = None,
    no_color: NoColorOption = False,
) -> None:
    """Set up MongoDB 7.0 with security hardening.

    Performs complete MongoDB installation and configuration:
    - Installs MongoDB 7.0 from official repository
    - Configures WiredTiger storage engine
    - Enables authorization with SCRAM-SHA-256
    - Creates admin user with secure password
    - Binds to localhost only (secure default)

    [bold]Prerequisites:[/bold]
    - Debian or Ubuntu system
    - Root access

    [bold]Examples:[/bold]

        # Full setup
        sudo sm mongodb setup

        # Preview what would happen
        sm mongodb setup --dry-run
    """
    from sm.commands.mongodb.setup import run_setup

    ctx = get_context(
        dry_run=dry_run,
        yes=yes,
        verbose=verbose,
        config=config,
        no_color=no_color,
    )

    # Check root
    import os
    if os.geteuid() != 0:
        ctx.console.error("This operation requires root privileges")
        ctx.console.hint("Run with: sudo sm mongodb setup")
        raise typer.Exit(6)

    # Show configuration
    ctx.console.print()
    ctx.console.print("[bold]MongoDB Setup Configuration[/bold]")
    ctx.console.print("  MongoDB version: 7.0")
    ctx.console.print("  Storage engine:  WiredTiger")
    ctx.console.print("  Auth mechanism:  SCRAM-SHA-256")
    ctx.console.print("  Bind address:    127.0.0.1 (localhost only)")
    ctx.console.print()

    if not yes and not dry_run:
        if not ctx.console.confirm("Proceed with MongoDB setup?"):
            ctx.console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        run_setup(ctx)
    except SMError as e:
        handle_error(e)


# ============================================================================
# PostgreSQL setup command
# ============================================================================

@postgres_app.command("setup")
def postgres_setup_cmd(
    pg_version: Annotated[
        str,
        typer.Option(
            "--version",
            help="PostgreSQL version to install (e.g., 17, 18)",
        ),
    ] = "18",
    skip_backup: Annotated[
        bool,
        typer.Option(
            "--skip-backup",
            help="Skip pgBackRest backup configuration",
        ),
    ] = False,
    dry_run: DryRunOption = False,
    force: ForceOption = False,
    yes: YesOption = False,
    verbose: VerboseOption = 0,
    config: ConfigOption = None,
    no_color: NoColorOption = False,
) -> None:
    """Set up PostgreSQL with PgBouncer and pgBackRest.

    Performs complete PostgreSQL installation and configuration:
    - Installs PostgreSQL from PGDG repository
    - Configures PgBouncer connection pooler
    - Sets up pgBackRest with S3/B2 backups (if configured)
    - Configures secure defaults

    [bold]Prerequisites:[/bold]
    - Debian or Ubuntu system
    - Root access
    - Configuration file with backup settings (if not using --skip-backup)

    [bold]Examples:[/bold]

        # Full setup with backups (requires config)
        sm postgres setup

        # Setup without backups
        sm postgres setup --skip-backup

        # Preview what would happen
        sm postgres setup --dry-run
    """
    from sm.commands.postgres.setup import run_setup, require_root

    ctx = get_context(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
        config=config,
        no_color=no_color,
    )

    # Check root
    import os
    if os.geteuid() != 0:
        ctx.console.error("This operation requires root privileges")
        ctx.console.hint("Run with: sudo sm postgres setup")
        raise typer.Exit(6)

    # Load config
    try:
        app_config = ctx.config
    except SMError as e:
        handle_error(e)
        return

    # Get PgBouncer config
    pgbouncer_config = {
        "port": app_config.pgbouncer.port,
        "pool_mode": app_config.pgbouncer.pool_mode,
        "max_client_conn": app_config.pgbouncer.max_client_conn,
        "default_pool_size": app_config.pgbouncer.default_pool_size,
    }

    # Get backup config if not skipping
    backup_config = None
    if not skip_backup and app_config.backup.enabled:
        if not app_config.has_backup_credentials():
            ctx.console.error("Backup is enabled but credentials not set")
            ctx.console.hint("Set SM_B2_KEY, SM_B2_SECRET, SM_BACKUP_PASSPHRASE env vars")
            ctx.console.hint("Or use --skip-backup to skip backup configuration")
            raise typer.Exit(2)

        backup_config = {
            "s3_endpoint": app_config.backup.s3_endpoint,
            "s3_region": app_config.backup.s3_region,
            "s3_bucket": app_config.backup.s3_bucket,
            "repo_path": app_config.backup.repo_path,
            "s3_key": app_config.secrets.sm_b2_key,
            "s3_secret": app_config.secrets.sm_b2_secret,
            "passphrase": app_config.secrets.sm_backup_passphrase,
        }

    # Confirmation
    ctx.console.print()
    ctx.console.print("[bold]PostgreSQL Setup Configuration[/bold]")
    ctx.console.print(f"  PostgreSQL version: {pg_version}")
    ctx.console.print(f"  PgBouncer port:     {pgbouncer_config['port']}")
    ctx.console.print(f"  Backup:             {'Enabled' if backup_config else 'Disabled'}")
    ctx.console.print()

    if not yes and not dry_run:
        if not ctx.console.confirm("Proceed with PostgreSQL setup?"):
            ctx.console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        run_setup(ctx, pg_version, pgbouncer_config, backup_config, skip_backup)
    except SMError as e:
        handle_error(e)


@security_app.command("harden")
def security_harden(
    dry_run: DryRunOption = False,
    force: ForceOption = False,
    yes: YesOption = False,
    verbose: VerboseOption = 0,
    config: ConfigOption = None,
    no_color: NoColorOption = False,
    bantime: Annotated[
        str,
        typer.Option(
            "--bantime",
            help="fail2ban ban duration (e.g., 10m, 1h, 1d)",
        ),
    ] = "10m",
    findtime: Annotated[
        str,
        typer.Option(
            "--findtime",
            help="fail2ban time window for counting failures",
        ),
    ] = "10m",
    maxretry: Annotated[
        int,
        typer.Option(
            "--maxretry",
            help="fail2ban maximum retry count before ban",
        ),
    ] = 5,
    skip_fail2ban: Annotated[
        bool,
        typer.Option(
            "--skip-fail2ban",
            help="Skip fail2ban configuration",
        ),
    ] = False,
    skip_auditd: Annotated[
        bool,
        typer.Option(
            "--skip-auditd",
            help="Skip auditd configuration",
        ),
    ] = False,
    skip_upgrades: Annotated[
        bool,
        typer.Option(
            "--skip-upgrades",
            help="Skip unattended-upgrades configuration",
        ),
    ] = False,
) -> None:
    """Apply security hardening baseline.

    Installs and configures security tools:
    - fail2ban for SSH brute-force protection
    - auditd for security auditing with baseline rules
    - unattended-upgrades for automatic security updates

    [bold]Prerequisites:[/bold]
    - Debian or Ubuntu system
    - Root access

    [bold]Examples:[/bold]

        # Full security hardening (requires root)
        sudo sm security harden

        # Preview what would happen
        sm security harden --dry-run

        # Custom fail2ban settings
        sm security harden --bantime=1h --maxretry=3

        # Skip specific components
        sm security harden --skip-auditd
    """
    from sm.commands.security.harden import run_harden

    ctx = get_context(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
        config=config,
        no_color=no_color,
    )

    # Check root
    import os
    if os.geteuid() != 0:
        ctx.console.error("This operation requires root privileges")
        ctx.console.hint("Run with: sudo sm security harden")
        raise typer.Exit(6)

    # Show configuration
    ctx.console.print()
    ctx.console.print("[bold]Security Hardening Configuration[/bold]")
    ctx.console.print(f"  fail2ban:            {'Skip' if skip_fail2ban else 'Enable'}")
    if not skip_fail2ban:
        ctx.console.print(f"    - bantime:         {bantime}")
        ctx.console.print(f"    - findtime:        {findtime}")
        ctx.console.print(f"    - maxretry:        {maxretry}")
    ctx.console.print(f"  auditd:              {'Skip' if skip_auditd else 'Enable'}")
    ctx.console.print(f"  unattended-upgrades: {'Skip' if skip_upgrades else 'Enable'}")
    ctx.console.print()

    if not yes and not dry_run:
        if not ctx.console.confirm("Proceed with security hardening?"):
            ctx.console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        run_harden(
            ctx,
            bantime=bantime,
            findtime=findtime,
            maxretry=maxretry,
            skip_fail2ban=skip_fail2ban,
            skip_auditd=skip_auditd,
            skip_upgrades=skip_upgrades,
        )
    except SMError as e:
        handle_error(e)


# Import and register security audit command
from sm.commands.security.audit import audit as security_audit_command

security_app.command("audit")(security_audit_command)


@observability_app.command("setup")
def observability_setup_cmd(
    dry_run: DryRunOption = False,
    force: ForceOption = False,
    yes: YesOption = False,
    verbose: VerboseOption = 0,
    config: ConfigOption = None,
    no_color: NoColorOption = False,
    otlp_endpoint: Annotated[
        Optional[str],
        typer.Option(
            "--otlp-endpoint",
            help="OTLP endpoint URL (e.g., http://signoz:4318)",
        ),
    ] = None,
    otel_version: Annotated[
        str,
        typer.Option(
            "--otel-version",
            help="OpenTelemetry Collector version to install",
        ),
    ] = "0.104.0",
    install_dir: Annotated[
        str,
        typer.Option(
            "--install-dir",
            help="Installation directory for OTEL collector",
        ),
    ] = "/opt/otel-host",
    service_name: Annotated[
        str,
        typer.Option(
            "--service-name",
            help="Systemd service name",
        ),
    ] = "otel-host-metrics",
    collection_interval: Annotated[
        str,
        typer.Option(
            "--collection-interval",
            help="Metrics collection interval (e.g., 10s, 1m)",
        ),
    ] = "10s",
    skip_logs: Annotated[
        bool,
        typer.Option(
            "--skip-logs",
            help="Skip log collection (fail2ban, auth, audit)",
        ),
    ] = False,
    skip_cloud_detection: Annotated[
        bool,
        typer.Option(
            "--skip-cloud-detection",
            help="Skip cloud provider detection (GCP, EC2)",
        ),
    ] = False,
) -> None:
    """Set up OpenTelemetry collector for observability.

    Installs and configures the OpenTelemetry Collector Contrib to:
    - Collect host metrics (CPU, memory, disk, network, load, etc.)
    - Collect logs (fail2ban, auth, audit)
    - Send to configured OTLP endpoint (e.g., SigNoz)

    [bold]Prerequisites:[/bold]
    - Debian or Ubuntu system
    - Root access
    - x86_64 or arm64 architecture

    [bold]Examples:[/bold]

        # Full setup with OTLP endpoint
        sudo sm observability setup --otlp-endpoint http://signoz:4318

        # Preview what would happen
        sm observability setup --otlp-endpoint http://signoz:4318 --dry-run

        # Metrics only (no log collection)
        sudo sm observability setup --otlp-endpoint http://signoz:4318 --skip-logs

        # Use endpoint from config file
        sudo sm observability setup
    """
    from sm.commands.observability.setup import run_observability_setup

    ctx = get_context(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
        config=config,
        no_color=no_color,
    )

    # Check root
    import os
    if os.geteuid() != 0:
        ctx.console.error("This operation requires root privileges")
        ctx.console.hint("Run with: sudo sm observability setup")
        raise typer.Exit(6)

    # Get OTLP endpoint from option or config
    endpoint = otlp_endpoint
    if not endpoint:
        try:
            app_config = ctx.config
            if app_config.observability.otlp_endpoint:
                endpoint = app_config.observability.otlp_endpoint
        except SMError:
            pass

    if not endpoint:
        ctx.console.error("OTLP endpoint is required")
        ctx.console.hint("Use --otlp-endpoint or set observability.otlp_endpoint in config")
        raise typer.Exit(2)

    # Validate endpoint format
    if not endpoint.startswith(("http://", "https://")):
        ctx.console.error("OTLP endpoint must start with http:// or https://")
        raise typer.Exit(3)

    # Show configuration
    ctx.console.print()
    ctx.console.print("[bold]Observability Setup Configuration[/bold]")
    ctx.console.print(f"  OTLP endpoint:        {endpoint}")
    ctx.console.print(f"  OTEL version:         {otel_version}")
    ctx.console.print(f"  Install directory:    {install_dir}")
    ctx.console.print(f"  Service name:         {service_name}")
    ctx.console.print(f"  Collection interval:  {collection_interval}")
    ctx.console.print(f"  Collect logs:         {'No' if skip_logs else 'Yes'}")
    ctx.console.print(f"  Cloud detection:      {'No' if skip_cloud_detection else 'Yes'}")
    ctx.console.print()

    if not yes and not dry_run:
        if not ctx.console.confirm("Proceed with observability setup?"):
            ctx.console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        run_observability_setup(
            ctx,
            otlp_endpoint=endpoint,
            otel_version=otel_version,
            install_dir=install_dir,
            service_name=service_name,
            collection_interval=collection_interval,
            collect_logs=not skip_logs,
            enable_cloud_detection=not skip_cloud_detection,
        )
    except SMError as e:
        handle_error(e)


# ============================================================================
# Server setup command
# ============================================================================

@app.command("setup")
def setup_cmd(
    docker: Annotated[
        bool,
        typer.Option(
            "--docker",
            help="Install Docker with Hetzner MTU fix",
            is_flag=True,
        ),
    ] = False,
    security: Annotated[
        bool,
        typer.Option(
            "--security",
            help="Apply security hardening (fail2ban, auditd, upgrades)",
            is_flag=True,
        ),
    ] = False,
    observability: Annotated[
        bool,
        typer.Option(
            "--observability",
            help="Setup OpenTelemetry collector",
            is_flag=True,
        ),
    ] = False,
    postgres: Annotated[
        bool,
        typer.Option(
            "--postgres",
            help="Setup PostgreSQL 18",
            is_flag=True,
        ),
    ] = False,
    mongodb: Annotated[
        bool,
        typer.Option(
            "--mongodb",
            help="Setup MongoDB 7.0",
            is_flag=True,
        ),
    ] = False,
    otlp_endpoint: Annotated[
        Optional[str],
        typer.Option(
            "--otlp-endpoint",
            help="OTLP endpoint (required with --observability)",
        ),
    ] = None,
    hostname: Annotated[
        Optional[str],
        typer.Option(
            "--hostname",
            help="Set server hostname",
        ),
    ] = None,
    mtu: Annotated[
        Optional[int],
        typer.Option(
            "--mtu",
            help="Docker MTU value (default 1450 for Hetzner, 1500 for AWS/GCP)",
        ),
    ] = None,
    dry_run: DryRunOption = False,
    yes: YesOption = False,
    verbose: VerboseOption = 0,
    no_color: NoColorOption = False,
) -> None:
    """Setup server with selected components.

    One command to configure your server with Docker, security hardening,
    observability, PostgreSQL, and MongoDB.

    [bold]Examples:[/bold]

        # Docker + security (most common)
        sudo sm setup --docker --security

        # Full stack with PostgreSQL
        sudo sm setup --docker --security --postgres

        # Full stack with MongoDB
        sudo sm setup --docker --security --mongodb

        # With observability
        sudo sm setup --docker --security --observability --otlp-endpoint=http://signoz:4318

        # Preview changes
        sm setup --docker --security --dry-run
    """
    from sm.commands.setup import run_setup

    ctx = get_context(
        dry_run=dry_run,
        force=False,
        yes=yes,
        verbose=verbose,
        no_color=no_color,
    )

    # Check root
    import os
    if os.geteuid() != 0 and not dry_run:
        ctx.console.error("This operation requires root privileges")
        ctx.console.hint("Run with: sudo sm setup ...")
        raise typer.Exit(6)

    if not yes and not dry_run:
        components = []
        if docker:
            components.append("Docker")
        if security:
            components.append("Security")
        if observability:
            components.append("Observability")
        if postgres:
            components.append("PostgreSQL")
        if mongodb:
            components.append("MongoDB")

        if components:
            ctx.console.print(f"Components to install: {', '.join(components)}")
            if not ctx.console.confirm("Proceed?"):
                ctx.console.warn("Cancelled")
                raise typer.Exit(0)

    try:
        run_setup(
            ctx,
            docker=docker,
            security=security,
            observability=observability,
            postgres=postgres,
            mongodb=mongodb,
            otlp_endpoint=otlp_endpoint,
            hostname=hostname,
            mtu=mtu,
        )
    except SMError as e:
        handle_error(e)


# Entry point
if __name__ == "__main__":
    app()
