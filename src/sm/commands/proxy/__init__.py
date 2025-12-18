"""Reverse proxy management commands.

Commands:
- sm proxy setup      - Install and configure OpenResty proxy
- sm proxy status     - Show proxy status
- sm proxy reload     - Reload proxy configuration
- sm proxy uninstall  - Remove proxy
"""

import typer
from rich.table import Table

from sm.commands.proxy.endpoint import app as endpoint_app
from sm.commands.proxy.key import app as key_app
from sm.core import (
    AuditEvent,
    AuditEventType,
    AuditResult,
    CommandExecutor,
    ExecutionContext,
    ProxyError,
    SMError,
    console,
    create_context,
    get_audit_logger,
    require_root,
)
from sm.services.proxy import ProxyService

app = typer.Typer(
    name="proxy",
    help="Reverse proxy management with API key authentication.",
    no_args_is_help=True,
)

# Register sub-commands
app.add_typer(endpoint_app)
app.add_typer(key_app)


def _get_service(ctx: ExecutionContext) -> tuple[CommandExecutor, ProxyService]:
    """Create service instances."""
    executor = CommandExecutor(ctx)
    proxy = ProxyService(ctx, executor)
    return executor, proxy


@app.command("setup")
@require_root
def setup_proxy(
    bind_address: str = typer.Option(
        # Binding to 0.0.0.0 is intentional - proxy needs to accept external connections
        "0.0.0.0",
        "--bind",
        "-b",
        help="Address to bind proxy to",
    ),
    worker_processes: str = typer.Option(
        "auto",
        "--workers",
        help="Number of worker processes ('auto' or number)",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow dangerous operations"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Install and configure the reverse proxy.

    Sets up OpenResty (nginx + Lua) as a high-performance reverse proxy
    with API key authentication support.

    Examples:

        sm proxy setup

        sm proxy setup --bind 127.0.0.1 --workers 4
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()

    try:
        executor, proxy = _get_service(ctx)

        with executor.transaction() as rollback:
            proxy.setup(rollback=rollback)

        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_SETUP,
                result=AuditResult.SUCCESS,
                operation="proxy_setup",
                parameters={
                    "bind_address": bind_address,
                    "worker_processes": worker_processes,
                },
            )
        )

    except SMError as e:
        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_SETUP,
                result=AuditResult.FAILURE,
                operation="proxy_setup",
                parameters={"error": str(e)},
            )
        )
        console.error(e.message)
        if e.details:
            for detail in e.details:
                console.print(f"  [dim]{detail}[/dim]")
        if e.hint:
            console.hint(e.hint)
        raise typer.Exit(e.exit_code) from e


@app.command("status")
def proxy_status(
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Show proxy status and configuration.

    Displays:
    - OpenResty installation status and version
    - Service running status
    - Configured endpoints
    - API key count

    Examples:

        sm proxy status
    """
    ctx = create_context(verbose=verbose)
    executor, proxy = _get_service(ctx)

    # Installation status
    if proxy.is_installed():
        version = proxy.detect_version() or "unknown"
        console.success(f"OpenResty installed: v{version}")
    else:
        console.warn("OpenResty not installed")
        console.info("Run 'sm proxy setup' to install")
        return

    # Service status
    if proxy.is_running():
        console.success("Service status: running")
    else:
        console.warn("Service status: stopped")

    # Endpoints
    endpoints = proxy.list_endpoints()
    if endpoints:
        console.info(f"\nEndpoints: {len(endpoints)}")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("Port")
        table.add_column("Upstream")
        table.add_column("Protocol")
        table.add_column("Auth")
        table.add_column("Health")

        for ep in endpoints:
            table.add_row(
                ep.name,
                str(ep.listen_port),
                ep.upstream,
                ep.protocol.upper(),
                "[green]Yes[/green]" if ep.require_auth else "[yellow]No[/yellow]",
                "[green]OK[/green]" if ep.is_healthy else "[red]Down[/red]",
            )

        console.print(table)
    else:
        console.info("\nNo endpoints configured")
        console.info(
            "Add one with: sm proxy endpoint add "
            "--name <name> --listen-port <port> --upstream <host:port>"
        )

    # Keys
    keys = proxy.list_keys()
    console.info(f"\nAPI keys: {len(keys)} active")


@app.command("reload")
@require_root
def reload_proxy(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Reload proxy configuration.

    Validates the configuration and performs a graceful reload
    without dropping existing connections.

    Examples:

        sm proxy reload
    """
    ctx = create_context(dry_run=dry_run, verbose=verbose)
    executor, proxy = _get_service(ctx)

    if not proxy.is_installed():
        console.error("OpenResty not installed")
        console.info("Run 'sm proxy setup' to install")
        raise typer.Exit(1)

    try:
        # Regenerate configs from YAML
        proxy.generate_nginx_config()
        proxy.generate_lua_scripts()

        # Reload service
        proxy.reload()

    except ProxyError as e:
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e


@app.command("start")
@require_root
def start_proxy(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Start the proxy service.

    Examples:

        sm proxy start
    """
    ctx = create_context(dry_run=dry_run, verbose=verbose)
    executor, proxy = _get_service(ctx)

    if not proxy.is_installed():
        console.error("OpenResty not installed")
        console.info("Run 'sm proxy setup' to install")
        raise typer.Exit(1)

    try:
        proxy.start()
    except ProxyError as e:
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e


@app.command("stop")
@require_root
def stop_proxy(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Stop the proxy service.

    Examples:

        sm proxy stop
    """
    ctx = create_context(dry_run=dry_run, verbose=verbose)
    executor, proxy = _get_service(ctx)

    if not proxy.is_installed():
        console.error("OpenResty not installed")
        raise typer.Exit(1)

    try:
        proxy.stop()
    except ProxyError as e:
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e


@app.command("uninstall")
@require_root
def uninstall_proxy(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Skip confirmation"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Uninstall the proxy.

    Stops the service and removes OpenResty.
    Configuration files are preserved.

    Examples:

        sm proxy uninstall --force
    """
    ctx = create_context(dry_run=dry_run, force=force, verbose=verbose)
    executor, proxy = _get_service(ctx)

    if not proxy.is_installed():
        console.info("OpenResty not installed")
        return

    if not force and not dry_run:
        confirm = typer.confirm("Are you sure you want to uninstall the proxy?")
        if not confirm:
            console.info("Cancelled")
            return

    try:
        proxy.uninstall()
        console.info("Configuration files preserved in /etc/sm/")
    except ProxyError as e:
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e


@app.command("reset")
@require_root
def reset_proxy(
    uninstall: bool = typer.Option(
        False, "--uninstall", help="Also uninstall OpenResty package"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Completely reset proxy configuration.

    Stops service, removes all config files, API keys, and logs.
    Use --uninstall to also remove the OpenResty package.

    After reset, run 'sm proxy setup' to start fresh.

    Examples:

        sm proxy reset --force

        sm proxy reset --uninstall --force
    """
    ctx = create_context(dry_run=dry_run, force=force, verbose=verbose)
    executor, proxy = _get_service(ctx)

    if not force and not dry_run:
        msg = "This will remove ALL proxy configuration, API keys, and logs."
        if uninstall:
            msg += " OpenResty will also be uninstalled."
        console.warn(msg)
        confirm = typer.confirm("Are you sure you want to reset?")
        if not confirm:
            console.info("Cancelled")
            return

    try:
        proxy.reset(uninstall_openresty=uninstall)
        console.info("\nTo set up the proxy again, run: sm proxy setup")
    except ProxyError as e:
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e
