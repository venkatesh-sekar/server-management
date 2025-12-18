"""Proxy API key management commands.

Commands:
- sm proxy key create  - Create a new API key
- sm proxy key list    - List all API keys
- sm proxy key show    - Show full key details
- sm proxy key rotate  - Rotate an API key
- sm proxy key revoke  - Revoke an API key
- sm proxy key delete  - Permanently delete an API key
"""

from datetime import datetime, timedelta, timezone

import typer
from rich.panel import Panel
from rich.table import Table

from sm.core import (
    AuditEvent,
    AuditEventType,
    AuditResult,
    CommandExecutor,
    ExecutionContext,
    ProxyError,
    console,
    create_context,
    get_audit_logger,
    require_root,
)
from sm.services.proxy import ProxyService

app = typer.Typer(
    name="key",
    help="Proxy API key management.",
    no_args_is_help=True,
)


def _get_service(ctx: ExecutionContext) -> tuple[CommandExecutor, ProxyService]:
    """Create service instances."""
    executor = CommandExecutor(ctx)
    proxy = ProxyService(ctx, executor)
    return executor, proxy


@app.command("create")
@require_root
def create_key(
    name: str = typer.Option(
        ...,
        "--name",
        "-n",
        help="Key name for identification",
    ),
    endpoints: str | None = typer.Option(
        None,
        "--endpoints",
        "-e",
        help="Comma-separated endpoint names (default: all)",
    ),
    rate_limit: int | None = typer.Option(
        None,
        "--rate-limit",
        "-r",
        help="Requests per minute limit",
    ),
    expires_days: int | None = typer.Option(
        None,
        "--expires-days",
        help="Key expiration in days",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Create a new API key.

    Generates a cryptographically secure API key for authenticating
    requests to proxy endpoints.

    The key is displayed ONCE after creation - store it securely!

    Examples:

        # Key for all endpoints
        sm proxy key create --name collector-prod

        # Key for specific endpoints with rate limit
        sm proxy key create \\
            --name collector-staging \\
            --endpoints otel-http,otel-grpc \\
            --rate-limit 1000

        # Key that expires in 90 days
        sm proxy key create \\
            --name temp-access \\
            --expires-days 90
    """
    ctx = create_context(dry_run=dry_run, verbose=verbose)
    audit = get_audit_logger()

    # Parse endpoints
    endpoint_list: list[str] | None = None
    if endpoints:
        endpoint_list = [e.strip() for e in endpoints.split(",")]

    # Calculate expiry
    expires_at: datetime | None = None
    if expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

    try:
        executor, proxy = _get_service(ctx)

        with executor.transaction() as rollback:
            api_key = proxy.create_key(
                name=name,
                endpoints=endpoint_list,
                rate_limit=rate_limit,
                expires_at=expires_at,
                rollback=rollback,
            )

        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_KEY_CREATE,
                result=AuditResult.SUCCESS,
                operation="proxy_key_create",
                parameters={
                    "key_name": name,
                    "endpoints": endpoint_list or ["*"],
                    "rate_limit": rate_limit,
                },
            )
        )

        # Display the key prominently
        console.print()
        console.print(
            Panel(
                f"[bold green]{api_key}[/bold green]",
                title="[bold]Your API Key[/bold]",
                subtitle="[yellow]Save this key - it won't be shown again![/yellow]",
                border_style="green",
            )
        )
        console.print()

        # Usage instructions
        console.info("Usage:")
        console.info(
            f'  curl -H "Authorization: Bearer {api_key}" http://localhost:<port>/'
        )
        console.info("  or")
        console.info(f'  curl -H "X-API-Key: {api_key}" http://localhost:<port>/')

    except ProxyError as e:
        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_KEY_CREATE,
                result=AuditResult.FAILURE,
                operation="proxy_key_create",
                parameters={
                    "key_name": name,
                    "error": str(e),
                },
            )
        )
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e


@app.command("list")
def list_keys(
    include_disabled: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="Include disabled/revoked keys",
    ),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """List all API keys.

    Keys are shown with masked values for security.
    Use 'sm proxy key show --name <name>' to see a specific key.

    Examples:

        sm proxy key list

        sm proxy key list --all
    """
    ctx = create_context(verbose=verbose)
    executor, proxy = _get_service(ctx)

    keys = proxy.list_keys(include_disabled=include_disabled)

    if not keys:
        console.info("No API keys configured")
        console.info("\nCreate one with:")
        console.info("  sm proxy key create --name <name>")
        return

    table = Table(
        show_header=True,
        header_style="bold",
        title="API Keys",
    )
    table.add_column("Name", style="cyan")
    table.add_column("Prefix")
    table.add_column("Endpoints")
    table.add_column("Rate Limit", justify="right")
    table.add_column("Created")
    table.add_column("Expires")
    table.add_column("Status")

    for key in keys:
        # Format endpoints
        if key.endpoints == ["*"]:
            ep_display = "[dim]all[/dim]"
        else:
            ep_display = ", ".join(key.endpoints[:3])
            if len(key.endpoints) > 3:
                ep_display += f" +{len(key.endpoints) - 3}"

        # Format rate limit
        rate_display = (
            str(key.rate_limit) + "/min" if key.rate_limit else "[dim]-[/dim]"
        )

        # Format dates
        created = key.created_at.strftime("%Y-%m-%d") if key.created_at else "-"

        if key.expires_at:
            if key.expires_at < datetime.now(timezone.utc):
                expires = f"[red]{key.expires_at.strftime('%Y-%m-%d')}[/red]"
            else:
                expires = key.expires_at.strftime("%Y-%m-%d")
        else:
            expires = "[dim]never[/dim]"

        # Status
        if not key.enabled:
            status = "[red]revoked[/red]"
        elif key.expires_at and key.expires_at < datetime.now(timezone.utc):
            status = "[red]expired[/red]"
        else:
            status = "[green]active[/green]"

        table.add_row(
            key.name,
            key.key_prefix + "...",
            ep_display,
            rate_display,
            created,
            expires,
            status,
        )

    console.print(table)

    active_count = sum(1 for k in keys if k.enabled)
    console.info(f"\nTotal: {len(keys)} key(s), {active_count} active")


@app.command("show")
@require_root
def show_key(
    name: str = typer.Option(
        ...,
        "--name",
        "-n",
        help="Key name to show",
    ),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Show full details of an API key.

    Displays the actual key value - use with caution!

    Examples:

        sm proxy key show --name collector-prod
    """
    ctx = create_context(verbose=verbose)
    executor, proxy = _get_service(ctx)

    try:
        key = proxy.show_key(name)

        console.print()
        console.print(
            Panel(
                f"[bold]{key.key}[/bold]",
                title=f"[bold]API Key: {key.name}[/bold]",
                border_style="cyan",
            )
        )

        console.info(f"\nEndpoints: {', '.join(key.endpoints)}")
        console.info(f"Rate limit: {key.rate_limit or 'unlimited'}/min")
        console.info(f"Created: {key.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if key.rotated_at:
            console.info(
                f"Last rotated: {key.rotated_at.strftime('%Y-%m-%d %H:%M:%S')}"
            )
        if key.expires_at:
            console.info(f"Expires: {key.expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
        console.info(f"Status: {'active' if key.enabled else 'revoked'}")

    except ProxyError as e:
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e


@app.command("rotate")
@require_root
def rotate_key(
    name: str = typer.Option(
        ...,
        "--name",
        "-n",
        help="Key name to rotate",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Rotate an API key.

    Generates a new key value while keeping the same name and settings.
    The old key immediately becomes invalid.

    Examples:

        sm proxy key rotate --name collector-prod
    """
    ctx = create_context(dry_run=dry_run, verbose=verbose)
    audit = get_audit_logger()

    try:
        executor, proxy = _get_service(ctx)
        new_key = proxy.rotate_key(name)

        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_KEY_ROTATE,
                result=AuditResult.SUCCESS,
                operation="proxy_key_rotate",
                parameters={"key_name": name},
            )
        )

        # Display the new key
        console.print()
        console.print(
            Panel(
                f"[bold green]{new_key}[/bold green]",
                title=f"[bold]New API Key for '{name}'[/bold]",
                subtitle="[yellow]Save this key - the old one is now invalid![/yellow]",
                border_style="green",
            )
        )

    except ProxyError as e:
        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_KEY_ROTATE,
                result=AuditResult.FAILURE,
                operation="proxy_key_rotate",
                parameters={
                    "key_name": name,
                    "error": str(e),
                },
            )
        )
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e


@app.command("revoke")
@require_root
def revoke_key(
    name: str = typer.Option(
        ...,
        "--name",
        "-n",
        help="Key name to revoke",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Skip confirmation"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Revoke an API key.

    Disables the key immediately. The key is kept for audit purposes.
    Use 'sm proxy key delete' to permanently remove a key.

    Examples:

        sm proxy key revoke --name compromised-key --force
    """
    ctx = create_context(dry_run=dry_run, force=force, verbose=verbose)
    audit = get_audit_logger()

    if not force and not dry_run:
        confirm = typer.confirm(
            f"Revoke API key '{name}'? This will immediately invalidate it."
        )
        if not confirm:
            console.info("Cancelled")
            return

    try:
        executor, proxy = _get_service(ctx)
        proxy.revoke_key(name)

        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_KEY_REVOKE,
                result=AuditResult.SUCCESS,
                operation="proxy_key_revoke",
                parameters={"key_name": name},
            )
        )

    except ProxyError as e:
        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_KEY_REVOKE,
                result=AuditResult.FAILURE,
                operation="proxy_key_revoke",
                parameters={
                    "key_name": name,
                    "error": str(e),
                },
            )
        )
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e


@app.command("delete")
@require_root
def delete_key(
    name: str = typer.Option(
        ...,
        "--name",
        "-n",
        help="Key name to delete",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Skip confirmation"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Permanently delete an API key.

    Removes the key completely. This action cannot be undone.

    Examples:

        sm proxy key delete --name old-key --force
    """
    ctx = create_context(dry_run=dry_run, force=force, verbose=verbose)
    audit = get_audit_logger()

    if not force and not dry_run:
        confirm = typer.confirm(
            f"Permanently delete API key '{name}'? This cannot be undone."
        )
        if not confirm:
            console.info("Cancelled")
            return

    try:
        executor, proxy = _get_service(ctx)
        proxy.delete_key(name)

        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_KEY_DELETE,
                result=AuditResult.SUCCESS,
                operation="proxy_key_delete",
                parameters={"key_name": name},
            )
        )

    except ProxyError as e:
        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_KEY_DELETE,
                result=AuditResult.FAILURE,
                operation="proxy_key_delete",
                parameters={
                    "key_name": name,
                    "error": str(e),
                },
            )
        )
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e
