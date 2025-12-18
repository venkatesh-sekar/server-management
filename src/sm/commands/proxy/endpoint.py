"""Proxy endpoint management commands.

Commands:
- sm proxy endpoint add     - Add a new proxy endpoint
- sm proxy endpoint remove  - Remove an endpoint
- sm proxy endpoint list    - List all endpoints
"""


import typer
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
from sm.core.config import ProxyEndpoint
from sm.services.proxy import ProxyService

app = typer.Typer(
    name="endpoint",
    help="Proxy endpoint management.",
    no_args_is_help=True,
)


def _get_service(ctx: ExecutionContext) -> tuple[CommandExecutor, ProxyService]:
    """Create service instances."""
    executor = CommandExecutor(ctx)
    proxy = ProxyService(ctx, executor)
    return executor, proxy


@app.command("add")
@require_root
def add_endpoint(
    name: str = typer.Option(
        ...,
        "--name",
        "-n",
        help="Endpoint name (lowercase, alphanumeric, hyphens)",
    ),
    listen_port: int = typer.Option(
        ...,
        "--listen-port",
        "-p",
        help="Port to listen on",
    ),
    upstream: str = typer.Option(
        ...,
        "--upstream",
        "-u",
        help="Upstream address (host:port)",
    ),
    protocol: str = typer.Option(
        "http",
        "--protocol",
        help="Protocol: http or grpc",
    ),
    require_auth: bool = typer.Option(
        True,
        "--require-auth/--no-auth",
        help="Require API key authentication",
    ),
    allowed_methods: str | None = typer.Option(
        None,
        "--methods",
        help="Comma-separated list of allowed HTTP methods (e.g., POST,GET)",
    ),
    health_check_path: str = typer.Option(
        "/health",
        "--health-path",
        help="Health check endpoint path",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Add a new proxy endpoint.

    Creates an endpoint that proxies requests to an upstream service.
    Supports both HTTP and gRPC protocols.

    Examples:

        # HTTP endpoint for OpenTelemetry
        sm proxy endpoint add \\
            --name otel-http \\
            --listen-port 4318 \\
            --upstream localhost:4317 \\
            --protocol http \\
            --require-auth

        # gRPC endpoint
        sm proxy endpoint add \\
            --name otel-grpc \\
            --listen-port 4319 \\
            --upstream localhost:4317 \\
            --protocol grpc \\
            --require-auth

        # Public endpoint without auth
        sm proxy endpoint add \\
            --name public-api \\
            --listen-port 8080 \\
            --upstream localhost:3000 \\
            --no-auth
    """
    ctx = create_context(dry_run=dry_run, verbose=verbose)
    audit = get_audit_logger()

    # Parse allowed methods
    methods: list[str] = []
    if allowed_methods:
        methods = [m.strip().upper() for m in allowed_methods.split(",")]

    try:
        # Create endpoint config
        endpoint = ProxyEndpoint(
            name=name,
            listen_port=listen_port,
            upstream=upstream,
            protocol=protocol,
            require_auth=require_auth,
            allowed_methods=methods,
            health_check_path=health_check_path,
        )

        executor, proxy = _get_service(ctx)

        with executor.transaction() as rollback:
            proxy.add_endpoint(endpoint, rollback=rollback)

        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_ENDPOINT_ADD,
                result=AuditResult.SUCCESS,
                operation="proxy_endpoint_add",
                parameters={
                    "endpoint_name": name,
                    "listen_port": listen_port,
                    "upstream": upstream,
                    "protocol": protocol,
                },
            )
        )

        # Show usage example
        if require_auth:
            console.info("\nUsage with API key:")
            console.info(
                f'  curl -H "Authorization: Bearer <your-key>" '
                f"http://localhost:{listen_port}/"
            )
            console.info(
                "\nCreate an API key with: sm proxy key create --name <key-name>"
            )

    except ProxyError as e:
        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_ENDPOINT_ADD,
                result=AuditResult.FAILURE,
                operation="proxy_endpoint_add",
                parameters={
                    "endpoint_name": name,
                    "error": str(e),
                },
            )
        )
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e


@app.command("remove")
@require_root
def remove_endpoint(
    name: str = typer.Option(
        ...,
        "--name",
        "-n",
        help="Endpoint name to remove",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Skip confirmation"),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """Remove a proxy endpoint.

    Examples:

        sm proxy endpoint remove --name otel-http

        sm proxy endpoint remove -n otel-grpc --force
    """
    ctx = create_context(dry_run=dry_run, force=force, verbose=verbose)
    audit = get_audit_logger()

    if not force and not dry_run:
        confirm = typer.confirm(f"Remove endpoint '{name}'?")
        if not confirm:
            console.info("Cancelled")
            return

    try:
        executor, proxy = _get_service(ctx)
        proxy.remove_endpoint(name)

        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_ENDPOINT_REMOVE,
                result=AuditResult.SUCCESS,
                operation="proxy_endpoint_remove",
                parameters={"endpoint_name": name},
            )
        )

    except ProxyError as e:
        audit.log(
            AuditEvent(
                event_type=AuditEventType.PROXY_ENDPOINT_REMOVE,
                result=AuditResult.FAILURE,
                operation="proxy_endpoint_remove",
                parameters={
                    "endpoint_name": name,
                    "error": str(e),
                },
            )
        )
        console.error(str(e))
        raise typer.Exit(e.exit_code) from e


@app.command("list")
def list_endpoints(
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity"
    ),
) -> None:
    """List all proxy endpoints.

    Examples:

        sm proxy endpoint list
    """
    ctx = create_context(verbose=verbose)
    executor, proxy = _get_service(ctx)

    if not proxy.is_installed():
        console.warn("OpenResty not installed")
        console.info("Run 'sm proxy setup' to install")
        return

    endpoints = proxy.list_endpoints()

    if not endpoints:
        console.info("No endpoints configured")
        console.info("\nAdd one with:")
        console.info(
            "  sm proxy endpoint add "
            "--name <name> --listen-port <port> --upstream <host:port>"
        )
        return

    table = Table(
        show_header=True,
        header_style="bold",
        title="Proxy Endpoints",
    )
    table.add_column("Name", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("Upstream")
    table.add_column("Protocol")
    table.add_column("Auth Required")
    table.add_column("Health")

    for ep in endpoints:
        auth_status = "[green]Yes[/green]" if ep.require_auth else "[yellow]No[/yellow]"
        health_status = "[green]OK[/green]" if ep.is_healthy else "[red]Down[/red]"

        table.add_row(
            ep.name,
            str(ep.listen_port),
            ep.upstream,
            ep.protocol.upper(),
            auth_status,
            health_status,
        )

    console.print(table)
    console.info(f"\nTotal: {len(endpoints)} endpoint(s)")
