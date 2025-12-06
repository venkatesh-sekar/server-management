"""Server setup command.

One command to configure all server components.
"""

from typing import Optional
from sm.core.context import ExecutionContext
from sm.core.exceptions import SMError


def run_setup(
    ctx: ExecutionContext,
    docker: bool = False,
    security: bool = False,
    observability: bool = False,
    postgres: bool = False,
    otlp_endpoint: Optional[str] = None,
    hostname: Optional[str] = None,
) -> None:
    """Run server setup with selected components.

    Args:
        ctx: Execution context
        docker: Install Docker with MTU fix
        security: Apply security hardening
        observability: Setup OpenTelemetry collector
        postgres: Setup PostgreSQL
        otlp_endpoint: OTLP endpoint for observability
        hostname: Set server hostname
    """
    components = []
    if docker:
        components.append("Docker")
    if security:
        components.append("Security")
    if observability:
        components.append("Observability")
    if postgres:
        components.append("PostgreSQL")
    if hostname:
        components.append(f"Hostname ({hostname})")

    if not components:
        ctx.console.warn("No components selected. Use --docker, --security, etc.")
        return

    ctx.console.print()
    ctx.console.print("[bold]Server Setup[/bold]")
    ctx.console.print(f"  Components: {', '.join(components)}")
    ctx.console.print()

    # Validate observability requirements
    if observability and not otlp_endpoint:
        raise SMError(
            message="Observability requires --otlp-endpoint",
            hint="Example: sm setup --observability --otlp-endpoint=http://signoz:4318",
            exit_code=2,
        )

    # Set hostname first
    if hostname:
        ctx.console.step(f"Setting hostname to {hostname}")
        if ctx.dry_run:
            ctx.console.dry_run(f"Would run: hostnamectl set-hostname {hostname}")
        else:
            import subprocess
            result = subprocess.run(
                ["hostnamectl", "set-hostname", hostname],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                ctx.console.warn(f"Failed to set hostname: {result.stderr}")
            else:
                ctx.console.success(f"Hostname set to {hostname}")

    # Docker
    if docker:
        ctx.console.step("Installing Docker")
        if ctx.dry_run:
            ctx.console.dry_run("Would run: sm docker install")
        else:
            from sm.commands.docker.install import run_install
            run_install(ctx, mtu=1450, skip_mtu_fix=False)

    # Security
    if security:
        ctx.console.step("Applying security hardening")
        if ctx.dry_run:
            ctx.console.dry_run("Would run: sm security harden")
        else:
            from sm.commands.security.harden import run_harden
            run_harden(ctx)

    # Observability
    if observability:
        ctx.console.step("Setting up observability")
        if ctx.dry_run:
            ctx.console.dry_run(f"Would run: sm observability setup --otlp-endpoint={otlp_endpoint}")
        else:
            from sm.commands.observability.setup import run_observability_setup
            run_observability_setup(
                ctx,
                otlp_endpoint=otlp_endpoint,
                otel_version="0.104.0",
                install_dir="/opt/otel-host",
                service_name="otel-host-metrics",
                collection_interval="10s",
                collect_logs=True,
                enable_cloud_detection=True,
            )

    # PostgreSQL
    if postgres:
        ctx.console.step("Setting up PostgreSQL")
        if ctx.dry_run:
            ctx.console.dry_run("Would run: sm postgres setup --skip-backup")
        else:
            from sm.commands.postgres.setup import run_setup as run_postgres_setup
            run_postgres_setup(
                ctx,
                pg_version="18",
                pgbouncer_config={
                    "port": 6432,
                    "pool_mode": "transaction",
                    "max_client_conn": 1000,
                    "default_pool_size": 20,
                },
                backup_config=None,
                skip_backup=True,
            )

    ctx.console.print()
    ctx.console.success("Server setup complete!")
