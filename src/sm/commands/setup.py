"""Server setup command.

One command to configure all server components.
"""

import subprocess
from typing import Optional

from sm.core.context import ExecutionContext
from sm.core.exceptions import SMError
from sm.core.safety import run_preflight_checks
from sm.core.audit import get_audit_logger, AuditEventType


def run_setup(
    ctx: ExecutionContext,
    docker: bool = False,
    security: bool = False,
    observability: bool = False,
    postgres: bool = False,
    mongodb: bool = False,
    otlp_endpoint: Optional[str] = None,
    hostname: Optional[str] = None,
    mtu: Optional[int] = None,
) -> None:
    """Run server setup with selected components.

    Args:
        ctx: Execution context
        docker: Install Docker with MTU fix
        security: Apply security hardening
        observability: Setup OpenTelemetry collector
        postgres: Setup PostgreSQL
        mongodb: Setup MongoDB 7.0
        otlp_endpoint: OTLP endpoint for observability
        hostname: Set server hostname
        mtu: Docker MTU value (default 1450 for Hetzner)
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
    if mongodb:
        components.append("MongoDB")
    if hostname:
        components.append(f"Hostname ({hostname})")

    if not components:
        ctx.console.warn("No components selected. Use --docker, --security, etc.")
        return

    audit = get_audit_logger()

    ctx.console.print()
    ctx.console.print("[bold]Server Setup[/bold]")
    ctx.console.print(f"  Components: {', '.join(components)}")
    ctx.console.print()

    try:
        # Run preflight checks
        if not ctx.dry_run:
            ctx.console.step("Running preflight checks")
            run_preflight_checks(dry_run=ctx.dry_run)
            ctx.console.success("Preflight checks passed")
        else:
            ctx.console.dry_run_msg("Would run preflight checks (root, OS, disk space)")

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
                ctx.console.dry_run_msg(f"Would run: hostnamectl set-hostname {hostname}")
            else:
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
            docker_mtu = mtu if mtu is not None else 1450
            if ctx.dry_run:
                ctx.console.dry_run_msg(f"Would run: sm docker install --mtu={docker_mtu}")
            else:
                from sm.commands.docker.install import run_install
                run_install(ctx, mtu=docker_mtu, skip_mtu_fix=False)
                # Verify Docker is working
                result = subprocess.run(
                    ["docker", "info"],
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    ctx.console.success("Docker verified and running")
                else:
                    ctx.console.warn("Docker installed but verification failed")

        # Security
        if security:
            ctx.console.step("Applying security hardening")
            if ctx.dry_run:
                ctx.console.dry_run_msg("Would run: sm security harden")
            else:
                from sm.commands.security.harden import run_harden
                run_harden(ctx)

        # Observability
        if observability:
            ctx.console.step("Setting up observability")
            if ctx.dry_run:
                ctx.console.dry_run_msg(f"Would run: sm observability setup --otlp-endpoint={otlp_endpoint}")
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
                # Verify OTEL collector is running
                result = subprocess.run(
                    ["systemctl", "is-active", "otel-host-metrics"],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    ctx.console.success("OTEL collector verified and running")
                else:
                    ctx.console.warn("OTEL collector installed but may need time to start")

        # PostgreSQL
        if postgres:
            ctx.console.step("Setting up PostgreSQL")
            if ctx.dry_run:
                ctx.console.dry_run_msg("Would run: sm postgres setup --skip-backup")
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
                # Verify PostgreSQL is accepting connections
                result = subprocess.run(
                    ["pg_isready", "-h", "127.0.0.1", "-p", "5432"],
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    ctx.console.success("PostgreSQL verified and accepting connections")
                else:
                    ctx.console.warn("PostgreSQL installed but may need time to start")

        # MongoDB
        if mongodb:
            ctx.console.step("Setting up MongoDB 7.0")
            if ctx.dry_run:
                ctx.console.dry_run_msg("Would run: sm mongodb setup")
            else:
                from sm.commands.mongodb.setup import run_setup as run_mongodb_setup
                run_mongodb_setup(ctx)
                # Verify MongoDB is accepting connections
                result = subprocess.run(
                    ["mongosh", "--quiet", "--eval", "db.adminCommand('ping')",
                     "mongodb://127.0.0.1:27017/admin"],
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    ctx.console.success("MongoDB verified and accepting connections")
                else:
                    ctx.console.warn("MongoDB installed but may need time to start")

        ctx.console.print()
        ctx.console.success("Server setup complete!")

        # Audit log success
        audit.log_success(
            AuditEventType.CONFIG_MODIFY,
            "server",
            "setup",
            message=f"Server setup completed: {', '.join(components)}",
        )

    except SMError as e:
        # Audit log failure
        audit.log_failure(
            AuditEventType.CONFIG_MODIFY,
            "server",
            "setup",
            error=str(e),
        )
        raise
