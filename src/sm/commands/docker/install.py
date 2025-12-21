"""Docker installation functionality.

Installs Docker and applies MTU configuration for Hetzner Cloud.
"""

import subprocess
from sm.core.context import ExecutionContext
from sm.core.exceptions import SMError
from sm.core.audit import get_audit_logger, AuditEventType


def run_install(ctx: ExecutionContext, mtu: int = 1450, skip_mtu_fix: bool = False) -> None:
    """Install Docker with optional MTU fix.

    Args:
        ctx: Execution context
        mtu: MTU value for overlay networks (default 1450 for Hetzner)
        skip_mtu_fix: Skip MTU configuration
    """
    audit = get_audit_logger()

    # Check if Docker is already installed
    docker_exists = subprocess.run(
        ["which", "docker"],
        capture_output=True,
    ).returncode == 0

    if docker_exists:
        ctx.console.info("Docker is already installed")
        # Still apply MTU fix if needed
        if not skip_mtu_fix:
            ctx.console.info("Applying MTU configuration...")
            from sm.commands.docker.fix_mtu import run_fix_mtu
            run_fix_mtu(ctx, mtu)
        return

    try:
        # Step 1: Install Docker
        ctx.console.step("Installing Docker via get.docker.com")

        if ctx.dry_run:
            ctx.console.dry_run_msg("Would run: curl -fsSL https://get.docker.com | sh")
        else:
            result = subprocess.run(
                ["bash", "-c", "curl -fsSL https://get.docker.com | sh"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise SMError(
                    message="Failed to install Docker",
                    details=[result.stderr] if result.stderr else None,
                    hint="Check network connectivity and try again",
                    exit_code=1,
                )

        # Step 2: Apply MTU fix (before starting Docker for clean config)
        if not skip_mtu_fix:
            ctx.console.step(f"Configuring MTU {mtu} for overlay networks")
            from sm.commands.docker.fix_mtu import run_fix_mtu
            run_fix_mtu(ctx, mtu)

        # Step 3: Enable and start Docker
        ctx.console.step("Enabling Docker service")

        if ctx.dry_run:
            ctx.console.dry_run_msg("Would run: systemctl enable docker")
            ctx.console.dry_run_msg("Would run: systemctl start docker")
        else:
            # Enable
            result = subprocess.run(
                ["systemctl", "enable", "docker"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                ctx.console.warn(f"Failed to enable Docker: {result.stderr}")

            # Start
            result = subprocess.run(
                ["systemctl", "start", "docker"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise SMError(
                    message="Failed to start Docker",
                    details=[result.stderr] if result.stderr else None,
                    hint="Check systemctl status docker for details",
                    exit_code=1,
                )

        # Verify
        ctx.console.step("Verifying Docker installation")

        if ctx.dry_run:
            ctx.console.dry_run_msg("Would run: docker --version")
        else:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                ctx.console.success(f"Docker installed: {result.stdout.strip()}")
            else:
                ctx.console.warn("Docker installed but version check failed")

        ctx.console.success("Docker installation complete")

        # Audit log success
        audit.log_success(
            AuditEventType.CONFIG_MODIFY,
            "docker",
            "install",
            message=f"Docker installed with MTU={mtu}" if not skip_mtu_fix else "Docker installed",
        )

    except SMError as e:
        # Audit log failure
        audit.log_failure(
            AuditEventType.CONFIG_MODIFY,
            "docker",
            "install",
            error=str(e),
        )
        raise
