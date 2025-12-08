"""Firewall sync command.

Synchronizes SM state to iptables. This command is idempotent and can be
called:
- Manually when needed
- At boot via systemd service
- After Docker restart via systemd drop-in
"""

import os
import time
from typing import Annotated, Optional

import typer

from sm.core import (
    console,
    create_context,
    CommandExecutor,
    get_audit_logger,
    AuditEventType,
)
from sm.services.iptables import IptablesService
from sm.services.systemd import SystemdService


def sync(
    boot: Annotated[
        bool,
        typer.Option("--boot", help="Boot mode - wait for Docker if needed"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress non-error output"),
    ] = False,
    install_hooks: Annotated[
        bool,
        typer.Option("--install-hooks", help="Install systemd hooks for persistence"),
    ] = False,
    remove_hooks: Annotated[
        bool,
        typer.Option("--remove-hooks", help="Remove systemd hooks"),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", "-n", help="Show what would be done"),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
) -> None:
    """Synchronize SM firewall state to iptables.

    This command applies all rules from SM's state file to iptables.
    It's idempotent - rules that already exist are skipped.

    Use cases:
    - After Docker restart (rules in DOCKER-USER chain are lost)
    - At boot (before iptables-persistent or as replacement)
    - Manual sync after editing state file

    Examples:
        sm firewall sync              # Sync now
        sm firewall sync --boot       # Sync at boot (waits for Docker)
        sm firewall sync --install-hooks  # Install systemd auto-sync
    """
    # Check root
    if os.geteuid() != 0 and not dry_run:
        console.error("This operation requires root privileges")
        console.hint("Run with: sudo sm firewall sync ...")
        raise typer.Exit(6)

    ctx = create_context(
        dry_run=dry_run,
        verbose=verbose,
    )
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    iptables = IptablesService(ctx, executor, systemd)

    # Handle hook management
    if install_hooks:
        iptables.install_systemd_hooks()
        raise typer.Exit(0)

    if remove_hooks:
        iptables.remove_systemd_hooks()
        raise typer.Exit(0)

    # Boot mode: wait for Docker if it's starting
    if boot:
        _wait_for_docker(systemd, quiet)

    # Perform sync
    if not quiet:
        ctx.console.step("Synchronizing SM firewall state to iptables")

    try:
        applied = iptables.sync_state_to_iptables(quiet=quiet)

        if not quiet:
            if applied > 0:
                ctx.console.success(f"Synchronized {applied} rule(s) to iptables")
            else:
                ctx.console.info("All rules already in sync")

        # Log to audit
        audit = get_audit_logger()
        audit.log(
            AuditEventType.CONFIG_CHANGE,
            "firewall_sync",
            details={"rules_applied": applied, "boot_mode": boot},
        )

    except Exception as e:
        console.error(f"Sync failed: {e}")
        raise typer.Exit(1)


def _wait_for_docker(systemd: SystemdService, quiet: bool) -> None:
    """Wait for Docker to be ready (boot mode).

    Args:
        systemd: SystemdService instance
        quiet: Suppress output
    """
    # Only wait if Docker service exists
    if not systemd.exists("docker.service"):
        return

    max_wait = 30  # seconds
    waited = 0

    while waited < max_wait:
        if systemd.is_active("docker.service"):
            if not quiet:
                console.info("Docker is ready")
            # Give Docker a moment to create chains
            time.sleep(1)
            return

        if not quiet and waited == 0:
            console.info("Waiting for Docker to start...")

        time.sleep(1)
        waited += 1

    if not quiet:
        console.warn("Docker not ready after waiting, proceeding anyway")
