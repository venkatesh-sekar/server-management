"""Firewall exclusive mode command.

Manages SM's exclusive firewall mode, which disables and masks other
firewall management tools (UFW, firewalld) to prevent conflicts.
"""

import os
from typing import Annotated

import typer
from rich.table import Table

from sm.core import (
    console,
    create_context,
    CommandExecutor,
    get_audit_logger,
    AuditEventType,
)
from sm.services.iptables import IptablesService, detect_firewall_providers
from sm.services.systemd import SystemdService
from sm.services.firewall_state import EXCLUSIVE_MARKER


def exclusive(
    enable: Annotated[
        bool,
        typer.Option("--enable", help="Enable exclusive mode (disable UFW/firewalld)"),
    ] = False,
    disable: Annotated[
        bool,
        typer.Option("--disable", help="Disable exclusive mode (unmask services)"),
    ] = False,
    status: Annotated[
        bool,
        typer.Option("--status", "-s", help="Show exclusive mode status"),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", "-n", help="Show what would be done"),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Force operation even with warnings"),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
) -> None:
    """Manage SM exclusive firewall mode.

    When exclusive mode is enabled:
    - UFW is stopped, disabled, and masked
    - firewalld is stopped, disabled, and masked
    - SM becomes the only firewall manager
    - Other tools cannot accidentally be started

    When disabled:
    - Services are unmasked (but not re-enabled)
    - You can manually re-enable UFW/firewalld if needed

    Examples:
        sm firewall exclusive --status    # Check current status
        sm firewall exclusive --enable    # Make SM exclusive
        sm firewall exclusive --disable   # Allow other tools again
    """
    # Default to status if no action specified
    if not enable and not disable:
        status = True

    # Check root for enable/disable
    if (enable or disable) and os.geteuid() != 0 and not dry_run:
        console.error("This operation requires root privileges")
        console.hint("Run with: sudo sm firewall exclusive ...")
        raise typer.Exit(6)

    ctx = create_context(
        dry_run=dry_run,
        force=force,
        verbose=verbose,
    )
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    iptables = IptablesService(ctx, executor, systemd)

    if status:
        _show_status(iptables, systemd)
        return

    if enable:
        _enable_exclusive(iptables, systemd, ctx)
    elif disable:
        _disable_exclusive(iptables, systemd, ctx)


def _show_status(iptables: IptablesService, systemd: SystemdService) -> None:
    """Show exclusive mode status."""
    state = iptables.state_manager.state
    provider_status = detect_firewall_providers()

    table = Table(title="Exclusive Mode Status", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    # Exclusive mode
    is_exclusive = EXCLUSIVE_MARKER.exists() or state.exclusive_mode
    table.add_row(
        "Exclusive Mode",
        "[green]Enabled[/green]" if is_exclusive else "[yellow]Disabled[/yellow]"
    )

    # Marker file
    table.add_row(
        "Marker File",
        "[green]Present[/green]" if EXCLUSIVE_MARKER.exists() else "[dim]Not present[/dim]"
    )

    console.print(table)
    console.print()

    # Other providers table
    providers_table = Table(title="Other Firewall Providers", show_header=True)
    providers_table.add_column("Provider", style="cyan")
    providers_table.add_column("Installed")
    providers_table.add_column("Status")
    providers_table.add_column("Masked")

    # UFW
    ufw_installed = provider_status.ufw_installed
    ufw_active = provider_status.ufw_active
    ufw_masked = systemd.is_masked("ufw") if ufw_installed else False

    providers_table.add_row(
        "UFW",
        "[green]Yes[/green]" if ufw_installed else "[dim]No[/dim]",
        "[red]Active[/red]" if ufw_active else "[green]Inactive[/green]",
        "[green]Masked[/green]" if ufw_masked else "[dim]Not masked[/dim]",
    )

    # firewalld
    firewalld_installed = provider_status.firewalld_installed
    firewalld_active = provider_status.firewalld_active
    firewalld_masked = systemd.is_masked("firewalld") if firewalld_installed else False

    providers_table.add_row(
        "firewalld",
        "[green]Yes[/green]" if firewalld_installed else "[dim]No[/dim]",
        "[red]Active[/red]" if firewalld_active else "[green]Inactive[/green]",
        "[green]Masked[/green]" if firewalld_masked else "[dim]Not masked[/dim]",
    )

    console.print(providers_table)

    # Warnings
    if ufw_active or firewalld_active:
        console.print()
        console.warn("Other firewall providers are active!")
        console.hint("Run 'sm firewall exclusive --enable' to disable them")


def _enable_exclusive(iptables: IptablesService, systemd: SystemdService, ctx) -> None:
    """Enable exclusive mode."""
    ctx.console.step("Enabling exclusive firewall mode")

    provider_status = detect_firewall_providers()
    audit = get_audit_logger()

    # Stop and mask UFW if installed
    if provider_status.ufw_installed:
        if provider_status.ufw_active:
            ctx.console.step("Stopping UFW")
            if not ctx.dry_run:
                # UFW has its own disable command
                import subprocess
                subprocess.run(["ufw", "disable"], capture_output=True)

        if not systemd.is_masked("ufw"):
            systemd.disable("ufw", stop=True, description="Disabling UFW")
            systemd.mask("ufw", description="Masking UFW")

    # Stop and mask firewalld if installed
    if provider_status.firewalld_installed:
        if provider_status.firewalld_active:
            systemd.stop("firewalld", description="Stopping firewalld")

        if not systemd.is_masked("firewalld"):
            systemd.disable("firewalld", stop=True, description="Disabling firewalld")
            systemd.mask("firewalld", description="Masking firewalld")

    # Update state
    iptables.state_manager.set_exclusive_mode(True)
    iptables.state_manager.save()

    # Log to audit
    audit.log(
        AuditEventType.CONFIG_CHANGE,
        "firewall_exclusive_enabled",
        details={
            "ufw_was_active": provider_status.ufw_active,
            "firewalld_was_active": provider_status.firewalld_active,
        },
    )

    ctx.console.success("Exclusive mode enabled - SM is now the only firewall manager")
    ctx.console.hint("Other firewall tools have been masked and cannot be started")


def _disable_exclusive(iptables: IptablesService, systemd: SystemdService, ctx) -> None:
    """Disable exclusive mode."""
    ctx.console.step("Disabling exclusive firewall mode")

    provider_status = detect_firewall_providers()
    audit = get_audit_logger()

    # Unmask UFW if it was masked
    if provider_status.ufw_installed and systemd.is_masked("ufw"):
        systemd.unmask("ufw", description="Unmasking UFW")

    # Unmask firewalld if it was masked
    if provider_status.firewalld_installed and systemd.is_masked("firewalld"):
        systemd.unmask("firewalld", description="Unmasking firewalld")

    # Update state
    iptables.state_manager.set_exclusive_mode(False)
    iptables.state_manager.save()

    # Log to audit
    audit.log(
        AuditEventType.CONFIG_CHANGE,
        "firewall_exclusive_disabled",
    )

    ctx.console.success("Exclusive mode disabled")
    ctx.console.warn("UFW and firewalld are unmasked but not enabled")
    ctx.console.hint("You can manually enable them if needed, but this may cause conflicts")
