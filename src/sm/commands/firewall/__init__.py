"""Firewall management commands.

Provides comprehensive iptables firewall management with:
- Docker DOCKER-USER chain compatibility
- SSH always-allow safety mechanism
- Preset profiles (web, postgres, docker-swarm)
- Rule persistence across reboots
"""

import os
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.table import Table

from sm.core import (
    SMError,
    FirewallError,
    ValidationError,
    console,
    ExecutionContext,
    create_context,
    CommandExecutor,
    RollbackStack,
    get_audit_logger,
    AuditEventType,
)
from sm.services.iptables import (
    IptablesService,
    Protocol,
    Action,
    Chain,
    FirewallRule,
    PRESETS,
    validate_port,
    validate_source,
)
from sm.services.systemd import SystemdService
from sm.services.network import get_ssh_client_ip


def _parse_protocol(protocol: str) -> Protocol:
    """Parse and validate protocol string.

    Args:
        protocol: Protocol string (tcp, udp, etc.)

    Returns:
        Protocol enum value

    Raises:
        FirewallError: If protocol is invalid
    """
    try:
        return Protocol(protocol.lower())
    except ValueError:
        valid = ", ".join(p.value for p in Protocol)
        raise FirewallError(
            f"Invalid protocol: {protocol}",
            hint=f"Valid protocols: {valid}",
        )


# Create the firewall Typer app
app = typer.Typer(
    name="firewall",
    help="Manage iptables firewall rules with Docker compatibility.",
    no_args_is_help=True,
)

# Preset subcommand group
preset_app = typer.Typer(
    name="preset",
    help="Manage firewall presets.",
    no_args_is_help=True,
)
app.add_typer(preset_app, name="preset")


def _get_firewall_service(
    dry_run: bool = False,
    force: bool = False,
    yes: bool = False,
    verbose: int = 0,
    no_color: bool = False,
) -> tuple:
    """Create firewall service and context."""
    ctx = create_context(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
        no_color=no_color,
    )
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    iptables = IptablesService(ctx, executor, systemd)

    return ctx, iptables


def _check_root(ctx: ExecutionContext) -> None:
    """Check for root privileges."""
    if os.geteuid() != 0 and not ctx.dry_run:
        ctx.console.error("This operation requires root privileges")
        ctx.console.hint("Run with: sudo sm firewall ...")
        raise typer.Exit(6)


def _handle_error(error: SMError) -> None:
    """Handle an SMError by printing formatted error and exiting."""
    console.error(error.message)

    if error.details:
        for detail in error.details:
            console.print(f"  [dim]{detail}[/dim]")

    if error.hint:
        console.hint(error.hint)

    raise typer.Exit(error.exit_code)


# =============================================================================
# Status Command
# =============================================================================

@app.command("status")
def firewall_status(
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Show current firewall status and summary.

    Displays:
    - Firewall state (enabled/disabled)
    - Default policy
    - Docker compatibility status
    - Rule counts
    - Persistence status

    [bold]Examples:[/bold]

        sm firewall status
        sm firewall status -v
    """
    ctx, iptables = _get_firewall_service(verbose=verbose, no_color=no_color)

    try:
        status = iptables.status()

        ctx.console.print()
        ctx.console.print("[bold]Firewall Status[/bold]")
        ctx.console.print("=" * 40)
        ctx.console.print()

        # State
        state_color = "green" if status.active else "yellow"
        state_text = "Enabled (DROP)" if status.active else "Disabled (ACCEPT)"
        ctx.console.print(f"State:           [{state_color}]{state_text}[/{state_color}]")
        ctx.console.print(f"Default Policy:  {status.default_policy}")
        ctx.console.print()

        # Docker
        docker_status = "Active" if status.docker_detected else "Not detected"
        docker_user = "Configured" if status.docker_user_chain_exists else "Not configured"
        ctx.console.print(f"Docker:          {docker_status}")
        if status.docker_detected:
            ctx.console.print(f"DOCKER-USER:     {docker_user}")
        ctx.console.print()

        # Rules
        ctx.console.print(f"IPv4 Rules:      {status.ipv4_rules_count}")
        ctx.console.print(f"IPv6 Rules:      {status.ipv6_rules_count}")
        ctx.console.print()

        # Safety
        ssh_color = "green" if status.ssh_protected else "red"
        ssh_text = "Protected" if status.ssh_protected else "NOT PROTECTED"
        ctx.console.print(f"SSH Protection:  [{ssh_color}]{ssh_text}[/{ssh_color}]")
        ctx.console.print(f"SSH Port:        {iptables.ssh_port}")
        ctx.console.print()

        # Persistence
        persist_text = "Installed" if status.persistence_installed else "Not installed"
        ctx.console.print(f"Persistence:     {persist_text}")
        if status.last_saved:
            ctx.console.print(f"Last Saved:      {status.last_saved.strftime('%Y-%m-%d %H:%M:%S')}")
        ctx.console.print()

        ctx.console.hint("Use 'sm firewall list' for detailed rules")

    except SMError as e:
        _handle_error(e)


# =============================================================================
# List Command
# =============================================================================

@app.command("list")
def firewall_list(
    chain: Annotated[
        str,
        typer.Option("--chain", "-c", help="Chain to list (INPUT, DOCKER-USER, all)"),
    ] = "INPUT",
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """List all firewall rules in formatted table.

    [bold]Examples:[/bold]

        sm firewall list
        sm firewall list --chain DOCKER-USER
        sm firewall list --chain all
    """
    ctx, iptables = _get_firewall_service(verbose=verbose, no_color=no_color)

    try:
        chains_to_list = ["INPUT", "DOCKER-USER"] if chain == "all" else [chain]

        for chain_name in chains_to_list:
            try:
                chain_enum = Chain(chain_name)
            except ValueError:
                ctx.console.error(f"Invalid chain: {chain_name}")
                continue

            rules = iptables.list_rules(chain_enum)

            # Create table
            table = Table(title=f"{chain_name} Chain")
            table.add_column("#", style="dim")
            table.add_column("Proto", style="cyan")
            table.add_column("Port")
            table.add_column("Source")
            table.add_column("Action", style="bold")
            table.add_column("Description", style="dim")

            for rule in rules:
                action_color = "green" if rule.target == "ACCEPT" else "red"
                port_str = str(rule.port) if rule.port else "-"

                table.add_row(
                    str(rule.num),
                    rule.protocol,
                    port_str,
                    rule.source,
                    f"[{action_color}]{rule.target}[/{action_color}]",
                    rule.comment or "",
                )

            ctx.console.print()
            ctx.console.print(table)

        if not rules:
            ctx.console.info("No rules found")

    except SMError as e:
        _handle_error(e)


# =============================================================================
# Enable Command
# =============================================================================

@app.command("enable")
def firewall_enable(
    preset: Annotated[
        Optional[list[str]],
        typer.Option("--preset", "-p", help="Preset(s) to apply (web, postgres, docker-swarm)"),
    ] = None,
    allow: Annotated[
        Optional[list[int]],
        typer.Option("--allow", help="Additional ports to allow"),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without executing"),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompts"),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Enable firewall with DROP policy and apply presets.

    SSH access (port 22) is ALWAYS allowed for safety.

    [bold]Presets:[/bold]
    - web: HTTP (80), HTTPS (443)
    - postgres: PostgreSQL (5432), PgBouncer (6432) - internal only
    - docker-swarm: Swarm ports - internal only

    [bold]Examples:[/bold]

        # Enable with web preset
        sudo sm firewall enable --preset web

        # Multiple presets
        sudo sm firewall enable --preset web --preset postgres

        # With custom ports
        sudo sm firewall enable --preset web --allow 8080

        # Preview changes
        sm firewall enable --preset web --dry-run
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        yes=yes,
        verbose=verbose,
        no_color=no_color,
    )
    _check_root(ctx)
    audit = get_audit_logger()

    try:
        # Show configuration
        ctx.console.print()
        ctx.console.print("[bold]Firewall Configuration[/bold]")

        presets_to_apply = preset or []
        ctx.console.print(f"  Presets:  {', '.join(presets_to_apply) if presets_to_apply else 'None'}")
        ctx.console.print(f"  SSH:      Port {iptables.ssh_port} (always allowed, auto-detected)")

        if allow:
            ctx.console.print(f"  Custom:   Ports {', '.join(str(p) for p in allow)}")

        # Docker status
        if iptables.docker_detected():
            ctx.console.print(f"  Docker:   Detected - DOCKER-USER chain will be configured")

        ctx.console.print()

        # Confirmation
        if not yes and not dry_run:
            if not ctx.console.confirm("Enable firewall with these settings?"):
                ctx.console.warn("Operation cancelled")
                raise typer.Exit(0)

        # Create rollback stack
        rollback = RollbackStack()

        try:
            # Backup current rules
            iptables.backup(suffix="-pre-enable")

            # Ensure safety rules
            iptables.ensure_loopback_allowed()
            iptables.ensure_established_allowed()
            iptables.ensure_ssh_allowed()

            # Apply presets
            for preset_name in presets_to_apply:
                iptables.apply_preset(preset_name, rollback=rollback)

            # Apply custom ports
            if allow:
                for port in allow:
                    iptables.allow_port(port, rollback=rollback)

            # Set DROP policy
            iptables.set_default_policy("DROP")

            # Save rules
            iptables.save()

            # Install persistence
            iptables.install_persistence()

            # Success
            ctx.console.print()
            ctx.console.success("Firewall enabled!")

            audit.log_success(
                AuditEventType.FIREWALL_ENABLE,
                "firewall",
                "iptables",
                message=f"Firewall enabled with presets: {', '.join(presets_to_apply) or 'none'}",
            )

        except SMError as e:
            audit.log_failure(
                AuditEventType.FIREWALL_ENABLE,
                "firewall",
                "iptables",
                error=str(e),
            )
            if rollback.has_items():
                ctx.console.warn("Rolling back changes...")
                rollback.rollback_all()
            raise

    except SMError as e:
        _handle_error(e)


# =============================================================================
# Disable Command
# =============================================================================

@app.command("disable")
def firewall_disable(
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Allow dangerous operation"),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without executing"),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompts"),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Disable firewall by setting ACCEPT policy.

    [bold red]WARNING:[/bold red] This removes all firewall protection!

    Requires --force flag for safety.

    [bold]Examples:[/bold]

        sudo sm firewall disable --force
        sm firewall disable --force --dry-run
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
        no_color=no_color,
    )
    _check_root(ctx)
    audit = get_audit_logger()

    if not force:
        ctx.console.error("Disabling firewall requires --force flag")
        ctx.console.hint("This is a dangerous operation that removes all protection")
        raise typer.Exit(4)

    try:
        ctx.console.print()
        ctx.console.warn("This will disable all firewall protections!")
        ctx.console.print()

        # Show current status
        status = iptables.status()
        ctx.console.print(f"Current policy: {status.default_policy}")
        ctx.console.print(f"Current rules:  {status.ipv4_rules_count}")
        ctx.console.print()

        # Confirmation
        if not yes and not dry_run:
            if not ctx.console.confirm("Disable firewall?"):
                ctx.console.warn("Operation cancelled")
                raise typer.Exit(0)

        # Backup first
        iptables.backup(suffix="-pre-disable")

        # Flush and set ACCEPT
        iptables.flush(keep_ssh=True)

        # Save rules
        iptables.save()

        ctx.console.print()
        ctx.console.success("Firewall disabled")

        audit.log_success(
            AuditEventType.FIREWALL_DISABLE,
            "firewall",
            "iptables",
            message="Firewall disabled",
        )

    except SMError as e:
        audit.log_failure(
            AuditEventType.FIREWALL_DISABLE,
            "firewall",
            "iptables",
            error=str(e),
        )
        _handle_error(e)


# =============================================================================
# Allow Command
# =============================================================================

@app.command("allow")
def firewall_allow(
    port: Annotated[int, typer.Argument(help="Port number to allow")],
    protocol: Annotated[
        str,
        typer.Option("--protocol", "--proto", help="Protocol (tcp/udp)"),
    ] = "tcp",
    source: Annotated[
        str,
        typer.Option("--source", "-s", help="Source IP/CIDR (default: any)"),
    ] = "0.0.0.0/0",
    comment: Annotated[
        Optional[str],
        typer.Option("--comment", help="Rule description"),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without executing"),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Add rule to allow traffic on a port.

    [bold]Examples:[/bold]

        # Allow port 8080
        sudo sm firewall allow 8080

        # Allow from specific network
        sudo sm firewall allow 5432 --source 10.0.0.0/8

        # UDP port
        sudo sm firewall allow 53 --protocol udp

        # With description
        sudo sm firewall allow 3000 --comment "Dev server"
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        verbose=verbose,
        no_color=no_color,
    )
    _check_root(ctx)
    audit = get_audit_logger()

    try:
        # Validate inputs early
        validate_port(port)
        validate_source(source)
        proto = _parse_protocol(protocol)

        # Backup before making changes
        iptables.backup(suffix="-pre-allow")

        iptables.allow_port(
            port=port,
            protocol=proto,
            source=source,
            comment=comment,
        )

        iptables.save()

        ctx.console.print()
        ctx.console.success(f"Allowed {protocol.upper()}/{port}")

        audit.log_success(
            AuditEventType.FIREWALL_RULE_ADD,
            "firewall",
            f"{protocol}/{port}",
            message=f"Allowed {protocol.upper()}/{port} from {source}",
        )

    except SMError as e:
        audit.log_failure(
            AuditEventType.FIREWALL_RULE_ADD,
            "firewall",
            f"{protocol}/{port}",
            error=str(e),
        )
        _handle_error(e)


# =============================================================================
# Deny Command
# =============================================================================

@app.command("deny")
def firewall_deny(
    port: Annotated[int, typer.Argument(help="Port number to block")],
    protocol: Annotated[
        str,
        typer.Option("--protocol", "--proto", help="Protocol (tcp/udp)"),
    ] = "tcp",
    source: Annotated[
        str,
        typer.Option("--source", "-s", help="Source IP/CIDR (default: any)"),
    ] = "0.0.0.0/0",
    comment: Annotated[
        Optional[str],
        typer.Option("--comment", help="Rule description"),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Allow dangerous operation"),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without executing"),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Add rule to block traffic on a port.

    Requires --force flag. Cannot block SSH port (auto-detected from sshd_config).

    [bold]Examples:[/bold]

        # Block port 3306 (MySQL)
        sudo sm firewall deny 3306 --force

        # Block from specific IP
        sudo sm firewall deny 8080 --source 1.2.3.4 --force
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        force=force,
        verbose=verbose,
        no_color=no_color,
    )
    _check_root(ctx)
    audit = get_audit_logger()

    if not force:
        ctx.console.error("Blocking ports requires --force flag")
        raise typer.Exit(4)

    try:
        # Validate inputs early
        validate_port(port)
        validate_source(source)
        proto = _parse_protocol(protocol)

        # Backup before making changes
        iptables.backup(suffix="-pre-deny")

        iptables.deny_port(
            port=port,
            protocol=proto,
            source=source,
            comment=comment,
        )

        iptables.save()

        ctx.console.print()
        ctx.console.success(f"Blocked {protocol.upper()}/{port}")

        audit.log_success(
            AuditEventType.FIREWALL_RULE_ADD,
            "firewall",
            f"{protocol}/{port}",
            message=f"Blocked {protocol.upper()}/{port}",
        )

    except SMError as e:
        audit.log_failure(
            AuditEventType.FIREWALL_RULE_ADD,
            "firewall",
            f"{protocol}/{port}",
            error=str(e),
        )
        _handle_error(e)


# =============================================================================
# Save Command
# =============================================================================

@app.command("save")
def firewall_save(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without executing"),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Save current firewall rules to persist across reboots.

    [bold]Examples:[/bold]

        sudo sm firewall save
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        verbose=verbose,
        no_color=no_color,
    )
    _check_root(ctx)
    audit = get_audit_logger()

    try:
        iptables.save()
        iptables.install_persistence()

        ctx.console.print()
        ctx.console.success("Firewall rules saved and persistence configured")

        audit.log_success(
            AuditEventType.FIREWALL_SAVE,
            "firewall",
            "iptables",
            message="Firewall rules saved",
        )

    except SMError as e:
        audit.log_failure(
            AuditEventType.FIREWALL_SAVE,
            "firewall",
            "iptables",
            error=str(e),
        )
        _handle_error(e)


# =============================================================================
# Restore Command
# =============================================================================

@app.command("restore")
def firewall_restore(
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Allow dangerous operation"),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without executing"),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompts"),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Restore firewall rules from saved configuration.

    [bold]Examples:[/bold]

        sudo sm firewall restore --force
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
        no_color=no_color,
    )
    _check_root(ctx)
    audit = get_audit_logger()

    if not force:
        ctx.console.error("Restoring rules requires --force flag")
        raise typer.Exit(4)

    try:
        if not yes and not dry_run:
            if not ctx.console.confirm("Restore saved rules?"):
                ctx.console.warn("Operation cancelled")
                raise typer.Exit(0)

        iptables.restore()

        ctx.console.print()
        ctx.console.success("Firewall rules restored")

        audit.log_success(
            AuditEventType.FIREWALL_RESTORE,
            "firewall",
            "iptables",
            message="Firewall rules restored from saved configuration",
        )

    except SMError as e:
        audit.log_failure(
            AuditEventType.FIREWALL_RESTORE,
            "firewall",
            "iptables",
            error=str(e),
        )
        _handle_error(e)


# =============================================================================
# Reset Command
# =============================================================================

@app.command("reset")
def firewall_reset(
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Allow dangerous operation"),
    ] = False,
    confirm_name: Annotated[
        Optional[str],
        typer.Option("--confirm-name", help="Confirm resource name for critical operations"),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without executing"),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Reset firewall to default state (flush all rules).

    [bold red]CRITICAL:[/bold red] Removes ALL firewall rules!

    Requires --force and --confirm-name=firewall

    [bold]Examples:[/bold]

        sudo sm firewall reset --force --confirm-name=firewall
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        force=force,
        verbose=verbose,
        no_color=no_color,
    )
    _check_root(ctx)
    audit = get_audit_logger()

    if not force:
        ctx.console.error("Resetting firewall requires --force flag")
        raise typer.Exit(4)

    if confirm_name != "firewall":
        ctx.console.error("Must confirm with --confirm-name=firewall")
        raise typer.Exit(4)

    try:
        ctx.console.print()
        ctx.console.warn("This will remove ALL firewall rules!")
        ctx.console.print()

        # Backup first
        backup_path = iptables.backup(suffix="-pre-reset")
        ctx.console.info(f"Backup created: {backup_path}")

        # Flush all rules
        iptables.flush(keep_ssh=True)

        # Save the clean state
        iptables.save()

        ctx.console.print()
        ctx.console.success("Firewall reset to default state")
        ctx.console.info("SSH access is still allowed for safety")

        audit.log_success(
            AuditEventType.FIREWALL_RESET,
            "firewall",
            "iptables",
            message="Firewall reset to default state",
        )

    except SMError as e:
        audit.log_failure(
            AuditEventType.FIREWALL_RESET,
            "firewall",
            "iptables",
            error=str(e),
        )
        _handle_error(e)


# =============================================================================
# Preset Commands
# =============================================================================

@preset_app.command("list")
def preset_list(
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """List available firewall presets.

    [bold]Examples:[/bold]

        sm firewall preset list
    """
    ctx, iptables = _get_firewall_service(verbose=verbose, no_color=no_color)

    ctx.console.print()
    ctx.console.print("[bold]Available Presets[/bold]")
    ctx.console.print()

    table = Table()
    table.add_column("Name", style="bold cyan")
    table.add_column("Description")
    table.add_column("Docker Aware", style="dim")

    for name, preset in PRESETS.items():
        docker = "Yes" if preset.docker_aware else "No"
        table.add_row(name, preset.description, docker)

    ctx.console.print(table)
    ctx.console.print()
    ctx.console.hint("Use 'sm firewall preset show <name>' for details")


@preset_app.command("show")
def preset_show(
    name: Annotated[str, typer.Argument(help="Preset name")],
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Show detailed preset configuration.

    [bold]Examples:[/bold]

        sm firewall preset show web
        sm firewall preset show postgres
    """
    ctx, iptables = _get_firewall_service(verbose=verbose, no_color=no_color)

    try:
        preset = iptables.get_preset(name)

        ctx.console.print()
        ctx.console.print(f"[bold]Preset: {preset.name}[/bold]")
        ctx.console.print(f"Description: {preset.description}")
        if preset.docker_aware:
            ctx.console.print("Docker: Will configure DOCKER-USER chain")
        ctx.console.print()

        if preset.rules:
            table = Table(title="Rules")
            table.add_column("Protocol", style="cyan")
            table.add_column("Port")
            table.add_column("Source")
            table.add_column("Action", style="green")
            table.add_column("Description", style="dim")

            for rule in preset.rules:
                table.add_row(
                    rule.protocol.value,
                    str(rule.port) if rule.port else "-",
                    rule.source,
                    rule.action.value,
                    rule.comment or "",
                )

            ctx.console.print(table)
        else:
            ctx.console.info("No rules defined (preset may generate rules dynamically)")

    except SMError as e:
        _handle_error(e)


@preset_app.command("apply")
def preset_apply(
    names: Annotated[list[str], typer.Argument(help="Preset name(s) to apply")],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without executing"),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompts"),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity"),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Apply preset configuration(s).

    [bold]Examples:[/bold]

        sudo sm firewall preset apply web
        sudo sm firewall preset apply web postgres
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        yes=yes,
        verbose=verbose,
        no_color=no_color,
    )
    _check_root(ctx)
    audit = get_audit_logger()

    try:
        # Validate presets first
        for name in names:
            iptables.get_preset(name)  # Will raise if invalid

        ctx.console.print()
        ctx.console.print(f"[bold]Applying presets:[/bold] {', '.join(names)}")
        ctx.console.print()

        if not yes and not dry_run:
            if not ctx.console.confirm("Apply these presets?"):
                ctx.console.warn("Operation cancelled")
                raise typer.Exit(0)

        # Backup before making changes
        iptables.backup(suffix="-pre-preset")

        rollback = RollbackStack()

        try:
            for name in names:
                iptables.apply_preset(name, rollback=rollback)

            iptables.save()

            ctx.console.print()
            ctx.console.success(f"Applied presets: {', '.join(names)}")

            audit.log_success(
                AuditEventType.FIREWALL_PRESET_APPLY,
                "firewall",
                ",".join(names),
                message=f"Applied presets: {', '.join(names)}",
            )

        except SMError as e:
            audit.log_failure(
                AuditEventType.FIREWALL_PRESET_APPLY,
                "firewall",
                ",".join(names),
                error=str(e),
            )
            if rollback.has_items():
                ctx.console.warn("Rolling back changes...")
                rollback.rollback_all()
            raise

    except SMError as e:
        _handle_error(e)
