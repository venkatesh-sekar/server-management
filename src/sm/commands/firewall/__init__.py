"""Firewall management commands.

Provides comprehensive iptables firewall management with:
- Docker DOCKER-USER chain compatibility
- SSH always-allow safety mechanism
- Preset profiles (web, postgres, docker-swarm)
- Rule persistence across reboots
- State management (SM as source of truth)
- Fail2ban coexistence
- Exclusive mode (disable other firewall tools)
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
    detect_firewall_providers,
)
from sm.services.systemd import SystemdService
from sm.services.network import get_ssh_client_ip
from sm.services.firewall_services import (
    resolve_service,
    resolve_source,
    get_source_definition,
    is_port_number,
    format_source_for_display,
    SERVICES,
    SOURCE_ALIASES,
)


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
    technical: Annotated[
        bool,
        typer.Option("--technical", "-t", help="Show technical details"),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """Show current firewall status.

    Shows what traffic is allowed through your firewall in an easy-to-read format.

    [bold]Examples:[/bold]

        sm firewall status
        sm firewall status --technical   # Show technical details
    """
    ctx, iptables = _get_firewall_service(verbose=verbose, no_color=no_color)

    try:
        status = iptables.status()

        ctx.console.print()
        ctx.console.print("[bold]Firewall Status[/bold]")
        ctx.console.print()

        # Main status - simple and clear
        if status.active:
            ctx.console.print("  Protection:  [green]ENABLED[/green]")
            ctx.console.print()
            ctx.console.print("  Your server is protected. Only allowed traffic can get through.")
        else:
            ctx.console.print("  Protection:  [yellow]DISABLED[/yellow]")
            ctx.console.print()
            ctx.console.print("  [yellow]Your server accepts ALL traffic![/yellow]")
            ctx.console.print("  Run [bold]sm firewall setup[/bold] to enable protection.")

        ctx.console.print()

        # Show what's allowed
        rules = iptables.list_rules(Chain.INPUT)

        # Find ports that are blocked (DROP rule comes before any ACCEPT for that port)
        # Rules are processed in order - first matching rule wins
        blocked_ports: set[tuple[int, str]] = set()  # (port, protocol)
        seen_ports: set[tuple[int, str]] = set()
        for rule in rules:
            if not rule.port:
                continue
            port_key = (rule.port, (rule.protocol or "tcp").lower())
            if port_key in seen_ports:
                continue
            seen_ports.add(port_key)
            # First rule for this port determines if it's blocked or allowed
            if rule.target == "DROP":
                blocked_ports.add(port_key)

        # Filter ACCEPT rules, excluding ports that have a DROP rule first
        accept_rules = [
            r for r in rules
            if r.target == "ACCEPT"
            and r.port
            and (r.port, (r.protocol or "tcp").lower()) not in blocked_ports
        ]

        if accept_rules:
            ctx.console.print("[bold]Allowed Traffic:[/bold]")
            ctx.console.print()

            # Group by port and format nicely
            from sm.services.firewall_services import get_service_by_port

            displayed_ports = set()
            for rule in accept_rules:
                if rule.port in displayed_ports:
                    continue
                displayed_ports.add(rule.port)

                # Try to find service name
                try:
                    proto = Protocol(rule.protocol.lower()) if rule.protocol else Protocol.TCP
                    service = get_service_by_port(rule.port, proto)
                except (ValueError, KeyError):
                    service = None

                if service:
                    name = f"{service.display_name} ({rule.port})"
                else:
                    name = f"Port {rule.port}/{rule.protocol or 'tcp'}"

                # Format source
                source_display = format_source_for_display(rule.source)

                # Check if it's SSH (protected)
                is_ssh = rule.port == iptables.ssh_port
                ssh_marker = " [dim][protected][/dim]" if is_ssh else ""

                ctx.console.print(f"  {name:30} from {source_display}{ssh_marker}")

            ctx.console.print()

        # Show explicitly blocked ports (if any DROP rules exist)
        drop_rules = [r for r in rules if r.target == "DROP" and r.port]
        if drop_rules:
            ctx.console.print("[bold]Blocked Traffic:[/bold]")
            ctx.console.print()

            displayed_blocked: set[int] = set()
            for rule in drop_rules:
                if rule.port in displayed_blocked:
                    continue
                displayed_blocked.add(rule.port)

                name = f"Port {rule.port}/{rule.protocol or 'tcp'}"
                source_display = format_source_for_display(rule.source)
                ctx.console.print(f"  {name:30} from {source_display}")

            ctx.console.print()

        # Show what's blocked
        if status.active:
            ctx.console.print("  [dim]Everything else is BLOCKED[/dim]")
            ctx.console.print()

        # Docker status (simplified)
        if status.docker_detected:
            ctx.console.print(f"  Docker:      Detected - container traffic is protected")
            ctx.console.print()

        # Technical details (only if requested)
        if technical or verbose > 0:
            ctx.console.print("[bold]Technical Details:[/bold]")
            ctx.console.print()
            ctx.console.print(f"  Default Policy:  {status.default_policy}")
            ctx.console.print(f"  IPv4 Rules:      {status.ipv4_rules_count}")
            ctx.console.print(f"  IPv6 Rules:      {status.ipv6_rules_count}")
            ctx.console.print(f"  SSH Port:        {iptables.ssh_port}")

            ssh_color = "green" if status.ssh_protected else "red"
            ssh_text = "Yes" if status.ssh_protected else "NO!"
            ctx.console.print(f"  SSH Protected:   [{ssh_color}]{ssh_text}[/{ssh_color}]")

            persist_text = "Yes" if status.persistence_installed else "No"
            ctx.console.print(f"  Persistence:     {persist_text}")

            if status.last_saved:
                ctx.console.print(f"  Last Saved:      {status.last_saved.strftime('%Y-%m-%d %H:%M:%S')}")

            if status.docker_detected:
                docker_user = "Yes" if status.docker_user_chain_exists else "No"
                ctx.console.print(f"  DOCKER-USER:     {docker_user}")

            # Check for other firewall providers
            providers = iptables.get_provider_status()
            if providers.has_conflicts:
                conflicts = ", ".join(providers.conflict_names)
                ctx.console.print()
                ctx.console.print(f"  [bold red]WARNING:[/bold red] Other firewalls active: {conflicts}")
            if providers.nftables_active:
                ctx.console.print(f"  Backend:         iptables-nft")

            ctx.console.print()

        ctx.console.hint("Use 'sm firewall list' for all rules, or 'sm firewall setup' to configure")

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
    ] = "all",
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

        # Print explanation header
        ctx.console.print()
        ctx.console.print("[bold]Firewall Rules[/bold]")
        ctx.console.print()
        ctx.console.print("[dim]How to read this table:[/dim]")
        ctx.console.print("  [cyan]#[/cyan]        Rule number (order matters - first match wins)")
        ctx.console.print("  [cyan]Proto[/cyan]    Protocol: tcp, udp, icmp, or all")
        ctx.console.print("  [cyan]Port[/cyan]     Port number (- means all ports)")
        ctx.console.print("  [cyan]Source[/cyan]   Who can connect: IP address or 0.0.0.0/0 (anyone)")
        ctx.console.print("  [cyan]Match[/cyan]    Extra criteria: interface (lo), connection state, etc.")
        ctx.console.print("  [cyan]Action[/cyan]   [green]ACCEPT[/green] = allow, [red]DROP[/red] = block silently, [yellow]f2b-*[/yellow] = fail2ban check")
        ctx.console.print()

        for chain_name in chains_to_list:
            try:
                chain_enum = Chain(chain_name)
            except ValueError:
                ctx.console.error(f"Invalid chain: {chain_name}")
                continue

            rules = iptables.list_rules(chain_enum)

            # Explain what this chain does
            if chain_name == "INPUT":
                chain_desc = "Controls traffic coming INTO your server"
            elif chain_name == "DOCKER-USER":
                chain_desc = "Controls traffic to Docker containers (processed before Docker's own rules)"
            else:
                chain_desc = ""

            # Create table
            table = Table(title=f"{chain_name} Chain", caption=chain_desc if chain_desc else None)
            table.add_column("#", style="dim", justify="right")
            table.add_column("Proto", style="cyan")
            table.add_column("Port", justify="right")
            table.add_column("Source")
            table.add_column("Match", style="dim")  # Technical matching criteria
            table.add_column("Action", style="bold")
            table.add_column("Description", style="dim")

            for rule in rules:
                # Determine action color based on target
                if rule.target == "ACCEPT":
                    action_color = "green"
                elif rule.target in ("DROP", "REJECT"):
                    action_color = "red"
                elif rule.is_chain_jump:
                    action_color = "yellow"  # Chain jumps in yellow
                else:
                    action_color = "dim"

                port_str = str(rule.port) if rule.port else "-"

                # Make source more readable
                source_display = rule.source
                if rule.source == "0.0.0.0/0":
                    source_display = "anywhere"
                elif rule.source == "127.0.0.1" or rule.source == "127.0.0.0/8":
                    source_display = "localhost"

                # Human-readable description
                description = rule.comment or rule.action_description or ""

                # Technical matching criteria (interface, state, etc.)
                match_criteria = rule.technical_details or ""

                table.add_row(
                    str(rule.num),
                    rule.protocol,
                    port_str,
                    source_display,
                    match_criteria,
                    f"[{action_color}]{rule.display_action}[/{action_color}]",
                    description,
                )

            ctx.console.print(table)
            ctx.console.print()

        if not rules:
            ctx.console.info("No rules found")
        else:
            # Print helpful footer
            ctx.console.print("[dim]─────────────────────────────────────────────────────────────[/dim]")
            ctx.console.print()
            ctx.console.print("[bold]What does this mean?[/bold]")
            ctx.console.print()
            ctx.console.print("  Rules are processed top-to-bottom. The first matching rule wins.")
            ctx.console.print("  Traffic that doesn't match any rule uses the chain's default policy.")
            ctx.console.print()
            ctx.console.print("[bold]Common patterns:[/bold]")
            ctx.console.print("  • [green]ACCEPT[/green] tcp port 22 from anywhere  → SSH access allowed")
            ctx.console.print("  • [green]ACCEPT[/green] tcp port 80 from anywhere  → Web traffic allowed")
            ctx.console.print("  • [green]ACCEPT[/green] tcp port 5432 from 10.x.x.x → Database access from internal network only")
            ctx.console.print("  • [red]DROP[/red] all from anywhere            → Block everything else")
            ctx.console.print()
            ctx.console.hint("Use 'sm firewall status' for a simpler overview")

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
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Proceed even if other firewall providers are active"),
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
        force=force,
        yes=yes,
        verbose=verbose,
        no_color=no_color,
    )
    _check_root(ctx)
    audit = get_audit_logger()

    try:
        # Check for conflicting firewall providers
        iptables.check_provider_conflicts(force=force)

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

            # Initialize state manager and set Docker awareness
            if iptables.docker_detected():
                iptables.state_manager.set_docker_aware(True)

            # Apply presets and save rules to state
            for preset_name in presets_to_apply:
                preset = iptables.get_preset(preset_name)
                for rule in preset.rules:
                    iptables.add_rule(rule, rollback=rollback)
                    # Save to state
                    iptables.save_rule_to_state(rule)

            # Apply custom ports and save to state
            if allow:
                for port in allow:
                    rule = FirewallRule(
                        port=port,
                        protocol=Protocol.TCP,
                        source="0.0.0.0/0",
                        action=Action.ACCEPT,
                        comment=f"Allow TCP/{port}",
                    )
                    iptables.add_rule(rule, rollback=rollback)
                    iptables.save_rule_to_state(rule)

            # Set DROP policy (includes safety rules: loopback, established, SSH, ICMP)
            iptables.set_default_policy("DROP")

            # Save SSH rule to state as protected
            ssh_rule = FirewallRule(
                port=iptables.ssh_port,
                protocol=Protocol.TCP,
                source="0.0.0.0/0",
                action=Action.ACCEPT,
                comment="SSH always allowed (sm safety)",
            )
            iptables.save_rule_to_state(ssh_rule, protected=True)

            # Save rules to persistent storage
            iptables.save()

            # Save SM state file
            iptables.state_manager.save()

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

        # Save rules to persistent storage
        iptables.save()

        # Clear SM state (but keep protected rules like SSH)
        iptables.state_manager.clear_rules(keep_protected=True)
        iptables.state_manager.save()

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
    target: Annotated[
        str,
        typer.Argument(help="Service name (web, postgres) or port number (8080)"),
    ],
    from_source: Annotated[
        Optional[str],
        typer.Option(
            "--from", "-f",
            help="Who can connect: anywhere, local-network, this-machine, or IP/CIDR",
        ),
    ] = None,
    source: Annotated[
        Optional[str],
        typer.Option("--source", "-s", hidden=True, help="Alias for --from"),
    ] = None,
    protocol: Annotated[
        str,
        typer.Option("--protocol", "--proto", help="Protocol (tcp/udp) - only for port numbers"),
    ] = "tcp",
    comment: Annotated[
        Optional[str],
        typer.Option("--comment", help="Rule description"),
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
    """Allow a service or port through the firewall.

    [bold]Services:[/bold]
    web, http, https, postgres, mysql, redis, ssh, dns, docker-swarm, mail

    [bold]Access Sources (--from):[/bold]
    - anywhere: Any IP address (use for public services)
    - local-network: Only private/internal networks
    - this-machine: Only localhost
    - IP/CIDR: Specific address (e.g., 10.0.0.0/8)

    [bold]Examples:[/bold]

        # Allow web traffic from anywhere
        sudo sm firewall allow web

        # Allow PostgreSQL from local network only
        sudo sm firewall allow postgres --from local-network

        # Allow custom port
        sudo sm firewall allow 8080 --from anywhere

        # Allow from specific IP
        sudo sm firewall allow postgres --from 10.0.0.5

        # Legacy syntax still works
        sudo sm firewall allow 5432 --source 10.0.0.0/8
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        yes=yes,
        verbose=verbose,
        no_color=no_color,
    )
    _check_root(ctx)
    audit = get_audit_logger()

    # Handle --source as alias for --from (backwards compatibility)
    effective_source = from_source or source

    try:
        # Resolve service name or port
        service = resolve_service(target)

        if service:
            # It's a service name
            _allow_service(
                ctx, iptables, audit, service, effective_source, comment, dry_run, yes
            )
        elif is_port_number(target):
            # It's a port number
            port = int(target)
            _allow_port(
                ctx, iptables, audit, port, protocol, effective_source, comment
            )
        else:
            # Unknown target
            ctx.console.error(f"Unknown service or invalid port: {target}")
            ctx.console.print()
            ctx.console.print("[bold]Available services:[/bold]")
            for name, svc in SERVICES.items():
                ports = ", ".join(f"{p.port}/{p.protocol.value}" for p in svc.ports)
                ctx.console.print(f"  {name:15} {svc.display_name} ({ports})")
            ctx.console.print()
            ctx.console.hint("Or use a port number: sm firewall allow 8080")
            raise typer.Exit(1)

    except SMError as e:
        audit.log_failure(
            AuditEventType.FIREWALL_RULE_ADD,
            "firewall",
            target,
            error=str(e),
        )
        _handle_error(e)


def _allow_service(
    ctx,
    iptables: IptablesService,
    audit,
    service,
    source_input: Optional[str],
    comment: Optional[str],
    dry_run: bool,
    yes: bool,
) -> None:
    """Allow a service through the firewall."""
    # Determine source - use service default if not specified
    if source_input:
        source_str = source_input
    else:
        source_str = service.default_source

    # Resolve source to CIDRs
    source_cidrs = resolve_source(source_str)
    source_def = get_source_definition(source_str)
    source_display = source_def.display_name if source_def else source_str

    # Show what we're about to do
    ctx.console.print()
    ctx.console.print(f"[bold]Allowing {service.display_name}[/bold]")
    ctx.console.print()

    ports_str = ", ".join(f"{p.port}/{p.protocol.value}" for p in service.ports)
    ctx.console.print(f"  Service: {service.display_name}")
    ctx.console.print(f"  Ports:   {ports_str}")
    ctx.console.print(f"  From:    {source_display}")
    if len(source_cidrs) > 1:
        ctx.console.print(f"           ({', '.join(source_cidrs)})")
    ctx.console.print()

    # Show warning if applicable
    if service.warning and source_str == "anywhere":
        ctx.console.warn(service.warning)
        ctx.console.print()

    # Confirm if opening sensitive service to anywhere
    if (service.category == "database" and source_str == "anywhere"
            and not yes and not dry_run):
        if not ctx.console.confirm(
            f"Open {service.display_name} to the ENTIRE INTERNET? This is risky!"
        ):
            ctx.console.warn("Operation cancelled")
            raise typer.Exit(0)

    # Backup before making changes
    iptables.backup(suffix="-pre-allow")

    # Add rules for each port and source CIDR
    for port_spec in service.ports:
        rule_comment = comment or f"{service.display_name}"
        for cidr in source_cidrs:
            rule = FirewallRule(
                port=port_spec.port,
                protocol=port_spec.protocol,
                source=cidr,
                action=Action.ACCEPT,
                comment=rule_comment,
            )
            iptables.add_rule(rule)
            # Save to state
            iptables.save_rule_to_state(rule)

    iptables.save()
    iptables.state_manager.save()

    ctx.console.print()
    ctx.console.success(f"Allowed {service.display_name} from {source_display}")

    audit.log_success(
        AuditEventType.FIREWALL_RULE_ADD,
        "firewall",
        service.name,
        message=f"Allowed {service.display_name} from {source_display}",
    )


def _allow_port(
    ctx,
    iptables: IptablesService,
    audit,
    port: int,
    protocol: str,
    source_input: Optional[str],
    comment: Optional[str],
) -> None:
    """Allow a single port through the firewall."""
    # Default source is anywhere
    source_str = source_input or "anywhere"

    # Resolve source to CIDRs
    source_cidrs = resolve_source(source_str)
    source_def = get_source_definition(source_str)
    source_display = source_def.display_name if source_def else source_str

    # Validate
    validate_port(port)
    for cidr in source_cidrs:
        validate_source(cidr)
    proto = _parse_protocol(protocol)

    # Backup before making changes
    iptables.backup(suffix="-pre-allow")

    # Add rule for each source CIDR
    for cidr in source_cidrs:
        rule = FirewallRule(
            port=port,
            protocol=proto,
            source=cidr,
            action=Action.ACCEPT,
            comment=comment or f"Allow {proto.value.upper()}/{port}",
        )
        iptables.add_rule(rule)
        # Save to state
        iptables.save_rule_to_state(rule)

    iptables.save()
    iptables.state_manager.save()

    ctx.console.print()
    ctx.console.success(f"Allowed {protocol.upper()}/{port} from {source_display}")

    audit.log_success(
        AuditEventType.FIREWALL_RULE_ADD,
        "firewall",
        f"{protocol}/{port}",
        message=f"Allowed {protocol.upper()}/{port} from {source_display}",
    )


# =============================================================================
# Deny Command
# =============================================================================

@app.command("deny")
def firewall_deny(
    target: Annotated[
        str,
        typer.Argument(help="Service name (mysql, redis) or port number (3306)"),
    ],
    from_source: Annotated[
        Optional[str],
        typer.Option(
            "--from",
            help="Block from: anywhere, local-network, this-machine, or IP/CIDR",
        ),
    ] = None,
    source: Annotated[
        Optional[str],
        typer.Option("--source", "-s", hidden=True, help="Alias for --from"),
    ] = None,
    protocol: Annotated[
        str,
        typer.Option("--protocol", "--proto", help="Protocol (tcp/udp) - only for port numbers"),
    ] = "tcp",
    comment: Annotated[
        Optional[str],
        typer.Option("--comment", help="Rule description"),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Required to confirm blocking"),
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
    """Block a service or port.

    Requires --force flag. Cannot block SSH (safety protection).

    [bold]Examples:[/bold]

        # Block MySQL
        sudo sm firewall deny mysql --force

        # Block a specific port
        sudo sm firewall deny 3306 --force

        # Block from specific IP only
        sudo sm firewall deny 8080 --from 1.2.3.4 --force
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
        ctx.console.error("Blocking requires --force flag")
        ctx.console.hint("Use: sm firewall deny <target> --force")
        raise typer.Exit(4)

    # Handle --source as alias for --from
    effective_source = from_source or source or "anywhere"

    try:
        # Resolve service name or port
        service = resolve_service(target)

        if service:
            # Check if it's SSH (protected)
            if service.always_allowed:
                ctx.console.error(f"Cannot block {service.display_name} - it is protected")
                ctx.console.hint("SSH must remain accessible for server management")
                raise typer.Exit(4)

            # Block service
            _deny_service(ctx, iptables, audit, service, effective_source, comment)
        elif is_port_number(target):
            # It's a port number
            port = int(target)
            _deny_port(ctx, iptables, audit, port, protocol, effective_source, comment)
        else:
            # Unknown target
            ctx.console.error(f"Unknown service or invalid port: {target}")
            raise typer.Exit(1)

    except SMError as e:
        audit.log_failure(
            AuditEventType.FIREWALL_RULE_ADD,
            "firewall",
            target,
            error=str(e),
        )
        _handle_error(e)


def _deny_service(
    ctx,
    iptables: IptablesService,
    audit,
    service,
    source_str: str,
    comment: Optional[str],
) -> None:
    """Block a service.

    Since default policy is DROP, blocking just means removing any ACCEPT rules.
    No explicit DROP rules are needed (that would be redundant).
    """
    # Resolve source to CIDRs
    source_cidrs = resolve_source(source_str)
    source_def = get_source_definition(source_str)
    source_display = source_def.display_name if source_def else source_str

    # Backup before making changes
    iptables.backup(suffix="-pre-deny")

    # Remove ACCEPT rules for each port
    existing_rules = iptables.list_rules(Chain.INPUT)
    is_anywhere = source_str == "anywhere" or "0.0.0.0/0" in source_cidrs
    removed_any = False

    for port_spec in service.ports:
        for rule in existing_rules:
            if rule.port != port_spec.port:
                continue
            if rule.target != "ACCEPT":
                continue
            rule_proto = (rule.protocol or "tcp").lower()
            if rule_proto != port_spec.protocol.value.lower():
                continue
            if is_anywhere or rule.source in source_cidrs or rule.source == "0.0.0.0/0":
                try:
                    remove_rule = FirewallRule(
                        port=rule.port,
                        protocol=Protocol(rule_proto),
                        source=rule.source or "0.0.0.0/0",
                        action=Action.ACCEPT,
                    )
                    iptables.remove_rule(remove_rule)
                    # Also remove from state
                    iptables.remove_rule_from_state(remove_rule)
                    ctx.console.info(
                        f"Removed allow rule for {port_spec.protocol.value.upper()}/{port_spec.port}"
                    )
                    removed_any = True
                except Exception:
                    pass

    # No need to add explicit DROP rules - default policy is DROP
    # Traffic to these ports is now blocked by default

    iptables.save()
    iptables.state_manager.save()

    ctx.console.print()
    if removed_any:
        ctx.console.success(f"Blocked {service.display_name} from {source_display}")
        ctx.console.info("Removed ACCEPT rules - traffic now blocked by default policy")
    else:
        ctx.console.success(f"{service.display_name} is already blocked (no ACCEPT rules found)")
        ctx.console.info("Default policy is DROP - all non-allowed traffic is blocked")

    audit.log_success(
        AuditEventType.FIREWALL_RULE_ADD,
        "firewall",
        service.name,
        message=f"Blocked {service.display_name} from {source_display}",
    )


def _deny_port(
    ctx,
    iptables: IptablesService,
    audit,
    port: int,
    protocol: str,
    source_str: str,
    comment: Optional[str],
) -> None:
    """Block a single port.

    Since default policy is DROP, blocking just means removing any ACCEPT rules.
    No explicit DROP rule is needed (that would be redundant).
    """
    # Resolve source to CIDRs
    source_cidrs = resolve_source(source_str)
    source_def = get_source_definition(source_str)
    source_display = source_def.display_name if source_def else source_str

    # Validate
    validate_port(port)
    for cidr in source_cidrs:
        validate_source(cidr)
    proto = _parse_protocol(protocol)

    # Backup before making changes
    iptables.backup(suffix="-pre-deny")

    # Remove ACCEPT rules for the same port/protocol
    # When blocking from "anywhere", remove ALL accept rules for this port
    # When blocking from specific source, only remove matching accept rules
    existing_rules = iptables.list_rules(Chain.INPUT)
    is_anywhere = source_str == "anywhere" or "0.0.0.0/0" in source_cidrs
    removed_any = False

    for rule in existing_rules:
        if rule.port != port:
            continue
        if rule.target != "ACCEPT":
            continue
        # Normalize protocol for comparison
        rule_proto = (rule.protocol or "tcp").lower()
        if rule_proto != proto.value.lower():
            continue
        # If blocking from anywhere, remove all ACCEPT rules
        # If blocking from specific source, only remove matching source
        if is_anywhere or rule.source in source_cidrs or rule.source == "0.0.0.0/0":
            try:
                # Create a FirewallRule to remove
                remove_rule = FirewallRule(
                    port=rule.port,
                    protocol=Protocol(rule_proto),
                    source=rule.source or "0.0.0.0/0",
                    action=Action.ACCEPT,
                )
                iptables.remove_rule(remove_rule)
                # Also remove from state
                iptables.remove_rule_from_state(remove_rule)
                ctx.console.info(f"Removed allow rule for {proto.value.upper()}/{port}")
                removed_any = True
            except Exception:
                # Rule might not exist exactly as listed (e.g., different comment)
                pass

    # No need to add explicit DROP rules - default policy is DROP
    # Traffic to this port is now blocked by default

    iptables.save()
    iptables.state_manager.save()

    ctx.console.print()
    if removed_any:
        ctx.console.success(f"Blocked {protocol.upper()}/{port} from {source_display}")
        ctx.console.info("Removed ACCEPT rules - traffic now blocked by default policy")
    else:
        ctx.console.success(f"{protocol.upper()}/{port} is already blocked (no ACCEPT rules found)")
        ctx.console.info("Default policy is DROP - all non-allowed traffic is blocked")

    audit.log_success(
        AuditEventType.FIREWALL_RULE_ADD,
        "firewall",
        f"{protocol}/{port}",
        message=f"Blocked {protocol.upper()}/{port} from {source_display}",
    )


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
    include_docker: Annotated[
        bool,
        typer.Option("--include-docker", help="Also flush DOCKER-USER chain"),
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
    """Reset firewall to default state (flush all rules).

    [bold red]CRITICAL:[/bold red] Removes ALL firewall rules!

    Requires --force and --confirm-name=firewall

    [bold]Examples:[/bold]

        sudo sm firewall reset --force --confirm-name=firewall
        sudo sm firewall reset --force --confirm-name=firewall --include-docker
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
        iptables.flush(keep_ssh=True, include_docker=include_docker)

        # Save the clean state to persistent storage
        iptables.save()

        # Clear SM state (all rules including protected)
        iptables.state_manager.clear_rules(keep_protected=False)
        iptables.state_manager.save()

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


# =============================================================================
# Setup Command (Interactive Wizard)
# =============================================================================

@app.command("setup")
def firewall_setup(
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
) -> None:
    """Interactive firewall setup wizard.

    Guides you through setting up your firewall step by step.
    Perfect for users who are new to firewall configuration.

    [bold]What it does:[/bold]

    1. Asks what type of server you're running
    2. Helps you select which services to allow
    3. Configures who can access each service
    4. Reviews the configuration before applying
    5. Enables the firewall with your settings

    SSH access is ALWAYS kept open so you don't get locked out.

    [bold]Examples:[/bold]

        sudo sm firewall setup
        sm firewall setup --dry-run   # Preview without changes
    """
    from sm.commands.firewall.wizard import FirewallWizard

    try:
        wizard = FirewallWizard(dry_run=dry_run, yes=yes, verbose=verbose)
        wizard.run()
    except SMError as e:
        _handle_error(e)


# =============================================================================
# Services Command (List available services)
# =============================================================================

@app.command("services")
def firewall_services(
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
) -> None:
    """List available service names for allow/deny commands.

    [bold]Examples:[/bold]

        sm firewall services
    """
    ctx, _ = _get_firewall_service(no_color=no_color)

    ctx.console.print()
    ctx.console.print("[bold]Available Services[/bold]")
    ctx.console.print()
    ctx.console.print("Use these names with [bold]sm firewall allow[/bold] or [bold]sm firewall deny[/bold]")
    ctx.console.print()

    # Group by category
    categories = {}
    for name, svc in SERVICES.items():
        if svc.category not in categories:
            categories[svc.category] = []
        categories[svc.category].append((name, svc))

    category_names = {
        "web": "Web Services",
        "database": "Databases",
        "system": "System Services",
        "containers": "Docker/Containers",
        "monitoring": "Monitoring",
        "mail": "Mail Services",
    }

    for category, services in categories.items():
        title = category_names.get(category, category.title())
        ctx.console.print(f"[bold cyan]{title}[/bold cyan]")

        for name, svc in services:
            ports = ", ".join(f"{p.port}/{p.protocol.value}" for p in svc.ports)
            default = f"[dim](default: {svc.default_source})[/dim]"
            ctx.console.print(f"  {name:15} {svc.display_name:20} {ports:15} {default}")

        ctx.console.print()

    ctx.console.print("[bold]Access Sources (--from option)[/bold]")
    ctx.console.print()

    for name, source_def in SOURCE_ALIASES.items():
        ctx.console.print(f"  {name:15} {source_def.display_name}")

    ctx.console.print()
    ctx.console.print("[dim]You can also use IP addresses or CIDR notation (e.g., 10.0.0.0/8)[/dim]")
    ctx.console.print()


# =============================================================================
# New Commands: sync, exclusive, audit
# =============================================================================

# Import new commands and add them to the app
from sm.commands.firewall.sync import sync as sync_command
from sm.commands.firewall.exclusive import exclusive as exclusive_command
from sm.commands.firewall.audit import audit as audit_command
from sm.commands.firewall.cleanup import cleanup as cleanup_command

app.command("sync")(sync_command)
app.command("exclusive")(exclusive_command)
app.command("audit")(audit_command)
app.command("cleanup")(cleanup_command)
