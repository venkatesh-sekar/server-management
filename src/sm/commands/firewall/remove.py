"""Firewall remove command - remove specific rules."""

import os
from typing import Annotated, Optional

import typer

from sm.core import (
    SMError,
    FirewallError,
    console,
    create_context,
    CommandExecutor,
    get_audit_logger,
    AuditEventType,
)
from sm.services.iptables import (
    IptablesService,
    Protocol,
    Action,
    Chain,
    FirewallRule,
    validate_port,
    validate_source,
)
from sm.services.systemd import SystemdService
from sm.services.firewall_services import (
    resolve_service,
    resolve_source,
    get_source_definition,
    is_port_number,
    SERVICES,
)


def _get_firewall_service(
    dry_run: bool = False,
    verbose: int = 0,
    no_color: bool = False,
) -> tuple:
    """Create firewall service and context."""
    ctx = create_context(
        dry_run=dry_run,
        verbose=verbose,
        no_color=no_color,
    )
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    iptables = IptablesService(ctx, executor, systemd)

    return ctx, iptables


def _handle_error(error: SMError) -> None:
    """Handle an SMError by printing formatted error and exiting."""
    console.error(error.message)

    if error.details:
        for detail in error.details:
            console.print(f"  [dim]{detail}[/dim]")

    if error.hint:
        console.hint(error.hint)

    raise typer.Exit(error.exit_code)


def _parse_protocol(protocol: str) -> Protocol:
    """Parse and validate protocol string."""
    try:
        return Protocol(protocol.lower())
    except ValueError:
        valid = ", ".join(p.value for p in Protocol)
        raise FirewallError(
            f"Invalid protocol: {protocol}",
            hint=f"Valid protocols: {valid}",
        )


def remove(
    target: Annotated[
        str,
        typer.Argument(help="Service name (web, postgres) or port number (8080)"),
    ],
    from_source: Annotated[
        Optional[str],
        typer.Option(
            "--from", "-f",
            help="Source to match: anywhere, local-network, this-machine, or IP/CIDR",
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
    action: Annotated[
        Optional[str],
        typer.Option("--action", "-a", help="Rule action to remove: allow or block (default: any)"),
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
    """Remove a firewall rule for a service or port.

    Removes matching rules from both INPUT and DOCKER-USER chains.
    By default removes rules with any action (ACCEPT or DROP).

    [bold]Examples:[/bold]

        # Remove all rules for port 5555
        sudo sm firewall remove 5555

        # Remove only ACCEPT rule for port 8080
        sudo sm firewall remove 8080 --action allow

        # Remove only DROP rule for port 3306
        sudo sm firewall remove 3306 --action block

        # Remove rule for a specific source
        sudo sm firewall remove 8080 --from 10.0.0.5

        # Preview what would be removed
        sm firewall remove 5555 --dry-run
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        verbose=verbose,
        no_color=no_color,
    )

    # Check for root
    if os.geteuid() != 0 and not ctx.dry_run:
        ctx.console.error("This operation requires root privileges")
        ctx.console.hint("Run with: sudo sm firewall remove ...")
        raise typer.Exit(6)

    audit = get_audit_logger()

    # Handle --source as alias for --from
    effective_source = from_source or source

    # Parse action filter
    action_filter: Optional[Action] = None
    if action:
        action_lower = action.lower()
        if action_lower in ("allow", "accept"):
            action_filter = Action.ACCEPT
        elif action_lower in ("block", "drop", "deny"):
            action_filter = Action.DROP
        else:
            ctx.console.error(f"Invalid action: {action}")
            ctx.console.hint("Valid actions: allow, block")
            raise typer.Exit(1)

    try:
        # Resolve service name or port
        service = resolve_service(target)

        if service:
            _remove_service_rules(
                ctx, iptables, audit, service, effective_source, action_filter, dry_run, yes
            )
        elif is_port_number(target):
            port = int(target)
            _remove_port_rules(
                ctx, iptables, audit, port, protocol, effective_source, action_filter, dry_run, yes
            )
        else:
            ctx.console.error(f"Unknown service or invalid port: {target}")
            ctx.console.print()
            ctx.console.print("[bold]Available services:[/bold]")
            for name, svc in SERVICES.items():
                ports = ", ".join(f"{p.port}/{p.protocol.value}" for p in svc.ports)
                ctx.console.print(f"  {name:15} {svc.display_name} ({ports})")
            ctx.console.print()
            ctx.console.hint("Or use a port number: sm firewall remove 8080")
            raise typer.Exit(1)

    except SMError as e:
        audit.log_failure(
            AuditEventType.FIREWALL_RULE_REMOVE,
            "firewall",
            target,
            error=str(e),
        )
        _handle_error(e)


def _remove_service_rules(
    ctx,
    iptables: IptablesService,
    audit,
    service,
    source_input: Optional[str],
    action_filter: Optional[Action],
    dry_run: bool,
    yes: bool,
) -> None:
    """Remove rules for a service."""
    # Check if it's SSH (protected)
    if service.always_allowed:
        ctx.console.error(f"Cannot remove rules for {service.display_name} - it is protected")
        ctx.console.hint("SSH must remain accessible for server management")
        raise typer.Exit(4)

    # Resolve source
    source_cidrs = resolve_source(source_input) if source_input else None
    source_def = get_source_definition(source_input) if source_input else None
    source_display = source_def.display_name if source_def else (source_input or "any source")

    # Build action description
    if action_filter == Action.ACCEPT:
        action_desc = "ACCEPT"
    elif action_filter == Action.DROP:
        action_desc = "DROP"
    else:
        action_desc = "all"

    ctx.console.print()
    ctx.console.print(f"[bold]Removing {action_desc} rules for {service.display_name}[/bold]")
    if source_input:
        ctx.console.print(f"  Source: {source_display}")
    ctx.console.print()

    # Backup before making changes
    if not dry_run:
        iptables.backup(suffix="-pre-remove")

    total_removed = 0
    for port_spec in service.ports:
        removed = _remove_matching_rules(
            ctx, iptables, port_spec.port, port_spec.protocol,
            source_cidrs, action_filter, dry_run, verbose=True
        )
        total_removed += removed

    if total_removed > 0 and not dry_run:
        iptables.save()
        iptables.state_manager.save()

    ctx.console.print()
    if total_removed > 0:
        if dry_run:
            ctx.console.dry_run_msg(f"Would remove {total_removed} rule(s)")
        else:
            ctx.console.success(f"Removed {total_removed} rule(s) for {service.display_name}")
    else:
        ctx.console.info(f"No matching rules found for {service.display_name}")

    if not dry_run and total_removed > 0:
        audit.log_success(
            AuditEventType.FIREWALL_RULE_REMOVE,
            "firewall",
            service.name,
            message=f"Removed {total_removed} rules for {service.display_name}",
        )


def _remove_port_rules(
    ctx,
    iptables: IptablesService,
    audit,
    port: int,
    protocol: str,
    source_input: Optional[str],
    action_filter: Optional[Action],
    dry_run: bool,
    yes: bool,
) -> None:
    """Remove rules for a specific port."""
    # Validate
    validate_port(port)
    proto = _parse_protocol(protocol)

    # Resolve source
    source_cidrs = resolve_source(source_input) if source_input else None
    source_def = get_source_definition(source_input) if source_input else None
    source_display = source_def.display_name if source_def else (source_input or "any source")

    # Check if trying to remove SSH
    if port == iptables.ssh_port and (action_filter is None or action_filter == Action.ACCEPT):
        ctx.console.error(f"Cannot remove SSH allow rule for port {port}")
        ctx.console.hint("SSH access is always allowed for safety")
        raise typer.Exit(4)

    # Build action description
    if action_filter == Action.ACCEPT:
        action_desc = "ACCEPT"
    elif action_filter == Action.DROP:
        action_desc = "DROP"
    else:
        action_desc = "all"

    ctx.console.print()
    ctx.console.print(f"[bold]Removing {action_desc} rules for {proto.value.upper()}/{port}[/bold]")
    if source_input:
        ctx.console.print(f"  Source: {source_display}")
    ctx.console.print()

    # Backup before making changes
    if not dry_run:
        iptables.backup(suffix="-pre-remove")

    total_removed = _remove_matching_rules(
        ctx, iptables, port, proto, source_cidrs, action_filter, dry_run, verbose=True
    )

    if total_removed > 0 and not dry_run:
        iptables.save()
        iptables.state_manager.save()

    ctx.console.print()
    if total_removed > 0:
        if dry_run:
            ctx.console.dry_run_msg(f"Would remove {total_removed} rule(s)")
        else:
            ctx.console.success(f"Removed {total_removed} rule(s) for {proto.value.upper()}/{port}")
    else:
        ctx.console.info(f"No matching rules found for {proto.value.upper()}/{port}")

    if not dry_run and total_removed > 0:
        audit.log_success(
            AuditEventType.FIREWALL_RULE_REMOVE,
            "firewall",
            f"{protocol}/{port}",
            message=f"Removed {total_removed} rules for {proto.value.upper()}/{port}",
        )


def _remove_matching_rules(
    ctx,
    iptables: IptablesService,
    port: int,
    protocol: Protocol,
    source_cidrs: Optional[list[str]],
    action_filter: Optional[Action],
    dry_run: bool,
    verbose: bool = False,
) -> int:
    """Remove rules matching the given criteria from both INPUT and DOCKER-USER chains.

    Args:
        ctx: Execution context
        iptables: Iptables service
        port: Port number to match
        protocol: Protocol to match
        source_cidrs: Source CIDRs to match (None = any source)
        action_filter: Action to match (None = any action)
        dry_run: Preview mode
        verbose: Show detailed output

    Returns:
        Number of rules removed
    """
    total_removed = 0

    # Process INPUT chain
    removed = _remove_from_chain(
        ctx, iptables, Chain.INPUT, port, protocol, source_cidrs, action_filter, dry_run, verbose
    )
    total_removed += removed

    # Process DOCKER-USER chain if it exists
    if iptables.docker_user_chain_exists():
        removed = _remove_from_chain(
            ctx, iptables, Chain.DOCKER_USER, port, protocol, source_cidrs, action_filter, dry_run, verbose
        )
        total_removed += removed

    return total_removed


def _remove_from_chain(
    ctx,
    iptables: IptablesService,
    chain: Chain,
    port: int,
    protocol: Protocol,
    source_cidrs: Optional[list[str]],
    action_filter: Optional[Action],
    dry_run: bool,
    verbose: bool,
) -> int:
    """Remove matching rules from a specific chain.

    Returns:
        Number of rules removed
    """
    existing_rules = iptables.list_rules(chain)
    removed = 0

    for rule in existing_rules:
        # Match port
        if rule.port != port:
            continue

        # Match protocol
        rule_proto = (rule.protocol or "tcp").lower()
        if rule_proto != protocol.value.lower():
            continue

        # Match action if specified
        if action_filter:
            if action_filter == Action.ACCEPT and rule.target != "ACCEPT":
                continue
            if action_filter == Action.DROP and rule.target not in ("DROP", "REJECT"):
                continue

        # Match source if specified
        if source_cidrs:
            rule_source = rule.source or "0.0.0.0/0"
            if rule_source not in source_cidrs and rule_source != "0.0.0.0/0":
                continue

        # Skip chain jumps (like fail2ban)
        if rule.is_chain_jump:
            continue

        # Found a matching rule
        try:
            # Determine the action for the FirewallRule
            if rule.target == "ACCEPT":
                rule_action = Action.ACCEPT
            elif rule.target in ("DROP", "REJECT"):
                rule_action = Action.DROP
            else:
                continue  # Unknown action, skip

            remove_rule = FirewallRule(
                port=rule.port,
                protocol=Protocol(rule_proto),
                source=rule.source or "0.0.0.0/0",
                action=rule_action,
                chain=chain,
                comment=rule.comment,
                interface=rule.in_interface,
            )

            if dry_run:
                if verbose:
                    ctx.console.info(
                        f"  Would remove from {chain.value}: "
                        f"{rule.target} {rule_proto.upper()}/{port} "
                        f"from {rule.source or 'anywhere'}"
                    )
                removed += 1
            else:
                iptables.remove_rule(remove_rule, ipv6=True)
                # Also remove from state
                iptables.remove_rule_from_state(remove_rule)
                if verbose:
                    ctx.console.info(
                        f"  Removed from {chain.value}: "
                        f"{rule.target} {rule_proto.upper()}/{port} "
                        f"from {rule.source or 'anywhere'}"
                    )
                removed += 1

        except Exception as e:
            if verbose:
                ctx.console.warn(f"  Failed to remove rule: {e}")

    return removed
