"""Firewall cleanup command - remove duplicate rules."""

import os
from typing import Annotated

import typer

from sm.core import (
    SMError,
    console,
    create_context,
    CommandExecutor,
    get_audit_logger,
    AuditEventType,
)
from sm.services.iptables import (
    IptablesService,
    Chain,
)
from sm.services.systemd import SystemdService


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


def cleanup(
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
    """Remove duplicate firewall rules.

    Identifies and removes duplicate rules in the INPUT and DOCKER-USER chains.
    Rules are considered duplicates if they have the same port, protocol, source,
    and action. Only the first occurrence of each rule is kept.

    [bold]Examples:[/bold]

        sudo sm firewall cleanup
        sm firewall cleanup --dry-run   # Preview without changes
    """
    ctx, iptables = _get_firewall_service(
        dry_run=dry_run,
        verbose=verbose,
        no_color=no_color,
    )

    # Check for root
    if os.geteuid() != 0 and not ctx.dry_run:
        ctx.console.error("This operation requires root privileges")
        ctx.console.hint("Run with: sudo sm firewall cleanup")
        raise typer.Exit(6)

    audit = get_audit_logger()

    try:
        ctx.console.print()
        ctx.console.print("[bold]Firewall Cleanup[/bold]")
        ctx.console.print()

        total_removed = 0

        # Process INPUT chain
        input_removed = _cleanup_chain(ctx, iptables, Chain.INPUT, dry_run)
        total_removed += input_removed

        # Process DOCKER-USER chain if it exists
        if iptables.docker_user_chain_exists():
            docker_removed = _cleanup_chain(ctx, iptables, Chain.DOCKER_USER, dry_run)
            total_removed += docker_removed

        if total_removed > 0:
            # Save changes
            if not dry_run:
                iptables.save()

            ctx.console.print()
            ctx.console.success(f"Removed {total_removed} duplicate rule(s)")

            audit.log_success(
                AuditEventType.FIREWALL_RULE_REMOVE,
                "firewall",
                "cleanup",
                message=f"Removed {total_removed} duplicate rules",
            )
        else:
            ctx.console.print()
            ctx.console.success("No duplicate rules found - firewall is clean")

    except SMError as e:
        audit.log_failure(
            AuditEventType.FIREWALL_RULE_REMOVE,
            "firewall",
            "cleanup",
            error=str(e),
        )
        _handle_error(e)


def _cleanup_chain(ctx, iptables: IptablesService, chain: Chain, dry_run: bool) -> int:
    """Clean up duplicate rules in a single chain.

    Args:
        ctx: Execution context
        iptables: Iptables service
        chain: Chain to clean
        dry_run: Preview mode

    Returns:
        Number of rules removed
    """
    rules = iptables.list_rules(chain)

    if not rules:
        return 0

    ctx.console.step(f"Scanning {chain.value} chain ({len(rules)} rules)")

    # Track seen rules by their key (port, protocol, source, action, interface, extra)
    seen: dict[tuple, int] = {}  # key -> first rule number
    duplicates: list[int] = []  # rule numbers to remove (in reverse order)

    for rule in rules:
        # Create a key for deduplication
        # Include interface and extra info to distinguish loopback, established, etc.
        key = (
            rule.port,
            (rule.protocol or "").lower(),
            rule.source,
            rule.target,
            rule.in_interface,
            # Normalize extra field for comparison (remove whitespace variations)
            _normalize_extra(rule.extra),
        )

        if key in seen:
            duplicates.append(rule.num)
            if ctx.verbose > 0 or dry_run:
                ctx.console.info(
                    f"  Duplicate: #{rule.num} {rule.target} "
                    f"{rule.protocol or 'all'}/{rule.port or '-'} "
                    f"(same as #{seen[key]})"
                )
        else:
            seen[key] = rule.num

    if not duplicates:
        ctx.console.info(f"  No duplicates found in {chain.value}")
        return 0

    ctx.console.info(f"  Found {len(duplicates)} duplicate(s) in {chain.value}")

    if dry_run:
        ctx.console.dry_run_msg(f"Would remove {len(duplicates)} duplicate rules from {chain.value}")
        return len(duplicates)

    # Remove duplicates in reverse order (highest rule number first)
    # This prevents rule number shifting issues
    removed = 0
    for rule_num in sorted(duplicates, reverse=True):
        result = iptables._run_iptables(
            ["-D", chain.value, str(rule_num)],
            check=False,
        )
        if result.returncode == 0:
            removed += 1
            if ctx.verbose > 0:
                ctx.console.info(f"  Removed rule #{rule_num}")
        else:
            ctx.console.warn(f"  Failed to remove rule #{rule_num}")

    return removed


def _normalize_extra(extra: str | None) -> str:
    """Normalize extra field for comparison.

    Removes whitespace variations and sorts tokens for consistent comparison.
    """
    if not extra:
        return ""

    # Split into tokens, sort, and rejoin
    tokens = extra.split()
    # Remove comments for comparison (they don't affect rule behavior)
    tokens = [t for t in tokens if not t.startswith("/*") and not t.endswith("*/")]
    return " ".join(sorted(tokens))
