"""Firewall audit command.

Detects drift between SM state and actual iptables rules.
Reports rules that exist in iptables but not in SM state (drift),
and rules in SM state that are missing from iptables.
"""

import json
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
from sm.services.iptables import IptablesService
from sm.services.systemd import SystemdService
from sm.services.firewall_state import StoredRule, STATE_FILE


def audit(
    import_unknown: Annotated[
        bool,
        typer.Option("--import", "-i", help="Import unknown rules into SM state"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
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
    """Audit firewall rules for drift from SM state.

    Drift occurs when rules are added to iptables outside of SM.
    This command helps identify and optionally import such rules.

    What is detected:
    - Unknown rules: In iptables but not in SM state (drift)
    - Missing rules: In SM state but not in iptables
    - Preserved rules: Fail2ban chains (intentionally not tracked)

    Examples:
        sm firewall audit              # Show drift report
        sm firewall audit --import     # Import unknown rules to SM state
        sm firewall audit --json       # JSON output for scripting
    """
    # Check root for import
    if import_unknown and os.geteuid() != 0 and not dry_run:
        console.error("This operation requires root privileges")
        console.hint("Run with: sudo sm firewall audit --import")
        raise typer.Exit(6)

    ctx = create_context(
        dry_run=dry_run,
        verbose=verbose,
    )
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    iptables = IptablesService(ctx, executor, systemd)

    # Check if state file exists
    if not STATE_FILE.exists() and not dry_run:
        console.warn("No SM state file found")
        console.hint(
            "Run 'sm firewall enable' to set up firewall with state tracking, "
            "or 'sm firewall audit --import' to import existing rules into SM state"
        )
        if not import_unknown:
            raise typer.Exit(0)

    # Detect drift
    report = iptables.detect_drift()

    if json_output:
        _output_json(report)
        return

    # Show report
    _show_report(report, iptables, ctx)

    # Import if requested
    if import_unknown and report.unknown_rules:
        _import_rules(report, iptables, ctx)


def _output_json(report) -> None:
    """Output drift report as JSON."""
    output = {
        "has_drift": report.has_drift,
        "unknown_rules": report.unknown_rules,
        "missing_rules": [str(r) for r in report.missing_rules],
        "preserved_rules": report.preserved_rules,
        "counts": {
            "unknown": report.unknown_count,
            "missing": report.missing_count,
            "preserved": len(report.preserved_rules),
        },
    }
    print(json.dumps(output, indent=2))


def _show_report(report, iptables: IptablesService, ctx) -> None:
    """Display drift report."""
    state = iptables.state_manager.state

    # Summary
    console.print()
    console.print("[bold]Firewall Drift Report[/bold]")
    console.print()

    # State info
    console.print(f"State file: {STATE_FILE}")
    console.print(f"Rules in state: {len(state.rules)}")
    console.print(f"Docker aware: {'Yes' if state.docker_aware else 'No'}")
    console.print(f"Exclusive mode: {'Yes' if state.exclusive_mode else 'No'}")
    console.print()

    if not report.has_drift:
        console.success("No drift detected - iptables matches SM state")

        if report.preserved_rules:
            console.print()
            console.info(f"Preserved chains (fail2ban): {len(report.preserved_rules)}")

        return

    # Unknown rules (drift)
    if report.unknown_rules:
        console.print()
        console.warn(f"Unknown rules in iptables: {report.unknown_count}")
        console.print("[dim]These rules exist in iptables but not in SM state[/dim]")
        console.print()

        table = Table(show_header=True)
        table.add_column("#", style="dim")
        table.add_column("Action")
        table.add_column("Protocol")
        table.add_column("Port")
        table.add_column("Source")
        table.add_column("Comment")

        for rule in report.unknown_rules:
            table.add_row(
                str(rule.get("num", "")),
                rule.get("target", ""),
                rule.get("protocol", ""),
                str(rule.get("port", "")) or "-",
                rule.get("source", ""),
                rule.get("comment", "") or "-",
            )

        console.print(table)

    # Missing rules
    if report.missing_rules:
        console.print()
        console.warn(f"Missing rules from iptables: {report.missing_count}")
        console.print("[dim]These rules are in SM state but not in iptables[/dim]")
        console.print()

        table = Table(show_header=True)
        table.add_column("Action")
        table.add_column("Protocol")
        table.add_column("Port")
        table.add_column("Source")
        table.add_column("Comment")

        for rule in report.missing_rules:
            table.add_row(
                rule.action,
                rule.protocol,
                str(rule.port) if rule.port else "-",
                rule.source,
                rule.comment or "-",
            )

        console.print(table)
        console.print()
        console.hint("Run 'sm firewall sync' to apply missing rules")

    # Preserved rules
    if report.preserved_rules and ctx.is_verbose:
        console.print()
        console.info(f"Preserved chains: {len(report.preserved_rules)}")
        for rule in report.preserved_rules:
            console.print(f"  - {rule.get('target')} ({rule.get('type')})")

    # Suggestions
    if report.unknown_rules:
        console.print()
        console.print("[bold]Actions:[/bold]")
        console.print("  - Import unknown rules: [cyan]sm firewall audit --import[/cyan]")
        console.print("  - Or manually review and decide which to keep")


def _import_rules(report, iptables: IptablesService, ctx) -> None:
    """Import unknown rules into SM state."""
    ctx.console.step("Importing unknown rules to SM state")

    imported = 0
    for rule_dict in report.unknown_rules:
        # Create StoredRule from parsed data
        stored = StoredRule(
            port=rule_dict.get("port"),
            protocol=rule_dict.get("protocol", "tcp"),
            source=rule_dict.get("source", "0.0.0.0/0"),
            action=rule_dict.get("target", "ACCEPT"),
            chain="INPUT",
            comment=rule_dict.get("comment") or "Imported from iptables",
            protected=False,
        )

        if iptables.state_manager.add_rule(stored):
            imported += 1
            ctx.console.info(f"Imported: {stored}")

    if imported > 0:
        iptables.state_manager.save()

        # Log to audit
        audit_logger = get_audit_logger()
        audit_logger.log(
            AuditEventType.CONFIG_CHANGE,
            "firewall_audit_import",
            details={"rules_imported": imported},
        )

        ctx.console.success(f"Imported {imported} rule(s) to SM state")
    else:
        ctx.console.info("No new rules to import")
