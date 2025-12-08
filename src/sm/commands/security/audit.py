"""Security audit command implementation.

This module implements the `sm security audit` command which performs
comprehensive security assessment of the system.
"""

import os
from typing import Annotated, Optional

import typer
from rich.panel import Panel
from rich.table import Table

from sm.core.context import create_context
from sm.core.executor import CommandExecutor
from sm.core.output import console
from sm.core.audit import get_audit_logger, AuditEventType
from sm.services.security_audit import (
    SecurityAuditService,
    AuditReport,
    AuditSeverity,
    SECURITY_CHECKS,
)


def audit(
    category: Annotated[
        Optional[list[str]],
        typer.Option(
            "--category",
            "-c",
            help="Categories to audit: network, users, filesystem, services",
        ),
    ] = None,
    quick: Annotated[
        bool,
        typer.Option(
            "--quick",
            "-q",
            help="Quick audit (essential checks only, skip slow scans)",
        ),
    ] = False,
    use_external: Annotated[
        bool,
        typer.Option(
            "--external/--no-external",
            help="Run external tools (lynis, rkhunter, chkrootkit) if available",
        ),
    ] = True,
    install_tools: Annotated[
        bool,
        typer.Option(
            "--install-tools",
            "-i",
            help="Install external security tools before audit",
        ),
    ] = False,
    list_checks: Annotated[
        bool,
        typer.Option(
            "--list-checks",
            "-l",
            help="List all available security checks and exit",
        ),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option(
            "--verbose",
            "-v",
            count=True,
            help="Increase verbosity",
        ),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option(
            "--no-color",
            help="Disable colored output",
        ),
    ] = False,
) -> None:
    """Perform comprehensive security audit of the system.

    Checks multiple security aspects:

    [bold]Network:[/bold] SSH configuration, open ports, firewall status

    [bold]Users:[/bold] UID 0 accounts, empty passwords, sudo NOPASSWD rules, failed logins

    [bold]Filesystem:[/bold] Shadow permissions, SUID/SGID binaries, world-writable files

    [bold]Services:[/bold] Dangerous services, pending updates, fail2ban status

    [bold]External tools:[/bold] Lynis, rkhunter, chkrootkit (if installed)

    [bold]Examples:[/bold]

        # Full security audit
        sudo sm security audit

        # Quick audit (skip slow scans)
        sudo sm security audit --quick

        # Audit specific category
        sudo sm security audit --category network

        # Install and run external tools
        sudo sm security audit --install-tools

        # Skip external tools
        sudo sm security audit --no-external

        # List all available checks
        sm security audit --list-checks
    """
    ctx = create_context(verbose=verbose, no_color=no_color)

    # Handle --list-checks (doesn't require root)
    if list_checks:
        _display_available_checks()
        raise typer.Exit(0)

    # Root check - audit needs to read sensitive files
    if os.geteuid() != 0:
        console.error("Security audit requires root privileges")
        console.print()
        console.print("[dim]The audit needs to read sensitive files like:[/dim]")
        console.print("[dim]  - /etc/shadow (password hashes)[/dim]")
        console.print("[dim]  - /etc/sudoers (sudo configuration)[/dim]")
        console.print("[dim]  - System logs (failed logins)[/dim]")
        console.print()
        console.hint("Run with: sudo sm security audit")
        raise typer.Exit(6)

    executor = CommandExecutor(ctx)
    audit_log = get_audit_logger()

    # Validate categories
    valid_categories = {"network", "users", "filesystem", "services"}
    if category:
        invalid = set(category) - valid_categories
        if invalid:
            console.error(f"Invalid categories: {', '.join(invalid)}")
            console.info(f"Valid categories: {', '.join(sorted(valid_categories))}")
            raise typer.Exit(1)

    audit_service = SecurityAuditService(ctx, executor)

    console.print()
    console.print("[bold]Security Audit[/bold]")
    console.print("=" * 40)
    console.print()

    try:
        # Run the audit
        report = audit_service.run_audit(
            categories=category,
            quick=quick,
            use_external=use_external,
            install_tools=install_tools,
        )

        # Display results
        _display_report(report, ctx, verbose)

        # Log audit completion
        audit_log.log_success(
            AuditEventType.CONFIG_MODIFY,
            "security",
            "audit",
            message=f"Security audit completed. Score: {report.score}/100",
        )

    except Exception as e:
        audit_log.log_failure(
            AuditEventType.CONFIG_MODIFY,
            "security",
            "audit",
            error=str(e),
        )
        console.error(f"Audit failed: {e}")
        raise typer.Exit(1)


def _display_report(report: AuditReport, ctx, verbose: int) -> None:
    """Display audit report with Rich formatting."""
    console.print()

    # Severity colors
    severity_colors = {
        AuditSeverity.PASS: "green",
        AuditSeverity.INFO: "blue",
        AuditSeverity.WARN: "yellow",
        AuditSeverity.FAIL: "red",
        AuditSeverity.SKIP: "dim",
    }

    # Category display order
    category_order = ["network", "users", "filesystem", "services", "external"]

    # Display findings by category
    for cat_name in category_order:
        if cat_name not in report.categories:
            continue

        findings = report.categories[cat_name]

        table = Table(
            title=f"[bold]{cat_name.title()}[/bold]",
            show_header=True,
            header_style="bold",
        )
        table.add_column("Status", width=6, justify="center")
        table.add_column("Check", min_width=25)
        table.add_column("Result", min_width=30)
        if verbose > 0:
            table.add_column("Details", style="dim")

        for finding in findings:
            color = severity_colors.get(finding.severity, "white")
            status = f"[{color}]{finding.severity.value}[/{color}]"

            row = [status, finding.check_name, finding.message]
            if verbose > 0:
                row.append(finding.details or "")

            table.add_row(*row)

        console.print(table)
        console.print()

    # Summary statistics
    pass_count = sum(1 for f in report.findings if f.severity == AuditSeverity.PASS)
    info_count = sum(1 for f in report.findings if f.severity == AuditSeverity.INFO)
    warn_count = sum(1 for f in report.findings if f.severity == AuditSeverity.WARN)
    fail_count = sum(1 for f in report.findings if f.severity == AuditSeverity.FAIL)
    skip_count = sum(1 for f in report.findings if f.severity == AuditSeverity.SKIP)

    # Score color based on value
    if report.score >= 90:
        score_color = "green"
        score_label = "Excellent"
    elif report.score >= 80:
        score_color = "green"
        score_label = "Good"
    elif report.score >= 60:
        score_color = "yellow"
        score_label = "Fair"
    elif report.score >= 40:
        score_color = "yellow"
        score_label = "Poor"
    else:
        score_color = "red"
        score_label = "Critical"

    summary_text = f"""
[bold]Score:[/bold] [{score_color}]{report.score}/100 ({score_label})[/{score_color}]

[green]PASS:[/green] {pass_count}  [blue]INFO:[/blue] {info_count}  [yellow]WARN:[/yellow] {warn_count}  [red]FAIL:[/red] {fail_count}  [dim]SKIP:[/dim] {skip_count}
"""

    if report.external_tools_used:
        summary_text += f"\n[dim]External tools: {', '.join(report.external_tools_used)}[/dim]"

    summary_text += f"\n[dim]Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}[/dim]"

    console.print(Panel(summary_text, title="Summary", border_style="blue"))

    # Show top recommendations if there are failures or warnings
    failures = [f for f in report.findings if f.severity == AuditSeverity.FAIL]
    warnings = [f for f in report.findings if f.severity == AuditSeverity.WARN]

    if failures or warnings:
        console.print()
        console.print("[bold]Recommendations:[/bold]")

        # Show failures first (up to 3)
        for finding in failures[:3]:
            if finding.remediation:
                console.print(f"  [red]*[/red] {finding.check_name}: {finding.remediation}")

        # Then warnings (up to 2)
        for finding in warnings[:2]:
            if finding.remediation:
                console.print(f"  [yellow]*[/yellow] {finding.check_name}: {finding.remediation}")

        console.print()


def _display_available_checks() -> None:
    """Display all available security checks."""
    console.print()
    console.print("[bold]Available Security Checks[/bold]")
    console.print("=" * 60)
    console.print()

    # Group checks by category
    categories = {}
    for check in SECURITY_CHECKS:
        cat = check["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(check)

    # Display order
    category_order = ["network", "users", "filesystem", "services", "external"]

    for cat_name in category_order:
        if cat_name not in categories:
            continue

        checks = categories[cat_name]
        console.print(f"[bold cyan]{cat_name.upper()}[/bold cyan]")

        for check in checks:
            quick_marker = "" if check.get("quick", True) else " [dim](slow)[/dim]"
            console.print(f"  [green]{check['id']}[/green]  {check['name']}{quick_marker}")
            if check.get("description"):
                console.print(f"         [dim]{check['description']}[/dim]")

        console.print()

    console.print("[dim]Checks marked (slow) are skipped with --quick flag[/dim]")
    console.print()
