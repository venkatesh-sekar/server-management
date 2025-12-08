"""Interactive firewall setup wizard.

Provides a step-by-step guided setup for users who don't know networking.
"""

import os
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from sm.core import (
    SMError,
    console,
    create_context,
    CommandExecutor,
    RollbackStack,
    get_audit_logger,
    AuditEventType,
)
from sm.services.iptables import IptablesService, Protocol, detect_firewall_providers
from sm.services.systemd import SystemdService
from sm.services.firewall_services import (
    SERVICES,
    SOURCE_ALIASES,
    ServiceDefinition,
    resolve_source,
    get_services_by_category,
)


# Server type presets
SERVER_TYPES = {
    "web": {
        "name": "Web Server",
        "description": "Websites, APIs, web applications",
        "services": ["web"],
        "default_source": "anywhere",
    },
    "database": {
        "name": "Database Server",
        "description": "PostgreSQL, MySQL, Redis, etc.",
        "services": ["postgres"],
        "default_source": "local-network",
    },
    "docker": {
        "name": "Docker Host",
        "description": "Docker containers and Swarm",
        "services": ["docker-swarm"],
        "default_source": "local-network",
    },
    "custom": {
        "name": "Custom Setup",
        "description": "Choose specific services",
        "services": [],
        "default_source": "anywhere",
    },
    "minimal": {
        "name": "Minimal (SSH only)",
        "description": "Block everything except SSH",
        "services": [],
        "default_source": "anywhere",
    },
}


class FirewallWizard:
    """Interactive firewall setup wizard."""

    def __init__(self, dry_run: bool = False, yes: bool = False, verbose: int = 0):
        self.dry_run = dry_run
        self.yes = yes
        self.verbose = verbose
        self.ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
        self.executor = CommandExecutor(self.ctx)
        self.systemd = SystemdService(self.ctx, self.executor)
        self.iptables = IptablesService(self.ctx, self.executor, self.systemd)
        self.audit = get_audit_logger()

        # Configuration to build
        self.selected_services: list[ServiceDefinition] = []
        self.service_sources: dict[str, str] = {}  # service_name -> source
        self.custom_ports: list[tuple[int, str]] = []  # (port, source)

        # New options
        self.enable_exclusive_mode: bool = False
        self.install_systemd_hooks: bool = False

    def run(self) -> None:
        """Run the interactive wizard."""
        self._check_root()
        self._show_welcome()

        # Step 1: Server type
        server_type = self._select_server_type()
        if server_type is None:
            return

        # Step 2: Additional services (if custom or adding more)
        if server_type == "custom":
            self._select_services()
        elif server_type != "minimal":
            self._maybe_add_services(server_type)

        # Step 3: Configure sources for each service
        self._configure_sources()

        # Step 4: Advanced options (exclusive mode, systemd hooks)
        self._configure_advanced_options(server_type)

        # Step 5: Review and confirm
        if not self._review_configuration():
            return

        # Step 6: Apply
        self._apply_configuration()

    def _check_root(self) -> None:
        """Check for root privileges."""
        if os.geteuid() != 0 and not self.dry_run:
            self.ctx.console.error("This operation requires root privileges")
            self.ctx.console.hint("Run with: sudo sm firewall setup")
            raise typer.Exit(6)

    def _show_welcome(self) -> None:
        """Show welcome message."""
        self.ctx.console.print()
        self.ctx.console.print(Panel(
            "[bold]Firewall Setup Wizard[/bold]\n\n"
            "This wizard will help you set up your server's firewall.\n"
            "A firewall controls which network traffic can reach your server.\n\n"
            "[green]SSH access will ALWAYS be allowed[/green] so you don't get locked out.",
            title="Welcome",
            border_style="blue",
        ))
        self.ctx.console.print()

    def _select_server_type(self) -> Optional[str]:
        """Ask user what type of server this is."""
        self.ctx.console.print("[bold]Step 1: What does this server do?[/bold]")
        self.ctx.console.print()

        options = list(SERVER_TYPES.items())
        for i, (key, info) in enumerate(options, 1):
            self.ctx.console.print(f"  [{i}] {info['name']}")
            self.ctx.console.print(f"      [dim]{info['description']}[/dim]")

        self.ctx.console.print()
        self.ctx.console.print("  [0] Cancel")
        self.ctx.console.print()

        while True:
            try:
                choice = self.ctx.console.input("[bold]Enter choice (1-5, or 0 to cancel): [/bold]")
                choice = int(choice.strip())

                if choice == 0:
                    self.ctx.console.warn("Setup cancelled")
                    return None

                if 1 <= choice <= len(options):
                    selected_key = options[choice - 1][0]
                    selected_info = options[choice - 1][1]

                    # Pre-populate services based on server type
                    for service_name in selected_info["services"]:
                        if service_name in SERVICES:
                            self.selected_services.append(SERVICES[service_name])
                            self.service_sources[service_name] = selected_info["default_source"]

                    self.ctx.console.print()
                    self.ctx.console.print(f"  Selected: [bold]{selected_info['name']}[/bold]")
                    self.ctx.console.print()
                    return selected_key

                self.ctx.console.warn(f"Please enter a number between 0 and {len(options)}")

            except ValueError:
                self.ctx.console.warn("Please enter a number")
            except (EOFError, KeyboardInterrupt):
                self.ctx.console.print()
                self.ctx.console.warn("Setup cancelled")
                return None

    def _maybe_add_services(self, server_type: str) -> None:
        """Ask if user wants to add more services."""
        self.ctx.console.print("[bold]Step 2: Additional Services[/bold]")
        self.ctx.console.print()

        current = [s.display_name for s in self.selected_services]
        if current:
            self.ctx.console.print(f"  Current services: {', '.join(current)}")
            self.ctx.console.print()

        if not self.ctx.console.confirm("Would you like to add additional services?"):
            self.ctx.console.print()
            return

        self._select_services()

    def _select_services(self) -> None:
        """Let user select services from categories."""
        self.ctx.console.print()
        self.ctx.console.print("[bold]Select services to allow:[/bold]")
        self.ctx.console.print()

        categories = ["web", "database", "containers", "monitoring", "mail", "system"]
        all_services = []

        for category in categories:
            services = get_services_by_category(category)
            for svc in services:
                if svc.name != "ssh":  # SSH is always allowed
                    all_services.append(svc)

        # Display services with numbers
        for i, svc in enumerate(all_services, 1):
            ports = ", ".join(str(p.port) for p in svc.ports)
            already_selected = "  [green]*[/green]" if svc in self.selected_services else ""
            self.ctx.console.print(f"  [{i:2}] {svc.display_name:20} ({ports}){already_selected}")

        self.ctx.console.print()
        self.ctx.console.print("  [dim]Enter numbers separated by spaces, or 'done' to continue[/dim]")
        self.ctx.console.print()

        while True:
            try:
                choice = self.ctx.console.input("[bold]Select services: [/bold]")
                choice = choice.strip().lower()

                if choice == "done" or choice == "":
                    break

                # Parse numbers
                for num_str in choice.split():
                    try:
                        num = int(num_str)
                        if 1 <= num <= len(all_services):
                            svc = all_services[num - 1]
                            if svc not in self.selected_services:
                                self.selected_services.append(svc)
                                self.service_sources[svc.name] = svc.default_source
                                self.ctx.console.print(f"    Added: {svc.display_name}")
                    except ValueError:
                        pass

            except (EOFError, KeyboardInterrupt):
                break

        self.ctx.console.print()

    def _configure_sources(self) -> None:
        """Configure who can access each service."""
        if not self.selected_services:
            return

        self.ctx.console.print("[bold]Step 3: Who should have access?[/bold]")
        self.ctx.console.print()

        # Show source options
        self.ctx.console.print("  [bold]Access options:[/bold]")
        self.ctx.console.print("  [1] Anywhere      - Any IP on the internet")
        self.ctx.console.print("  [2] Local Network - Only private networks (10.x, 192.168.x)")
        self.ctx.console.print("  [3] This Machine  - Only localhost")
        self.ctx.console.print()

        source_map = {
            "1": "anywhere",
            "2": "local-network",
            "3": "this-machine",
        }

        # Ask about each service (or all at once for simplicity)
        if len(self.selected_services) == 1:
            # Single service - just ask
            svc = self.selected_services[0]
            self._configure_service_source(svc, source_map)
        else:
            # Multiple services - ask if same for all
            if self.ctx.console.confirm("Use the same access setting for all services?"):
                self.ctx.console.print()
                while True:
                    try:
                        choice = self.ctx.console.input("[bold]Access level (1-3): [/bold]")
                        if choice in source_map:
                            for svc in self.selected_services:
                                self.service_sources[svc.name] = source_map[choice]
                            break
                        self.ctx.console.warn("Please enter 1, 2, or 3")
                    except (EOFError, KeyboardInterrupt):
                        break
            else:
                # Configure each service
                self.ctx.console.print()
                for svc in self.selected_services:
                    self._configure_service_source(svc, source_map)

        self.ctx.console.print()

    def _configure_service_source(self, svc: ServiceDefinition, source_map: dict) -> None:
        """Configure source for a single service."""
        default = self.service_sources.get(svc.name, svc.default_source)
        default_num = {"anywhere": "1", "local-network": "2", "this-machine": "3"}.get(default, "1")

        while True:
            try:
                choice = self.ctx.console.input(
                    f"  {svc.display_name} access [{default_num}]: "
                )
                choice = choice.strip() or default_num

                if choice in source_map:
                    self.service_sources[svc.name] = source_map[choice]

                    # Warn about risky configs
                    if svc.warning and source_map[choice] == "anywhere":
                        self.ctx.console.warn(f"    {svc.warning}")

                    break
                self.ctx.console.warn("Please enter 1, 2, or 3")

            except (EOFError, KeyboardInterrupt):
                self.service_sources[svc.name] = default
                break

    def _configure_advanced_options(self, server_type: str) -> None:
        """Configure advanced options like exclusive mode and systemd hooks."""
        self.ctx.console.print("[bold]Step 4: Advanced Options[/bold]")
        self.ctx.console.print()

        # Check for other firewall providers
        providers = detect_firewall_providers()
        has_other_providers = providers.ufw_installed or providers.firewalld_installed
        has_docker = self.systemd.exists("docker.service")

        # Exclusive mode
        if has_other_providers:
            self.ctx.console.print("  [bold]Other firewall tools detected:[/bold]")
            if providers.ufw_installed:
                status = "[red]Active[/red]" if providers.ufw_active else "[dim]Inactive[/dim]"
                self.ctx.console.print(f"    - UFW: {status}")
            if providers.firewalld_installed:
                status = "[red]Active[/red]" if providers.firewalld_active else "[dim]Inactive[/dim]"
                self.ctx.console.print(f"    - firewalld: {status}")
            self.ctx.console.print()

            self.ctx.console.print("  [bold]Exclusive Mode[/bold]")
            self.ctx.console.print("  [dim]Disables and masks UFW/firewalld so only SM manages the firewall.[/dim]")
            self.ctx.console.print("  [dim]This prevents conflicts and accidental rule changes.[/dim]")
            self.ctx.console.print()

            self.enable_exclusive_mode = self.ctx.console.confirm(
                "Enable exclusive mode (recommended)?",
                default=True,
            )
            self.ctx.console.print()

        # Docker integration (systemd hooks)
        if has_docker or server_type == "docker":
            self.ctx.console.print("  [bold]Docker Integration[/bold]")
            self.ctx.console.print("  [dim]When Docker restarts, it recreates its firewall chains.[/dim]")
            self.ctx.console.print("  [dim]Installing systemd hooks ensures SM rules persist after Docker restarts.[/dim]")
            self.ctx.console.print()

            self.install_systemd_hooks = self.ctx.console.confirm(
                "Install systemd hooks for Docker persistence (recommended)?",
                default=True,
            )
            self.ctx.console.print()

        # If no prompts were shown, show a brief message
        if not has_other_providers and not has_docker and server_type != "docker":
            self.ctx.console.print("  [dim]No advanced options needed for this configuration.[/dim]")
            self.ctx.console.print()

    def _review_configuration(self) -> bool:
        """Show configuration review and confirm."""
        self.ctx.console.print("[bold]Step 5: Review Configuration[/bold]")
        self.ctx.console.print()

        # Build summary table
        table = Table(title="Firewall Configuration", show_header=True)
        table.add_column("Service", style="cyan")
        table.add_column("Ports")
        table.add_column("Access From", style="yellow")
        table.add_column("Notes", style="dim")

        # SSH is always allowed
        table.add_row("SSH", str(self.iptables.ssh_port), "Anywhere", "[protected]")

        # Selected services
        for svc in self.selected_services:
            ports = ", ".join(str(p.port) for p in svc.ports)
            source = self.service_sources.get(svc.name, "anywhere")
            source_def = SOURCE_ALIASES.get(source)
            source_display = source_def.display_name if source_def else source
            notes = ""
            if svc.warning and source == "anywhere":
                notes = "[yellow]Warning![/yellow]"
            table.add_row(svc.display_name, ports, source_display, notes)

        # Everything else
        table.add_row("[dim]Everything else[/dim]", "-", "-", "[red]BLOCKED[/red]")

        self.ctx.console.print(table)
        self.ctx.console.print()

        # Show advanced options if any are enabled
        if self.enable_exclusive_mode or self.install_systemd_hooks:
            self.ctx.console.print("[bold]Advanced Options:[/bold]")
            if self.enable_exclusive_mode:
                self.ctx.console.print("  - [green]Exclusive mode[/green]: Will disable UFW/firewalld")
            if self.install_systemd_hooks:
                self.ctx.console.print("  - [green]Systemd hooks[/green]: Will persist rules across Docker restarts")
            self.ctx.console.print()

        if self.dry_run:
            self.ctx.console.print("[blue][DRY-RUN][/blue] Would apply this configuration")
            return True

        return self.ctx.console.confirm("Apply this configuration?")

    def _apply_configuration(self) -> None:
        """Apply the firewall configuration."""
        self.ctx.console.print()
        self.ctx.console.print("[bold]Applying configuration...[/bold]")
        self.ctx.console.print()

        rollback = RollbackStack()

        try:
            # Backup current rules
            self.iptables.backup(suffix="-pre-wizard")

            # Ensure safety rules
            self.iptables.ensure_loopback_allowed()
            self.iptables.ensure_established_allowed()
            self.iptables.ensure_ssh_allowed()

            # Apply selected services
            for svc in self.selected_services:
                source_str = self.service_sources.get(svc.name, "anywhere")
                source_cidrs = resolve_source(source_str)

                for port_spec in svc.ports:
                    for cidr in source_cidrs:
                        self.iptables.allow_port(
                            port=port_spec.port,
                            protocol=port_spec.protocol,
                            source=cidr,
                            comment=svc.display_name,
                            rollback=rollback,
                        )

                self.ctx.console.step(f"Allowed {svc.display_name}")

            # Set DROP policy
            self.iptables.set_default_policy("DROP")

            # Save rules
            self.iptables.save()

            # Install persistence
            self.iptables.install_persistence()

            # Enable exclusive mode if selected
            if self.enable_exclusive_mode:
                self.ctx.console.step("Enabling exclusive mode")
                self._enable_exclusive_mode()

            # Install systemd hooks if selected
            if self.install_systemd_hooks:
                self.ctx.console.step("Installing systemd hooks")
                self.iptables.install_systemd_hooks()

            self.ctx.console.print()
            self.ctx.console.success("Firewall configured successfully!")
            self.ctx.console.print()

            # Show relevant hints
            self.ctx.console.hint("Use 'sm firewall status' to see current configuration")
            if self.enable_exclusive_mode:
                self.ctx.console.hint("Exclusive mode enabled - UFW/firewalld are now disabled and masked")
            if self.install_systemd_hooks:
                self.ctx.console.hint("Systemd hooks installed - rules will persist across Docker restarts")

            # Log audit event
            services_str = ", ".join(s.name for s in self.selected_services) or "ssh-only"
            extras = []
            if self.enable_exclusive_mode:
                extras.append("exclusive_mode")
            if self.install_systemd_hooks:
                extras.append("systemd_hooks")
            extras_str = f" ({', '.join(extras)})" if extras else ""
            self.audit.log_success(
                AuditEventType.FIREWALL_ENABLE,
                "firewall",
                "wizard",
                message=f"Firewall configured via wizard: {services_str}{extras_str}",
            )

        except SMError as e:
            self.audit.log_failure(
                AuditEventType.FIREWALL_ENABLE,
                "firewall",
                "wizard",
                error=str(e),
            )
            if rollback.has_items():
                self.ctx.console.warn("Rolling back changes...")
                rollback.rollback_all()
            raise

    def _enable_exclusive_mode(self) -> None:
        """Enable exclusive mode by disabling and masking other firewall tools."""
        import subprocess

        providers = detect_firewall_providers()

        # Stop and mask UFW if installed
        if providers.ufw_installed:
            if providers.ufw_active:
                # UFW has its own disable command
                if not self.dry_run:
                    subprocess.run(["ufw", "disable"], capture_output=True)

            if not self.systemd.is_masked("ufw"):
                self.systemd.disable("ufw", stop=True, description="Disabling UFW")
                self.systemd.mask("ufw", description="Masking UFW")

        # Stop and mask firewalld if installed
        if providers.firewalld_installed:
            if providers.firewalld_active:
                self.systemd.stop("firewalld", description="Stopping firewalld")

            if not self.systemd.is_masked("firewalld"):
                self.systemd.disable("firewalld", stop=True, description="Disabling firewalld")
                self.systemd.mask("firewalld", description="Masking firewalld")

        # Update state
        self.iptables.state_manager.set_exclusive_mode(True)
        self.iptables.state_manager.save()
