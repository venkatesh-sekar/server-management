"""Security hardening command implementation.

This module implements the `sm security harden` command which:
- Installs and configures fail2ban for SSH brute-force protection
- Installs and configures auditd with baseline rules
- Configures unattended-upgrades for automatic security updates
"""

import os
import subprocess
from pathlib import Path
from typing import Optional

import typer
from jinja2 import Environment, PackageLoader, select_autoescape

from sm.core.context import ExecutionContext
from sm.core.output import console
from sm.core.executor import RollbackStack, CommandExecutor
from sm.core.exceptions import SMError, ExecutionError
from sm.core.audit import get_audit_logger, AuditEventType
from sm.services.systemd import SystemdService

# Jinja2 environment for templates
jinja_env = Environment(
    loader=PackageLoader("sm", "templates"),
    autoescape=select_autoescape(),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _config_matches(path: Path, expected: str) -> bool:
    """Check if config file already has expected content.

    Args:
        path: Path to the config file
        expected: Expected content

    Returns:
        True if file exists and content matches (ignoring trailing whitespace)
    """
    if not path.exists():
        return False
    return path.read_text().strip() == expected.strip()


class SecurityHarden:
    """Handles security hardening operations."""

    def __init__(self, ctx: ExecutionContext):
        self.ctx = ctx
        self.rollback = RollbackStack()
        self.executor = CommandExecutor(ctx)
        self.systemd = SystemdService(ctx, self.executor)

    def install_packages(self) -> None:
        """Install security packages via apt."""
        packages = [
            "fail2ban",
            "unattended-upgrades",
            "python3-systemd",
            "auditd",
            "audispd-plugins",
        ]

        self.ctx.console.step("Installing security packages")

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would install: {', '.join(packages)}")
            return

        # Update apt cache
        self.ctx.console.info("Updating apt cache...")
        result = subprocess.run(
            ["apt-get", "update", "-y"],
            capture_output=True,
            text=True,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        if result.returncode != 0:
            raise ExecutionError(
                message="Failed to update apt cache",
                command="apt-get update",
                return_code=result.returncode,
                stderr=result.stderr,
            )

        # Install packages
        self.ctx.console.info(f"Installing: {', '.join(packages)}")
        result = subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends"] + packages,
            capture_output=True,
            text=True,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        if result.returncode != 0:
            raise ExecutionError(
                message="Failed to install security packages",
                command="apt-get install",
                return_code=result.returncode,
                stderr=result.stderr,
            )

        self.ctx.console.success("Security packages installed")

    def configure_fail2ban(
        self,
        bantime: str = "10m",
        findtime: str = "10m",
        maxretry: int = 5,
    ) -> None:
        """Configure fail2ban for SSH protection."""
        self.ctx.console.step("Configuring fail2ban")

        jail_local = Path("/etc/fail2ban/jail.local")

        # Render template
        template = jinja_env.get_template("fail2ban/jail.local.j2")
        content = template.render(
            bantime=bantime,
            findtime=findtime,
            maxretry=maxretry,
        )

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would create {jail_local}")
            self.ctx.console.code(content, language="ini", title="jail.local")
            return

        # Check if config already matches - skip if already in desired state
        if _config_matches(jail_local, content):
            self.ctx.console.info(f"{jail_local} already configured correctly")
            # Still ensure service is enabled and running
            self.systemd.enable("fail2ban")
            self.ctx.console.success("fail2ban already configured and running")
            return

        # Check if already exists and backup
        if jail_local.exists():
            self.ctx.console.warn(f"{jail_local} already exists, backing up")
            backup_path = jail_local.with_suffix(".local.bak")
            # Create backup
            import shutil
            shutil.copy2(jail_local, backup_path)
            self.rollback.push(
                lambda: shutil.move(str(backup_path), str(jail_local)),
                f"Restore {jail_local} from backup",
            )

        # Write config
        jail_local.write_text(content)
        self.ctx.console.info(f"Created {jail_local}")

        # Enable and restart fail2ban
        self.systemd.enable("fail2ban")
        self.systemd.restart("fail2ban")

        self.ctx.console.success("fail2ban configured and running")

    def configure_auditd(self) -> None:
        """Configure auditd with baseline rules."""
        self.ctx.console.step("Configuring auditd baseline rules")

        rules_dir = Path("/etc/audit/rules.d")
        rules_file = rules_dir / "hardening.rules"

        # Render template
        template = jinja_env.get_template("auditd/hardening.rules.j2")
        content = template.render(extra_watches=[])

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would create {rules_file}")
            self.ctx.console.code(content, language="bash", title="hardening.rules")
            return

        # Check if config already matches - skip if already in desired state
        if _config_matches(rules_file, content):
            self.ctx.console.info(f"{rules_file} already configured correctly")
            # Still ensure service is enabled
            self.systemd.enable("auditd")
            self.ctx.console.success("auditd already configured with baseline rules")
            return

        # Create directory if needed
        rules_dir.mkdir(parents=True, exist_ok=True)

        # Check if already exists and backup
        if rules_file.exists():
            self.ctx.console.warn(f"{rules_file} already exists, backing up")
            backup_path = rules_file.with_suffix(".rules.bak")
            import shutil
            shutil.copy2(rules_file, backup_path)
            self.rollback.push(
                lambda: shutil.move(str(backup_path), str(rules_file)),
                f"Restore {rules_file} from backup",
            )

        # Write rules
        rules_file.write_text(content)
        self.ctx.console.info(f"Created {rules_file}")

        # Enable auditd
        self.systemd.enable("auditd")

        # Restart auditd (may fail if in immutable mode, which is OK)
        try:
            # Use service command for auditd (systemctl restart doesn't always work)
            if not self.ctx.dry_run:
                result = subprocess.run(
                    ["service", "auditd", "restart"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    self.ctx.console.warn("auditd restart signal sent (may fail if immutable)")
        except Exception:
            self.ctx.console.warn("auditd restart signal sent")

        # Load rules with augenrules
        if not self.ctx.dry_run:
            result = subprocess.run(
                ["which", "augenrules"],
                capture_output=True,
            )
            if result.returncode == 0:
                subprocess.run(
                    ["augenrules", "--load"],
                    capture_output=True,
                )
                self.ctx.console.info("Loaded audit rules with augenrules")

        self.ctx.console.success("auditd configured with baseline rules")

    def configure_unattended_upgrades(self) -> None:
        """Configure unattended-upgrades for automatic security updates."""
        self.ctx.console.step("Configuring unattended-upgrades")

        config_file = Path("/etc/apt/apt.conf.d/20auto-upgrades")

        # Render template
        template = jinja_env.get_template("unattended-upgrades/20auto-upgrades.j2")
        content = template.render(
            update_package_lists=1,
            unattended_upgrade=1,
            download_upgradeable=1,
            autoclean_interval=7,
        )

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would configure {config_file}")
            self.ctx.console.code(content, language="text", title="20auto-upgrades")
            return

        # Check if config already matches - skip if already in desired state
        if _config_matches(config_file, content):
            self.ctx.console.info(f"{config_file} already configured correctly")
            self.ctx.console.success("unattended-upgrades already configured")
            return

        # Backup if exists
        if config_file.exists():
            self.ctx.console.warn(f"{config_file} already exists, backing up")
            backup_path = config_file.with_suffix(".bak")
            import shutil
            shutil.copy2(config_file, backup_path)
            self.rollback.push(
                lambda: shutil.move(str(backup_path), str(config_file)),
                f"Restore {config_file} from backup",
            )

        # Write config
        config_file.write_text(content)
        self.ctx.console.info(f"Updated {config_file}")

        # Run dpkg-reconfigure
        result = subprocess.run(
            ["dpkg-reconfigure", "--priority=low", "unattended-upgrades"],
            capture_output=True,
            text=True,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        if result.returncode != 0:
            self.ctx.console.warn("dpkg-reconfigure completed with warnings")

        self.ctx.console.success("unattended-upgrades configured")


def run_harden(
    ctx: ExecutionContext,
    bantime: str = "10m",
    findtime: str = "10m",
    maxretry: int = 5,
    skip_fail2ban: bool = False,
    skip_auditd: bool = False,
    skip_upgrades: bool = False,
) -> None:
    """Run security hardening operations.

    Args:
        ctx: Execution context
        bantime: fail2ban ban duration
        findtime: fail2ban find time window
        maxretry: fail2ban max retry count
        skip_fail2ban: Skip fail2ban configuration
        skip_auditd: Skip auditd configuration
        skip_upgrades: Skip unattended-upgrades configuration
    """
    hardener = SecurityHarden(ctx)
    audit = get_audit_logger()

    # Build list of components being configured
    configured_components = []
    if not skip_fail2ban:
        configured_components.append("fail2ban")
    if not skip_auditd:
        configured_components.append("auditd")
    if not skip_upgrades:
        configured_components.append("unattended-upgrades")

    try:
        # Install packages (unless all components skipped)
        if not (skip_fail2ban and skip_auditd and skip_upgrades):
            hardener.install_packages()

        # Configure fail2ban
        if not skip_fail2ban:
            hardener.configure_fail2ban(bantime, findtime, maxretry)

        # Configure auditd
        if not skip_auditd:
            hardener.configure_auditd()

        # Configure unattended-upgrades
        if not skip_upgrades:
            hardener.configure_unattended_upgrades()

        # Summary
        ctx.console.print()
        ctx.console.success("Security hardening complete!")
        ctx.console.print()

        components = []
        if not skip_fail2ban:
            components.append("fail2ban: enabled and running")
        if not skip_auditd:
            components.append("auditd: enabled with hardening rules")
        if not skip_upgrades:
            components.append("unattended-upgrades: configured for security updates")

        ctx.console.summary("Security Components", {
            comp.split(":")[0]: comp.split(":")[1].strip()
            for comp in components
        })

        # Audit log success
        audit.log_success(
            AuditEventType.CONFIG_MODIFY,
            "security",
            "hardening",
            message=f"Security hardening completed: {', '.join(configured_components)}",
        )

    except SMError as e:
        # Audit log failure
        audit.log_failure(
            AuditEventType.CONFIG_MODIFY,
            "security",
            "hardening",
            error=str(e),
        )
        # Rollback on error
        if hardener.rollback.has_items():
            ctx.console.warn("Rolling back changes...")
            hardener.rollback.rollback_all()
        raise
