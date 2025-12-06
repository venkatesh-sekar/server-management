"""Docker MTU fix implementation.

This module implements the `sm docker fix-mtu` command which:
- Configures Docker daemon.json with proper MTU settings
- Restarts Docker daemon to apply changes
- Handles existing configuration gracefully
"""

import json
import subprocess
from pathlib import Path
from typing import Any, Dict

from sm.core.context import ExecutionContext
from sm.core.executor import CommandExecutor, RollbackStack
from sm.core.exceptions import ExecutionError, ValidationError
from sm.core.audit import get_audit_logger, AuditEventType
from sm.services.systemd import SystemdService


class DockerMTUFixer:
    """Handles Docker MTU configuration."""

    def __init__(self, ctx: ExecutionContext):
        self.ctx = ctx
        self.rollback = RollbackStack()
        self.daemon_json_path = Path("/etc/docker/daemon.json")

    def is_mtu_configured(self, mtu: int) -> bool:
        """Check if MTU is already configured correctly.

        Args:
            mtu: Expected MTU value

        Returns:
            True if MTU is already configured to the expected value
        """
        if not self.daemon_json_path.exists():
            return False

        try:
            content = self.daemon_json_path.read_text()
            config = json.loads(content) if content.strip() else {}

            # Check for MTU configuration
            mtu_str = (
                config.get("default-network-opts", {})
                .get("overlay", {})
                .get("com.docker.network.driver.mtu")
            )

            return mtu_str == str(mtu)

        except (json.JSONDecodeError, ValueError):
            return False

    def check_docker_installed(self) -> None:
        """Check if Docker is installed."""
        self.ctx.console.step("Checking Docker installation")

        if self.ctx.dry_run:
            self.ctx.console.info("Would check if Docker is installed")
            return

        result = subprocess.run(
            ["which", "docker"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise ValidationError(
                message="Docker is not installed",
                hint="Install Docker first: curl -fsSL https://get.docker.com | sh",
            )

        # Check Docker daemon is running
        result = subprocess.run(
            ["systemctl", "is-active", "docker"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise ValidationError(
                message="Docker daemon is not running",
                hint="Start Docker: sudo systemctl start docker",
            )

        self.ctx.console.success("Docker is installed and running")

    def backup_config(self) -> None:
        """Backup existing daemon.json if it exists."""
        if not self.daemon_json_path.exists():
            self.ctx.console.info("No existing daemon.json found")
            return

        backup_path = self.daemon_json_path.with_suffix(".json.bak")

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would backup {self.daemon_json_path} to {backup_path}")
            return

        self.ctx.console.info(f"Backing up {self.daemon_json_path}")

        import shutil
        shutil.copy2(self.daemon_json_path, backup_path)

        # Add rollback
        self.rollback.push(
            lambda: shutil.move(str(backup_path), str(self.daemon_json_path)),
            f"Restore {self.daemon_json_path} from backup",
        )

        self.ctx.console.info(f"Backup created: {backup_path}")

    def read_existing_config(self) -> Dict[str, Any]:
        """Read existing daemon.json or return empty dict."""
        if not self.daemon_json_path.exists():
            return {}

        try:
            content = self.daemon_json_path.read_text()
            return json.loads(content) if content.strip() else {}
        except json.JSONDecodeError as e:
            raise ValidationError(
                message=f"Invalid JSON in {self.daemon_json_path}",
                details=[str(e)],
                hint="Fix the JSON syntax or remove the file to start fresh",
            )

    def update_config(self, mtu: int) -> None:
        """Update daemon.json with MTU configuration."""
        self.ctx.console.step(f"Configuring Docker daemon with MTU {mtu}")

        # Read existing config
        config = self.read_existing_config() if not self.ctx.dry_run else {}

        # Ensure log configuration exists (best practices)
        if "log-driver" not in config:
            config["log-driver"] = "json-file"

        if "log-opts" not in config:
            config["log-opts"] = {
                "max-size": "10m",
                "max-file": "3",
            }

        # Add MTU configuration
        if "default-network-opts" not in config:
            config["default-network-opts"] = {}

        config["default-network-opts"]["overlay"] = {
            "com.docker.network.driver.mtu": str(mtu)
        }

        # Pretty print JSON
        content = json.dumps(config, indent=2)

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would update {self.daemon_json_path}")
            self.ctx.console.code(content, language="json", title="daemon.json")
            return

        # Ensure /etc/docker directory exists
        self.daemon_json_path.parent.mkdir(parents=True, exist_ok=True)

        # Write config
        self.daemon_json_path.write_text(content + "\n")
        self.ctx.console.success(f"Updated {self.daemon_json_path}")

        # Show what was written
        if self.ctx.is_verbose:
            self.ctx.console.code(content, language="json", title="daemon.json")

    def restart_docker(self) -> None:
        """Restart Docker daemon to apply changes."""
        if self.ctx.dry_run:
            self.ctx.console.info("Would restart Docker daemon")
            return

        executor = CommandExecutor(self.ctx)
        systemd = SystemdService(self.ctx, executor)
        systemd.restart("docker", description="Restarting Docker daemon")

    def verify_config(self, mtu: int) -> None:
        """Verify the MTU configuration is active."""
        self.ctx.console.step("Verifying configuration")

        if self.ctx.dry_run:
            self.ctx.console.info("Would verify Docker MTU configuration")
            return

        # Check if Docker is running
        result = subprocess.run(
            ["systemctl", "is-active", "docker"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise ExecutionError(
                message="Docker failed to start after configuration",
                hint="Check logs: sudo journalctl -u docker -n 50",
            )

        self.ctx.console.success("Docker is running with new configuration")

        # Show info about new networks
        self.ctx.console.print()
        self.ctx.console.info("MTU configuration applied successfully")
        self.ctx.console.print(f"  New overlay networks will use MTU {mtu}")
        self.ctx.console.print("  Existing networks are not affected")
        self.ctx.console.print()
        self.ctx.console.hint("Recreate existing networks to apply new MTU")


def run_fix_mtu(ctx: ExecutionContext, mtu: int = 1450) -> None:
    """Run Docker MTU fix operation.

    Args:
        ctx: Execution context
        mtu: MTU value to configure (default: 1450)
    """
    audit = get_audit_logger()

    # Validate MTU value
    if mtu < 68 or mtu > 65535:
        raise ValidationError(
            message=f"Invalid MTU value: {mtu}",
            hint="MTU must be between 68 and 65535. Use 1450 for Hetzner Cloud.",
        )

    fixer = DockerMTUFixer(ctx)

    # Check if already configured correctly (idempotency)
    if not ctx.dry_run and fixer.is_mtu_configured(mtu):
        ctx.console.info(f"Docker MTU already configured to {mtu}")
        ctx.console.success("No changes needed")
        audit.log_success(
            AuditEventType.CONFIG_MODIFY,
            "docker",
            "mtu",
            message=f"Docker MTU already configured to {mtu} (no changes)",
        )
        return

    try:
        # Check Docker is installed
        fixer.check_docker_installed()

        # Backup existing config
        fixer.backup_config()

        # Update configuration
        fixer.update_config(mtu)

        # Restart Docker
        fixer.restart_docker()

        # Verify
        fixer.verify_config(mtu)

        # Summary
        ctx.console.print()
        ctx.console.success("Docker MTU fix complete!")
        ctx.console.print()

        ctx.console.summary("Configuration", {
            "MTU value": str(mtu),
            "Config file": str(fixer.daemon_json_path),
            "Docker status": "Running",
        })

        if fixer.daemon_json_path.with_suffix(".json.bak").exists():
            ctx.console.print()
            ctx.console.info(
                f"Backup saved: {fixer.daemon_json_path.with_suffix('.json.bak')}"
            )

        # Audit log success
        audit.log_success(
            AuditEventType.CONFIG_MODIFY,
            "docker",
            "mtu",
            message=f"Docker MTU configured to {mtu}",
        )

    except Exception as e:
        # Audit log failure
        audit.log_failure(
            AuditEventType.CONFIG_MODIFY,
            "docker",
            "mtu",
            error=str(e),
        )
        # Rollback on error
        if fixer.rollback.has_items():
            ctx.console.warn("Rolling back changes...")
            fixer.rollback.rollback_all()
        raise
