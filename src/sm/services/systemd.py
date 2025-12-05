"""Systemd service abstraction.

Provides a safe interface for managing systemd services.
"""

from dataclasses import dataclass
from typing import Optional

from sm.core.context import ExecutionContext
from sm.core.executor import CommandExecutor
from sm.core.exceptions import ServiceError


@dataclass
class ServiceStatus:
    """Status of a systemd service."""
    name: str
    active: bool
    enabled: bool
    running: bool
    description: Optional[str] = None
    pid: Optional[int] = None


class SystemdService:
    """Safe interface for managing systemd services.

    All operations respect dry-run mode and log appropriately.
    """

    def __init__(self, ctx: ExecutionContext, executor: CommandExecutor) -> None:
        """Initialize systemd service manager.

        Args:
            ctx: Execution context
            executor: Command executor
        """
        self.ctx = ctx
        self.executor = executor

    def is_active(self, service: str) -> bool:
        """Check if a service is active (running).

        Args:
            service: Service name

        Returns:
            True if service is active
        """
        if self.ctx.dry_run:
            return False

        result = self.executor.run(
            ["systemctl", "is-active", "--quiet", service],
            check=False,
        )
        return result.success

    def is_enabled(self, service: str) -> bool:
        """Check if a service is enabled.

        Args:
            service: Service name

        Returns:
            True if service is enabled
        """
        if self.ctx.dry_run:
            return False

        result = self.executor.run(
            ["systemctl", "is-enabled", "--quiet", service],
            check=False,
        )
        return result.success

    def exists(self, service: str) -> bool:
        """Check if a service unit file exists.

        Args:
            service: Service name

        Returns:
            True if service exists
        """
        if self.ctx.dry_run:
            return True  # Assume exists in dry-run

        result = self.executor.run(
            ["systemctl", "list-unit-files", "--no-pager", service],
            check=False,
        )
        return service in result.stdout

    def status(self, service: str) -> ServiceStatus:
        """Get detailed status of a service.

        Args:
            service: Service name

        Returns:
            ServiceStatus with details
        """
        if self.ctx.dry_run:
            return ServiceStatus(
                name=service,
                active=False,
                enabled=False,
                running=False,
            )

        active = self.is_active(service)
        enabled = self.is_enabled(service)

        # Get more details
        result = self.executor.run(
            ["systemctl", "show", service,
             "--property=MainPID,Description"],
            check=False,
        )

        pid = None
        description = None
        for line in result.stdout.splitlines():
            if line.startswith("MainPID="):
                try:
                    pid = int(line.split("=")[1])
                    if pid == 0:
                        pid = None
                except (ValueError, IndexError):
                    pass
            elif line.startswith("Description="):
                description = line.split("=", 1)[1] if "=" in line else None

        return ServiceStatus(
            name=service,
            active=active,
            enabled=enabled,
            running=active and pid is not None,
            description=description,
            pid=pid,
        )

    def start(self, service: str, *, description: Optional[str] = None) -> None:
        """Start a service.

        Args:
            service: Service name
            description: Optional description for logging

        Raises:
            ServiceError: If service fails to start
        """
        desc = description or f"Starting {service}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"systemctl start {service}")
            return

        try:
            self.executor.run(["systemctl", "start", service])
        except Exception as e:
            raise ServiceError(
                f"Failed to start {service}",
                service=service,
                hint=f"Check logs: journalctl -xeu {service}",
            ) from e

    def stop(self, service: str, *, description: Optional[str] = None) -> None:
        """Stop a service.

        Args:
            service: Service name
            description: Optional description for logging

        Raises:
            ServiceError: If service fails to stop
        """
        desc = description or f"Stopping {service}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"systemctl stop {service}")
            return

        try:
            self.executor.run(["systemctl", "stop", service])
        except Exception as e:
            raise ServiceError(
                f"Failed to stop {service}",
                service=service,
            ) from e

    def restart(self, service: str, *, description: Optional[str] = None) -> None:
        """Restart a service.

        Args:
            service: Service name
            description: Optional description for logging

        Raises:
            ServiceError: If service fails to restart
        """
        desc = description or f"Restarting {service}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"systemctl restart {service}")
            return

        try:
            self.executor.run(["systemctl", "restart", service])
        except Exception as e:
            raise ServiceError(
                f"Failed to restart {service}",
                service=service,
                hint=f"Check logs: journalctl -xeu {service}",
            ) from e

    def reload(self, service: str, *, description: Optional[str] = None) -> None:
        """Reload a service configuration.

        Args:
            service: Service name
            description: Optional description for logging

        Raises:
            ServiceError: If service fails to reload
        """
        desc = description or f"Reloading {service}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"systemctl reload {service}")
            return

        try:
            self.executor.run(["systemctl", "reload", service])
        except Exception as e:
            # Try restart as fallback
            self.ctx.console.warn(f"Reload failed for {service}, trying restart...")
            self.restart(service, description=f"Restart {service} (reload fallback)")

    def enable(
        self,
        service: str,
        *,
        start: bool = False,
        description: Optional[str] = None,
    ) -> None:
        """Enable a service to start on boot.

        Args:
            service: Service name
            start: Also start the service now
            description: Optional description for logging
        """
        desc = description or f"Enabling {service}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            cmd = "systemctl enable --now" if start else "systemctl enable"
            self.ctx.console.dry_run_msg(f"{cmd} {service}")
            return

        args = ["systemctl", "enable"]
        if start:
            args.append("--now")
        args.append(service)

        self.executor.run(args)

    def disable(
        self,
        service: str,
        *,
        stop: bool = False,
        description: Optional[str] = None,
    ) -> None:
        """Disable a service from starting on boot.

        Args:
            service: Service name
            stop: Also stop the service now
            description: Optional description for logging
        """
        desc = description or f"Disabling {service}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            cmd = "systemctl disable --now" if stop else "systemctl disable"
            self.ctx.console.dry_run_msg(f"{cmd} {service}")
            return

        args = ["systemctl", "disable"]
        if stop:
            args.append("--now")
        args.append(service)

        self.executor.run(args)

    def daemon_reload(self) -> None:
        """Reload systemd daemon configuration."""
        self.ctx.console.step("Reloading systemd daemon")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("systemctl daemon-reload")
            return

        self.executor.run(["systemctl", "daemon-reload"])

    def get_service_user(self, service: str) -> tuple[str, str]:
        """Get the user and group that a service runs as.

        Args:
            service: Service name

        Returns:
            Tuple of (user, group)
        """
        if self.ctx.dry_run:
            return (service.replace(".service", ""), service.replace(".service", ""))

        result = self.executor.run(
            ["systemctl", "show", service, "--property=User,Group"],
            check=False,
        )

        user = service.replace(".service", "")
        group = user

        for line in result.stdout.splitlines():
            if line.startswith("User="):
                val = line.split("=")[1].strip()
                if val and val != "root":
                    user = val
            elif line.startswith("Group="):
                val = line.split("=")[1].strip()
                if val and val != "root":
                    group = val

        return (user, group)
