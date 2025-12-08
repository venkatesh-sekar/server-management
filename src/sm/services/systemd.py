"""Systemd service abstraction.

Provides a safe interface for managing systemd services.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sm.core.context import ExecutionContext
from sm.core.executor import CommandExecutor
from sm.core.exceptions import ServiceError


# Standard systemd paths
SYSTEMD_SYSTEM_DIR = Path("/etc/systemd/system")


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

    def is_masked(self, service: str) -> bool:
        """Check if a service is masked.

        Args:
            service: Service name

        Returns:
            True if service is masked
        """
        if self.ctx.dry_run:
            return False

        result = self.executor.run(
            ["systemctl", "is-enabled", service],
            check=False,
        )
        return result.stdout.strip() == "masked"

    def mask(
        self,
        service: str,
        *,
        description: Optional[str] = None,
    ) -> None:
        """Mask a service to prevent it from starting.

        Masking creates a symlink to /dev/null, preventing the service
        from being started manually or automatically.

        Args:
            service: Service name
            description: Optional description for logging
        """
        desc = description or f"Masking {service}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"systemctl mask {service}")
            return

        self.executor.run(["systemctl", "mask", service])

    def unmask(
        self,
        service: str,
        *,
        description: Optional[str] = None,
    ) -> None:
        """Unmask a previously masked service.

        This removes the mask but does not enable or start the service.

        Args:
            service: Service name
            description: Optional description for logging
        """
        desc = description or f"Unmasking {service}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"systemctl unmask {service}")
            return

        self.executor.run(["systemctl", "unmask", service])

    def install_drop_in(
        self,
        service: str,
        drop_in_name: str,
        content: str,
        *,
        description: Optional[str] = None,
    ) -> Path:
        """Install a systemd drop-in configuration file.

        Drop-in files extend or override service configurations.
        They are placed in /etc/systemd/system/<service>.d/<name>.conf

        Args:
            service: Service name (e.g., "docker.service")
            drop_in_name: Name for the drop-in file (without .conf)
            content: Content of the drop-in file
            description: Optional description for logging

        Returns:
            Path to the created drop-in file
        """
        # Ensure service name has .service suffix for directory
        if not service.endswith(".service"):
            service = f"{service}.service"

        drop_in_dir = SYSTEMD_SYSTEM_DIR / f"{service}.d"
        drop_in_path = drop_in_dir / f"{drop_in_name}.conf"

        desc = description or f"Installing drop-in {drop_in_name} for {service}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would create {drop_in_path}")
            return drop_in_path

        # Create drop-in directory if it doesn't exist
        drop_in_dir.mkdir(parents=True, exist_ok=True)

        # Write drop-in file
        with open(drop_in_path, "w") as f:
            f.write(content)

        self.ctx.console.debug(f"Created drop-in: {drop_in_path}")
        return drop_in_path

    def remove_drop_in(
        self,
        service: str,
        drop_in_name: str,
        *,
        description: Optional[str] = None,
    ) -> bool:
        """Remove a systemd drop-in configuration file.

        Args:
            service: Service name (e.g., "docker.service")
            drop_in_name: Name of the drop-in file (without .conf)
            description: Optional description for logging

        Returns:
            True if file was removed, False if it didn't exist
        """
        if not service.endswith(".service"):
            service = f"{service}.service"

        drop_in_dir = SYSTEMD_SYSTEM_DIR / f"{service}.d"
        drop_in_path = drop_in_dir / f"{drop_in_name}.conf"

        desc = description or f"Removing drop-in {drop_in_name} from {service}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would remove {drop_in_path}")
            return drop_in_path.exists()

        if not drop_in_path.exists():
            return False

        drop_in_path.unlink()

        # Remove directory if empty
        try:
            drop_in_dir.rmdir()
        except OSError:
            pass  # Directory not empty

        return True

    def install_service(
        self,
        name: str,
        content: str,
        *,
        enable: bool = True,
        start: bool = False,
        description: Optional[str] = None,
    ) -> Path:
        """Install a systemd service unit file.

        Creates the service file in /etc/systemd/system/ and optionally
        enables/starts it.

        Args:
            name: Service name (e.g., "sm-firewall" or "sm-firewall.service")
            content: Content of the service file
            enable: Whether to enable the service after installation
            start: Whether to start the service after installation
            description: Optional description for logging

        Returns:
            Path to the created service file
        """
        # Ensure name has .service suffix
        if not name.endswith(".service"):
            name = f"{name}.service"

        service_path = SYSTEMD_SYSTEM_DIR / name

        desc = description or f"Installing service {name}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would create {service_path}")
            if enable:
                self.ctx.console.dry_run_msg(f"Would enable {name}")
            if start:
                self.ctx.console.dry_run_msg(f"Would start {name}")
            return service_path

        # Write service file
        with open(service_path, "w") as f:
            f.write(content)

        self.ctx.console.debug(f"Created service: {service_path}")

        # Reload daemon to pick up new service
        self.daemon_reload()

        # Enable if requested
        if enable:
            self.enable(name, start=start, description=f"Enabling {name}")

        return service_path

    def remove_service(
        self,
        name: str,
        *,
        description: Optional[str] = None,
    ) -> bool:
        """Remove a systemd service unit file.

        Stops, disables, and removes the service file.

        Args:
            name: Service name (e.g., "sm-firewall" or "sm-firewall.service")
            description: Optional description for logging

        Returns:
            True if service was removed, False if it didn't exist
        """
        if not name.endswith(".service"):
            name = f"{name}.service"

        service_path = SYSTEMD_SYSTEM_DIR / name

        desc = description or f"Removing service {name}"
        self.ctx.console.step(desc)

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would stop and disable {name}")
            self.ctx.console.dry_run_msg(f"Would remove {service_path}")
            return service_path.exists()

        if not service_path.exists():
            return False

        # Stop if running
        if self.is_active(name):
            self.stop(name, description=f"Stopping {name}")

        # Disable if enabled
        if self.is_enabled(name):
            self.disable(name, description=f"Disabling {name}")

        # Remove file
        service_path.unlink()

        # Reload daemon
        self.daemon_reload()

        return True

    def drop_in_exists(self, service: str, drop_in_name: str) -> bool:
        """Check if a drop-in file exists.

        Args:
            service: Service name
            drop_in_name: Name of the drop-in file (without .conf)

        Returns:
            True if drop-in file exists
        """
        if not service.endswith(".service"):
            service = f"{service}.service"

        drop_in_path = SYSTEMD_SYSTEM_DIR / f"{service}.d" / f"{drop_in_name}.conf"
        return drop_in_path.exists()

    def service_file_exists(self, name: str) -> bool:
        """Check if a service file exists in /etc/systemd/system/.

        Args:
            name: Service name

        Returns:
            True if service file exists
        """
        if not name.endswith(".service"):
            name = f"{name}.service"

        return (SYSTEMD_SYSTEM_DIR / name).exists()
