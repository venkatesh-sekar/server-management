"""Docker network MTU management.

This module provides commands to check and fix MTU issues in Docker networks.
"""

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from sm.core.context import ExecutionContext
from sm.core.exceptions import ExecutionError, ValidationError
from sm.core.audit import get_audit_logger, AuditEventType


@dataclass
class NetworkInfo:
    """Information about a Docker network."""

    name: str
    driver: str
    mtu: Optional[int]
    created: str
    needs_recreation: bool


class NetworkMTUManager:
    """Manages Docker network MTU configuration."""

    def __init__(self, ctx: ExecutionContext):
        self.ctx = ctx
        self.daemon_json_path = Path("/etc/docker/daemon.json")

    def check_daemon_config(self) -> tuple[bool, Optional[int]]:
        """Check if daemon.json has MTU configuration.

        Returns:
            Tuple of (is_configured, mtu_value)
        """
        if not self.daemon_json_path.exists():
            return False, None

        try:
            content = self.daemon_json_path.read_text()
            config = json.loads(content) if content.strip() else {}

            # Check for MTU configuration
            mtu_str = (
                config.get("default-network-opts", {})
                .get("overlay", {})
                .get("com.docker.network.driver.mtu")
            )

            if mtu_str:
                return True, int(mtu_str)

            return False, None

        except (json.JSONDecodeError, ValueError) as e:
            raise ValidationError(
                message=f"Invalid JSON in {self.daemon_json_path}",
                details=[str(e)],
            )

    def get_network_info(self, network_name: str) -> NetworkInfo:
        """Get information about a specific network.

        Args:
            network_name: Name of the network

        Returns:
            NetworkInfo object
        """
        try:
            # Get network details
            result = subprocess.run(
                [
                    "docker",
                    "network",
                    "inspect",
                    network_name,
                    "--format",
                    "{{json .}}",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            data = json.loads(result.stdout)
            driver = data.get("Driver", "unknown")
            created = data.get("Created", "unknown")

            # Try to get MTU from options
            options = data.get("Options") or {}
            mtu_str = options.get("com.docker.network.driver.mtu")
            mtu = int(mtu_str) if mtu_str else None

            # Determine if recreation is needed
            needs_recreation = False
            if driver == "overlay":
                if mtu is None or mtu != 1450:
                    needs_recreation = True

            return NetworkInfo(
                name=network_name,
                driver=driver,
                mtu=mtu,
                created=created,
                needs_recreation=needs_recreation,
            )

        except subprocess.CalledProcessError as e:
            raise ExecutionError(
                message=f"Failed to inspect network: {network_name}",
                details=[e.stderr] if e.stderr else [],
            )
        except (json.JSONDecodeError, ValueError) as e:
            raise ExecutionError(
                message=f"Failed to parse network info: {network_name}",
                details=[str(e)],
            )

    def list_all_networks(self) -> List[NetworkInfo]:
        """List all Docker networks with their MTU information.

        Returns:
            List of NetworkInfo objects
        """
        try:
            # Get all network names
            result = subprocess.run(
                ["docker", "network", "ls", "--format", "{{.Name}}"],
                capture_output=True,
                text=True,
                check=True,
            )

            network_names = [
                name.strip()
                for name in result.stdout.strip().split("\n")
                if name.strip()
            ]

            # Get info for each network
            networks = []
            for name in network_names:
                try:
                    networks.append(self.get_network_info(name))
                except ExecutionError:
                    # Skip networks we can't inspect
                    continue

            return networks

        except subprocess.CalledProcessError as e:
            raise ExecutionError(
                message="Failed to list Docker networks",
                details=[e.stderr] if e.stderr else [],
                hint="Make sure Docker is running",
            )

    def get_network_containers(self, network_name: str) -> List[Dict[str, str]]:
        """Get containers connected to a network.

        Args:
            network_name: Name of the network

        Returns:
            List of container info dicts with 'id' and 'name'
        """
        try:
            result = subprocess.run(
                [
                    "docker",
                    "ps",
                    "--filter",
                    f"network={network_name}",
                    "--format",
                    "{{.ID}}\t{{.Names}}",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            containers = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        containers.append({"id": parts[0], "name": parts[1]})

            return containers

        except subprocess.CalledProcessError as e:
            raise ExecutionError(
                message=f"Failed to list containers for network: {network_name}",
                details=[e.stderr] if e.stderr else [],
            )

    def get_network_config(self, network_name: str) -> Dict[str, Any]:
        """Get detailed network configuration for recreation.

        Args:
            network_name: Name of the network

        Returns:
            Dict with network configuration
        """
        try:
            result = subprocess.run(
                ["docker", "network", "inspect", network_name],
                capture_output=True,
                text=True,
                check=True,
            )

            data = json.loads(result.stdout)[0]

            # Extract relevant config
            config = {
                "driver": data.get("Driver", "overlay"),
                "attachable": data.get("Attachable", False),
                "internal": data.get("Internal", False),
                "ipv6": data.get("EnableIPv6", False),
            }

            # Get IPAM config
            ipam = data.get("IPAM", {})
            ipam_config = ipam.get("Config", [])
            if ipam_config:
                first_config = ipam_config[0]
                config["subnet"] = first_config.get("Subnet")
                config["gateway"] = first_config.get("Gateway")
                config["ip_range"] = first_config.get("IPRange")

            # Get options
            options = data.get("Options") or {}
            config["encrypted"] = options.get("encrypted") == "true"

            return config

        except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError) as e:
            raise ExecutionError(
                message=f"Failed to get network configuration: {network_name}",
                details=[str(e)],
            )

    def recreate_network(
        self, network_name: str, config: Dict[str, Any], dry_run: bool = False
    ) -> None:
        """Recreate a network with proper MTU configuration.

        Args:
            network_name: Name of the network to recreate
            config: Network configuration from get_network_config()
            dry_run: If True, only show what would be done
        """
        # Build docker network create command
        cmd = ["docker", "network", "create", "--driver", config["driver"]]

        # Add subnet/gateway if present
        if config.get("subnet"):
            cmd.extend(["--subnet", config["subnet"]])
        if config.get("gateway"):
            cmd.extend(["--gateway", config["gateway"]])
        if config.get("ip_range"):
            cmd.extend(["--ip-range", config["ip_range"]])

        # Add flags
        if config.get("attachable"):
            cmd.append("--attachable")
        if config.get("internal"):
            cmd.append("--internal")
        if config.get("ipv6"):
            cmd.append("--ipv6")
        if config.get("encrypted"):
            cmd.extend(["--opt", "encrypted=true"])

        # Add network name
        cmd.append(network_name)

        if dry_run:
            self.ctx.console.info("Would run:")
            self.ctx.console.code(" ".join(cmd), language="bash")
            return

        # Remove old network
        self.ctx.console.info(f"Removing old network: {network_name}")
        try:
            subprocess.run(
                ["docker", "network", "rm", network_name],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise ExecutionError(
                message=f"Failed to remove network: {network_name}",
                details=[e.stderr] if e.stderr else [],
                hint="Make sure all containers are disconnected first",
            )

        # Create new network
        self.ctx.console.info(f"Creating new network: {network_name}")
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.ctx.console.success(f"Network recreated: {network_name}")
        except subprocess.CalledProcessError as e:
            raise ExecutionError(
                message=f"Failed to create network: {network_name}",
                details=[e.stderr] if e.stderr else [],
            )


def run_check_mtu(ctx: ExecutionContext) -> None:
    """Check if Docker MTU fix is applied.

    Args:
        ctx: Execution context
    """
    manager = NetworkMTUManager(ctx)

    ctx.console.print()
    ctx.console.print("[bold]Docker MTU Configuration Check[/bold]")
    ctx.console.print()

    # Check daemon.json
    ctx.console.step("Checking daemon.json configuration")
    is_configured, mtu_value = manager.check_daemon_config()

    if is_configured:
        ctx.console.success(
            f"MTU configuration found in {manager.daemon_json_path}: {mtu_value}"
        )
    else:
        ctx.console.error(f"MTU configuration NOT found in {manager.daemon_json_path}")
        ctx.console.print()
        ctx.console.hint("Apply the fix with: sudo sm docker fix-mtu")
        ctx.console.print()
        return

    # Check Docker daemon status
    ctx.console.step("Checking Docker daemon status")
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "docker"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            ctx.console.success("Docker daemon is running")
        else:
            ctx.console.error("Docker daemon is not running")
            return
    except Exception as e:
        ctx.console.error(f"Failed to check Docker status: {e}")
        return

    # Check existing networks
    ctx.console.step("Checking existing overlay networks")
    networks = manager.list_all_networks()

    overlay_networks = [n for n in networks if n.driver == "overlay"]

    if not overlay_networks:
        ctx.console.info("No overlay networks found")
    else:
        needs_recreation = [n for n in overlay_networks if n.needs_recreation]

        ctx.console.print()
        for network in overlay_networks:
            mtu_display = network.mtu if network.mtu else "default (1500)"
            if network.needs_recreation:
                ctx.console.print(
                    f"  ❌ {network.name} (MTU: {mtu_display}) - needs recreation"
                )
            else:
                ctx.console.print(f"  ✅ {network.name} (MTU: {mtu_display})")

        ctx.console.print()

        if needs_recreation:
            ctx.console.warn(
                f"{len(needs_recreation)} overlay network(s) need recreation"
            )
            ctx.console.print()
            ctx.console.hint(
                "Recreate networks with: sm docker recreate-network <network_name>"
            )
        else:
            ctx.console.success("All overlay networks have correct MTU")

    ctx.console.print()


def run_list_networks(ctx: ExecutionContext) -> None:
    """List all Docker networks with their MTU values.

    Args:
        ctx: Execution context
    """
    manager = NetworkMTUManager(ctx)

    ctx.console.print()
    ctx.console.print("[bold]Docker Networks[/bold]")
    ctx.console.print()

    networks = manager.list_all_networks()

    if not networks:
        ctx.console.info("No networks found")
        return

    # Group by driver
    from collections import defaultdict

    by_driver = defaultdict(list)
    for network in networks:
        by_driver[network.driver].append(network)

    for driver, nets in sorted(by_driver.items()):
        ctx.console.print(f"[bold]{driver.upper()} Networks:[/bold]")
        for network in sorted(nets, key=lambda n: n.name):
            mtu_display = network.mtu if network.mtu else "default (1500)"
            status = "❌" if network.needs_recreation else "✅"
            ctx.console.print(f"  {status} {network.name:20s} MTU: {mtu_display}")
        ctx.console.print()


def run_recreate_network(
    ctx: ExecutionContext, network_name: str, force_recreate: bool = False
) -> None:
    """Recreate a Docker network with proper MTU.

    Args:
        ctx: Execution context
        network_name: Name of the network to recreate
        force_recreate: If True, skip confirmation
    """
    audit = get_audit_logger()
    manager = NetworkMTUManager(ctx)

    ctx.console.print()
    ctx.console.print(f"[bold]Recreating Network: {network_name}[/bold]")
    ctx.console.print()

    # Check daemon.json is configured
    is_configured, mtu_value = manager.check_daemon_config()
    if not is_configured:
        ctx.console.error("MTU fix not applied in daemon.json")
        ctx.console.hint("First run: sudo sm docker fix-mtu")
        raise ValidationError(
            message="Cannot recreate network without daemon.json configuration"
        )

    # Get network info
    ctx.console.step(f"Getting network information: {network_name}")
    try:
        network_info = manager.get_network_info(network_name)
    except ExecutionError:
        raise ValidationError(
            message=f"Network not found: {network_name}",
            hint="List networks with: sm docker list-networks",
        )

    if network_info.driver != "overlay":
        raise ValidationError(
            message=f"Network {network_name} is not an overlay network (driver: {network_info.driver})",
            hint="Only overlay networks need MTU fixes",
        )

    if not network_info.needs_recreation and not force_recreate:
        ctx.console.success(f"Network {network_name} already has correct MTU")
        return

    # Get containers
    containers = manager.get_network_containers(network_name)

    if containers and not ctx.force:
        ctx.console.error(f"Network has {len(containers)} connected container(s):")
        for container in containers:
            ctx.console.print(f"  - {container['name']} ({container['id'][:12]})")
        ctx.console.print()
        ctx.console.hint(
            "Stop containers first, then recreate with: sm docker recreate-network --force"
        )
        raise ValidationError(
            message="Cannot recreate network with connected containers"
        )

    # Get network config
    ctx.console.step("Reading network configuration")
    config = manager.get_network_config(network_name)

    # Show configuration
    ctx.console.print()
    ctx.console.print("[bold]Network Configuration:[/bold]")
    ctx.console.print(f"  Name:       {network_name}")
    ctx.console.print(f"  Driver:     {config['driver']}")
    if config.get("subnet"):
        ctx.console.print(f"  Subnet:     {config['subnet']}")
    if config.get("gateway"):
        ctx.console.print(f"  Gateway:    {config['gateway']}")
    ctx.console.print(f"  Attachable: {config.get('attachable', False)}")
    ctx.console.print(f"  Encrypted:  {config.get('encrypted', False)}")
    ctx.console.print(f"  New MTU:    {mtu_value}")
    ctx.console.print()

    if not ctx.dry_run and not ctx.yes:
        if not ctx.console.confirm(f"Recreate network {network_name}?"):
            ctx.console.warn("Operation cancelled")
            return

    try:
        # Recreate network
        manager.recreate_network(network_name, config, ctx.dry_run)

        if not ctx.dry_run:
            # Verify new MTU
            ctx.console.step("Verifying new network")
            new_info = manager.get_network_info(network_name)
            if new_info.mtu == mtu_value:
                ctx.console.success(f"Network recreated with MTU {new_info.mtu}")
            else:
                ctx.console.warn(
                    f"Network recreated but MTU is {new_info.mtu} (expected {mtu_value})"
                )

            if containers:
                ctx.console.print()
                ctx.console.hint(
                    "Restart your containers to reconnect them to the network"
                )
                for container in containers:
                    ctx.console.print(f"  docker start {container['name']}")

        ctx.console.print()

        # Audit log success
        audit.log_success(
            AuditEventType.CONFIG_MODIFY,
            "docker",
            f"network/{network_name}",
            message=f"Docker network {network_name} recreated with MTU {mtu_value}",
        )

    except Exception as e:
        # Audit log failure
        audit.log_failure(
            AuditEventType.CONFIG_MODIFY,
            "docker",
            f"network/{network_name}",
            error=str(e),
        )
        raise
