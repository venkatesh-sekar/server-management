"""Network detection utilities for firewall management.

Provides:
- Private network detection
- Interface discovery
- SSH connection detection
"""

import ipaddress
import os
import subprocess
from dataclasses import dataclass
from typing import Optional


# RFC 1918 private network ranges
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Default internal CIDRs for firewall rules
DEFAULT_INTERNAL_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]


@dataclass
class NetworkInterface:
    """Detected network interface information."""
    name: str
    address: str
    netmask: str
    cidr: str
    is_private: bool
    is_loopback: bool


def is_private_address(ip: str) -> bool:
    """Check if an IP address is in a private range.

    Args:
        ip: IP address string

    Returns:
        True if the IP is in a private (RFC 1918) range
    """
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def detect_internal_networks() -> list[str]:
    """Auto-detect private network CIDRs from system interfaces.

    Scans network interfaces and returns CIDRs for any interfaces
    that are in private address ranges.

    Returns:
        List of CIDR strings for detected internal networks.
        Falls back to default private ranges if detection fails.
    """
    cidrs = set()

    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            return DEFAULT_INTERNAL_CIDRS.copy()

        for line in result.stdout.strip().splitlines():
            parts = line.split()
            # Format: index: interface inet IP/prefix scope ...
            for i, part in enumerate(parts):
                if part == "inet" and i + 1 < len(parts):
                    cidr_str = parts[i + 1]
                    ip = cidr_str.split("/")[0]
                    if is_private_address(ip):
                        try:
                            network = ipaddress.ip_network(cidr_str, strict=False)
                            cidrs.add(str(network))
                        except ValueError:
                            continue

        if cidrs:
            return sorted(cidrs)

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Fallback to default private ranges
    return DEFAULT_INTERNAL_CIDRS.copy()


def get_interface_info() -> list[NetworkInterface]:
    """Get detailed information about all network interfaces.

    Returns:
        List of NetworkInterface objects with interface details
    """
    interfaces = []

    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            return interfaces

        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface_name = parts[1].rstrip(":")
                for i, part in enumerate(parts):
                    if part == "inet" and i + 1 < len(parts):
                        cidr_str = parts[i + 1]
                        try:
                            ip, prefix = cidr_str.split("/")
                            network = ipaddress.ip_network(cidr_str, strict=False)

                            interfaces.append(NetworkInterface(
                                name=iface_name,
                                address=ip,
                                netmask=str(network.netmask),
                                cidr=str(network),
                                is_private=is_private_address(ip),
                                is_loopback=ip.startswith("127."),
                            ))
                        except (ValueError, IndexError):
                            continue

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return interfaces


def get_current_ssh_connection() -> Optional[tuple[str, int]]:
    """Detect current SSH connection to prevent lockout.

    Uses SSH_CONNECTION environment variable set by SSH daemon.

    Returns:
        Tuple of (client_ip, client_port) or None if not in SSH session
    """
    ssh_conn = os.environ.get("SSH_CONNECTION")
    if ssh_conn:
        parts = ssh_conn.split()
        if len(parts) >= 2:
            try:
                return (parts[0], int(parts[1]))
            except (ValueError, IndexError):
                pass
    return None


def get_ssh_client_ip() -> Optional[str]:
    """Get the IP address of the current SSH client.

    Returns:
        Client IP address string or None if not in SSH session
    """
    conn = get_current_ssh_connection()
    return conn[0] if conn else None


def validate_cidr(cidr: str) -> bool:
    """Validate a CIDR notation string.

    Args:
        cidr: CIDR string like "10.0.0.0/8" or "192.168.1.1"

    Returns:
        True if valid CIDR or IP address
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_ip(ip: str) -> bool:
    """Validate an IP address string.

    Args:
        ip: IP address string

    Returns:
        True if valid IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
