"""Iptables firewall service.

Provides safe interface for managing iptables firewall rules with:
- Docker DOCKER-USER chain compatibility
- SSH always-allow safety mechanism
- IPv4 and IPv6 support
- Persistence via iptables-persistent
- Dry-run mode support
- Rollback on failure
- State management (SM as source of truth)
- Fail2ban chain preservation
"""

import fnmatch
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from sm.core.context import ExecutionContext
from sm.core.executor import CommandExecutor, RollbackStack
from sm.core.exceptions import FirewallError, ValidationError
from sm.services.network import DEFAULT_INTERNAL_CIDRS, detect_internal_networks, validate_cidr
from sm.services.systemd import SystemdService
from sm.services.firewall_state import (
    FirewallStateManager,
    StoredRule,
    DriftReport,
    STATE_FILE,
)


# Constants
DEFAULT_SSH_PORT = 22
SSHD_CONFIG_PATH = Path("/etc/ssh/sshd_config")
RULES_V4_PATH = Path("/etc/iptables/rules.v4")
RULES_V6_PATH = Path("/etc/iptables/rules.v6")
BACKUP_DIR = Path("/var/lib/sm/firewall")

# Validation constants
MIN_PORT = 1
MAX_PORT = 65535
MAX_COMMENT_LENGTH = 256


class Protocol(str, Enum):
    """Network protocol."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"


class Action(str, Enum):
    """Firewall rule action."""
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"
    RETURN = "RETURN"


class Chain(str, Enum):
    """Iptables chain."""
    INPUT = "INPUT"
    OUTPUT = "OUTPUT"
    FORWARD = "FORWARD"
    DOCKER_USER = "DOCKER-USER"


@dataclass
class FirewallRule:
    """Represents a single firewall rule."""
    port: Optional[int] = None
    protocol: Protocol = Protocol.TCP
    source: str = "0.0.0.0/0"
    destination: str = "0.0.0.0/0"
    action: Action = Action.ACCEPT
    chain: Chain = Chain.INPUT
    comment: Optional[str] = None
    interface: Optional[str] = None

    def to_iptables_args(self) -> list[str]:
        """Convert rule to iptables command arguments."""
        args = []

        if self.interface:
            args.extend(["-i", self.interface])

        if self.protocol != Protocol.ALL:
            args.extend(["-p", self.protocol.value])

        if self.source and self.source != "0.0.0.0/0":
            args.extend(["-s", self.source])

        if self.destination and self.destination != "0.0.0.0/0":
            args.extend(["-d", self.destination])

        if self.port is not None and self.protocol in (Protocol.TCP, Protocol.UDP):
            args.extend(["--dport", str(self.port)])

        args.extend(["-j", self.action.value])

        if self.comment:
            args.extend(["-m", "comment", "--comment", self.comment])

        return args

    def __str__(self) -> str:
        """Human-readable representation."""
        parts = [self.action.value]
        if self.port:
            parts.append(f"{self.protocol.value}/{self.port}")
        if self.source != "0.0.0.0/0":
            parts.append(f"from {self.source}")
        if self.comment:
            parts.append(f"({self.comment})")
        return " ".join(parts)


@dataclass
class FirewallPreset:
    """A preset firewall configuration."""
    name: str
    description: str
    rules: list[FirewallRule] = field(default_factory=list)
    docker_aware: bool = False

    def __str__(self) -> str:
        return f"{self.name}: {self.description}"


@dataclass
class FirewallStatus:
    """Overall firewall status."""
    active: bool
    default_policy: str
    docker_detected: bool
    docker_user_chain_exists: bool
    ipv4_rules_count: int
    ipv6_rules_count: int
    ssh_protected: bool
    persistence_installed: bool
    last_saved: Optional[datetime] = None

    def __str__(self) -> str:
        status = "Enabled" if self.active else "Disabled"
        return f"Firewall: {status}, Policy: {self.default_policy}"


@dataclass
class ParsedRule:
    """A rule parsed from iptables output."""
    num: int
    target: str
    protocol: str
    source: str
    destination: str
    port: Optional[int] = None
    comment: Optional[str] = None
    extra: Optional[str] = None


# Built-in presets
PRESETS: dict[str, FirewallPreset] = {
    "ssh-only": FirewallPreset(
        name="ssh-only",
        description="SSH access only (most restrictive)",
        rules=[
            FirewallRule(
                port=22,
                protocol=Protocol.TCP,
                action=Action.ACCEPT,
                comment="SSH (always allowed)",
            ),
        ],
    ),
    "web": FirewallPreset(
        name="web",
        description="Web server (HTTP/HTTPS)",
        rules=[
            FirewallRule(
                port=80,
                protocol=Protocol.TCP,
                action=Action.ACCEPT,
                comment="HTTP",
            ),
            FirewallRule(
                port=443,
                protocol=Protocol.TCP,
                action=Action.ACCEPT,
                comment="HTTPS",
            ),
        ],
    ),
    "postgres": FirewallPreset(
        name="postgres",
        description="PostgreSQL (internal networks only)",
        docker_aware=True,
        rules=[],  # Rules generated dynamically for internal networks
    ),
    "docker-swarm": FirewallPreset(
        name="docker-swarm",
        description="Docker Swarm cluster (internal networks only)",
        rules=[],  # Rules generated dynamically for internal networks
    ),
}


def _get_postgres_rules(internal_cidrs: list[str]) -> list[FirewallRule]:
    """Generate PostgreSQL preset rules for internal networks."""
    rules = []
    for cidr in internal_cidrs:
        rules.append(FirewallRule(
            port=5432,
            protocol=Protocol.TCP,
            source=cidr,
            action=Action.ACCEPT,
            comment=f"PostgreSQL from {cidr}",
        ))
        rules.append(FirewallRule(
            port=6432,
            protocol=Protocol.TCP,
            source=cidr,
            action=Action.ACCEPT,
            comment=f"PgBouncer from {cidr}",
        ))
    return rules


def _get_docker_swarm_rules(internal_cidrs: list[str]) -> list[FirewallRule]:
    """Generate Docker Swarm preset rules for internal networks."""
    rules = []
    for cidr in internal_cidrs:
        rules.extend([
            FirewallRule(
                port=2377,
                protocol=Protocol.TCP,
                source=cidr,
                action=Action.ACCEPT,
                comment=f"Swarm management from {cidr}",
            ),
            FirewallRule(
                port=7946,
                protocol=Protocol.TCP,
                source=cidr,
                action=Action.ACCEPT,
                comment=f"Swarm gossip TCP from {cidr}",
            ),
            FirewallRule(
                port=7946,
                protocol=Protocol.UDP,
                source=cidr,
                action=Action.ACCEPT,
                comment=f"Swarm gossip UDP from {cidr}",
            ),
            FirewallRule(
                port=4789,
                protocol=Protocol.UDP,
                source=cidr,
                action=Action.ACCEPT,
                comment=f"Swarm VXLAN from {cidr}",
            ),
        ])
    return rules


def validate_port(port: int) -> None:
    """Validate port number is in valid range.

    Args:
        port: Port number to validate

    Raises:
        ValidationError: If port is out of range
    """
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValidationError(
            f"Invalid port number: {port}",
            hint=f"Port must be between {MIN_PORT} and {MAX_PORT}",
        )


def validate_source(source: str) -> None:
    """Validate source IP/CIDR.

    Args:
        source: Source IP or CIDR notation

    Raises:
        ValidationError: If source is invalid
    """
    if source and source != "0.0.0.0/0" and source != "::/0":
        if not validate_cidr(source):
            raise ValidationError(
                f"Invalid source IP/CIDR: {source}",
                hint="Use format like '10.0.0.0/8' or '192.168.1.1'",
            )


def sanitize_comment(comment: Optional[str]) -> Optional[str]:
    """Sanitize comment string for iptables.

    Args:
        comment: Comment string to sanitize

    Returns:
        Sanitized comment or None
    """
    if not comment:
        return None

    # Remove newlines and control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f]', ' ', comment)

    # Truncate to max length
    if len(sanitized) > MAX_COMMENT_LENGTH:
        sanitized = sanitized[:MAX_COMMENT_LENGTH - 3] + "..."

    return sanitized.strip()


def detect_ssh_port() -> int:
    """Detect SSH port from sshd_config.

    Returns:
        Detected SSH port or DEFAULT_SSH_PORT
    """
    try:
        if not SSHD_CONFIG_PATH.exists():
            return DEFAULT_SSH_PORT

        content = SSHD_CONFIG_PATH.read_text()

        # Look for Port directive (not commented)
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            if line.lower().startswith("port "):
                parts = line.split()
                if len(parts) >= 2:
                    port = int(parts[1])
                    if MIN_PORT <= port <= MAX_PORT:
                        return port
    except (OSError, ValueError, PermissionError):
        pass

    return DEFAULT_SSH_PORT


@dataclass
class FirewallProviderStatus:
    """Status of other firewall providers on the system."""
    ufw_active: bool = False
    ufw_installed: bool = False
    firewalld_active: bool = False
    firewalld_installed: bool = False
    nftables_active: bool = False

    @property
    def has_conflicts(self) -> bool:
        """Check if any conflicting provider is active."""
        return self.ufw_active or self.firewalld_active

    @property
    def conflict_names(self) -> list[str]:
        """Get names of active conflicting providers."""
        conflicts = []
        if self.ufw_active:
            conflicts.append("UFW")
        if self.firewalld_active:
            conflicts.append("firewalld")
        return conflicts


def detect_firewall_providers() -> FirewallProviderStatus:
    """Detect other firewall management tools on the system.

    Returns:
        FirewallProviderStatus with detection results
    """
    status = FirewallProviderStatus()

    # Check UFW
    try:
        result = subprocess.run(
            ["which", "ufw"],
            capture_output=True,
            timeout=5,
        )
        status.ufw_installed = result.returncode == 0

        if status.ufw_installed:
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                status.ufw_active = "Status: active" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Check firewalld
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "firewalld"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        status.firewalld_installed = True
        status.firewalld_active = result.stdout.strip() == "active"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Check if nftables is the primary backend
    try:
        result = subprocess.run(
            ["iptables", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # If using nf_tables backend, version includes "nf_tables"
        status.nftables_active = "nf_tables" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return status


class IptablesService:
    """Safe interface for iptables firewall management.

    Features:
    - Docker DOCKER-USER chain compatibility
    - SSH always-allow safety mechanism
    - IPv4 and IPv6 support
    - Persistence via iptables-persistent
    - Dry-run mode support
    - Rollback on failure
    - State management (SM as source of truth)
    - Fail2ban chain preservation
    """

    # Fail2ban chain patterns to preserve
    FAIL2BAN_CHAIN_PATTERNS = ["f2b-*", "fail2ban-*"]

    def __init__(
        self,
        ctx: ExecutionContext,
        executor: CommandExecutor,
        systemd: SystemdService,
        *,
        ssh_port: Optional[int] = None,
        auto_detect_ssh: bool = True,
    ) -> None:
        """Initialize iptables service.

        Args:
            ctx: Execution context
            executor: Command executor
            systemd: Systemd service manager
            ssh_port: SSH port to always protect (None = auto-detect)
            auto_detect_ssh: Auto-detect SSH port from sshd_config
        """
        self.ctx = ctx
        self.executor = executor
        self.systemd = systemd

        # Auto-detect SSH port if not specified
        if ssh_port is not None:
            self.ssh_port = ssh_port
        elif auto_detect_ssh:
            self.ssh_port = detect_ssh_port()
        else:
            self.ssh_port = DEFAULT_SSH_PORT

        self._docker_detected: Optional[bool] = None
        self._internal_cidrs: Optional[list[str]] = None
        self._ipv6_ssh_rule_ok: bool = False  # Track IPv6 SSH rule success
        self._provider_status: Optional[FirewallProviderStatus] = None

        # State management
        self._state_manager: Optional[FirewallStateManager] = None

    @property
    def state_manager(self) -> FirewallStateManager:
        """Get lazy-initialized state manager."""
        if self._state_manager is None:
            self._state_manager = FirewallStateManager(self.ctx)
        return self._state_manager

    # =========================================================================
    # Detection Methods
    # =========================================================================

    def check_provider_conflicts(self, *, force: bool = False) -> None:
        """Check for conflicting firewall providers.

        Args:
            force: If True, warn but don't block

        Raises:
            FirewallError: If conflicting provider is active and force=False
        """
        if self._provider_status is None:
            self._provider_status = detect_firewall_providers()

        if self._provider_status.has_conflicts:
            conflicts = ", ".join(self._provider_status.conflict_names)
            if force:
                self.ctx.console.warn(
                    f"Other firewall providers active: {conflicts}. "
                    "This may cause conflicts!"
                )
            else:
                raise FirewallError(
                    f"Conflicting firewall provider(s) active: {conflicts}",
                    hint=f"Disable with: sudo {'ufw disable' if self._provider_status.ufw_active else 'systemctl stop firewalld'}, "
                         "or use --force to proceed anyway",
                )

        if self._provider_status.nftables_active:
            self.ctx.console.info(
                "Using iptables-nft (nftables backend) - this is supported"
            )

    def get_provider_status(self) -> FirewallProviderStatus:
        """Get firewall provider detection status.

        Returns:
            FirewallProviderStatus object
        """
        if self._provider_status is None:
            self._provider_status = detect_firewall_providers()
        return self._provider_status

    def docker_detected(self) -> bool:
        """Check if Docker is installed and running.

        Returns:
            True if Docker daemon is running
        """
        if self._docker_detected is not None:
            return self._docker_detected

        if self.ctx.dry_run:
            self._docker_detected = False
            return False

        self._docker_detected = self.systemd.is_active("docker.service")
        return self._docker_detected

    def docker_user_chain_exists(self) -> bool:
        """Check if DOCKER-USER chain exists.

        Returns:
            True if DOCKER-USER chain is present
        """
        if self.ctx.dry_run:
            return self.docker_detected()

        result = self._run_iptables(["-L", "DOCKER-USER", "-n"], check=False)
        return result.returncode == 0

    def is_persistence_installed(self) -> bool:
        """Check if iptables-persistent is installed.

        Returns:
            True if iptables-persistent package is installed
        """
        if self.ctx.dry_run:
            return True

        result = subprocess.run(
            ["dpkg", "-l", "iptables-persistent"],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0 and "ii" in result.stdout

    def get_internal_cidrs(self) -> list[str]:
        """Get internal network CIDRs.

        Returns:
            List of internal network CIDR strings
        """
        if self._internal_cidrs is None:
            self._internal_cidrs = detect_internal_networks()
        return self._internal_cidrs

    # =========================================================================
    # Rule Management
    # =========================================================================

    def rule_exists(
        self,
        rule: FirewallRule,
        *,
        chain: Optional[Chain] = None,
    ) -> bool:
        """Check if a rule already exists in iptables.

        Args:
            rule: FirewallRule to check
            chain: Chain to check (default: rule's chain)

        Returns:
            True if rule exists
        """
        if self.ctx.dry_run:
            return False  # In dry-run, assume rule doesn't exist

        target_chain = (chain or rule.chain).value
        args = rule.to_iptables_args()

        # Use -C (check) to see if rule exists
        result = self._run_iptables(["-C", target_chain] + args, check=False)
        return result.returncode == 0

    def add_rule(
        self,
        rule: FirewallRule,
        *,
        ipv6: bool = True,
        position: int = 1,
        rollback: Optional[RollbackStack] = None,
        skip_if_exists: bool = True,
    ) -> bool:
        """Add a firewall rule (idempotent).

        Args:
            rule: FirewallRule to add
            ipv6: Also add equivalent IPv6 rule
            position: Position to insert rule (1 = top)
            rollback: Rollback stack for cleanup on failure
            skip_if_exists: Skip adding if rule already exists (default: True)

        Returns:
            True if rule was added, False if skipped (already exists)

        Raises:
            ValidationError: If port or source is invalid
            FirewallError: If trying to block SSH
        """
        # Validate port
        if rule.port is not None:
            validate_port(rule.port)

        # Validate source
        validate_source(rule.source)

        # Sanitize comment
        if rule.comment:
            rule.comment = sanitize_comment(rule.comment)

        # Safety check: cannot block SSH
        if rule.action in (Action.DROP, Action.REJECT) and rule.port == self.ssh_port:
            raise FirewallError(
                f"Cannot block SSH port {self.ssh_port}",
                hint="SSH access is always allowed for safety",
            )

        chain = rule.chain.value
        args = rule.to_iptables_args()

        # Check if rule already exists (idempotency)
        if skip_if_exists and not self.ctx.dry_run and self.rule_exists(rule):
            self.ctx.console.info(f"Rule already exists, skipping: {rule}")
            return False

        self.ctx.console.step(f"Adding rule: {rule}")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"iptables -I {chain} {position} {' '.join(args)}")
            return True

        # Add to main chain
        self._run_iptables(["-I", chain, str(position)] + args)

        if rollback:
            # Capture variables by value using default arguments to avoid closure issues
            rollback.push(
                lambda c=chain, a=args: self._run_iptables(["-D", c] + a, check=False),
                f"Remove rule: {rule}",
            )

        # Add to DOCKER-USER if Docker detected and rule is for INPUT
        if rule.chain == Chain.INPUT and self.docker_detected() and self.docker_user_chain_exists():
            docker_args = rule.to_iptables_args()
            # Check DOCKER-USER chain too for idempotency
            docker_check = self._run_iptables(["-C", "DOCKER-USER"] + docker_args, check=False)
            if docker_check.returncode != 0:
                self._run_iptables(["-I", "DOCKER-USER", str(position)] + docker_args, check=False)

        # Add IPv6 equivalent
        if ipv6 and rule.source == "0.0.0.0/0":
            ipv6_args = rule.to_iptables_args()
            # Check IPv6 too for idempotency
            ipv6_check = self._run_ip6tables(["-C", chain] + ipv6_args, check=False)
            if ipv6_check.returncode != 0:
                self._run_ip6tables(["-I", chain, str(position)] + ipv6_args, check=False)

        return True

    def remove_rule(
        self,
        rule: FirewallRule,
        *,
        ipv6: bool = True,
    ) -> None:
        """Remove a firewall rule.

        Args:
            rule: FirewallRule to remove
            ipv6: Also remove equivalent IPv6 rule
        """
        # Safety check: cannot remove SSH allow rule
        if rule.port == self.ssh_port and rule.action == Action.ACCEPT:
            raise FirewallError(
                f"Cannot remove SSH allow rule for port {self.ssh_port}",
                hint="SSH access is always allowed for safety",
            )

        chain = rule.chain.value
        args = rule.to_iptables_args()

        self.ctx.console.step(f"Removing rule: {rule}")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"iptables -D {chain} {' '.join(args)}")
            return

        self._run_iptables(["-D", chain] + args)

        # Remove from DOCKER-USER if exists
        if rule.chain == Chain.INPUT and self.docker_user_chain_exists():
            docker_args = rule.to_iptables_args()
            self._run_iptables(["-D", "DOCKER-USER"] + docker_args, check=False)

        # Remove IPv6 equivalent
        if ipv6 and rule.source == "0.0.0.0/0":
            ipv6_args = rule.to_iptables_args()
            self._run_ip6tables(["-D", chain] + ipv6_args, check=False)

    def allow_port(
        self,
        port: int,
        protocol: Protocol = Protocol.TCP,
        source: str = "0.0.0.0/0",
        comment: Optional[str] = None,
        rollback: Optional[RollbackStack] = None,
    ) -> None:
        """Allow traffic on a port.

        Args:
            port: Port number
            protocol: Protocol (tcp/udp)
            source: Source IP/CIDR
            comment: Rule description
            rollback: Rollback stack
        """
        rule = FirewallRule(
            port=port,
            protocol=protocol,
            source=source,
            action=Action.ACCEPT,
            comment=comment or f"Allow {protocol.value.upper()}/{port}",
        )
        self.add_rule(rule, rollback=rollback)

    def deny_port(
        self,
        port: int,
        protocol: Protocol = Protocol.TCP,
        source: str = "0.0.0.0/0",
        comment: Optional[str] = None,
        rollback: Optional[RollbackStack] = None,
    ) -> None:
        """Block traffic on a port.

        Args:
            port: Port number
            protocol: Protocol (tcp/udp)
            source: Source IP/CIDR
            comment: Rule description
            rollback: Rollback stack for cleanup on failure
        """
        if port == self.ssh_port:
            raise FirewallError(
                f"Cannot block SSH port {self.ssh_port}",
                hint="SSH access is always allowed for safety",
            )

        rule = FirewallRule(
            port=port,
            protocol=protocol,
            source=source,
            action=Action.DROP,
            comment=comment or f"Block {protocol.value.upper()}/{port}",
        )
        self.add_rule(rule, rollback=rollback)

    # =========================================================================
    # Listing and Status
    # =========================================================================

    def list_rules(self, chain: Optional[Chain] = None) -> list[ParsedRule]:
        """List all rules in a chain.

        Args:
            chain: Chain name (None = INPUT)

        Returns:
            List of parsed rules
        """
        target_chain = chain.value if chain else "INPUT"

        if self.ctx.dry_run:
            return []

        result = self._run_iptables(
            ["-L", target_chain, "-n", "--line-numbers", "-v"],
            check=False,
        )

        if result.returncode != 0:
            return []

        return self._parse_iptables_output(result.stdout)

    def _parse_iptables_output(self, output: str) -> list[ParsedRule]:
        """Parse iptables -L -v --line-numbers output into ParsedRule objects.

        The verbose (-v) output format has these columns:
        num  pkts bytes target  prot opt in  out  source       destination  [extras]
        0    1    2     3       4    5   6   7    8            9            10+

        Example line:
        1    29111  271K ACCEPT  tcp  --  *   *    0.0.0.0/0    0.0.0.0/0    tcp dpt:22
        """
        rules = []
        lines = output.strip().splitlines()

        # Skip header lines (Chain info + column headers)
        for line in lines[2:]:
            parts = line.split()
            if len(parts) < 10:
                continue

            try:
                # Verbose format with line numbers:
                # [0]=num [1]=pkts [2]=bytes [3]=target [4]=prot [5]=opt [6]=in [7]=out [8]=source [9]=dest
                num = int(parts[0])
                target = parts[3]
                protocol = parts[4]
                source = parts[8]
                destination = parts[9]

                # Extract port from rest of line (everything after the 10 standard columns)
                port = None
                comment = None
                rest = " ".join(parts[10:]) if len(parts) > 10 else ""

                # Look for dpt:PORT (destination port)
                port_match = re.search(r"dpt:(\d+)", rest)
                if port_match:
                    port = int(port_match.group(1))

                # Look for comment in /* ... */ format
                comment_match = re.search(r'/\* (.+?) \*/', rest)
                if comment_match:
                    comment = comment_match.group(1)

                rules.append(ParsedRule(
                    num=num,
                    target=target,
                    protocol=protocol,
                    source=source,
                    destination=destination,
                    port=port,
                    comment=comment,
                    extra=rest if rest else None,
                ))
            except (ValueError, IndexError):
                continue

        return rules

    def status(self) -> FirewallStatus:
        """Get comprehensive firewall status.

        Returns:
            FirewallStatus with current state
        """
        if self.ctx.dry_run:
            return FirewallStatus(
                active=False,
                default_policy="ACCEPT",
                docker_detected=False,
                docker_user_chain_exists=False,
                ipv4_rules_count=0,
                ipv6_rules_count=0,
                ssh_protected=True,
                persistence_installed=True,
            )

        # Get INPUT chain policy
        result = self._run_iptables(["-L", "INPUT", "-n"], check=False)
        policy = "ACCEPT"
        ipv4_count = 0
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            if lines:
                # First line: "Chain INPUT (policy ACCEPT)"
                match = re.search(r"policy (\w+)", lines[0])
                if match:
                    policy = match.group(1)
                ipv4_count = max(0, len(lines) - 2)  # Subtract header lines

        # Check IPv6
        result6 = self._run_ip6tables(["-L", "INPUT", "-n"], check=False)
        ipv6_count = 0
        if result6.returncode == 0:
            lines6 = result6.stdout.splitlines()
            ipv6_count = max(0, len(lines6) - 2)

        # Check SSH protection
        ssh_protected = self._check_ssh_rule_exists()

        # Check last saved time
        last_saved = None
        if RULES_V4_PATH.exists():
            try:
                last_saved = datetime.fromtimestamp(RULES_V4_PATH.stat().st_mtime)
            except OSError:
                pass

        return FirewallStatus(
            active=policy == "DROP",
            default_policy=policy,
            docker_detected=self.docker_detected(),
            docker_user_chain_exists=self.docker_user_chain_exists(),
            ipv4_rules_count=ipv4_count,
            ipv6_rules_count=ipv6_count,
            ssh_protected=ssh_protected,
            persistence_installed=self.is_persistence_installed(),
            last_saved=last_saved,
        )

    def _check_ssh_rule_exists(self) -> bool:
        """Check if SSH allow rule exists."""
        result = self._run_iptables(
            ["-C", "INPUT", "-p", "tcp", "--dport", str(self.ssh_port), "-j", "ACCEPT"],
            check=False,
        )
        return result.returncode == 0

    # =========================================================================
    # Safety Mechanisms
    # =========================================================================

    def ensure_ssh_allowed(self) -> None:
        """Ensure SSH is always allowed (safety mechanism).

        This is called before any policy change to prevent lockout.
        """
        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Ensure SSH port {self.ssh_port} is allowed")
            self._ipv6_ssh_rule_ok = True  # Assume OK in dry-run
            return

        if not self._check_ssh_rule_exists():
            self.ctx.console.step(f"Ensuring SSH port {self.ssh_port} is allowed (safety)")
            self._run_iptables([
                "-I", "INPUT", "1",
                "-p", "tcp", "--dport", str(self.ssh_port),
                "-j", "ACCEPT",
                "-m", "comment", "--comment", "SSH always allowed (sm safety)",
            ])

            # Also for IPv6 - track success
            result = self._run_ip6tables([
                "-I", "INPUT", "1",
                "-p", "tcp", "--dport", str(self.ssh_port),
                "-j", "ACCEPT",
                "-m", "comment", "--comment", "SSH always allowed (sm safety)",
            ], check=False)
            self._ipv6_ssh_rule_ok = result.returncode == 0

            if not self._ipv6_ssh_rule_ok:
                self.ctx.console.warn(
                    f"Could not add IPv6 SSH rule - IPv6 policy will remain ACCEPT"
                )
        else:
            # Check if IPv6 rule also exists
            result = self._run_ip6tables([
                "-C", "INPUT", "-p", "tcp", "--dport", str(self.ssh_port), "-j", "ACCEPT",
            ], check=False)
            self._ipv6_ssh_rule_ok = result.returncode == 0

    def ensure_established_allowed(self) -> None:
        """Ensure established/related connections are allowed."""
        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Ensure established connections allowed")
            return

        # Check if rule exists
        result = self._run_iptables([
            "-C", "INPUT",
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ], check=False)

        if result.returncode != 0:
            self.ctx.console.step("Allowing established connections")
            self._run_iptables([
                "-I", "INPUT", "1",
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                "-j", "ACCEPT",
                "-m", "comment", "--comment", "Allow established connections",
            ])

            self._run_ip6tables([
                "-I", "INPUT", "1",
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                "-j", "ACCEPT",
                "-m", "comment", "--comment", "Allow established connections",
            ], check=False)

    def ensure_loopback_allowed(self) -> None:
        """Ensure loopback interface is allowed."""
        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Ensure loopback allowed")
            return

        # Check if rule exists
        result = self._run_iptables([
            "-C", "INPUT", "-i", "lo", "-j", "ACCEPT",
        ], check=False)

        if result.returncode != 0:
            self.ctx.console.step("Allowing loopback interface")
            self._run_iptables([
                "-I", "INPUT", "1",
                "-i", "lo", "-j", "ACCEPT",
                "-m", "comment", "--comment", "Allow loopback",
            ])

            self._run_ip6tables([
                "-I", "INPUT", "1",
                "-i", "lo", "-j", "ACCEPT",
                "-m", "comment", "--comment", "Allow loopback",
            ], check=False)

    def ensure_icmp_allowed(self) -> None:
        """Ensure essential ICMP types are allowed (idempotent).

        Allows critical ICMP messages needed for:
        - Path MTU discovery (type 3)
        - Source quench (type 4)
        - Time exceeded (type 11)
        - Parameter problem (type 12)
        - Ping/echo request (type 8) - optional but useful
        """
        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Ensure essential ICMP allowed")
            return

        # Essential ICMP types for IPv4
        icmp_types = [
            ("3", "destination-unreachable"),  # Path MTU discovery
            ("4", "source-quench"),            # Congestion control
            ("11", "time-exceeded"),           # Traceroute
            ("12", "parameter-problem"),       # Header problems
            ("8", "echo-request"),             # Ping (optional but useful)
        ]

        added_any = False
        for icmp_type, name in icmp_types:
            # Check if this specific ICMP type rule exists
            check_result = self._run_iptables([
                "-C", "INPUT", "-p", "icmp", "--icmp-type", icmp_type, "-j", "ACCEPT",
            ], check=False)

            if check_result.returncode != 0:
                if not added_any:
                    self.ctx.console.step("Allowing essential ICMP types")
                    added_any = True
                self._run_iptables([
                    "-A", "INPUT",
                    "-p", "icmp", "--icmp-type", icmp_type,
                    "-j", "ACCEPT",
                    "-m", "comment", "--comment", f"ICMP {name}",
                ], check=False)

        # Essential ICMPv6 types for IPv6
        icmpv6_types = [
            ("1", "destination-unreachable"),
            ("2", "packet-too-big"),           # Critical for PMTU
            ("3", "time-exceeded"),
            ("4", "parameter-problem"),
            ("128", "echo-request"),           # Ping
            ("129", "echo-reply"),             # Ping reply
            ("133", "router-solicitation"),    # NDP
            ("134", "router-advertisement"),   # NDP
            ("135", "neighbor-solicitation"),  # NDP (critical!)
            ("136", "neighbor-advertisement"), # NDP (critical!)
        ]

        for icmpv6_type, name in icmpv6_types:
            # Check if this specific ICMPv6 type rule exists
            check_result = self._run_ip6tables([
                "-C", "INPUT", "-p", "icmpv6", "--icmpv6-type", icmpv6_type, "-j", "ACCEPT",
            ], check=False)

            if check_result.returncode != 0:
                self._run_ip6tables([
                    "-A", "INPUT",
                    "-p", "icmpv6", "--icmpv6-type", icmpv6_type,
                    "-j", "ACCEPT",
                    "-m", "comment", "--comment", f"ICMPv6 {name}",
                ], check=False)

    def set_default_policy(self, policy: str = "DROP") -> None:
        """Set default INPUT policy with SSH protection.

        Args:
            policy: ACCEPT or DROP
        """
        if policy == "DROP":
            # Ensure safety rules are in place first
            self.ensure_loopback_allowed()
            self.ensure_established_allowed()
            self.ensure_ssh_allowed()
            self.ensure_icmp_allowed()

        self.ctx.console.step(f"Setting INPUT policy to {policy}")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"iptables -P INPUT {policy}")
            return

        # Set IPv4 policy
        self._run_iptables(["-P", "INPUT", policy])

        # Only set IPv6 DROP policy if SSH rule was successfully added
        # This prevents lockout for IPv6-only SSH connections
        if policy == "DROP" and not self._ipv6_ssh_rule_ok:
            self.ctx.console.warn(
                "IPv6 policy kept at ACCEPT (SSH rule not confirmed)"
            )
            self._run_ip6tables(["-P", "INPUT", "ACCEPT"], check=False)
        else:
            self._run_ip6tables(["-P", "INPUT", policy], check=False)

    # =========================================================================
    # Presets
    # =========================================================================

    def get_preset(self, name: str) -> FirewallPreset:
        """Get a preset by name.

        Args:
            name: Preset name

        Returns:
            FirewallPreset

        Raises:
            FirewallError: If preset not found
        """
        if name not in PRESETS:
            raise FirewallError(
                f"Unknown preset: {name}",
                hint=f"Available presets: {', '.join(PRESETS.keys())}",
            )

        preset = PRESETS[name]

        # Generate dynamic rules for postgres and docker-swarm
        if name == "postgres":
            preset = FirewallPreset(
                name=preset.name,
                description=preset.description,
                docker_aware=preset.docker_aware,
                rules=_get_postgres_rules(self.get_internal_cidrs()),
            )
        elif name == "docker-swarm":
            preset = FirewallPreset(
                name=preset.name,
                description=preset.description,
                docker_aware=preset.docker_aware,
                rules=_get_docker_swarm_rules(self.get_internal_cidrs()),
            )

        return preset

    def apply_preset(
        self,
        name: str,
        *,
        rollback: Optional[RollbackStack] = None,
    ) -> None:
        """Apply a preset configuration.

        Args:
            name: Preset name
            rollback: Rollback stack
        """
        preset = self.get_preset(name)

        self.ctx.console.step(f"Applying preset: {preset.name}")

        for rule in preset.rules:
            self.add_rule(rule, rollback=rollback)

        # For docker-aware presets, also add to DOCKER-USER
        if preset.docker_aware and self.docker_detected():
            self.ctx.console.info("Docker detected, applying to DOCKER-USER chain")

    def list_presets(self) -> list[FirewallPreset]:
        """List all available presets.

        Returns:
            List of FirewallPreset objects
        """
        return [self.get_preset(name) for name in PRESETS.keys()]

    # =========================================================================
    # Persistence
    # =========================================================================

    def install_persistence(self) -> None:
        """Install iptables-persistent for boot-time rule restoration."""
        self.ctx.console.step("Installing iptables-persistent")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("apt-get install iptables-persistent")
            return

        if self.is_persistence_installed():
            self.ctx.console.info("iptables-persistent already installed")
            return

        # Set preseed values to avoid interactive prompts
        preseed = (
            "iptables-persistent iptables-persistent/autosave_v4 boolean true\n"
            "iptables-persistent iptables-persistent/autosave_v6 boolean true\n"
        )
        subprocess.run(
            ["debconf-set-selections"],
            input=preseed,
            text=True,
            capture_output=True,
        )

        # Install package
        subprocess.run(
            ["apt-get", "install", "-y", "iptables-persistent"],
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            capture_output=True,
        )

        self.ctx.console.success("Persistence installed")

    def save(self) -> None:
        """Save current rules to persistent storage."""
        self.ctx.console.step("Saving firewall rules")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"iptables-save > {RULES_V4_PATH}")
            return

        # Ensure directory exists
        RULES_V4_PATH.parent.mkdir(parents=True, exist_ok=True)

        # Save IPv4 rules
        result = subprocess.run(
            ["iptables-save"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            RULES_V4_PATH.write_text(result.stdout)
            self.ctx.console.info(f"Saved IPv4 rules to {RULES_V4_PATH}")

        # Save IPv6 rules
        result6 = subprocess.run(
            ["ip6tables-save"],
            capture_output=True,
            text=True,
        )
        if result6.returncode == 0:
            RULES_V6_PATH.write_text(result6.stdout)
            self.ctx.console.info(f"Saved IPv6 rules to {RULES_V6_PATH}")

        self.ctx.console.success("Firewall rules saved")

    def restore(self) -> None:
        """Restore rules from persistent storage."""
        self.ctx.console.step("Restoring firewall rules")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"iptables-restore < {RULES_V4_PATH}")
            return

        if not RULES_V4_PATH.exists():
            raise FirewallError(
                f"No saved rules found at {RULES_V4_PATH}",
                hint="Run 'sm firewall save' first",
            )

        # Restore IPv4 rules
        with open(RULES_V4_PATH) as f:
            subprocess.run(
                ["iptables-restore"],
                stdin=f,
                check=True,
            )

        # Restore IPv6 rules if available
        if RULES_V6_PATH.exists():
            with open(RULES_V6_PATH) as f:
                subprocess.run(
                    ["ip6tables-restore"],
                    stdin=f,
                    check=False,
                )

        self.ctx.console.success("Firewall rules restored")

    def backup(self, suffix: str = "") -> Path:
        """Create backup of current rules.

        Args:
            suffix: Optional suffix for backup filename

        Returns:
            Path to backup file
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_name = f"rules-{timestamp}{suffix}.v4"
        backup_path = BACKUP_DIR / backup_name

        self.ctx.console.step(f"Backing up rules to {backup_path}")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"iptables-save > {backup_path}")
            return backup_path

        # Only create directory when actually executing
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            ["iptables-save"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            backup_path.write_text(result.stdout)
            self.ctx.console.info(f"Backup created: {backup_path}")

        return backup_path

    def flush(self, *, keep_ssh: bool = True, include_docker: bool = False) -> None:
        """Flush all firewall rules.

        Args:
            keep_ssh: Re-add SSH allow rule after flush (safety)
            include_docker: Also flush DOCKER-USER chain if it exists
        """
        self.ctx.console.step("Flushing firewall rules")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("iptables -F INPUT")
            if include_docker:
                self.ctx.console.dry_run_msg("iptables -F DOCKER-USER")
            return

        # Flush INPUT
        self._run_iptables(["-F", "INPUT"])
        self._run_ip6tables(["-F", "INPUT"], check=False)

        # Flush DOCKER-USER if requested and exists
        if include_docker and self.docker_user_chain_exists():
            self.ctx.console.step("Flushing DOCKER-USER chain")
            self._run_iptables(["-F", "DOCKER-USER"], check=False)
            # Re-add the RETURN rule that Docker expects at the end
            self._run_iptables(["-A", "DOCKER-USER", "-j", "RETURN"], check=False)

        # Set policy to ACCEPT
        self._run_iptables(["-P", "INPUT", "ACCEPT"])
        self._run_ip6tables(["-P", "INPUT", "ACCEPT"], check=False)

        # Re-add SSH rule for safety
        if keep_ssh:
            self.ensure_ssh_allowed()

        self.ctx.console.success("Firewall rules flushed")

    # =========================================================================
    # Private Helpers
    # =========================================================================

    def _run_iptables(
        self,
        args: list[str],
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run iptables command.

        Args:
            args: Command arguments
            check: Raise on non-zero exit

        Returns:
            CompletedProcess result
        """
        # Use -w flag to wait for xtables lock (prevents concurrent access failures)
        cmd = ["iptables", "-w"] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        if check and result.returncode != 0:
            raise FirewallError(
                f"iptables command failed: {' '.join(cmd)}",
                details=[result.stderr] if result.stderr else None,
            )

        return result

    def _run_ip6tables(
        self,
        args: list[str],
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run ip6tables command.

        Args:
            args: Command arguments
            check: Raise on non-zero exit

        Returns:
            CompletedProcess result
        """
        # Use -w flag to wait for xtables lock (prevents concurrent access failures)
        cmd = ["ip6tables", "-w"] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        if check and result.returncode != 0:
            raise FirewallError(
                f"ip6tables command failed: {' '.join(cmd)}",
                details=[result.stderr] if result.stderr else None,
            )

        return result

    # =========================================================================
    # Fail2ban Integration
    # =========================================================================

    def _is_fail2ban_chain(self, chain_name: str) -> bool:
        """Check if a chain name matches fail2ban patterns.

        Args:
            chain_name: Name of the chain

        Returns:
            True if chain is a fail2ban chain
        """
        for pattern in self.FAIL2BAN_CHAIN_PATTERNS:
            if fnmatch.fnmatch(chain_name, pattern):
                return True
        return False

    def get_fail2ban_chains(self) -> list[str]:
        """Get list of fail2ban chains in iptables.

        Returns:
            List of chain names starting with f2b- or fail2ban-
        """
        if self.ctx.dry_run:
            return []

        result = self._run_iptables(["-L", "-n"], check=False)
        if result.returncode != 0:
            return []

        chains = []
        for line in result.stdout.splitlines():
            if line.startswith("Chain "):
                # Format: "Chain f2b-sshd (1 references)"
                parts = line.split()
                if len(parts) >= 2:
                    chain_name = parts[1]
                    if self._is_fail2ban_chain(chain_name):
                        chains.append(chain_name)

        return chains

    def get_fail2ban_jump_rules(self, chain: str = "INPUT") -> list[dict]:
        """Get rules that jump to fail2ban chains.

        Args:
            chain: Chain to check (default INPUT)

        Returns:
            List of dicts with rule info (num, target, etc.)
        """
        if self.ctx.dry_run:
            return []

        result = self._run_iptables(
            ["-L", chain, "-n", "--line-numbers"],
            check=False,
        )
        if result.returncode != 0:
            return []

        rules = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    num = int(parts[0])
                    target = parts[1]
                    if self._is_fail2ban_chain(target):
                        rules.append({
                            "num": num,
                            "target": target,
                            "line": line,
                        })
                except ValueError:
                    continue

        return rules

    def _restore_fail2ban_jump_rule(self, target: str) -> None:
        """Restore a fail2ban jump rule in INPUT chain.

        Args:
            target: The fail2ban chain to jump to (e.g., f2b-sshd)
        """
        # Check if rule already exists
        result = self._run_iptables(
            ["-C", "INPUT", "-j", target],
            check=False,
        )
        if result.returncode != 0:
            # Rule doesn't exist, add it
            self._run_iptables(["-I", "INPUT", "-j", target], check=False)

    # =========================================================================
    # State Management and Sync
    # =========================================================================

    def save_rule_to_state(
        self,
        rule: "FirewallRule",
        *,
        protected: bool = False,
    ) -> bool:
        """Save a rule to SM state.

        Args:
            rule: FirewallRule to save
            protected: Whether rule is protected (cannot be removed)

        Returns:
            True if rule was added to state, False if already exists
        """
        stored = StoredRule(
            port=rule.port,
            protocol=rule.protocol.value if hasattr(rule.protocol, 'value') else rule.protocol,
            source=rule.source,
            destination=rule.destination,
            action=rule.action.value if hasattr(rule.action, 'value') else rule.action,
            chain=rule.chain.value if hasattr(rule.chain, 'value') else rule.chain,
            comment=rule.comment,
            interface=rule.interface,
            protected=protected or (rule.port == self.ssh_port and rule.action == Action.ACCEPT),
        )
        return self.state_manager.add_rule(stored)

    def remove_rule_from_state(self, rule: "FirewallRule") -> bool:
        """Remove a rule from SM state.

        Args:
            rule: FirewallRule to remove

        Returns:
            True if rule was removed, False if not found
        """
        stored = StoredRule(
            port=rule.port,
            protocol=rule.protocol.value if hasattr(rule.protocol, 'value') else rule.protocol,
            source=rule.source,
            destination=rule.destination,
            action=rule.action.value if hasattr(rule.action, 'value') else rule.action,
            chain=rule.chain.value if hasattr(rule.chain, 'value') else rule.chain,
            comment=rule.comment,
            interface=rule.interface,
        )
        return self.state_manager.remove_rule(stored)

    def sync_state_to_iptables(self, *, quiet: bool = False) -> int:
        """Apply SM state rules to iptables.

        This is idempotent - rules that already exist are skipped.

        Args:
            quiet: Suppress non-error output

        Returns:
            Number of rules applied
        """
        applied = 0
        state = self.state_manager.state

        # Update Docker awareness
        if self.docker_detected():
            self.state_manager.set_docker_aware(True)

        for stored_rule in state.rules:
            # Convert StoredRule to FirewallRule
            rule = FirewallRule(
                port=stored_rule.port,
                protocol=Protocol(stored_rule.protocol) if stored_rule.protocol != "all" else Protocol.ALL,
                source=stored_rule.source,
                destination=stored_rule.destination,
                action=Action(stored_rule.action),
                chain=Chain(stored_rule.chain) if stored_rule.chain in [c.value for c in Chain] else Chain.INPUT,
                comment=stored_rule.comment,
                interface=stored_rule.interface,
            )

            # Check if rule already exists
            if not self.rule_exists(rule):
                if not quiet:
                    self.ctx.console.step(f"Syncing rule: {stored_rule}")

                if self.ctx.dry_run:
                    self.ctx.console.dry_run_msg(f"Would add rule: {stored_rule}")
                else:
                    self.add_rule(rule, skip_if_exists=True)
                applied += 1

        return applied

    def detect_drift(self) -> DriftReport:
        """Detect rules in iptables not managed by SM state.

        Returns:
            DriftReport with unknown, missing, and preserved rules
        """
        report = DriftReport()

        if self.ctx.dry_run:
            return report

        # Get current iptables rules
        current_rules = self.list_rules(Chain.INPUT)

        # Get fail2ban chains for exclusion
        f2b_chains = self.get_fail2ban_chains()

        # Check each iptables rule against SM state
        for parsed in current_rules:
            # Skip system rules (ACCEPT all, RETURN, etc.)
            if parsed.target in ("RETURN", "LOG"):
                continue

            # Check if this is a fail2ban jump
            if self._is_fail2ban_chain(parsed.target):
                report.preserved_rules.append({
                    "num": parsed.num,
                    "target": parsed.target,
                    "type": "fail2ban",
                })
                continue

            # Skip conntrack/state rules
            if parsed.extra and "ctstate" in parsed.extra.lower():
                continue

            # Skip loopback rules
            if parsed.extra and "-i lo" in (parsed.extra or ""):
                continue

            # Create a StoredRule to check against state
            stored = StoredRule(
                port=parsed.port,
                protocol=parsed.protocol,
                source=parsed.source,
                action=parsed.target,
                chain="INPUT",
                comment=parsed.comment,
            )

            if not self.state_manager.state.has_rule(stored):
                report.unknown_rules.append({
                    "num": parsed.num,
                    "target": parsed.target,
                    "protocol": parsed.protocol,
                    "port": parsed.port,
                    "source": parsed.source,
                    "comment": parsed.comment,
                })

        # Check for rules in state that are missing from iptables
        for stored_rule in self.state_manager.state.rules:
            rule = FirewallRule(
                port=stored_rule.port,
                protocol=Protocol(stored_rule.protocol) if stored_rule.protocol != "all" else Protocol.ALL,
                source=stored_rule.source,
                action=Action(stored_rule.action),
                chain=Chain(stored_rule.chain) if stored_rule.chain in [c.value for c in Chain] else Chain.INPUT,
            )
            if not self.rule_exists(rule):
                report.missing_rules.append(stored_rule)

        return report

    def flush_with_fail2ban_preservation(
        self,
        *,
        keep_ssh: bool = True,
        include_docker: bool = False,
    ) -> None:
        """Flush rules while preserving fail2ban chains and jump rules.

        Args:
            keep_ssh: Re-add SSH allow rule after flush (safety)
            include_docker: Also flush DOCKER-USER chain
        """
        self.ctx.console.step("Flushing firewall rules (preserving fail2ban)")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Would flush INPUT (preserving fail2ban jumps)")
            return

        # Get fail2ban jump rules before flush
        f2b_jumps = self.get_fail2ban_jump_rules("INPUT")
        f2b_targets = [r["target"] for r in f2b_jumps]

        # Flush INPUT
        self._run_iptables(["-F", "INPUT"])
        self._run_ip6tables(["-F", "INPUT"], check=False)

        # Restore fail2ban jump rules
        for target in f2b_targets:
            self.ctx.console.debug(f"Restoring fail2ban jump: {target}")
            self._restore_fail2ban_jump_rule(target)

        # Flush DOCKER-USER if requested
        if include_docker and self.docker_user_chain_exists():
            self.ctx.console.step("Flushing DOCKER-USER chain")
            self._run_iptables(["-F", "DOCKER-USER"], check=False)
            self._run_iptables(["-A", "DOCKER-USER", "-j", "RETURN"], check=False)

        # Set policy to ACCEPT
        self._run_iptables(["-P", "INPUT", "ACCEPT"])
        self._run_ip6tables(["-P", "INPUT", "ACCEPT"], check=False)

        # Re-add SSH rule for safety
        if keep_ssh:
            self.ensure_ssh_allowed()

        self.ctx.console.success("Firewall rules flushed (fail2ban preserved)")

    # =========================================================================
    # Systemd Hooks for Docker Integration
    # =========================================================================

    def install_systemd_hooks(self) -> None:
        """Install systemd service and Docker drop-in for rule persistence.

        This ensures:
        1. Rules are applied at boot
        2. Rules are reapplied when Docker restarts
        """
        # Service content for boot-time sync
        service_content = """[Unit]
Description=SM Firewall Manager
After=network.target
# Wait for Docker if it exists (but don't fail if it doesn't)
After=docker.service
Wants=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/sm firewall sync --boot --quiet
ExecReload=/usr/local/bin/sm firewall sync --quiet

[Install]
WantedBy=multi-user.target
"""

        # Docker drop-in content
        docker_dropin_content = """# Generated by SM - ensures firewall rules persist after Docker restarts
[Service]
ExecStartPost=/usr/local/bin/sm firewall sync --quiet
"""

        self.ctx.console.step("Installing SM firewall systemd hooks")

        # Install main service
        self.systemd.install_service(
            "sm-firewall",
            service_content,
            enable=True,
            start=False,
            description="Installing SM firewall boot service",
        )

        # Install Docker drop-in if Docker is present
        if self.docker_detected() or self.systemd.exists("docker.service"):
            self.systemd.install_drop_in(
                "docker.service",
                "sm-firewall",
                docker_dropin_content,
                description="Installing Docker restart hook for firewall",
            )
            self.systemd.daemon_reload()

        # Update state
        self.state_manager.set_systemd_installed(True)
        self.state_manager.save()

        self.ctx.console.success("Systemd hooks installed")

    def remove_systemd_hooks(self) -> None:
        """Remove systemd service and Docker drop-in."""
        self.ctx.console.step("Removing SM firewall systemd hooks")

        # Remove Docker drop-in
        self.systemd.remove_drop_in(
            "docker.service",
            "sm-firewall",
            description="Removing Docker restart hook",
        )

        # Remove service
        self.systemd.remove_service(
            "sm-firewall",
            description="Removing SM firewall boot service",
        )

        # Update state
        self.state_manager.set_systemd_installed(False)
        self.state_manager.save()

        self.ctx.console.success("Systemd hooks removed")
