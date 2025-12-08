"""Firewall state management.

Provides persistent state tracking for SM-managed firewall rules.
SM becomes the source of truth for firewall configuration, enabling:
- Rule persistence across Docker restarts
- Drift detection (rules added outside SM)
- Fail2ban chain preservation
- Exclusive mode management
"""

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from sm.core.context import ExecutionContext
from sm.core.exceptions import FirewallError


# State file location
STATE_DIR = Path("/var/lib/sm/firewall")
STATE_FILE = STATE_DIR / "sm-rules.yaml"
EXCLUSIVE_MARKER = Path("/etc/sm-firewall-exclusive")

# Default preserved chain patterns (fail2ban, etc.)
DEFAULT_PRESERVED_PATTERNS = ["f2b-*", "fail2ban-*"]


@dataclass
class StoredRule:
    """A firewall rule stored in SM state.

    Similar to FirewallRule but designed for YAML serialization
    and state tracking.
    """
    port: Optional[int] = None
    protocol: str = "tcp"
    source: str = "0.0.0.0/0"
    destination: str = "0.0.0.0/0"
    action: str = "ACCEPT"
    chain: str = "INPUT"
    comment: Optional[str] = None
    interface: Optional[str] = None
    protected: bool = False  # Cannot be removed (e.g., SSH)
    created_at: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for YAML serialization."""
        d = {
            "action": self.action,
            "chain": self.chain,
            "protocol": self.protocol,
        }
        if self.port is not None:
            d["port"] = self.port
        if self.source != "0.0.0.0/0":
            d["source"] = self.source
        if self.destination != "0.0.0.0/0":
            d["destination"] = self.destination
        if self.comment:
            d["comment"] = self.comment
        if self.interface:
            d["interface"] = self.interface
        if self.protected:
            d["protected"] = True
        if self.created_at:
            d["created_at"] = self.created_at
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "StoredRule":
        """Create from dictionary (YAML deserialization)."""
        return cls(
            port=d.get("port"),
            protocol=d.get("protocol", "tcp"),
            source=d.get("source", "0.0.0.0/0"),
            destination=d.get("destination", "0.0.0.0/0"),
            action=d.get("action", "ACCEPT"),
            chain=d.get("chain", "INPUT"),
            comment=d.get("comment"),
            interface=d.get("interface"),
            protected=d.get("protected", False),
            created_at=d.get("created_at"),
        )

    def matches(self, other: "StoredRule") -> bool:
        """Check if this rule matches another (ignoring metadata)."""
        return (
            self.port == other.port
            and self.protocol == other.protocol
            and self.source == other.source
            and self.destination == other.destination
            and self.action == other.action
            and self.chain == other.chain
            and self.interface == other.interface
        )

    def to_iptables_check_args(self) -> list[str]:
        """Generate iptables -C check arguments."""
        args = []

        if self.interface:
            args.extend(["-i", self.interface])

        if self.protocol != "all":
            args.extend(["-p", self.protocol])

        if self.source and self.source != "0.0.0.0/0":
            args.extend(["-s", self.source])

        if self.destination and self.destination != "0.0.0.0/0":
            args.extend(["-d", self.destination])

        if self.port is not None and self.protocol in ("tcp", "udp"):
            args.extend(["--dport", str(self.port)])

        args.extend(["-j", self.action])

        return args

    def __str__(self) -> str:
        """Human-readable representation."""
        parts = [self.action]
        if self.port:
            parts.append(f"{self.protocol}/{self.port}")
        else:
            parts.append(self.protocol)
        if self.source != "0.0.0.0/0":
            parts.append(f"from {self.source}")
        if self.chain != "INPUT":
            parts.append(f"[{self.chain}]")
        if self.comment:
            parts.append(f"({self.comment})")
        if self.protected:
            parts.append("[protected]")
        return " ".join(parts)


@dataclass
class FirewallState:
    """SM's internal firewall state - the source of truth.

    This state file tracks:
    - All rules managed by SM
    - Whether exclusive mode is enabled
    - Whether Docker integration is active
    - Chain patterns to preserve (fail2ban, etc.)
    """
    version: int = 1
    last_modified: Optional[str] = None
    sm_managed: bool = True
    exclusive_mode: bool = False
    docker_aware: bool = False
    systemd_installed: bool = False
    rules: list[StoredRule] = field(default_factory=list)
    preserved_chain_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_PRESERVED_PATTERNS)
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for YAML serialization."""
        return {
            "version": self.version,
            "last_modified": self.last_modified,
            "sm_managed": self.sm_managed,
            "exclusive_mode": self.exclusive_mode,
            "docker_aware": self.docker_aware,
            "systemd_installed": self.systemd_installed,
            "preserved_chain_patterns": self.preserved_chain_patterns,
            "rules": [r.to_dict() for r in self.rules],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FirewallState":
        """Create from dictionary (YAML deserialization)."""
        rules = [StoredRule.from_dict(r) for r in d.get("rules", [])]
        return cls(
            version=d.get("version", 1),
            last_modified=d.get("last_modified"),
            sm_managed=d.get("sm_managed", True),
            exclusive_mode=d.get("exclusive_mode", False),
            docker_aware=d.get("docker_aware", False),
            systemd_installed=d.get("systemd_installed", False),
            rules=rules,
            preserved_chain_patterns=d.get(
                "preserved_chain_patterns",
                list(DEFAULT_PRESERVED_PATTERNS)
            ),
        )

    def find_rule(self, rule: StoredRule) -> Optional[StoredRule]:
        """Find a matching rule in state."""
        for r in self.rules:
            if r.matches(rule):
                return r
        return None

    def has_rule(self, rule: StoredRule) -> bool:
        """Check if a rule exists in state."""
        return self.find_rule(rule) is not None

    def is_chain_preserved(self, chain_name: str) -> bool:
        """Check if a chain should be preserved (not flushed).

        Args:
            chain_name: Name of the chain to check

        Returns:
            True if chain matches any preserved pattern
        """
        for pattern in self.preserved_chain_patterns:
            if fnmatch.fnmatch(chain_name, pattern):
                return True
        return False


class FirewallStateManager:
    """Manages SM's firewall state file.

    Provides load/save operations and rule management while
    respecting dry-run mode.
    """

    def __init__(self, ctx: ExecutionContext) -> None:
        """Initialize state manager.

        Args:
            ctx: Execution context
        """
        self.ctx = ctx
        self._state: Optional[FirewallState] = None

    @property
    def state(self) -> FirewallState:
        """Get current state, loading if necessary."""
        if self._state is None:
            self._state = self.load()
        return self._state

    def load(self) -> FirewallState:
        """Load state from file.

        Returns:
            FirewallState from file, or new state if file doesn't exist
        """
        if self.ctx.dry_run:
            # In dry-run, return empty state if file doesn't exist
            if STATE_FILE.exists():
                return self._read_state_file()
            return FirewallState()

        if not STATE_FILE.exists():
            return FirewallState()

        return self._read_state_file()

    def _read_state_file(self) -> FirewallState:
        """Read and parse state file."""
        try:
            with open(STATE_FILE) as f:
                data = yaml.safe_load(f) or {}
            return FirewallState.from_dict(data)
        except (yaml.YAMLError, OSError) as e:
            self.ctx.console.warn(f"Could not read state file: {e}")
            return FirewallState()

    def save(self) -> None:
        """Save current state to file."""
        if self._state is None:
            return

        self._state.last_modified = datetime.now().isoformat()

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would save state to {STATE_FILE}")
            return

        # Ensure directory exists
        STATE_DIR.mkdir(parents=True, exist_ok=True)

        # Write state file
        with open(STATE_FILE, "w") as f:
            yaml.dump(
                self._state.to_dict(),
                f,
                default_flow_style=False,
                sort_keys=False,
            )

        self.ctx.console.debug(f"State saved to {STATE_FILE}")

    def add_rule(self, rule: StoredRule) -> bool:
        """Add a rule to state.

        Args:
            rule: Rule to add

        Returns:
            True if rule was added, False if already exists
        """
        if self.state.has_rule(rule):
            return False

        # Set creation timestamp
        if not rule.created_at:
            rule.created_at = datetime.now().isoformat()

        self.state.rules.append(rule)
        return True

    def remove_rule(self, rule: StoredRule) -> bool:
        """Remove a rule from state.

        Args:
            rule: Rule to remove

        Returns:
            True if rule was removed, False if not found

        Raises:
            FirewallError: If trying to remove a protected rule
        """
        for i, r in enumerate(self.state.rules):
            if r.matches(rule):
                if r.protected:
                    raise FirewallError(
                        f"Cannot remove protected rule: {r}",
                        hint="Protected rules (like SSH) cannot be removed for safety.",
                    )
                self.state.rules.pop(i)
                return True
        return False

    def clear_rules(self, *, keep_protected: bool = True) -> int:
        """Clear all rules from state.

        Args:
            keep_protected: If True, keep protected rules

        Returns:
            Number of rules removed
        """
        if keep_protected:
            protected = [r for r in self.state.rules if r.protected]
            removed = len(self.state.rules) - len(protected)
            self.state.rules = protected
        else:
            removed = len(self.state.rules)
            self.state.rules = []

        return removed

    def set_exclusive_mode(self, enabled: bool) -> None:
        """Set exclusive mode.

        Args:
            enabled: Whether exclusive mode is enabled
        """
        self.state.exclusive_mode = enabled

        if self.ctx.dry_run:
            action = "create" if enabled else "remove"
            self.ctx.console.dry_run_msg(
                f"Would {action} exclusive marker at {EXCLUSIVE_MARKER}"
            )
            return

        if enabled:
            EXCLUSIVE_MARKER.touch()
        elif EXCLUSIVE_MARKER.exists():
            EXCLUSIVE_MARKER.unlink()

    def set_docker_aware(self, enabled: bool) -> None:
        """Set Docker awareness mode.

        Args:
            enabled: Whether Docker integration is enabled
        """
        self.state.docker_aware = enabled

    def set_systemd_installed(self, installed: bool) -> None:
        """Set whether systemd hooks are installed.

        Args:
            installed: Whether systemd service/drop-in are installed
        """
        self.state.systemd_installed = installed

    def is_exclusive_mode(self) -> bool:
        """Check if exclusive mode is enabled.

        Returns:
            True if exclusive mode is enabled (checks both state and marker)
        """
        # Check marker file (source of truth at runtime)
        if EXCLUSIVE_MARKER.exists():
            return True
        # Fall back to state
        return self.state.exclusive_mode

    def get_input_rules(self) -> list[StoredRule]:
        """Get all INPUT chain rules."""
        return [r for r in self.state.rules if r.chain == "INPUT"]

    def get_docker_user_rules(self) -> list[StoredRule]:
        """Get all DOCKER-USER chain rules."""
        return [r for r in self.state.rules if r.chain == "DOCKER-USER"]

    def import_rule_from_iptables(
        self,
        port: Optional[int],
        protocol: str,
        source: str,
        action: str,
        chain: str = "INPUT",
        comment: Optional[str] = None,
    ) -> StoredRule:
        """Create a StoredRule from iptables parsing.

        This is used when importing existing rules into SM state.

        Args:
            port: Port number (if any)
            protocol: Protocol (tcp, udp, etc.)
            source: Source address/CIDR
            action: Action (ACCEPT, DROP, etc.)
            chain: Chain name
            comment: Rule comment

        Returns:
            StoredRule instance
        """
        # Determine if this is a protected rule (SSH)
        is_ssh = port == 22 and protocol == "tcp" and action == "ACCEPT"

        return StoredRule(
            port=port,
            protocol=protocol,
            source=source,
            action=action,
            chain=chain,
            comment=comment,
            protected=is_ssh,
            created_at=datetime.now().isoformat(),
        )


@dataclass
class DriftReport:
    """Report of rule drift between SM state and iptables."""
    unknown_rules: list[dict] = field(default_factory=list)  # In iptables but not SM
    missing_rules: list[StoredRule] = field(default_factory=list)  # In SM but not iptables
    preserved_rules: list[dict] = field(default_factory=list)  # Fail2ban etc.

    @property
    def has_drift(self) -> bool:
        """Check if there is any drift."""
        return bool(self.unknown_rules) or bool(self.missing_rules)

    @property
    def unknown_count(self) -> int:
        """Number of unknown rules (drift)."""
        return len(self.unknown_rules)

    @property
    def missing_count(self) -> int:
        """Number of missing rules."""
        return len(self.missing_rules)
