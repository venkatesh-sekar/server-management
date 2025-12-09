"""Security audit service for comprehensive system security assessment.

This module provides security auditing capabilities including:
- Network security checks (SSH config, open ports, firewall)
- User account checks (UID 0, passwords, sudo configuration)
- Filesystem checks (SUID/SGID, world-writable files, permissions)
- Service checks (dangerous services, pending updates)
- External tool integration (Lynis, rkhunter, chkrootkit)
"""

import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from sm.core.context import ExecutionContext
from sm.core.executor import CommandExecutor
from sm.core.exceptions import ExecutionError


class AuditSeverity(Enum):
    """Severity levels for audit findings."""

    PASS = "PASS"  # Check passed
    INFO = "INFO"  # Informational
    WARN = "WARN"  # Warning - should be addressed
    FAIL = "FAIL"  # Failed - security issue
    SKIP = "SKIP"  # Check skipped


@dataclass
class AuditFinding:
    """Result of a single security check."""

    check_id: str  # Unique identifier (e.g., "SSH-001")
    check_name: str  # Human-readable name
    severity: AuditSeverity
    message: str  # Result message
    category: str = "general"
    details: Optional[str] = None  # Extended details
    remediation: Optional[str] = None  # How to fix
    score_weight: int = 1  # Weight for scoring


@dataclass
class AuditReport:
    """Complete audit report."""

    findings: list[AuditFinding]
    score: int  # 0-100
    categories: dict[str, list[AuditFinding]]
    external_tools_used: list[str]
    timestamp: datetime


# Category weights for scoring
CATEGORY_WEIGHTS = {
    "network": 1.5,
    "users": 1.3,
    "filesystem": 1.0,
    "services": 1.2,
    "external": 1.4,
}

# Dangerous ports that should not be publicly accessible
DANGEROUS_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    2375: "Docker API (unencrypted)",
    2376: "Docker API",
}

# Dangerous services that should not be running
DANGEROUS_SERVICES = [
    "telnet",
    "rsh",
    "rlogin",
    "rexec",
    "tftp",
    "talk",
    "ntalk",
]

# External security tools
EXTERNAL_TOOLS = {
    "lynis": {
        "package": "lynis",
        "check_cmd": ["lynis", "--version"],
        "run_cmd": ["lynis", "audit", "system", "--quick", "--no-colors"],
    },
    "rkhunter": {
        "package": "rkhunter",
        "check_cmd": ["rkhunter", "--version"],
        "run_cmd": ["rkhunter", "--check", "--skip-keypress", "--report-warnings-only"],
    },
    "chkrootkit": {
        "package": "chkrootkit",
        "check_cmd": ["chkrootkit", "-V"],
        "run_cmd": ["chkrootkit", "-q"],
    },
}

# Registry of all security checks for --list-checks
SECURITY_CHECKS = [
    # Network checks
    {
        "id": "SSH-001",
        "name": "SSH root login",
        "category": "network",
        "description": "Check if root login is disabled via SSH",
        "quick": True,
    },
    {
        "id": "SSH-002",
        "name": "SSH password authentication",
        "category": "network",
        "description": "Check if password auth is disabled (prefer SSH keys)",
        "quick": True,
    },
    {
        "id": "SSH-003",
        "name": "SSH empty passwords",
        "category": "network",
        "description": "Check if empty passwords are rejected",
        "quick": True,
    },
    {
        "id": "SSH-004",
        "name": "SSH X11 forwarding",
        "category": "network",
        "description": "Check X11 forwarding status",
        "quick": True,
    },
    {
        "id": "SSH-005",
        "name": "SSH max auth tries",
        "category": "network",
        "description": "Check maximum authentication attempts",
        "quick": True,
    },
    {
        "id": "NET-001",
        "name": "Dangerous open ports",
        "category": "network",
        "description": "Check for database/cache ports exposed publicly",
        "quick": True,
    },
    {
        "id": "FW-001",
        "name": "Firewall status",
        "category": "network",
        "description": "Check if UFW or iptables firewall is active",
        "quick": True,
    },
    # User checks
    {
        "id": "USR-001",
        "name": "UID 0 accounts",
        "category": "users",
        "description": "Check for unauthorized accounts with root privileges",
        "quick": True,
    },
    {
        "id": "USR-002",
        "name": "Empty passwords",
        "category": "users",
        "description": "Check for accounts with empty passwords",
        "quick": True,
    },
    {
        "id": "USR-003",
        "name": "Shell users",
        "category": "users",
        "description": "Audit users with login shell access",
        "quick": True,
    },
    {
        "id": "USR-004",
        "name": "Sudo NOPASSWD",
        "category": "users",
        "description": "Check for passwordless sudo rules",
        "quick": False,
    },
    {
        "id": "USR-005",
        "name": "Failed logins (24h)",
        "category": "users",
        "description": "Check for brute force attempts",
        "quick": True,
    },
    # Filesystem checks
    {
        "id": "FS-001",
        "name": "Shadow file permissions",
        "category": "filesystem",
        "description": "Check /etc/shadow has secure permissions",
        "quick": True,
    },
    {
        "id": "FS-002",
        "name": "SUID/SGID binaries",
        "category": "filesystem",
        "description": "Scan for unexpected setuid/setgid files",
        "quick": False,
    },
    {
        "id": "FS-003",
        "name": "World-writable files",
        "category": "filesystem",
        "description": "Find world-writable files in /etc and /usr",
        "quick": False,
    },
    {
        "id": "FS-004",
        "name": "SSH key permissions",
        "category": "filesystem",
        "description": "Check private SSH keys have correct permissions",
        "quick": True,
    },
    # Service checks
    {
        "id": "SVC-001",
        "name": "Dangerous services",
        "category": "services",
        "description": "Check for insecure services (telnet, rsh, etc.)",
        "quick": True,
    },
    {
        "id": "SVC-002",
        "name": "Pending updates",
        "category": "services",
        "description": "Check for pending security updates",
        "quick": True,
    },
    {
        "id": "SVC-003",
        "name": "fail2ban status",
        "category": "services",
        "description": "Check if fail2ban is protecting against brute force",
        "quick": True,
    },
    # External tools
    {
        "id": "LYN-001",
        "name": "Lynis hardening index",
        "category": "external",
        "description": "Overall system hardening score from Lynis",
        "quick": False,
    },
    {
        "id": "RKH-001",
        "name": "rkhunter scan",
        "category": "external",
        "description": "Rootkit detection scan",
        "quick": False,
    },
    {
        "id": "CHK-001",
        "name": "chkrootkit scan",
        "category": "external",
        "description": "Alternative rootkit detection",
        "quick": False,
    },
]


class SecurityAuditService:
    """Performs comprehensive security audits on the system."""

    def __init__(self, ctx: ExecutionContext, executor: CommandExecutor):
        """Initialize the security audit service.

        Args:
            ctx: Execution context
            executor: Command executor for running shell commands
        """
        self.ctx = ctx
        self.executor = executor

    def run_audit(
        self,
        categories: Optional[list[str]] = None,
        quick: bool = False,
        use_external: bool = True,
        install_tools: bool = False,
    ) -> AuditReport:
        """Run comprehensive security audit.

        Args:
            categories: List of categories to audit (None = all)
            quick: Run quick essential checks only
            use_external: Use external tools if available
            install_tools: Install external tools before audit

        Returns:
            AuditReport with all findings
        """
        findings: list[AuditFinding] = []
        external_tools_used: list[str] = []

        # Determine which categories to run
        all_categories = ["network", "users", "filesystem", "services"]
        run_categories = categories if categories else all_categories

        # Show what's being skipped in quick mode
        if quick:
            self.ctx.console.info(
                "Quick mode: skipping SUID/SGID scan, world-writable scan, "
                "sudo audit, and external tools"
            )

        # Install external tools if requested
        if install_tools and use_external:
            self.ctx.console.step("Installing external security tools")
            installed = self.install_external_tools()
            if installed:
                self.ctx.console.success(f"Installed: {', '.join(installed)}")

        # Run built-in checks by category
        if "network" in run_categories:
            self.ctx.console.step("Checking network security")
            findings.extend(self._check_network(quick))

        if "users" in run_categories:
            self.ctx.console.step("Checking user accounts")
            findings.extend(self._check_users(quick))

        if "filesystem" in run_categories:
            self.ctx.console.step("Checking filesystem security")
            findings.extend(self._check_filesystem(quick))

        if "services" in run_categories:
            self.ctx.console.step("Checking services")
            findings.extend(self._check_services(quick))

        # Run external tools
        if use_external and not quick:
            self.ctx.console.step("Running external security tools")
            ext_findings, tools_used = self._run_external_tools()
            findings.extend(ext_findings)
            external_tools_used = tools_used
        elif use_external and quick:
            self.ctx.console.info("External tools skipped (use full audit for deeper analysis)")

        # Group findings by category
        categories_map: dict[str, list[AuditFinding]] = {}
        for finding in findings:
            if finding.category not in categories_map:
                categories_map[finding.category] = []
            categories_map[finding.category].append(finding)

        # Calculate score
        score = self._calculate_score(findings)

        return AuditReport(
            findings=findings,
            score=score,
            categories=categories_map,
            external_tools_used=external_tools_used,
            timestamp=datetime.now(),
        )

    def install_external_tools(self) -> list[str]:
        """Install external security tools via apt.

        Returns:
            List of tool names that were installed
        """
        installed: list[str] = []
        tools_to_install: list[str] = []

        # Check which tools are missing
        available = self._detect_tools()
        for tool_name, is_available in available.items():
            if not is_available:
                tools_to_install.append(EXTERNAL_TOOLS[tool_name]["package"])

        if not tools_to_install:
            self.ctx.console.info("All external tools already installed")
            return installed

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would install: {', '.join(tools_to_install)}")
            return tools_to_install

        # Update apt cache
        self.ctx.console.info("Updating apt cache...")
        try:
            result = subprocess.run(
                ["apt-get", "update", "-y"],
                capture_output=True,
                text=True,
                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            )
            if result.returncode != 0:
                self.ctx.console.warn("Failed to update apt cache")
        except FileNotFoundError:
            self.ctx.console.warn("apt-get not found - cannot install tools")
            return installed

        # Install tools
        self.ctx.console.info(f"Installing: {', '.join(tools_to_install)}")
        try:
            result = subprocess.run(
                ["apt-get", "install", "-y", "--no-install-recommends"] + tools_to_install,
                capture_output=True,
                text=True,
                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            )
            if result.returncode == 0:
                installed = tools_to_install
            else:
                self.ctx.console.warn(f"Some tools failed to install: {result.stderr}")
        except FileNotFoundError:
            self.ctx.console.warn("apt-get not found - cannot install tools")
            return installed

        # Update rkhunter database if installed
        if "rkhunter" in tools_to_install:
            self.ctx.console.info("Updating rkhunter database...")
            try:
                subprocess.run(
                    ["rkhunter", "--update"],
                    capture_output=True,
                    text=True,
                )
                subprocess.run(
                    ["rkhunter", "--propupd"],
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError:
                self.ctx.console.warn("rkhunter not found after install - skipping database update")

        return installed

    def _detect_tools(self) -> dict[str, bool]:
        """Detect which external tools are installed.

        Returns:
            Dict mapping tool name to availability
        """
        available: dict[str, bool] = {}
        for tool_name, tool_info in EXTERNAL_TOOLS.items():
            try:
                result = subprocess.run(
                    ["which", tool_info["check_cmd"][0]],
                    capture_output=True,
                )
                available[tool_name] = result.returncode == 0
            except FileNotFoundError:
                # 'which' command not available, try direct execution check
                try:
                    result = subprocess.run(
                        tool_info["check_cmd"],
                        capture_output=True,
                    )
                    available[tool_name] = result.returncode == 0
                except FileNotFoundError:
                    available[tool_name] = False
        return available

    # ==================== Network Checks ====================

    def _check_network(self, quick: bool = False) -> list[AuditFinding]:
        """Run network security checks.

        Args:
            quick: Run only essential checks

        Returns:
            List of findings
        """
        findings: list[AuditFinding] = []

        # SSH configuration checks
        findings.extend(self._check_ssh_config())

        # Open ports check
        findings.append(self._check_open_ports())

        # Firewall status
        findings.append(self._check_firewall())

        return findings

    def _check_ssh_config(self) -> list[AuditFinding]:
        """Check SSH server configuration."""
        findings: list[AuditFinding] = []
        sshd_config = Path("/etc/ssh/sshd_config")

        if not sshd_config.exists():
            findings.append(
                AuditFinding(
                    check_id="SSH-000",
                    check_name="SSH configuration file",
                    severity=AuditSeverity.SKIP,
                    message="sshd_config not found",
                    category="network",
                )
            )
            return findings

        config_text = sshd_config.read_text()

        # Parse SSH config (handle Include directives)
        config = self._parse_sshd_config(config_text)

        # SSH-001: PermitRootLogin
        permit_root = config.get("permitrootlogin", "prohibit-password").lower()
        if permit_root in ("no", "prohibit-password", "forced-commands-only"):
            findings.append(
                AuditFinding(
                    check_id="SSH-001",
                    check_name="SSH root login",
                    severity=AuditSeverity.PASS,
                    message=f"PermitRootLogin={permit_root}",
                    category="network",
                )
            )
        else:
            findings.append(
                AuditFinding(
                    check_id="SSH-001",
                    check_name="SSH root login",
                    severity=AuditSeverity.FAIL,
                    message=f"PermitRootLogin={permit_root}",
                    category="network",
                    details="Root login should be disabled",
                    remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
                    score_weight=2,
                )
            )

        # SSH-002: PasswordAuthentication
        password_auth = config.get("passwordauthentication", "yes").lower()
        if password_auth == "no":
            findings.append(
                AuditFinding(
                    check_id="SSH-002",
                    check_name="SSH password authentication",
                    severity=AuditSeverity.PASS,
                    message="PasswordAuthentication=no",
                    category="network",
                )
            )
        else:
            findings.append(
                AuditFinding(
                    check_id="SSH-002",
                    check_name="SSH password authentication",
                    severity=AuditSeverity.WARN,
                    message="PasswordAuthentication=yes",
                    category="network",
                    details="Consider using SSH keys instead of passwords",
                    remediation="Set 'PasswordAuthentication no' and use SSH keys",
                )
            )

        # SSH-003: PermitEmptyPasswords
        empty_pass = config.get("permitemptypasswords", "no").lower()
        if empty_pass == "no":
            findings.append(
                AuditFinding(
                    check_id="SSH-003",
                    check_name="SSH empty passwords",
                    severity=AuditSeverity.PASS,
                    message="PermitEmptyPasswords=no",
                    category="network",
                )
            )
        else:
            findings.append(
                AuditFinding(
                    check_id="SSH-003",
                    check_name="SSH empty passwords",
                    severity=AuditSeverity.FAIL,
                    message="PermitEmptyPasswords=yes",
                    category="network",
                    details="Empty passwords are a critical security risk",
                    remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config",
                    score_weight=3,
                )
            )

        # SSH-004: X11Forwarding
        x11 = config.get("x11forwarding", "no").lower()
        if x11 == "no":
            findings.append(
                AuditFinding(
                    check_id="SSH-004",
                    check_name="SSH X11 forwarding",
                    severity=AuditSeverity.PASS,
                    message="X11Forwarding=no",
                    category="network",
                )
            )
        else:
            findings.append(
                AuditFinding(
                    check_id="SSH-004",
                    check_name="SSH X11 forwarding",
                    severity=AuditSeverity.INFO,
                    message="X11Forwarding=yes",
                    category="network",
                    details="X11 forwarding enabled (may be intentional)",
                )
            )

        # SSH-005: MaxAuthTries
        max_auth = config.get("maxauthtries", "6")
        try:
            max_auth_int = int(max_auth)
            if max_auth_int <= 4:
                findings.append(
                    AuditFinding(
                        check_id="SSH-005",
                        check_name="SSH max auth tries",
                        severity=AuditSeverity.PASS,
                        message=f"MaxAuthTries={max_auth}",
                        category="network",
                    )
                )
            else:
                findings.append(
                    AuditFinding(
                        check_id="SSH-005",
                        check_name="SSH max auth tries",
                        severity=AuditSeverity.WARN,
                        message=f"MaxAuthTries={max_auth}",
                        category="network",
                        details="Consider lowering max auth attempts",
                        remediation="Set 'MaxAuthTries 4' or lower",
                    )
                )
        except ValueError:
            pass

        return findings

    def _parse_sshd_config(self, config_text: str) -> dict[str, str]:
        """Parse sshd_config into a dictionary."""
        config: dict[str, str] = {}
        for line in config_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                config[parts[0].lower()] = parts[1]
        return config

    def _check_open_ports(self) -> AuditFinding:
        """Check for dangerous open ports.

        Considers firewall rules - ports protected by iptables DROP/REJECT
        rules are not flagged as dangerous.
        """
        try:
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return AuditFinding(
                    check_id="NET-001",
                    check_name="Open ports",
                    severity=AuditSeverity.SKIP,
                    message="Could not check open ports",
                    category="network",
                )

            # Get firewall-protected ports
            protected_ports = self._get_firewall_protected_ports()

            dangerous_found: list[str] = []
            protected_found: list[str] = []

            for line in result.stdout.splitlines():
                # Look for ports bound to 0.0.0.0 or *
                if "0.0.0.0:" in line or "*:" in line:
                    for port, service in DANGEROUS_PORTS.items():
                        if f":{port}" in line:
                            if port in protected_ports:
                                protected_found.append(f"{port} ({service})")
                            else:
                                dangerous_found.append(f"{port} ({service})")

            if dangerous_found:
                details = "These ports should not be publicly accessible"
                if protected_found:
                    details += f"\nFirewall-protected (OK): {', '.join(protected_found)}"
                return AuditFinding(
                    check_id="NET-001",
                    check_name="Dangerous open ports",
                    severity=AuditSeverity.FAIL,
                    message=f"Publicly accessible: {', '.join(dangerous_found)}",
                    category="network",
                    details=details,
                    remediation="Bind services to localhost or use firewall rules",
                    score_weight=2,
                )
            elif protected_found:
                return AuditFinding(
                    check_id="NET-001",
                    check_name="Dangerous open ports",
                    severity=AuditSeverity.PASS,
                    message=f"Dangerous ports protected by firewall: {', '.join(protected_found)}",
                    category="network",
                    details="These ports are listening but blocked by firewall rules",
                )
            else:
                return AuditFinding(
                    check_id="NET-001",
                    check_name="Dangerous open ports",
                    severity=AuditSeverity.PASS,
                    message="No dangerous ports publicly accessible",
                    category="network",
                )
        except Exception as e:
            return AuditFinding(
                check_id="NET-001",
                check_name="Open ports",
                severity=AuditSeverity.SKIP,
                message=f"Error checking ports: {e}",
                category="network",
            )

    def _get_firewall_protected_ports(self) -> set[int]:
        """Get ports that are protected by firewall DROP/REJECT rules.

        Checks iptables INPUT chain for rules that block incoming traffic
        to specific ports from all sources (0.0.0.0/0).

        Returns:
            Set of port numbers that are blocked by firewall
        """
        protected: set[int] = set()

        try:
            # Get iptables INPUT chain rules
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "-v", "--line-numbers"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return protected

            # Check if default policy is DROP (all ports blocked by default)
            lines = result.stdout.strip().splitlines()
            if lines:
                first_line = lines[0]
                if "policy DROP" in first_line or "policy REJECT" in first_line:
                    # With DROP policy, check which ports have ACCEPT rules
                    # Ports without ACCEPT rules are effectively protected
                    accepted_ports = self._get_accepted_ports_from_rules(lines[2:])
                    # All dangerous ports not in accepted_ports are protected
                    for port in DANGEROUS_PORTS:
                        if port not in accepted_ports:
                            protected.add(port)
                    return protected

            # With ACCEPT policy, look for explicit DROP/REJECT rules
            for line in lines[2:]:  # Skip header lines
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 4:
                    continue

                target = parts[3] if len(parts) > 3 else ""

                # Only consider DROP or REJECT rules
                if target not in ("DROP", "REJECT"):
                    continue

                # Look for destination port in the line
                # Format: dpt:PORT or dpts:PORT:PORT (range)
                for part in parts:
                    if part.startswith("dpt:"):
                        try:
                            port = int(part.split(":")[1])
                            protected.add(port)
                        except (ValueError, IndexError):
                            pass
                    elif part.startswith("dpts:"):
                        # Port range
                        try:
                            range_part = part.split(":")[1]
                            start, end = range_part.split(":")
                            for port in range(int(start), int(end) + 1):
                                protected.add(port)
                        except (ValueError, IndexError):
                            pass

        except FileNotFoundError:
            pass  # iptables not installed
        except Exception:
            pass

        return protected

    def _get_accepted_ports_from_rules(self, rule_lines: list[str]) -> set[int]:
        """Extract ports that have ACCEPT rules from iptables output.

        Args:
            rule_lines: Lines from iptables output (excluding headers)

        Returns:
            Set of port numbers with ACCEPT rules
        """
        accepted: set[int] = set()

        for line in rule_lines:
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            target = parts[3] if len(parts) > 3 else ""

            # Only consider ACCEPT rules
            if target != "ACCEPT":
                continue

            # Look for destination port
            for part in parts:
                if part.startswith("dpt:"):
                    try:
                        port = int(part.split(":")[1])
                        accepted.add(port)
                    except (ValueError, IndexError):
                        pass
                elif part.startswith("dpts:"):
                    try:
                        range_part = part.split(":")[1]
                        start, end = range_part.split(":")
                        for port in range(int(start), int(end) + 1):
                            accepted.add(port)
                    except (ValueError, IndexError):
                        pass

        return accepted

    def _check_firewall(self) -> AuditFinding:
        """Check if firewall is enabled."""
        # Try ufw first
        try:
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
            )
            ufw_available = True
        except FileNotFoundError:
            ufw_available = False
            result = None

        if ufw_available and result and result.returncode == 0:
            if "Status: active" in result.stdout:
                return AuditFinding(
                    check_id="FW-001",
                    check_name="Firewall status",
                    severity=AuditSeverity.PASS,
                    message="UFW firewall is active",
                    category="network",
                )
            else:
                return AuditFinding(
                    check_id="FW-001",
                    check_name="Firewall status",
                    severity=AuditSeverity.WARN,
                    message="UFW firewall is inactive",
                    category="network",
                    details="Firewall should be enabled",
                    remediation="Run 'sudo ufw enable' to enable firewall",
                )

        # Try iptables
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Check if there are any rules beyond default
                lines = [
                    line for line in result.stdout.splitlines()
                    if line and not line.startswith("Chain") and not line.startswith("target")
                ]
                if len(lines) > 0:
                    return AuditFinding(
                        check_id="FW-001",
                        check_name="Firewall status",
                        severity=AuditSeverity.PASS,
                        message="iptables has active rules",
                        category="network",
                    )
        except FileNotFoundError:
            pass  # iptables not installed

        return AuditFinding(
            check_id="FW-001",
            check_name="Firewall status",
            severity=AuditSeverity.WARN,
            message="No active firewall detected",
            category="network",
            details="No firewall rules found",
            remediation="Configure ufw or iptables firewall",
        )

    # ==================== User Checks ====================

    def _check_users(self, quick: bool = False) -> list[AuditFinding]:
        """Run user account security checks."""
        findings: list[AuditFinding] = []

        # UID 0 accounts
        findings.append(self._check_uid_zero())

        # Empty passwords
        findings.append(self._check_empty_passwords())

        # Shell users
        findings.append(self._check_shell_users())

        # Sudo NOPASSWD
        if not quick:
            findings.append(self._check_sudo_nopasswd())

        # Failed logins
        findings.append(self._check_failed_logins())

        return findings

    def _check_uid_zero(self) -> AuditFinding:
        """Check for unauthorized UID 0 accounts."""
        try:
            passwd = Path("/etc/passwd").read_text()
            uid_zero = [
                line.split(":")[0]
                for line in passwd.splitlines()
                if line and line.split(":")[2] == "0"
            ]

            if uid_zero == ["root"]:
                return AuditFinding(
                    check_id="USR-001",
                    check_name="UID 0 accounts",
                    severity=AuditSeverity.PASS,
                    message="Only root has UID 0",
                    category="users",
                )
            else:
                return AuditFinding(
                    check_id="USR-001",
                    check_name="UID 0 accounts",
                    severity=AuditSeverity.FAIL,
                    message=f"Multiple UID 0 accounts: {', '.join(uid_zero)}",
                    category="users",
                    details="Only root should have UID 0",
                    remediation="Investigate and remove unauthorized UID 0 accounts",
                    score_weight=3,
                )
        except Exception as e:
            return AuditFinding(
                check_id="USR-001",
                check_name="UID 0 accounts",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="users",
            )

    def _check_empty_passwords(self) -> AuditFinding:
        """Check for accounts with empty passwords."""
        try:
            shadow = Path("/etc/shadow").read_text()
            empty_pass_users: list[str] = []

            for line in shadow.splitlines():
                if not line:
                    continue
                parts = line.split(":")
                if len(parts) >= 2:
                    username = parts[0]
                    password_hash = parts[1]

                    # Skip locked accounts (!, !!, *, or similar)
                    # These are intentionally disabled, not a security risk
                    if password_hash in ("!", "!!", "*", "!*"):
                        continue

                    # Empty password field is a critical security risk
                    if password_hash == "":
                        # Only flag if account has a login shell
                        passwd_line = subprocess.run(
                            ["getent", "passwd", username],
                            capture_output=True,
                            text=True,
                        )
                        if passwd_line.returncode == 0:
                            shell = passwd_line.stdout.strip().split(":")[-1]
                            nologin_shells = (
                                "/usr/sbin/nologin",
                                "/bin/false",
                                "/sbin/nologin",
                            )
                            if shell not in nologin_shells:
                                empty_pass_users.append(username)

            if not empty_pass_users:
                return AuditFinding(
                    check_id="USR-002",
                    check_name="Empty passwords",
                    severity=AuditSeverity.PASS,
                    message="No accounts with empty passwords",
                    category="users",
                )
            else:
                return AuditFinding(
                    check_id="USR-002",
                    check_name="Empty passwords",
                    severity=AuditSeverity.FAIL,
                    message=f"Accounts with empty passwords: {', '.join(empty_pass_users)}",
                    category="users",
                    details="Empty passwords are a critical security risk",
                    remediation="Set passwords for these accounts or lock them",
                    score_weight=3,
                )
        except PermissionError:
            return AuditFinding(
                check_id="USR-002",
                check_name="Empty passwords",
                severity=AuditSeverity.SKIP,
                message="Need root to check /etc/shadow",
                category="users",
            )
        except Exception as e:
            return AuditFinding(
                check_id="USR-002",
                check_name="Empty passwords",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="users",
            )

    def _check_shell_users(self) -> AuditFinding:
        """Audit users with login shells."""
        try:
            passwd = Path("/etc/passwd").read_text()
            shell_users: list[str] = []
            nologin_shells = ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin")

            for line in passwd.splitlines():
                if not line:
                    continue
                parts = line.split(":")
                if len(parts) >= 7:
                    username = parts[0]
                    uid = int(parts[2])
                    shell = parts[6]
                    # Only report human users (UID >= 1000) with shells
                    if uid >= 1000 and shell not in nologin_shells:
                        shell_users.append(username)

            return AuditFinding(
                check_id="USR-003",
                check_name="Shell users",
                severity=AuditSeverity.INFO,
                message=f"{len(shell_users)} users with login shells",
                category="users",
                details=f"Users: {', '.join(shell_users)}" if shell_users else None,
            )
        except Exception as e:
            return AuditFinding(
                check_id="USR-003",
                check_name="Shell users",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="users",
            )

    def _check_sudo_nopasswd(self) -> AuditFinding:
        """Check for NOPASSWD sudo rules."""
        try:
            nopasswd_found: list[str] = []

            # Check /etc/sudoers
            sudoers = Path("/etc/sudoers")
            if sudoers.exists():
                content = sudoers.read_text()
                for line in content.splitlines():
                    if "NOPASSWD" in line and not line.strip().startswith("#"):
                        nopasswd_found.append(line.strip())

            # Check /etc/sudoers.d/
            sudoers_d = Path("/etc/sudoers.d")
            if sudoers_d.exists():
                for f in sudoers_d.iterdir():
                    if f.is_file() and not f.name.startswith("."):
                        try:
                            content = f.read_text()
                            for line in content.splitlines():
                                if "NOPASSWD" in line and not line.strip().startswith("#"):
                                    nopasswd_found.append(f"{f.name}: {line.strip()}")
                        except PermissionError:
                            pass

            if not nopasswd_found:
                return AuditFinding(
                    check_id="USR-004",
                    check_name="Sudo NOPASSWD",
                    severity=AuditSeverity.PASS,
                    message="No NOPASSWD sudo rules found",
                    category="users",
                )
            else:
                return AuditFinding(
                    check_id="USR-004",
                    check_name="Sudo NOPASSWD",
                    severity=AuditSeverity.WARN,
                    message=f"{len(nopasswd_found)} NOPASSWD rules found",
                    category="users",
                    details="\n".join(nopasswd_found),
                    remediation="Review and minimize NOPASSWD sudo rules",
                )
        except PermissionError:
            return AuditFinding(
                check_id="USR-004",
                check_name="Sudo NOPASSWD",
                severity=AuditSeverity.SKIP,
                message="Need root to check sudoers",
                category="users",
            )
        except Exception as e:
            return AuditFinding(
                check_id="USR-004",
                check_name="Sudo NOPASSWD",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="users",
            )

    def _check_failed_logins(self) -> AuditFinding:
        """Check for recent failed login attempts."""
        try:
            # Try journalctl first
            result = subprocess.run(
                ["journalctl", "-u", "ssh", "--since", "24 hours ago", "--no-pager"],
                capture_output=True,
                text=True,
            )

            failed_count = 0
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Failed password" in line or "Invalid user" in line:
                        failed_count += 1
            else:
                # Fallback to auth.log
                auth_log = Path("/var/log/auth.log")
                if auth_log.exists():
                    result = subprocess.run(
                        ["grep", "-c", "Failed password", str(auth_log)],
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode == 0:
                        failed_count = int(result.stdout.strip())

            if failed_count == 0:
                return AuditFinding(
                    check_id="USR-005",
                    check_name="Failed logins (24h)",
                    severity=AuditSeverity.PASS,
                    message="No failed login attempts",
                    category="users",
                )
            elif failed_count < 10:
                return AuditFinding(
                    check_id="USR-005",
                    check_name="Failed logins (24h)",
                    severity=AuditSeverity.INFO,
                    message=f"{failed_count} failed login attempts",
                    category="users",
                )
            elif failed_count < 100:
                return AuditFinding(
                    check_id="USR-005",
                    check_name="Failed logins (24h)",
                    severity=AuditSeverity.WARN,
                    message=f"{failed_count} failed login attempts",
                    category="users",
                    details="Elevated failed login attempts detected",
                    remediation="Consider enabling fail2ban",
                )
            else:
                return AuditFinding(
                    check_id="USR-005",
                    check_name="Failed logins (24h)",
                    severity=AuditSeverity.FAIL,
                    message=f"{failed_count} failed login attempts",
                    category="users",
                    details="High number of failed logins - possible brute force",
                    remediation="Enable fail2ban and review logs",
                    score_weight=2,
                )
        except Exception as e:
            return AuditFinding(
                check_id="USR-005",
                check_name="Failed logins (24h)",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="users",
            )

    # ==================== Filesystem Checks ====================

    def _check_filesystem(self, quick: bool = False) -> list[AuditFinding]:
        """Run filesystem security checks."""
        findings: list[AuditFinding] = []

        # Shadow file permissions
        findings.append(self._check_shadow_perms())

        # SUID/SGID (skip in quick mode - slow)
        if not quick:
            with self.ctx.console.status(
                "[bold blue]Scanning for SUID/SGID binaries...[/bold blue]",
                spinner="dots",
            ):
                findings.append(self._check_suid_sgid())

        # World-writable files in sensitive dirs (skip in quick mode)
        if not quick:
            with self.ctx.console.status(
                "[bold blue]Scanning for world-writable files...[/bold blue]",
                spinner="dots",
            ):
                findings.append(self._check_world_writable())

        # SSH key permissions
        findings.append(self._check_ssh_key_perms())

        return findings

    def _check_shadow_perms(self) -> AuditFinding:
        """Check /etc/shadow permissions."""
        try:
            shadow = Path("/etc/shadow")
            if not shadow.exists():
                return AuditFinding(
                    check_id="FS-001",
                    check_name="Shadow file permissions",
                    severity=AuditSeverity.SKIP,
                    message="/etc/shadow not found",
                    category="filesystem",
                )

            stat = shadow.stat()
            mode = oct(stat.st_mode)[-3:]

            # Should be 640 or 600 (owner rw, group r or none, others none)
            if mode in ("640", "600", "400"):
                return AuditFinding(
                    check_id="FS-001",
                    check_name="Shadow file permissions",
                    severity=AuditSeverity.PASS,
                    message=f"/etc/shadow has mode {mode}",
                    category="filesystem",
                )
            else:
                return AuditFinding(
                    check_id="FS-001",
                    check_name="Shadow file permissions",
                    severity=AuditSeverity.FAIL,
                    message=f"/etc/shadow has mode {mode}",
                    category="filesystem",
                    details="Shadow file should not be world-readable",
                    remediation="Run 'chmod 640 /etc/shadow'",
                    score_weight=3,
                )
        except Exception as e:
            return AuditFinding(
                check_id="FS-001",
                check_name="Shadow file permissions",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="filesystem",
            )

    def _check_suid_sgid(self) -> AuditFinding:
        """Check for unexpected SUID/SGID binaries."""
        try:
            # Known safe SUID binaries
            known_suid = {
                "/usr/bin/sudo",
                "/usr/bin/su",
                "/usr/bin/passwd",
                "/usr/bin/chsh",
                "/usr/bin/chfn",
                "/usr/bin/newgrp",
                "/usr/bin/gpasswd",
                "/usr/bin/mount",
                "/usr/bin/umount",
                "/usr/bin/pkexec",
                "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
                "/usr/lib/openssh/ssh-keysign",
                "/usr/lib/policykit-1/polkit-agent-helper-1",
                "/usr/libexec/polkit-agent-helper-1",
                "/bin/su",
                "/bin/mount",
                "/bin/umount",
                "/bin/ping",
                "/usr/bin/ping",
            }

            result = subprocess.run(
                ["find", "/usr", "/bin", "/sbin", "-perm", "/6000", "-type", "f"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            found_binaries = set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()
            unexpected = found_binaries - known_suid - {""}

            if not unexpected:
                return AuditFinding(
                    check_id="FS-002",
                    check_name="SUID/SGID binaries",
                    severity=AuditSeverity.PASS,
                    message=f"{len(found_binaries)} SUID/SGID binaries (all known)",
                    category="filesystem",
                )
            else:
                return AuditFinding(
                    check_id="FS-002",
                    check_name="SUID/SGID binaries",
                    severity=AuditSeverity.WARN,
                    message=f"{len(unexpected)} unexpected SUID/SGID binaries",
                    category="filesystem",
                    details="\n".join(sorted(unexpected)),
                    remediation="Review and remove unnecessary SUID/SGID bits",
                )
        except subprocess.TimeoutExpired:
            return AuditFinding(
                check_id="FS-002",
                check_name="SUID/SGID binaries",
                severity=AuditSeverity.SKIP,
                message="Check timed out",
                category="filesystem",
            )
        except Exception as e:
            return AuditFinding(
                check_id="FS-002",
                check_name="SUID/SGID binaries",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="filesystem",
            )

    def _check_world_writable(self) -> AuditFinding:
        """Check for world-writable files in sensitive directories."""
        try:
            result = subprocess.run(
                ["find", "/etc", "/usr", "-xdev", "-type", "f", "-perm", "-0002"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            files = [f for f in result.stdout.strip().split("\n") if f]

            if not files:
                return AuditFinding(
                    check_id="FS-003",
                    check_name="World-writable files",
                    severity=AuditSeverity.PASS,
                    message="No world-writable files in /etc or /usr",
                    category="filesystem",
                )
            else:
                return AuditFinding(
                    check_id="FS-003",
                    check_name="World-writable files",
                    severity=AuditSeverity.WARN,
                    message=f"{len(files)} world-writable files found",
                    category="filesystem",
                    details="\n".join(sorted(files)),
                    remediation="Remove world-writable permissions: chmod o-w <file>",
                )
        except subprocess.TimeoutExpired:
            return AuditFinding(
                check_id="FS-003",
                check_name="World-writable files",
                severity=AuditSeverity.SKIP,
                message="Check timed out",
                category="filesystem",
            )
        except Exception as e:
            return AuditFinding(
                check_id="FS-003",
                check_name="World-writable files",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="filesystem",
            )

    def _check_ssh_key_perms(self) -> AuditFinding:
        """Check SSH private key permissions."""
        try:
            issues: list[str] = []

            # Check root's SSH directory
            root_ssh = Path("/root/.ssh")
            if root_ssh.exists():
                for key_file in root_ssh.glob("id_*"):
                    if key_file.suffix != ".pub":
                        mode = oct(key_file.stat().st_mode)[-3:]
                        if mode != "600":
                            issues.append(f"{key_file}: mode {mode}")

            # Check /home users
            for home in Path("/home").iterdir():
                ssh_dir = home / ".ssh"
                if ssh_dir.exists():
                    for key_file in ssh_dir.glob("id_*"):
                        if key_file.suffix != ".pub":
                            mode = oct(key_file.stat().st_mode)[-3:]
                            if mode != "600":
                                issues.append(f"{key_file}: mode {mode}")

            if not issues:
                return AuditFinding(
                    check_id="FS-004",
                    check_name="SSH key permissions",
                    severity=AuditSeverity.PASS,
                    message="All SSH private keys have correct permissions",
                    category="filesystem",
                )
            else:
                return AuditFinding(
                    check_id="FS-004",
                    check_name="SSH key permissions",
                    severity=AuditSeverity.WARN,
                    message=f"{len(issues)} SSH keys with wrong permissions",
                    category="filesystem",
                    details="\n".join(issues),
                    remediation="Run 'chmod 600' on private key files",
                )
        except Exception as e:
            return AuditFinding(
                check_id="FS-004",
                check_name="SSH key permissions",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="filesystem",
            )

    # ==================== Services Checks ====================

    def _check_services(self, quick: bool = False) -> list[AuditFinding]:
        """Run service security checks."""
        findings: list[AuditFinding] = []

        # Dangerous services
        findings.append(self._check_dangerous_services())

        # Security updates
        findings.append(self._check_security_updates())

        # fail2ban status
        findings.append(self._check_fail2ban())

        return findings

    def _check_dangerous_services(self) -> AuditFinding:
        """Check for dangerous services running."""
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend"],
                capture_output=True,
                text=True,
            )

            running_dangerous: list[str] = []
            for line in result.stdout.splitlines():
                service = line.split()[0] if line.split() else ""
                for dangerous in DANGEROUS_SERVICES:
                    if dangerous in service.lower():
                        running_dangerous.append(service)

            if not running_dangerous:
                return AuditFinding(
                    check_id="SVC-001",
                    check_name="Dangerous services",
                    severity=AuditSeverity.PASS,
                    message="No dangerous services running",
                    category="services",
                )
            else:
                return AuditFinding(
                    check_id="SVC-001",
                    check_name="Dangerous services",
                    severity=AuditSeverity.FAIL,
                    message=f"Dangerous services: {', '.join(running_dangerous)}",
                    category="services",
                    details="These services are insecure and should be replaced",
                    remediation="Disable these services and use secure alternatives",
                    score_weight=2,
                )
        except Exception as e:
            return AuditFinding(
                check_id="SVC-001",
                check_name="Dangerous services",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="services",
            )

    def _check_security_updates(self) -> AuditFinding:
        """Check for pending security updates."""
        try:
            # Update apt cache info
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True,
                text=True,
                env={**os.environ, "LANG": "C"},
            )

            upgradable = [
                line for line in result.stdout.splitlines()
                if line and not line.startswith("Listing")
            ]
            security_updates = [
                line for line in upgradable
                if "security" in line.lower()
            ]

            if not upgradable:
                return AuditFinding(
                    check_id="SVC-002",
                    check_name="Pending updates",
                    severity=AuditSeverity.PASS,
                    message="System is up to date",
                    category="services",
                )
            elif not security_updates:
                return AuditFinding(
                    check_id="SVC-002",
                    check_name="Pending updates",
                    severity=AuditSeverity.INFO,
                    message=f"{len(upgradable)} updates available (no security)",
                    category="services",
                )
            else:
                return AuditFinding(
                    check_id="SVC-002",
                    check_name="Pending updates",
                    severity=AuditSeverity.WARN,
                    message=f"{len(security_updates)} security updates pending",
                    category="services",
                    details=f"Total updates: {len(upgradable)}",
                    remediation="Run 'apt update && apt upgrade' to apply updates",
                )
        except Exception as e:
            return AuditFinding(
                check_id="SVC-002",
                check_name="Pending updates",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="services",
            )

    def _check_fail2ban(self) -> AuditFinding:
        """Check if fail2ban is running."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "fail2ban"],
                capture_output=True,
                text=True,
            )

            if result.stdout.strip() == "active":
                return AuditFinding(
                    check_id="SVC-003",
                    check_name="fail2ban status",
                    severity=AuditSeverity.PASS,
                    message="fail2ban is active",
                    category="services",
                )
            else:
                return AuditFinding(
                    check_id="SVC-003",
                    check_name="fail2ban status",
                    severity=AuditSeverity.INFO,
                    message="fail2ban is not running",
                    category="services",
                    details="fail2ban helps protect against brute force attacks",
                    remediation="Run 'sm security harden' to install and configure",
                )
        except Exception as e:
            return AuditFinding(
                check_id="SVC-003",
                check_name="fail2ban status",
                severity=AuditSeverity.SKIP,
                message=f"Error: {e}",
                category="services",
            )

    # ==================== External Tools ====================

    def _run_external_tools(self) -> tuple[list[AuditFinding], list[str]]:
        """Run external security tools and parse results.

        Returns:
            Tuple of (findings list, tools used list)
        """
        findings: list[AuditFinding] = []
        tools_used: list[str] = []

        available = self._detect_tools()

        # Run Lynis
        if available.get("lynis"):
            with self.ctx.console.status(
                "[bold blue]Running Lynis audit (this may take a few minutes)...[/bold blue]",
                spinner="dots",
            ):
                lynis_findings = self._run_lynis()
            findings.extend(lynis_findings)
            if lynis_findings:
                tools_used.append("lynis")

        # Run rkhunter
        if available.get("rkhunter"):
            with self.ctx.console.status(
                "[bold blue]Running rkhunter scan (this may take several minutes)...[/bold blue]",
                spinner="dots",
            ):
                rkhunter_findings = self._run_rkhunter()
            findings.extend(rkhunter_findings)
            if rkhunter_findings:
                tools_used.append("rkhunter")

        # Run chkrootkit
        if available.get("chkrootkit"):
            with self.ctx.console.status(
                "[bold blue]Running chkrootkit scan...[/bold blue]",
                spinner="dots",
            ):
                chkrootkit_findings = self._run_chkrootkit()
            findings.extend(chkrootkit_findings)
            if chkrootkit_findings:
                tools_used.append("chkrootkit")

        if not tools_used:
            findings.append(
                AuditFinding(
                    check_id="EXT-000",
                    check_name="External tools",
                    severity=AuditSeverity.INFO,
                    message="No external tools available",
                    category="external",
                    details="Install lynis, rkhunter, or chkrootkit for deeper analysis",
                    remediation="Run 'sm security audit --install-tools' to install",
                )
            )

        return findings, tools_used

    def _run_lynis(self) -> list[AuditFinding]:
        """Run Lynis and parse results."""
        findings: list[AuditFinding] = []
        try:
            result = subprocess.run(
                ["lynis", "audit", "system", "--quick", "--no-colors"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse Lynis output for warnings and suggestions
            warnings = []
            suggestions = []
            hardening_index = None

            for line in result.stdout.splitlines():
                if "Warning:" in line:
                    warnings.append(line.split("Warning:")[-1].strip())
                elif "Suggestion:" in line:
                    suggestions.append(line.split("Suggestion:")[-1].strip())
                elif "Hardening index" in line:
                    match = re.search(r"(\d+)", line)
                    if match:
                        hardening_index = int(match.group(1))

            # Create finding for hardening index
            if hardening_index is not None:
                if hardening_index >= 80:
                    severity = AuditSeverity.PASS
                elif hardening_index >= 60:
                    severity = AuditSeverity.WARN
                else:
                    severity = AuditSeverity.FAIL

                findings.append(
                    AuditFinding(
                        check_id="LYN-001",
                        check_name="Lynis hardening index",
                        severity=severity,
                        message=f"Score: {hardening_index}/100",
                        category="external",
                        details=f"{len(warnings)} warnings, {len(suggestions)} suggestions",
                    )
                )

            # Add warning summary
            if warnings:
                findings.append(
                    AuditFinding(
                        check_id="LYN-002",
                        check_name="Lynis warnings",
                        severity=AuditSeverity.WARN,
                        message=f"{len(warnings)} warnings found",
                        category="external",
                        details="\n".join(warnings),
                    )
                )

        except subprocess.TimeoutExpired:
            findings.append(
                AuditFinding(
                    check_id="LYN-000",
                    check_name="Lynis audit",
                    severity=AuditSeverity.SKIP,
                    message="Lynis timed out",
                    category="external",
                )
            )
        except Exception as e:
            findings.append(
                AuditFinding(
                    check_id="LYN-000",
                    check_name="Lynis audit",
                    severity=AuditSeverity.SKIP,
                    message=f"Error: {e}",
                    category="external",
                )
            )

        return findings

    def _run_rkhunter(self) -> list[AuditFinding]:
        """Run rkhunter and parse results."""
        findings: list[AuditFinding] = []
        try:
            result = subprocess.run(
                ["rkhunter", "--check", "--skip-keypress", "--report-warnings-only"],
                capture_output=True,
                text=True,
                timeout=600,
            )

            # Parse warnings from output
            warnings = []
            for line in result.stdout.splitlines():
                if "Warning:" in line:
                    warnings.append(line.strip())

            if not warnings:
                findings.append(
                    AuditFinding(
                        check_id="RKH-001",
                        check_name="rkhunter scan",
                        severity=AuditSeverity.PASS,
                        message="No rootkits detected",
                        category="external",
                    )
                )
            else:
                findings.append(
                    AuditFinding(
                        check_id="RKH-001",
                        check_name="rkhunter scan",
                        severity=AuditSeverity.FAIL,
                        message=f"{len(warnings)} warnings found",
                        category="external",
                        details="\n".join(warnings),
                        remediation="Review rkhunter warnings carefully",
                        score_weight=3,
                    )
                )

        except subprocess.TimeoutExpired:
            findings.append(
                AuditFinding(
                    check_id="RKH-000",
                    check_name="rkhunter scan",
                    severity=AuditSeverity.SKIP,
                    message="rkhunter timed out",
                    category="external",
                )
            )
        except Exception as e:
            findings.append(
                AuditFinding(
                    check_id="RKH-000",
                    check_name="rkhunter scan",
                    severity=AuditSeverity.SKIP,
                    message=f"Error: {e}",
                    category="external",
                )
            )

        return findings

    def _run_chkrootkit(self) -> list[AuditFinding]:
        """Run chkrootkit and parse results."""
        findings: list[AuditFinding] = []
        try:
            result = subprocess.run(
                ["chkrootkit", "-q"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            # chkrootkit -q only outputs infected files
            infected = [line.strip() for line in result.stdout.splitlines() if line.strip()]

            if not infected:
                findings.append(
                    AuditFinding(
                        check_id="CHK-001",
                        check_name="chkrootkit scan",
                        severity=AuditSeverity.PASS,
                        message="No rootkits detected",
                        category="external",
                    )
                )
            else:
                findings.append(
                    AuditFinding(
                        check_id="CHK-001",
                        check_name="chkrootkit scan",
                        severity=AuditSeverity.FAIL,
                        message=f"{len(infected)} potential infections",
                        category="external",
                        details="\n".join(infected),
                        remediation="Investigate potential rootkit infections immediately",
                        score_weight=3,
                    )
                )

        except subprocess.TimeoutExpired:
            findings.append(
                AuditFinding(
                    check_id="CHK-000",
                    check_name="chkrootkit scan",
                    severity=AuditSeverity.SKIP,
                    message="chkrootkit timed out",
                    category="external",
                )
            )
        except Exception as e:
            findings.append(
                AuditFinding(
                    check_id="CHK-000",
                    check_name="chkrootkit scan",
                    severity=AuditSeverity.SKIP,
                    message=f"Error: {e}",
                    category="external",
                )
            )

        return findings

    # ==================== Scoring ====================

    def _calculate_score(self, findings: list[AuditFinding]) -> int:
        """Calculate overall security score (0-100).

        Args:
            findings: List of audit findings

        Returns:
            Score from 0-100
        """
        total_weighted_score = 0.0
        total_weight = 0.0

        for finding in findings:
            category_weight = CATEGORY_WEIGHTS.get(finding.category, 1.0)
            check_weight = finding.score_weight * category_weight

            if finding.severity == AuditSeverity.PASS:
                points = 100
            elif finding.severity == AuditSeverity.INFO:
                points = 100
            elif finding.severity == AuditSeverity.WARN:
                points = 50
            elif finding.severity == AuditSeverity.FAIL:
                points = 0
            else:  # SKIP
                continue

            total_weighted_score += points * check_weight
            total_weight += check_weight

        if total_weight == 0:
            return 0

        return int(total_weighted_score / total_weight)

    # ==================== Report Generation ====================

    def generate_text_report(self, report: AuditReport) -> str:
        """Generate full plain text report with all details.

        Args:
            report: The audit report to format

        Returns:
            Plain text report string
        """
        lines: list[str] = []

        # Header
        lines.append("SECURITY AUDIT REPORT")
        lines.append(f"Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

        # Score label
        if report.score >= 90:
            score_label = "Excellent"
        elif report.score >= 80:
            score_label = "Good"
        elif report.score >= 60:
            score_label = "Fair"
        elif report.score >= 40:
            score_label = "Poor"
        else:
            score_label = "Critical"

        lines.append(f"Score: {report.score}/100 ({score_label})")
        lines.append("=" * 80)
        lines.append("")

        # Category display order
        category_order = ["network", "users", "filesystem", "services", "external"]

        # Display findings by category
        for cat_name in category_order:
            if cat_name not in report.categories:
                continue

            findings = report.categories[cat_name]
            lines.append(cat_name.upper())
            lines.append("-" * 80)

            for finding in findings:
                # Status and check name
                lines.append(f"[{finding.severity.value}] {finding.check_id}: {finding.check_name}")
                lines.append(f"       {finding.message}")

                # Details (full, not truncated)
                if finding.details:
                    lines.append("       Details:")
                    for detail_line in finding.details.split("\n"):
                        lines.append(f"         {detail_line}")

                # Remediation
                if finding.remediation:
                    lines.append(f"       Remediation: {finding.remediation}")

                lines.append("")

            lines.append("")

        # Summary
        lines.append("=" * 80)
        lines.append("SUMMARY")

        pass_count = sum(1 for f in report.findings if f.severity == AuditSeverity.PASS)
        info_count = sum(1 for f in report.findings if f.severity == AuditSeverity.INFO)
        warn_count = sum(1 for f in report.findings if f.severity == AuditSeverity.WARN)
        fail_count = sum(1 for f in report.findings if f.severity == AuditSeverity.FAIL)
        skip_count = sum(1 for f in report.findings if f.severity == AuditSeverity.SKIP)

        lines.append(f"  PASS: {pass_count}  INFO: {info_count}  WARN: {warn_count}  FAIL: {fail_count}  SKIP: {skip_count}")

        if report.external_tools_used:
            lines.append(f"  External tools: {', '.join(report.external_tools_used)}")

        lines.append("")

        return "\n".join(lines)
