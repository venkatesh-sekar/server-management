"""Safety framework for preventing dangerous operations.

Provides:
- Pre-flight checks before any operation
- Danger level classification
- Operation guards for destructive actions
- Production environment detection
"""

import os
import re
import socket
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import wraps
from pathlib import Path
from typing import Callable, Optional, Any

import typer

from sm.core.exceptions import SafetyError, PrerequisiteError
from sm.core.output import console


class DangerLevel(Enum):
    """Classification of operation danger levels."""
    SAFE = auto()       # Read-only operations, status checks
    CAUTIOUS = auto()   # Creates new resources, non-destructive changes
    DANGEROUS = auto()  # Modifies existing resources
    CRITICAL = auto()   # Deletes data, drops databases, restores backups


class CheckResult(Enum):
    """Result of a pre-flight check."""
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class PreflightResult:
    """Immutable result of a pre-flight check."""
    check_name: str
    result: CheckResult
    message: str
    details: Optional[dict[str, Any]] = None
    remediation: Optional[str] = None


class PreflightCheck(ABC):
    """Base class for all pre-flight checks."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the check."""
        ...

    @property
    @abstractmethod
    def critical(self) -> bool:
        """If True, failure blocks all operations."""
        ...

    @abstractmethod
    def run(self) -> PreflightResult:
        """Execute the check and return result."""
        ...


class RootCheck(PreflightCheck):
    """Verify script is running as root or with sudo."""

    name = "Root/Sudo Verification"
    critical = True

    def run(self) -> PreflightResult:
        if os.geteuid() != 0:
            return PreflightResult(
                check_name=self.name,
                result=CheckResult.FAIL,
                message="Must be run as root or with sudo",
                remediation="Run with: sudo sm <command>",
            )
        return PreflightResult(
            check_name=self.name,
            result=CheckResult.PASS,
            message="Running with root privileges",
        )


class OSCompatibilityCheck(PreflightCheck):
    """Verify OS is Debian or Ubuntu."""

    name = "OS Compatibility"
    critical = True

    SUPPORTED_DISTROS = frozenset({"debian", "ubuntu"})

    def run(self) -> PreflightResult:
        os_release = self._parse_os_release()

        if os_release is None:
            return PreflightResult(
                check_name=self.name,
                result=CheckResult.FAIL,
                message="/etc/os-release not found",
                remediation="This tool requires Debian or Ubuntu Linux",
            )

        distro_id = os_release.get("ID", "").lower()
        pretty_name = os_release.get("PRETTY_NAME", distro_id)
        version = os_release.get("VERSION_ID", "unknown")

        if distro_id not in self.SUPPORTED_DISTROS:
            return PreflightResult(
                check_name=self.name,
                result=CheckResult.FAIL,
                message=f"Unsupported OS: {pretty_name}",
                details={"detected_os": distro_id, "version": version},
                remediation="This tool supports Debian and Ubuntu only",
            )

        return PreflightResult(
            check_name=self.name,
            result=CheckResult.PASS,
            message=f"OS: {pretty_name}",
            details={"distro": distro_id, "version": version},
        )

    def _parse_os_release(self) -> Optional[dict[str, str]]:
        try:
            with open("/etc/os-release") as f:
                result = {}
                for line in f:
                    line = line.strip()
                    if "=" in line:
                        key, _, value = line.partition("=")
                        result[key] = value.strip('"').strip("'")
                return result
        except FileNotFoundError:
            return None


class DiskSpaceCheck(PreflightCheck):
    """Verify sufficient disk space for operations."""

    name = "Disk Space"
    critical = False

    # Minimum free space requirements in GB
    REQUIREMENTS = {
        "/": 2.0,
        "/var": 5.0,
    }

    def run(self) -> PreflightResult:
        warnings = []
        failures = []
        details = {}

        for path, min_gb in self.REQUIREMENTS.items():
            if not os.path.exists(path):
                continue

            stat = os.statvfs(path)
            free_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
            details[path] = {"free_gb": round(free_gb, 2), "required_gb": min_gb}

            if free_gb < min_gb:
                failures.append(f"{path}: {free_gb:.1f}GB free, need {min_gb}GB")
            elif free_gb < min_gb * 2:
                warnings.append(f"{path}: only {free_gb:.1f}GB free")

        if failures:
            return PreflightResult(
                check_name=self.name,
                result=CheckResult.FAIL,
                message="Insufficient disk space",
                details=details,
                remediation="; ".join(failures),
            )

        if warnings:
            return PreflightResult(
                check_name=self.name,
                result=CheckResult.WARN,
                message="Low disk space warning",
                details=details,
            )

        return PreflightResult(
            check_name=self.name,
            result=CheckResult.PASS,
            message="Sufficient disk space available",
            details=details,
        )


class ServiceStatusCheck(PreflightCheck):
    """Check status of critical services."""

    name = "Service Status"
    critical = False

    SERVICES = ["postgresql", "pgbouncer"]

    def run(self) -> PreflightResult:
        statuses = {}

        for service in self.SERVICES:
            statuses[service] = self._check_service(service)

        running = [s for s, status in statuses.items() if status == "running"]
        stopped = [s for s, status in statuses.items() if status == "stopped"]
        missing = [s for s, status in statuses.items() if status == "not_installed"]

        return PreflightResult(
            check_name=self.name,
            result=CheckResult.PASS,
            message=f"Running: {len(running)}, Stopped: {len(stopped)}, Not installed: {len(missing)}",
            details=statuses,
        )

    def _check_service(self, service: str) -> str:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return "running"

            result = subprocess.run(
                ["systemctl", "cat", service],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "stopped" if result.returncode == 0 else "not_installed"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "unknown"


class ConfigPermissionsCheck(PreflightCheck):
    """Verify configuration file permissions are secure."""

    name = "Config Permissions"
    critical = False

    CONFIG_FILES = {
        "/etc/sm/config.yaml": 0o600,
        "/root/.sm/credentials": 0o700,
    }

    def run(self) -> PreflightResult:
        issues = []
        details = {}

        for filepath, expected_perms in self.CONFIG_FILES.items():
            path = Path(filepath)
            if not path.exists():
                details[filepath] = "not_found"
                continue

            actual = path.stat().st_mode & 0o777
            if actual != expected_perms:
                issues.append(
                    f"{filepath}: {oct(actual)} should be {oct(expected_perms)}"
                )
                details[filepath] = {"actual": oct(actual), "expected": oct(expected_perms)}
            else:
                details[filepath] = {"status": "ok", "permissions": oct(actual)}

        if issues:
            return PreflightResult(
                check_name=self.name,
                result=CheckResult.WARN,
                message=f"{len(issues)} permission issue(s)",
                details=details,
                remediation="; ".join(issues),
            )

        return PreflightResult(
            check_name=self.name,
            result=CheckResult.PASS,
            message="Configuration permissions secure",
            details=details,
        )


class PreflightRunner:
    """Orchestrates pre-flight checks."""

    DEFAULT_CHECKS: list[type[PreflightCheck]] = [
        RootCheck,
        OSCompatibilityCheck,
        DiskSpaceCheck,
        ServiceStatusCheck,
        ConfigPermissionsCheck,
    ]

    def __init__(
        self,
        checks: Optional[list[type[PreflightCheck]]] = None,
        skip_root_check: bool = False,
    ) -> None:
        check_classes = checks or self.DEFAULT_CHECKS
        if skip_root_check:
            check_classes = [c for c in check_classes if c != RootCheck]
        self.checks = [c() for c in check_classes]

    def run_all(self, fail_fast: bool = True) -> list[PreflightResult]:
        """Run all pre-flight checks.

        Args:
            fail_fast: If True, stop on first critical failure

        Returns:
            List of all check results
        """
        results = []

        for check in self.checks:
            result = check.run()
            results.append(result)

            if fail_fast and check.critical and result.result == CheckResult.FAIL:
                break

        return results

    def all_passed(self, results: list[PreflightResult]) -> bool:
        """Check if all critical checks passed."""
        return not any(
            r.result == CheckResult.FAIL
            for r in results
        )

    def display_results(self, results: list[PreflightResult]) -> None:
        """Display pre-flight check results."""
        console.print()
        console.rule("Pre-flight Checks")

        for result in results:
            if result.result == CheckResult.PASS:
                status = "[green]PASS[/green]"
            elif result.result == CheckResult.WARN:
                status = "[yellow]WARN[/yellow]"
            elif result.result == CheckResult.FAIL:
                status = "[red]FAIL[/red]"
            else:
                status = "[dim]SKIP[/dim]"

            console.print(f"  {status} {result.check_name}: {result.message}")

            if result.remediation and result.result in (CheckResult.FAIL, CheckResult.WARN):
                console.print(f"        [dim]Fix: {result.remediation}[/dim]")

        console.print()


# Production environment detection
class ProductionDetector:
    """Detects if running in a production environment."""

    PRODUCTION_PATTERNS = [
        r"^prod[-_]",
        r"[-_]prod$",
        r"[-_]production[-_]",
        r"^prd[-_]",
        r"[-_]prd$",
        r"^live[-_]",
        r"[-_]live$",
    ]

    PRODUCTION_ENV_VARS = {
        "ENVIRONMENT": {"production", "prod", "prd", "live"},
        "NODE_ENV": {"production"},
        "RAILS_ENV": {"production"},
        "APP_ENV": {"production", "prod"},
    }

    def __init__(self) -> None:
        self._is_production: Optional[bool] = None
        self._detection_reasons: list[str] = []

    def is_production(self) -> bool:
        """Detect if this is a production environment."""
        if self._is_production is not None:
            return self._is_production

        self._detection_reasons = []

        # Check hostname
        hostname = socket.gethostname().lower()
        for pattern in self.PRODUCTION_PATTERNS:
            if re.search(pattern, hostname, re.IGNORECASE):
                self._detection_reasons.append(f"Hostname matches production pattern: {hostname}")
                break

        # Check environment variables
        for var, prod_values in self.PRODUCTION_ENV_VARS.items():
            env_val = os.environ.get(var, "").lower()
            if env_val in prod_values:
                self._detection_reasons.append(f"Environment variable {var}={env_val}")

        self._is_production = len(self._detection_reasons) > 0
        return self._is_production

    def get_reasons(self) -> list[str]:
        """Return reasons why production was detected."""
        if self._is_production is None:
            self.is_production()
        return self._detection_reasons.copy()


# Protected resources
PROTECTED_DATABASES = frozenset({"postgres", "template0", "template1"})
PROTECTED_USERS = frozenset({"postgres", "pgbouncer", "root"})


# Safety decorators
def require_root(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator that requires root privileges."""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if os.geteuid() != 0:
            console.error("This operation requires root privileges")
            console.hint("Run with: sudo sm <command>")
            raise typer.Exit(6)
        return func(*args, **kwargs)
    return wrapper


def require_force(reason: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that requires --force flag for dangerous operations."""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Look for force in kwargs or first positional arg (context)
            force = kwargs.get("force", False)
            if not force and args:
                ctx = args[0]
                if hasattr(ctx, "force"):
                    force = ctx.force

            if not force:
                console.error(f"Operation blocked: {reason}")
                console.hint("Use --force to proceed with this dangerous operation")
                raise typer.Exit(5)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_confirmation(
    resource_type: str,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator for critical operations requiring name confirmation."""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get context and resource name
            ctx = args[0] if args else None
            name = kwargs.get("name") or kwargs.get("database") or kwargs.get("user")

            if not ctx or not hasattr(ctx, "force"):
                return func(*args, **kwargs)

            if not ctx.force:
                console.error(f"Deleting {resource_type} requires --force flag")
                console.hint(f"Use --force --confirm-name={name} to proceed")
                raise typer.Exit(5)

            if ctx.confirm_name != name:
                console.error("Name confirmation required for critical operation")
                console.hint(f"Use --confirm-name={name} to confirm deletion")
                raise typer.Exit(5)

            return func(*args, **kwargs)
        return wrapper
    return decorator


def check_not_protected_database(name: str) -> None:
    """Check that a database is not a protected system database."""
    if name.lower() in PROTECTED_DATABASES:
        raise SafetyError(
            f"Cannot modify protected system database: {name}",
            hint="System databases (postgres, template0, template1) cannot be modified",
        )


def check_not_protected_user(name: str) -> None:
    """Check that a user is not a protected system user."""
    if name.lower() in PROTECTED_USERS:
        raise SafetyError(
            f"Cannot modify protected system user: {name}",
            hint="System users (postgres, pgbouncer, root) cannot be modified",
        )


def run_preflight_checks(
    skip_on_dry_run: bool = False,
    dry_run: bool = False,
    verbose: bool = False,
) -> bool:
    """Run pre-flight checks and return success status.

    Args:
        skip_on_dry_run: Skip checks in dry-run mode
        dry_run: Whether dry-run mode is enabled
        verbose: Show detailed check results

    Returns:
        True if all checks passed

    Raises:
        PrerequisiteError: If critical checks fail
    """
    if skip_on_dry_run and dry_run:
        console.verbose("Skipping pre-flight checks in dry-run mode")
        return True

    runner = PreflightRunner()
    results = runner.run_all()

    if verbose:
        runner.display_results(results)

    if not runner.all_passed(results):
        failures = [r for r in results if r.result == CheckResult.FAIL]
        details = [f"{r.check_name}: {r.message}" for r in failures]

        raise PrerequisiteError(
            "Pre-flight checks failed",
            details=details,
            hint="Fix the issues above and try again",
        )

    return True
