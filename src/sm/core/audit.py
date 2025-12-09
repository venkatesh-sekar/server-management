"""Audit logging for all operations.

Provides:
- JSON-formatted audit logs
- Operation tracking with correlation IDs
- Sensitive data redaction
- Automatic log rotation
"""

import fcntl
import json
import os
import pwd
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Generator, Optional

from sm.core.output import console


# Default paths
DEFAULT_LOG_PATH = Path("/var/log/sm/audit.log")
DEFAULT_MAX_SIZE_MB = 100
DEFAULT_BACKUP_COUNT = 10


class AuditEventType(Enum):
    """Types of auditable events."""
    # Session events
    SESSION_START = "session.start"
    SESSION_END = "session.end"

    # Database operations
    DATABASE_CREATE = "database.create"
    DATABASE_DROP = "database.drop"
    DATABASE_MODIFY = "database.modify"

    # User operations
    USER_CREATE = "user.create"
    USER_DELETE = "user.delete"
    USER_MODIFY = "user.modify"
    USER_GRANT = "user.grant"
    USER_REVOKE = "user.revoke"
    PASSWORD_ROTATE = "user.password_rotate"

    # Configuration operations
    CONFIG_MODIFY = "config.modify"
    CONFIG_BACKUP = "config.backup"
    CONFIG_RESTORE = "config.restore"

    # Service operations
    SERVICE_START = "service.start"
    SERVICE_STOP = "service.stop"
    SERVICE_RESTART = "service.restart"
    SERVICE_RELOAD = "service.reload"

    # Security events
    SECURITY_PREFLIGHT = "security.preflight"
    SECURITY_BLOCKED = "security.blocked"
    SECURITY_WARNING = "security.warning"

    # Backup operations (pgBackRest scheduled backups)
    BACKUP_CREATE = "backup.create"
    BACKUP_RESTORE = "backup.restore"
    BACKUP_VERIFY = "backup.verify"

    # Export operations (pg_dump manual backups)
    BACKUP_EXPORT = "backup.export"
    BACKUP_EXPORT_DELETE = "backup.export_delete"

    # Restore operations
    RESTORE_FROM_EXPORT = "restore.from_export"
    RESTORE_FROM_BACKUP = "restore.from_backup"

    # Migration operations
    MIGRATE_DATABASE = "migrate.database"
    MIGRATE_CLUSTER = "migrate.cluster"

    # Firewall operations
    FIREWALL_ENABLE = "firewall.enable"
    FIREWALL_DISABLE = "firewall.disable"
    FIREWALL_RULE_ADD = "firewall.rule_add"
    FIREWALL_RULE_REMOVE = "firewall.rule_remove"
    FIREWALL_PRESET_APPLY = "firewall.preset_apply"
    FIREWALL_SAVE = "firewall.save"
    FIREWALL_RESTORE = "firewall.restore"
    FIREWALL_RESET = "firewall.reset"
    FIREWALL_SYNC = "firewall.sync"
    FIREWALL_EXCLUSIVE = "firewall.exclusive"
    FIREWALL_IMPORT = "firewall.import"

    # Extension operations
    EXTENSION_ENABLE = "extension.enable"
    EXTENSION_DISABLE = "extension.disable"


class AuditResult(Enum):
    """Result of an audited operation."""
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    DRY_RUN = "dry_run"
    PARTIAL = "partial"


# Keys that contain sensitive data
SENSITIVE_KEYS = frozenset({
    "password", "secret", "key", "token", "credential",
    "pass", "passwd", "api_key", "access_key", "secret_key",
})


def _sanitize_value(key: str, value: Any) -> Any:
    """Sanitize a value, redacting sensitive data.

    Args:
        key: Parameter key name
        value: Value to sanitize

    Returns:
        Sanitized value
    """
    key_lower = key.lower()

    # Check if key suggests sensitive data
    if any(s in key_lower for s in SENSITIVE_KEYS):
        return "***REDACTED***"

    # Recursively sanitize dicts
    if isinstance(value, dict):
        return {k: _sanitize_value(k, v) for k, v in value.items()}

    # Recursively sanitize lists
    if isinstance(value, list):
        return [_sanitize_value(key, v) for v in value]

    return value


@dataclass
class AuditEvent:
    """Represents a single audit event."""
    event_type: AuditEventType
    result: AuditResult
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Actor information
    actor_uid: int = field(default_factory=os.getuid)
    actor_username: str = field(default_factory=lambda: pwd.getpwuid(os.getuid()).pw_name)
    actor_sudo_user: Optional[str] = field(default_factory=lambda: os.environ.get("SUDO_USER"))

    # Target information
    target_type: Optional[str] = None
    target_name: Optional[str] = None

    # Operation details
    operation: Optional[str] = None
    parameters: dict[str, Any] = field(default_factory=dict)

    # Result details
    message: Optional[str] = None
    error: Optional[str] = None

    # Rollback information
    rollback_possible: bool = False
    rollback_command: Optional[str] = None

    # Correlation
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_type": self.event_type.value,
            "result": self.result.value,
            "timestamp": self.timestamp.isoformat(),
            "actor": {
                "uid": self.actor_uid,
                "username": self.actor_username,
                "sudo_user": self.actor_sudo_user,
            },
            "target": {
                "type": self.target_type,
                "name": self.target_name,
            },
            "operation": self.operation,
            "parameters": {k: _sanitize_value(k, v) for k, v in self.parameters.items()},
            "message": self.message,
            "error": self.error,
            "rollback": {
                "possible": self.rollback_possible,
                "command": self.rollback_command,
            } if self.rollback_possible else None,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """Audit logger for tracking all operations.

    Features:
    - Append-only JSON log file
    - Atomic writes with file locking
    - Automatic log rotation
    - Session and correlation tracking
    """

    def __init__(
        self,
        log_path: Optional[Path] = None,
        max_size_mb: int = DEFAULT_MAX_SIZE_MB,
        backup_count: int = DEFAULT_BACKUP_COUNT,
        enabled: bool = True,
    ) -> None:
        """Initialize audit logger.

        Args:
            log_path: Path to audit log file
            max_size_mb: Maximum log file size before rotation
            backup_count: Number of backup files to keep
            enabled: Whether logging is enabled
        """
        self.log_path = log_path or DEFAULT_LOG_PATH
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.backup_count = backup_count
        self.enabled = enabled

        # Session tracking
        self.session_id = str(uuid.uuid4())
        self._correlation_stack: list[str] = []

    def _ensure_log_directory(self) -> bool:
        """Create log directory with secure permissions.

        Returns:
            True if successful, False otherwise
        """
        try:
            log_dir = self.log_path.parent
            log_dir.mkdir(mode=0o750, parents=True, exist_ok=True)

            if not self.log_path.exists():
                self.log_path.touch(mode=0o640)

            return True
        except (OSError, PermissionError) as e:
            console.debug(f"Cannot create audit log directory: {e}")
            return False

    def log(self, event: AuditEvent) -> None:
        """Log an audit event.

        Args:
            event: Event to log
        """
        if not self.enabled:
            return

        # Add session context
        event.session_id = self.session_id
        if self._correlation_stack:
            event.correlation_id = self._correlation_stack[-1]

        # Serialize event
        log_line = event.to_json() + "\n"

        # Try to write
        if not self._ensure_log_directory():
            return

        try:
            with self._atomic_append() as f:
                f.write(log_line)
        except (OSError, IOError) as e:
            console.debug(f"Failed to write audit log: {e}")
            return

        # Check for rotation
        self._rotate_if_needed()

    @contextmanager
    def _atomic_append(self) -> Generator:
        """Context manager for atomic append with file locking."""
        fd = os.open(
            self.log_path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o640,
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with os.fdopen(fd, "a") as f:
                yield f
                f.flush()
                os.fsync(fd)
        except Exception:
            os.close(fd)
            raise

    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max size."""
        try:
            if self.log_path.stat().st_size > self.max_size_bytes:
                self._rotate_logs()
        except OSError:
            pass

    def _rotate_logs(self) -> None:
        """Rotate log files."""
        # Remove oldest backup
        oldest = self.log_path.with_suffix(f".{self.backup_count}")
        if oldest.exists():
            oldest.unlink()

        # Rotate existing backups
        for i in range(self.backup_count - 1, 0, -1):
            src = self.log_path.with_suffix(f".{i}")
            dst = self.log_path.with_suffix(f".{i + 1}")
            if src.exists():
                src.rename(dst)

        # Move current to .1
        backup = self.log_path.with_suffix(".1")
        self.log_path.rename(backup)

        # Create new log file
        self.log_path.touch(mode=0o640)

    @contextmanager
    def correlation(self, operation: str) -> Generator[str, None, None]:
        """Context manager for correlating related events.

        Usage:
            with audit.correlation("create_database") as corr_id:
                audit.log(event1)
                audit.log(event2)  # Both have same correlation_id
        """
        correlation_id = f"{operation}_{uuid.uuid4().hex[:8]}"
        self._correlation_stack.append(correlation_id)
        try:
            yield correlation_id
        finally:
            self._correlation_stack.pop()

    # Convenience methods
    def log_operation(
        self,
        event_type: AuditEventType,
        result: AuditResult,
        target_type: str,
        target_name: str,
        operation: str,
        parameters: Optional[dict[str, Any]] = None,
        message: Optional[str] = None,
        error: Optional[str] = None,
        rollback_command: Optional[str] = None,
    ) -> None:
        """Log an operation with common fields."""
        event = AuditEvent(
            event_type=event_type,
            result=result,
            target_type=target_type,
            target_name=target_name,
            operation=operation,
            parameters=parameters or {},
            message=message,
            error=error,
            rollback_possible=rollback_command is not None,
            rollback_command=rollback_command,
        )
        self.log(event)

    def log_session_start(self, command: str, args: list[str]) -> None:
        """Log session start."""
        self.log(AuditEvent(
            event_type=AuditEventType.SESSION_START,
            result=AuditResult.SUCCESS,
            operation=command,
            parameters={"args": args},
        ))

    def log_session_end(self, exit_code: int) -> None:
        """Log session end."""
        self.log(AuditEvent(
            event_type=AuditEventType.SESSION_END,
            result=AuditResult.SUCCESS if exit_code == 0 else AuditResult.FAILURE,
            parameters={"exit_code": exit_code},
        ))

    def log_blocked(
        self,
        operation: str,
        reason: str,
        target_type: Optional[str] = None,
        target_name: Optional[str] = None,
    ) -> None:
        """Log a blocked operation."""
        self.log(AuditEvent(
            event_type=AuditEventType.SECURITY_BLOCKED,
            result=AuditResult.BLOCKED,
            target_type=target_type,
            target_name=target_name,
            operation=operation,
            message=reason,
        ))

    def log_success(
        self,
        event_type: AuditEventType,
        target_type: str,
        target_name: str,
        message: Optional[str] = None,
    ) -> None:
        """Log a successful operation."""
        self.log(AuditEvent(
            event_type=event_type,
            result=AuditResult.SUCCESS,
            target_type=target_type,
            target_name=target_name,
            message=message,
        ))

    def log_failure(
        self,
        event_type: AuditEventType,
        target_type: str,
        target_name: str,
        error: str,
    ) -> None:
        """Log a failed operation."""
        self.log(AuditEvent(
            event_type=event_type,
            result=AuditResult.FAILURE,
            target_type=target_type,
            target_name=target_name,
            error=error,
        ))

    def log_dry_run(
        self,
        event_type: AuditEventType,
        target_type: str,
        target_name: str,
        message: Optional[str] = None,
    ) -> None:
        """Log a dry-run operation."""
        self.log(AuditEvent(
            event_type=event_type,
            result=AuditResult.DRY_RUN,
            target_type=target_type,
            target_name=target_name,
            message=message,
        ))


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create global audit logger."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def configure_audit_logger(
    log_path: Optional[Path] = None,
    enabled: bool = True,
) -> AuditLogger:
    """Configure and return the global audit logger."""
    global _audit_logger
    _audit_logger = AuditLogger(log_path=log_path, enabled=enabled)
    return _audit_logger
