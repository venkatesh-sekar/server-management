"""Core framework components for the Server Management CLI."""

from sm.core.exceptions import (
    SMError,
    ConfigurationError,
    ValidationError,
    SafetyError,
    ExecutionError,
    PrerequisiteError,
    PostgresError,
    PgBouncerError,
    BackupError,
    CredentialError,
    ServiceError,
    RollbackError,
    FirewallError,
    MongoDBError,
    ProxyError,
)

from sm.core.context import ExecutionContext, create_context
from sm.core.output import console, Console, Verbosity
from sm.core.config import AppConfig, MachineConfig
from sm.core.safety import (
    DangerLevel,
    PreflightRunner,
    ProductionDetector,
    require_root,
    require_force,
    run_preflight_checks,
    check_not_protected_database,
    check_not_protected_user,
)
from sm.core.credentials import CredentialManager, get_credential_manager
from sm.core.audit import AuditLogger, AuditEvent, AuditEventType, AuditResult, get_audit_logger
from sm.core.executor import CommandExecutor, RollbackStack

__all__ = [
    # Exceptions
    "SMError",
    "ConfigurationError",
    "ValidationError",
    "SafetyError",
    "ExecutionError",
    "PrerequisiteError",
    "PostgresError",
    "PgBouncerError",
    "BackupError",
    "CredentialError",
    "ServiceError",
    "RollbackError",
    "FirewallError",
    "MongoDBError",
    "ProxyError",
    # Context
    "ExecutionContext",
    "create_context",
    # Output
    "console",
    "Console",
    "Verbosity",
    # Config
    "AppConfig",
    "MachineConfig",
    # Safety
    "DangerLevel",
    "PreflightRunner",
    "ProductionDetector",
    "require_root",
    "require_force",
    "run_preflight_checks",
    "check_not_protected_database",
    "check_not_protected_user",
    # Credentials
    "CredentialManager",
    "get_credential_manager",
    # Audit
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "AuditResult",
    "get_audit_logger",
    # Executor
    "CommandExecutor",
    "RollbackStack",
]
