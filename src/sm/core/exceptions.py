"""Custom exceptions for the Server Management CLI.

All exceptions provide:
- Clear error messages
- Optional hints for resolution
- Optional details for debugging
- Exit codes for proper shell integration
"""

from typing import Optional


class SMError(Exception):
    """Base exception for all server-management errors.

    Attributes:
        message: Human-readable error description
        hint: Suggested action to resolve the error
        details: Additional context for debugging
        exit_code: Shell exit code (1-127)
    """

    exit_code: int = 1

    def __init__(
        self,
        message: str,
        *,
        hint: Optional[str] = None,
        details: Optional[list[str]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.details = details or []

    def __str__(self) -> str:
        return self.message


class ConfigurationError(SMError):
    """Configuration file or settings errors.

    Raised when:
    - Config file not found or unreadable
    - Invalid YAML syntax
    - Missing required configuration values
    - Invalid configuration values
    """
    exit_code = 2


class ValidationError(SMError):
    """Input validation errors.

    Raised when:
    - Invalid PostgreSQL identifiers
    - Invalid CIDR notation
    - Invalid URLs or paths
    - Password doesn't meet requirements
    """
    exit_code = 3


class SafetyError(SMError):
    """Safety check failures.

    Raised when:
    - Dangerous operation attempted without --force
    - Critical operation missing --confirm-name
    - Production environment detected
    - Pre-flight checks fail
    """
    exit_code = 4

    def __init__(
        self,
        message: str,
        *,
        blocked_operation: Optional[str] = None,
        required_flags: Optional[list[str]] = None,
        hint: Optional[str] = None,
        details: Optional[list[str]] = None,
    ) -> None:
        if not hint and required_flags:
            hint = f"Use {' '.join(required_flags)} to proceed"
        super().__init__(message, hint=hint, details=details)
        self.blocked_operation = blocked_operation
        self.required_flags = required_flags or []


class ExecutionError(SMError):
    """Command execution failures.

    Raised when:
    - Shell command returns non-zero exit code
    - SQL statement fails
    - Service operation fails
    """
    exit_code = 5

    def __init__(
        self,
        message: str,
        *,
        command: Optional[str] = None,
        return_code: Optional[int] = None,
        stderr: Optional[str] = None,
        hint: Optional[str] = None,
        details: Optional[list[str]] = None,
    ) -> None:
        if not details:
            details = []
        if return_code is not None:
            details.append(f"Exit code: {return_code}")
        if stderr:
            details.append(f"Error output: {stderr}")
        super().__init__(message, hint=hint, details=details)
        self.command = command
        self.return_code = return_code
        self.stderr = stderr


class PrerequisiteError(SMError):
    """Missing prerequisites.

    Raised when:
    - Required command not found
    - Required package not installed
    - Insufficient permissions
    - Unsupported OS
    - Insufficient disk space
    """
    exit_code = 6


class RollbackError(SMError):
    """Rollback operation failed.

    Raised when:
    - Rollback action fails during error recovery
    - System left in inconsistent state
    """
    exit_code = 7


# Domain-specific exceptions

class PostgresError(SMError):
    """PostgreSQL-specific errors.

    Raised when:
    - Cannot connect to PostgreSQL
    - SQL execution fails
    - Database/user operations fail
    """
    exit_code = 10


class PgBouncerError(SMError):
    """PgBouncer-specific errors.

    Raised when:
    - PgBouncer not installed or running
    - Config file update fails
    - Reload/restart fails
    """
    exit_code = 11


class BackupError(SMError):
    """Backup/restore errors.

    Raised when:
    - pgBackRest operation fails
    - B2/S3 connectivity issues
    - Backup verification fails
    """
    exit_code = 12


class ServiceError(SMError):
    """Systemd service errors.

    Raised when:
    - Service not found
    - Start/stop/restart fails
    - Status check fails
    """
    exit_code = 13


class CredentialError(SMError):
    """Credential management errors.

    Raised when:
    - Password file has wrong permissions
    - Cannot write credential file
    - Cannot read credential file
    """
    exit_code = 14


class FirewallError(SMError):
    """Firewall/iptables errors.

    Raised when:
    - iptables command fails
    - Rule validation fails
    - Cannot persist rules
    - Docker chain operations fail
    """
    exit_code = 15

    def __init__(
        self,
        message: str,
        *,
        rule: Optional[str] = None,
        chain: Optional[str] = None,
        hint: Optional[str] = None,
        details: Optional[list[str]] = None,
    ) -> None:
        super().__init__(message, hint=hint, details=details)
        self.rule = rule
        self.chain = chain


class MongoDBError(SMError):
    """MongoDB-specific errors.

    Raised when:
    - Cannot connect to MongoDB
    - mongosh execution fails
    - Database/user operations fail
    """
    exit_code = 16


class ProxyError(SMError):
    """Proxy-specific errors.

    Raised when:
    - OpenResty installation fails
    - Nginx configuration is invalid
    - API key operations fail
    - Endpoint management fails
    """
    exit_code = 17
