"""Configuration management using Pydantic.

Provides:
- Typed configuration models with validation
- YAML file loading with defaults
- Environment variable overrides for secrets
- Configuration initialization and display
"""

import os
from pathlib import Path
from typing import Optional, Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings

from sm.core.exceptions import ConfigurationError
from sm.core.validation import validate_port, validate_cidr, validate_url


# Default configuration paths
DEFAULT_CONFIG_PATH = Path("/etc/sm/config.yaml")
DEFAULT_CREDENTIALS_DIR = Path("/root/.sm/credentials")
DEFAULT_LOG_DIR = Path("/var/log/sm")


class PostgresConfig(BaseModel):
    """PostgreSQL configuration."""

    version: str = "18"
    host: str = "127.0.0.1"
    port: int = 5432
    data_dir: Optional[Path] = None

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        valid_versions = {"14", "15", "16", "17", "18"}
        if v not in valid_versions:
            raise ValueError(f"PostgreSQL version must be one of: {sorted(valid_versions)}")
        return v

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        return validate_port(v)


class PgBouncerConfig(BaseModel):
    """PgBouncer connection pooler configuration."""

    enabled: bool = True
    port: int = 6432
    listen_addr: str = "0.0.0.0"
    pool_mode: str = "transaction"
    max_client_conn: int = 1000
    default_pool_size: int = 20

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        return validate_port(v)

    @field_validator("pool_mode")
    @classmethod
    def validate_pool_mode(cls, v: str) -> str:
        valid_modes = {"session", "transaction", "statement"}
        if v not in valid_modes:
            raise ValueError(f"Pool mode must be one of: {sorted(valid_modes)}")
        return v


class BackupConfig(BaseModel):
    """Backup configuration for pgBackRest with B2/S3 storage."""

    enabled: bool = True

    # S3-compatible storage settings
    s3_endpoint: Optional[str] = None
    s3_region: Optional[str] = None
    s3_bucket: Optional[str] = None
    repo_path: str = "/pgbackrest"

    # Retention settings
    retention_full: int = 53  # weeks
    retention_archive: int = 60  # days

    # Schedule flags
    hourly_incr: bool = True
    daily_diff: bool = True
    weekly_full: bool = True

    @field_validator("repo_path")
    @classmethod
    def validate_repo_path(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("repo_path must start with /")
        return v


class ExportConfig(BaseModel):
    """Configuration for pg_dump exports (separate from pgBackRest).

    These exports use a separate S3 path to avoid conflicts with
    pgBackRest continuous backups.
    """

    # S3 path prefix - MUST be different from pgBackRest repo_path
    export_path: str = "/pg-exports"  # Results in s3://bucket/pg-exports/

    # Compression level for pg_dump (0-9, 0=none)
    compression_level: int = 6

    # Encrypt exports using same passphrase as pgBackRest
    encrypt: bool = True

    @field_validator("export_path")
    @classmethod
    def validate_export_path(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("export_path must start with /")
        # CRITICAL: Must not conflict with pgBackRest path
        if v.startswith("/pgbackrest"):
            raise ValueError("export_path cannot use /pgbackrest (reserved for pgBackRest)")
        return v

    @field_validator("compression_level")
    @classmethod
    def validate_compression_level(cls, v: int) -> int:
        if not 0 <= v <= 9:
            raise ValueError("compression_level must be between 0 and 9")
        return v


class SecurityConfig(BaseModel):
    """Security hardening configuration."""

    fail2ban_enabled: bool = True
    fail2ban_bantime: str = "10m"
    fail2ban_maxretry: int = 5
    fail2ban_findtime: str = "10m"

    auditd_enabled: bool = True
    unattended_upgrades: bool = True


class ObservabilityConfig(BaseModel):
    """Observability/monitoring configuration."""

    enabled: bool = True
    otel_version: str = "0.104.0"
    otlp_endpoint: Optional[str] = None
    collection_interval: str = "10s"

    @field_validator("otlp_endpoint")
    @classmethod
    def validate_endpoint(cls, v: Optional[str]) -> Optional[str]:
        if v:
            return validate_url(v)
        return v


class MachineConfig(BaseModel):
    """Root configuration model for a single machine.

    This is the main configuration loaded from /etc/sm/config.yaml.
    Secrets are NOT stored in this file - they come from environment variables.
    """

    # Machine identity
    hostname: Optional[str] = None
    environment: str = "development"

    # Feature sections
    postgres: PostgresConfig = Field(default_factory=PostgresConfig)
    pgbouncer: PgBouncerConfig = Field(default_factory=PgBouncerConfig)
    backup: BackupConfig = Field(default_factory=BackupConfig)
    export: ExportConfig = Field(default_factory=ExportConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        valid_envs = {"development", "staging", "production"}
        if v not in valid_envs:
            raise ValueError(f"Environment must be one of: {sorted(valid_envs)}")
        return v

    @classmethod
    def load(cls, path: Path) -> "MachineConfig":
        """Load configuration from YAML file.

        Args:
            path: Path to configuration file

        Returns:
            Loaded configuration

        Raises:
            ConfigurationError: If file not found or invalid
        """
        if not path.exists():
            raise ConfigurationError(
                f"Configuration file not found: {path}",
                hint=f"Create it with: sm config init",
            )

        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigurationError(
                f"Invalid YAML in configuration file: {path}",
                details=[str(e)],
            ) from e
        except PermissionError:
            raise ConfigurationError(
                f"Cannot read configuration file: {path}",
                hint="Check file permissions or run with sudo",
            )

        try:
            return cls(**data)
        except Exception as e:
            raise ConfigurationError(
                f"Invalid configuration: {e}",
                details=[str(e)],
            ) from e

    @classmethod
    def load_or_default(cls, path: Optional[Path] = None) -> "MachineConfig":
        """Load configuration, falling back to defaults if file doesn't exist.

        Args:
            path: Path to configuration file (uses default if None)

        Returns:
            Loaded or default configuration
        """
        if path is None:
            path = DEFAULT_CONFIG_PATH

        if path.exists():
            return cls.load(path)
        return cls()

    def to_yaml(self) -> str:
        """Convert configuration to YAML string."""
        data = self.model_dump(exclude_none=True)
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


class SecretsConfig(BaseSettings):
    """Secrets loaded from environment variables.

    These are NEVER stored in config files.
    """

    # B2/S3 credentials
    sm_b2_key: Optional[str] = Field(None, alias="SM_B2_KEY")
    sm_b2_secret: Optional[str] = Field(None, alias="SM_B2_SECRET")
    sm_backup_passphrase: Optional[str] = Field(None, alias="SM_BACKUP_PASSPHRASE")

    # PostgreSQL superuser password (for initial setup)
    sm_pg_superuser_pass: Optional[str] = Field(None, alias="SM_PG_SUPERUSER_PASS")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


class AppConfig:
    """Application configuration combining config file and secrets.

    This is the main interface for accessing configuration throughout the app.
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        config: Optional[MachineConfig] = None,
    ) -> None:
        """Initialize application configuration.

        Args:
            config_path: Path to config file (uses default if None)
            config: Pre-loaded config (skips file loading if provided)
        """
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self._config = config or MachineConfig.load_or_default(self.config_path)
        self._secrets = SecretsConfig()

    @property
    def config(self) -> MachineConfig:
        """Get the machine configuration."""
        return self._config

    @property
    def secrets(self) -> SecretsConfig:
        """Get the secrets configuration."""
        return self._secrets

    @property
    def postgres(self) -> PostgresConfig:
        """Shortcut to PostgreSQL config."""
        return self._config.postgres

    @property
    def pgbouncer(self) -> PgBouncerConfig:
        """Shortcut to PgBouncer config."""
        return self._config.pgbouncer

    @property
    def backup(self) -> BackupConfig:
        """Shortcut to backup config."""
        return self._config.backup

    @property
    def export(self) -> ExportConfig:
        """Shortcut to export config."""
        return self._config.export

    @property
    def security(self) -> SecurityConfig:
        """Shortcut to security config."""
        return self._config.security

    @property
    def observability(self) -> ObservabilityConfig:
        """Shortcut to observability config."""
        return self._config.observability

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self._config.environment == "production"

    @property
    def credentials_dir(self) -> Path:
        """Get credentials storage directory."""
        return DEFAULT_CREDENTIALS_DIR

    @property
    def log_dir(self) -> Path:
        """Get log directory."""
        return DEFAULT_LOG_DIR

    def has_backup_credentials(self) -> bool:
        """Check if backup credentials are configured."""
        return bool(
            self._secrets.sm_b2_key
            and self._secrets.sm_b2_secret
            and self._secrets.sm_backup_passphrase
        )


def get_example_config() -> str:
    """Generate example configuration file content."""
    return """# Server Management Configuration
# Single configuration file per machine
# Secrets are loaded from environment variables, NOT stored here

# Machine identity (optional - auto-detected if not set)
# hostname: db-prod-01
environment: development  # development, staging, production

# PostgreSQL settings
postgres:
  version: "18"
  host: 127.0.0.1
  port: 5432

# PgBouncer connection pooler
pgbouncer:
  enabled: true
  port: 6432
  pool_mode: transaction  # session, transaction, statement
  max_client_conn: 1000
  default_pool_size: 20

# Backup configuration (pgBackRest + B2/S3)
backup:
  enabled: true
  s3_endpoint: s3.us-west-004.backblazeb2.com
  s3_region: us-west-004
  s3_bucket: my-backups
  repo_path: /pgbackrest
  retention_full: 53  # weeks
  retention_archive: 60  # days
  # Credentials from environment:
  #   SM_B2_KEY, SM_B2_SECRET, SM_BACKUP_PASSPHRASE

# Export configuration (pg_dump to S3)
# Uses separate path from pgBackRest to avoid conflicts
export:
  export_path: /pg-exports  # s3://bucket/pg-exports/
  compression_level: 6  # 0-9
  encrypt: true

# Security hardening
security:
  fail2ban_enabled: true
  fail2ban_bantime: 10m
  fail2ban_maxretry: 5
  auditd_enabled: true
  unattended_upgrades: true

# Observability (OpenTelemetry)
observability:
  enabled: true
  otel_version: "0.104.0"
  otlp_endpoint: http://signoz.example.com:4318
"""


def init_config(path: Path, force: bool = False) -> None:
    """Initialize a new configuration file.

    Args:
        path: Path to create config file
        force: Overwrite if exists

    Raises:
        ConfigurationError: If file exists and force is False
    """
    if path.exists() and not force:
        raise ConfigurationError(
            f"Configuration file already exists: {path}",
            hint="Use --force to overwrite",
        )

    # Create parent directories
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write example config
    content = get_example_config()
    path.write_text(content)

    # Set secure permissions
    os.chmod(path, 0o600)
