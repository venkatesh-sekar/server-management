"""Migration session service for coordinating cross-host database migrations.

Provides a session-based coordination mechanism using S3 as the sole
communication channel between source and target hosts. No SSH required.

Session flow:
1. TARGET creates session with a short code (e.g., "XK7M2P")
2. SOURCE joins session using the code
3. SOURCE exports database and uploads to S3
4. TARGET polls for completion, downloads, and imports
"""

import secrets
import socket
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sm.core.context import ExecutionContext
from sm.core.exceptions import BackupError
from sm.core.output import console
from sm.services.s3 import S3Service

# Session status values
STATUS_WAITING = "waiting_for_export"
STATUS_EXPORTING = "exporting"
STATUS_EXPORTED = "exported"
STATUS_IMPORTING = "importing"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_EXPIRED = "expired"


@dataclass
class MigrationSession:
    """Migration session data stored in S3."""

    code: str
    database: str
    status: str
    target_host: str
    created_at: str  # ISO format
    expires_at: str  # ISO format
    source_host: str | None = None
    export_started_at: str | None = None
    export_completed_at: str | None = None
    import_started_at: str | None = None
    import_completed_at: str | None = None
    dump_key: str | None = None  # S3 key of the dump file
    dump_size: int | None = None  # Size in bytes
    dump_checksum: str | None = None  # SHA256 checksum
    source_row_counts: dict[str, int] = field(default_factory=dict)
    target_row_counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MigrationSession":
        """Create from dictionary."""
        # Handle missing fields with defaults
        return cls(
            code=data["code"],
            database=data["database"],
            status=data["status"],
            target_host=data["target_host"],
            created_at=data["created_at"],
            expires_at=data["expires_at"],
            source_host=data.get("source_host"),
            export_started_at=data.get("export_started_at"),
            export_completed_at=data.get("export_completed_at"),
            import_started_at=data.get("import_started_at"),
            import_completed_at=data.get("import_completed_at"),
            dump_key=data.get("dump_key"),
            dump_size=data.get("dump_size"),
            dump_checksum=data.get("dump_checksum"),
            source_row_counts=data.get("source_row_counts", {}),
            target_row_counts=data.get("target_row_counts", {}),
            error=data.get("error"),
        )

    def is_expired(self) -> bool:
        """Check if session has expired."""
        expires = datetime.fromisoformat(self.expires_at)
        return datetime.now(timezone.utc) > expires

    def time_remaining(self) -> str:
        """Get human-readable time remaining."""
        expires = datetime.fromisoformat(self.expires_at)
        remaining = expires - datetime.now(timezone.utc)

        if remaining.total_seconds() <= 0:
            return "expired"

        minutes = int(remaining.total_seconds() / 60)
        if minutes < 60:
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        hours = minutes // 60
        return f"{hours} hour{'s' if hours != 1 else ''}"


class MigrationSessionService:
    """Manages migration sessions via S3.

    Sessions are stored as JSON files in S3:
        pg-migrations/sessions/{CODE}/session.json

    The dump file is stored alongside:
        pg-migrations/sessions/{CODE}/{database}.dump
        pg-migrations/sessions/{CODE}/{database}.sha256
    """

    SESSION_PREFIX = "pg-migrations/sessions"

    # Code characters - excludes I/O/1/0 to avoid confusion
    CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    CODE_LENGTH = 6

    # Default session expiry
    DEFAULT_EXPIRY_HOURS = 1

    def __init__(self, ctx: ExecutionContext, s3: S3Service) -> None:
        """Initialize session service.

        Args:
            ctx: Execution context
            s3: Configured S3 service
        """
        self.ctx = ctx
        self.s3 = s3

    def _get_session_key(self, code: str) -> str:
        """Get S3 key for session metadata."""
        return f"{self.SESSION_PREFIX}/{code}/session.json"

    def get_dump_key(self, code: str, database: str) -> str:
        """Get S3 key for database dump.

        Args:
            code: Session code
            database: Database name

        Returns:
            S3 key for the dump file
        """
        return f"{self.SESSION_PREFIX}/{code}/{database}.dump"

    def _get_checksum_key(self, code: str, database: str) -> str:
        """Get S3 key for checksum file."""
        return f"{self.SESSION_PREFIX}/{code}/{database}.sha256"

    def generate_code(self) -> str:
        """Generate a unique session code.

        Returns:
            6-character alphanumeric code (e.g., "XK7M2P")
        """
        return "".join(secrets.choice(self.CODE_CHARS) for _ in range(self.CODE_LENGTH))

    def create_session(
        self,
        database: str,
        *,
        expiry_hours: int = DEFAULT_EXPIRY_HOURS,
    ) -> MigrationSession:
        """Create a new migration session (TARGET role).

        Args:
            database: Target database name
            expiry_hours: Hours until session expires

        Returns:
            Created MigrationSession

        Raises:
            BackupError: If session creation fails
        """
        # Generate unique code
        code = self.generate_code()

        # Ensure code doesn't already exist (very unlikely)
        session_key = self._get_session_key(code)
        if self.s3.object_exists(session_key):
            # Try again with new code
            code = self.generate_code()
            session_key = self._get_session_key(code)

        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=expiry_hours)

        session = MigrationSession(
            code=code,
            database=database,
            status=STATUS_WAITING,
            target_host=socket.gethostname(),
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
        )

        # Write to S3
        if self.ctx.dry_run:
            console.dry_run_msg(f"Would create session {code}")
        else:
            self.s3.upload_json(session_key, session.to_dict())

        return session

    def get_session(self, code: str) -> MigrationSession | None:
        """Retrieve session by code.

        Args:
            code: 6-character session code

        Returns:
            MigrationSession if found, None otherwise
        """
        code = code.upper().strip()

        if len(code) != self.CODE_LENGTH:
            return None

        session_key = self._get_session_key(code)

        if not self.s3.object_exists(session_key):
            return None

        try:
            data = self.s3.download_json(session_key)
            return MigrationSession.from_dict(data)
        except BackupError:
            return None

    def update_session(self, session: MigrationSession) -> None:
        """Update session metadata in S3.

        Args:
            session: Session to update
        """
        session_key = self._get_session_key(session.code)
        self.s3.upload_json(session_key, session.to_dict())

    def validate_for_export(self, session: MigrationSession) -> None:
        """Validate session is ready for export (SOURCE role).

        Args:
            session: Session to validate

        Raises:
            BackupError: If session is not valid for export
        """
        if session.is_expired():
            raise BackupError(
                f"Session '{session.code}' has expired",
                hint="Create a new session on the target host",
            )

        if session.status == STATUS_EXPORTED:
            raise BackupError(
                f"Session '{session.code}' has already been exported",
                hint="The target host should now import the database",
            )

        if session.status == STATUS_EXPORTING:
            raise BackupError(
                f"Session '{session.code}' is currently being exported",
                hint="Wait for the current export to complete or create a new session",
            )

        if session.status not in (STATUS_WAITING,):
            raise BackupError(
                f"Cannot export: session status is '{session.status}'",
                hint="Session may have been cancelled or already completed",
            )

    def validate_for_import(self, session: MigrationSession) -> None:
        """Validate session is ready for import (TARGET role).

        Args:
            session: Session to validate

        Raises:
            BackupError: If session is not valid for import
        """
        if session.status != STATUS_EXPORTED:
            raise BackupError(
                f"Cannot import: session status is '{session.status}'",
                hint="Wait for source to complete export",
            )

        if not session.dump_key:
            raise BackupError(
                "Export completed but dump file location is missing",
                hint="This shouldn't happen - try creating a new session",
            )

    def wait_for_export(
        self,
        code: str,
        *,
        poll_interval: int = 10,
        timeout: int = 3600,
    ) -> MigrationSession:
        """Poll until session status changes from waiting_for_export.

        Args:
            code: Session code to monitor
            poll_interval: Seconds between polls
            timeout: Maximum seconds to wait

        Returns:
            Updated MigrationSession

        Raises:
            BackupError: If timeout or error occurs
            KeyboardInterrupt: If user cancels
        """
        start_time = time.time()
        last_status = None

        while True:
            elapsed = time.time() - start_time

            if elapsed > timeout:
                raise BackupError(
                    f"Timed out waiting for source to export (waited {timeout // 60} minutes)",
                    hint="The source may not have started. Check the source host.",
                )

            session = self.get_session(code)

            if session is None:
                raise BackupError(
                    f"Session '{code}' not found",
                    hint="The session may have been deleted",
                )

            if session.is_expired():
                raise BackupError(
                    f"Session '{code}' has expired",
                    hint="Create a new session on the target host",
                )

            # Check for status changes
            if session.status != last_status:
                last_status = session.status

                if session.status == STATUS_EXPORTING:
                    console.info("Source has started exporting...")
                elif session.status == STATUS_EXPORTED:
                    console.success("Export complete!")
                    return session
                elif session.status == STATUS_FAILED:
                    raise BackupError(
                        f"Export failed: {session.error or 'Unknown error'}",
                        hint="Check the source host for details",
                    )

            # Sleep before next poll
            time.sleep(poll_interval)

    def cleanup_session(self, code: str) -> int:
        """Delete all S3 objects for a session.

        Args:
            code: Session code

        Returns:
            Number of objects deleted
        """
        prefix = f"{self.SESSION_PREFIX}/{code}/"
        return self.s3.delete_prefix(prefix)

    def get_session_prefix(self, code: str) -> str:
        """Get S3 prefix for session files.

        Args:
            code: Session code

        Returns:
            S3 prefix string
        """
        return f"{self.SESSION_PREFIX}/{code}/"
