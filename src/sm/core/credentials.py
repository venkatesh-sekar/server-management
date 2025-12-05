"""Secure credential management.

Provides:
- Cryptographically secure password generation
- Secure file storage with proper permissions
- Atomic writes with temp files
- Secure deletion (overwrite before unlink)
- Backup before rotation
"""

import contextlib
import os
import secrets
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Generator, Optional

from sm.core.exceptions import CredentialError
from sm.core.validation import generate_password, PASSWORD_ALPHABET
from sm.core.output import console


# Default paths
DEFAULT_CREDENTIALS_DIR = Path("/root/.sm/credentials")
DEFAULT_BACKUP_DIR = Path("/root/.sm/credentials/backups")

# File permission constants
SECURE_FILE_PERMS = 0o600
SECURE_DIR_PERMS = 0o700


class CredentialManager:
    """Manages credentials with security best practices.

    Features:
    - Cryptographically secure password generation
    - Atomic writes using temp file + rename
    - Strict file permissions (600)
    - Secure temp file cleanup
    - Backup before rotation
    """

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        backup_dir: Optional[Path] = None,
    ) -> None:
        """Initialize credential manager.

        Args:
            storage_dir: Directory for credential storage
            backup_dir: Directory for credential backups
        """
        self.storage_dir = storage_dir or DEFAULT_CREDENTIALS_DIR
        self.backup_dir = backup_dir or DEFAULT_BACKUP_DIR

    def ensure_directories(self) -> None:
        """Ensure credential directories exist with secure permissions."""
        for directory in [self.storage_dir, self.backup_dir]:
            if not directory.exists():
                directory.mkdir(parents=True, mode=SECURE_DIR_PERMS)
            else:
                # Fix permissions if wrong
                current_perms = directory.stat().st_mode & 0o777
                if current_perms != SECURE_DIR_PERMS:
                    os.chmod(directory, SECURE_DIR_PERMS)

    def get_password_path(
        self,
        username: str,
        database: Optional[str] = None,
    ) -> Path:
        """Get the path for a password file.

        Args:
            username: PostgreSQL username
            database: Optional database name (for database-specific passwords)

        Returns:
            Path to the password file
        """
        db_part = database if database else "_global"
        filename = f"pg_{db_part}_{username}.pass"
        return self.storage_dir / filename

    def generate_password(self, length: int = 32) -> str:
        """Generate a cryptographically secure password.

        Args:
            length: Password length (minimum 16)

        Returns:
            Generated password
        """
        return generate_password(length)

    def store_password(
        self,
        password: str,
        username: str,
        database: Optional[str] = None,
        dry_run: bool = False,
    ) -> Path:
        """Securely store a password to file.

        Uses atomic write (temp file + rename) and sets strict permissions.

        Args:
            password: Password to store
            username: PostgreSQL username
            database: Optional database name
            dry_run: If True, don't actually write

        Returns:
            Path to stored password file
        """
        filepath = self.get_password_path(username, database)

        if dry_run:
            console.dry_run_msg(f"Store password to {filepath}")
            return filepath

        self.ensure_directories()

        # Atomic write using temp file
        with self._secure_temp_file(self.storage_dir) as tmp_path:
            # Write password
            tmp_path.write_text(password + "\n")

            # Set permissions BEFORE moving
            os.chmod(tmp_path, SECURE_FILE_PERMS)

            # Atomic rename
            shutil.move(str(tmp_path), str(filepath))

        # Verify permissions after write
        self._verify_permissions(filepath)

        console.debug(f"Password stored: {filepath}")
        return filepath

    def load_password(
        self,
        username: str,
        database: Optional[str] = None,
    ) -> Optional[str]:
        """Load a password from secure storage.

        Args:
            username: PostgreSQL username
            database: Optional database name

        Returns:
            Password string, or None if not found

        Raises:
            CredentialError: If file has insecure permissions
        """
        filepath = self.get_password_path(username, database)

        if not filepath.exists():
            return None

        # Verify permissions before reading
        self._verify_permissions(filepath)

        return filepath.read_text().strip()

    def password_exists(
        self,
        username: str,
        database: Optional[str] = None,
    ) -> bool:
        """Check if a password file exists.

        Args:
            username: PostgreSQL username
            database: Optional database name

        Returns:
            True if password file exists
        """
        return self.get_password_path(username, database).exists()

    def ensure_password(
        self,
        username: str,
        database: Optional[str] = None,
        force_rotate: bool = False,
        dry_run: bool = False,
    ) -> tuple[str, bool]:
        """Ensure a password exists, generating if needed.

        Args:
            username: PostgreSQL username
            database: Optional database name
            force_rotate: Force new password generation
            dry_run: If True, don't actually write

        Returns:
            Tuple of (password, was_generated)
        """
        if not force_rotate:
            existing = self.load_password(username, database)
            if existing:
                return existing, False

        # Generate and store new password
        password = self.generate_password()

        if dry_run:
            console.dry_run_msg(f"Generate new password for {username}")
            return password, True

        self.store_password(password, username, database)
        return password, True

    def rotate_password(
        self,
        username: str,
        database: Optional[str] = None,
        dry_run: bool = False,
    ) -> tuple[str, Optional[Path]]:
        """Rotate a password, backing up the old one.

        Args:
            username: PostgreSQL username
            database: Optional database name
            dry_run: If True, don't actually write

        Returns:
            Tuple of (new_password, backup_path or None)
        """
        filepath = self.get_password_path(username, database)

        # Backup existing password if it exists
        backup_path = None
        if filepath.exists() and not dry_run:
            backup_path = self.backup_password(username, database)

        # Generate new password
        new_password = self.generate_password()

        if dry_run:
            console.dry_run_msg(f"Rotate password for {username}")
            return new_password, None

        # Store new password
        self.store_password(new_password, username, database)

        return new_password, backup_path

    def backup_password(
        self,
        username: str,
        database: Optional[str] = None,
    ) -> Optional[Path]:
        """Create a backup of an existing password file.

        Args:
            username: PostgreSQL username
            database: Optional database name

        Returns:
            Path to backup file, or None if no password exists
        """
        filepath = self.get_password_path(username, database)

        if not filepath.exists():
            return None

        self.ensure_directories()

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_name = f"{filepath.name}.{timestamp}"
        backup_path = self.backup_dir / backup_name

        # Copy with same permissions
        shutil.copy2(filepath, backup_path)
        os.chmod(backup_path, SECURE_FILE_PERMS)

        console.debug(f"Password backed up: {backup_path}")
        return backup_path

    def delete_password(
        self,
        username: str,
        database: Optional[str] = None,
        secure: bool = True,
        dry_run: bool = False,
    ) -> bool:
        """Delete a password file.

        Args:
            username: PostgreSQL username
            database: Optional database name
            secure: If True, overwrite before deleting
            dry_run: If True, don't actually delete

        Returns:
            True if file was deleted
        """
        filepath = self.get_password_path(username, database)

        if not filepath.exists():
            return False

        if dry_run:
            console.dry_run_msg(f"Delete password file: {filepath}")
            return True

        if secure:
            self._secure_delete(filepath)
        else:
            filepath.unlink()

        console.debug(f"Password deleted: {filepath}")
        return True

    def list_passwords(self) -> list[dict[str, str]]:
        """List all stored passwords.

        Returns:
            List of dicts with username, database, path keys
        """
        if not self.storage_dir.exists():
            return []

        passwords = []
        for path in self.storage_dir.glob("pg_*.pass"):
            # Parse filename: pg_{database}_{username}.pass
            parts = path.stem.split("_", 2)
            if len(parts) >= 3:
                database = parts[1] if parts[1] != "_global" else None
                username = parts[2]
                passwords.append({
                    "username": username,
                    "database": database,
                    "path": str(path),
                })

        return passwords

    @contextlib.contextmanager
    def _secure_temp_file(
        self,
        directory: Path,
    ) -> Generator[Path, None, None]:
        """Create a secure temporary file with cleanup.

        Args:
            directory: Directory to create temp file in

        Yields:
            Path to temporary file
        """
        # Generate random filename
        random_suffix = secrets.token_hex(16)
        tmp_path = directory / f".tmp_{random_suffix}"

        try:
            # Create with secure permissions
            fd = os.open(
                tmp_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                SECURE_FILE_PERMS,
            )
            os.close(fd)

            yield tmp_path

        except Exception:
            # Clean up on any error
            if tmp_path.exists():
                try:
                    self._secure_delete(tmp_path)
                except OSError:
                    pass
            raise

    def _verify_permissions(self, filepath: Path) -> None:
        """Verify file has secure permissions.

        Args:
            filepath: Path to check

        Raises:
            CredentialError: If permissions are insecure
        """
        st = filepath.stat()
        mode = st.st_mode

        # Check not world/group readable
        if mode & stat.S_IRWXG or mode & stat.S_IRWXO:
            raise CredentialError(
                f"Insecure permissions on {filepath}: {oct(mode & 0o777)}",
                hint=f"Fix with: chmod 600 {filepath}",
            )

    def _secure_delete(self, filepath: Path) -> None:
        """Securely delete a file by overwriting before unlinking.

        Args:
            filepath: Path to delete
        """
        try:
            size = filepath.stat().st_size
            if size > 0:
                # Overwrite with random data
                with open(filepath, "wb") as f:
                    f.write(secrets.token_bytes(size))
                    f.flush()
                    os.fsync(f.fileno())
        except (OSError, IOError):
            pass  # Best effort

        try:
            filepath.unlink()
        except OSError:
            pass


class AtomicFileWriter:
    """Atomic file writer using temp file and rename.

    Ensures file is either completely written or not modified at all.
    """

    def __init__(
        self,
        target_path: Path,
        permissions: int = SECURE_FILE_PERMS,
        owner_uid: Optional[int] = None,
        owner_gid: Optional[int] = None,
    ) -> None:
        """Initialize atomic writer.

        Args:
            target_path: Final destination path
            permissions: File permissions to set
            owner_uid: Owner UID (optional)
            owner_gid: Owner GID (optional)
        """
        self.target_path = Path(target_path)
        self.permissions = permissions
        self.owner_uid = owner_uid
        self.owner_gid = owner_gid

    @contextlib.contextmanager
    def open(self, mode: str = "w") -> Generator:
        """Open for atomic writing.

        Usage:
            with AtomicFileWriter(path).open() as f:
                f.write("content")
            # File is atomically replaced here
        """
        # Ensure parent directory exists
        self.target_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)

        # Create temp file in same directory for atomic rename
        random_suffix = secrets.token_hex(8)
        tmp_path = self.target_path.with_suffix(f".tmp_{random_suffix}")

        success = False
        fd = None

        try:
            # Create with secure permissions
            fd = os.open(
                tmp_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                self.permissions,
            )

            with os.fdopen(fd, mode) as f:
                fd = None  # fdopen takes ownership
                yield f
                f.flush()
                os.fsync(f.fileno())

            # Set ownership if specified
            if self.owner_uid is not None:
                os.chown(
                    tmp_path,
                    self.owner_uid,
                    self.owner_gid or self.owner_uid,
                )

            # Atomic rename
            os.rename(tmp_path, self.target_path)
            success = True

        finally:
            if fd is not None:
                os.close(fd)
            if not success and tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass


# Global credential manager instance
_credential_manager: Optional[CredentialManager] = None


def get_credential_manager() -> CredentialManager:
    """Get or create global credential manager."""
    global _credential_manager
    if _credential_manager is None:
        _credential_manager = CredentialManager()
    return _credential_manager
