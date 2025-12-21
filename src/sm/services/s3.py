"""S3-compatible storage service for backup exports.

Provides a safe interface for S3 operations using the same credentials
as pgBackRest (SM_B2_KEY, SM_B2_SECRET).

Supports:
- Backblaze B2
- AWS S3
- Any S3-compatible storage
"""

import hashlib
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sm.core.context import ExecutionContext
from sm.core.exceptions import BackupError, ConfigurationError
from sm.core.output import console


@dataclass
class S3ObjectInfo:
    """Information about an S3 object."""

    key: str
    size: int
    last_modified: datetime
    etag: str

    @property
    def name(self) -> str:
        """Get the object name (last part of key)."""
        return self.key.rsplit("/", 1)[-1]


@dataclass
class S3Config:
    """S3 connection configuration."""

    endpoint: str
    region: str
    bucket: str
    access_key: str
    secret_key: str

    def validate(self) -> None:
        """Validate configuration is complete.

        Raises:
            ConfigurationError: If any required fields are missing
        """
        missing = []
        if not self.endpoint:
            missing.append("s3_endpoint")
        if not self.region:
            missing.append("s3_region")
        if not self.bucket:
            missing.append("s3_bucket")
        if not self.access_key:
            missing.append("SM_B2_KEY")
        if not self.secret_key:
            missing.append("SM_B2_SECRET")

        if missing:
            raise ConfigurationError(
                f"Missing S3 configuration: {', '.join(missing)}",
                hint="Set these in config.yaml or environment variables",
            )


# Progress callback type: (bytes_transferred, total_bytes) -> None
ProgressCallback = Callable[[int, int], None]


class S3Service:
    """S3-compatible storage service for exports.

    Uses the same credentials as pgBackRest for consistency.
    All operations respect dry-run mode.

    Features:
    - Streaming upload/download for large files
    - Progress reporting
    - Checksum verification
    - Automatic retries
    """

    def __init__(self, ctx: ExecutionContext, config: S3Config) -> None:
        """Initialize S3 service.

        Args:
            ctx: Execution context
            config: S3 connection configuration
        """
        self.ctx = ctx
        self.config = config
        self._client = None

        # Validate config
        config.validate()

    @property
    def client(self):
        """Lazy-initialize S3 client."""
        if self._client is None:
            from sm.core.deps import ensure_package

            ensure_package(
                pip_name="boto3",
                apt_name="python3-boto3",
                apk_name="py3-boto3",
            )

            import boto3
            from botocore.config import Config as BotoConfig

            self._client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.config.endpoint}",
                region_name=self.config.region,
                aws_access_key_id=self.config.access_key,
                aws_secret_access_key=self.config.secret_key,
                config=BotoConfig(
                    retries={"max_attempts": 3, "mode": "standard"},
                    connect_timeout=30,
                    read_timeout=60,
                ),
            )
        return self._client

    def test_connectivity(self) -> bool:
        """Test S3 connectivity.

        Returns:
            True if connection successful

        Raises:
            BackupError: If connection fails
        """
        if self.ctx.dry_run:
            console.dry_run("Would test S3 connectivity")
            return True

        try:
            # Try to list bucket (will fail if no access)
            self.client.head_bucket(Bucket=self.config.bucket)
            return True
        except Exception as e:
            raise BackupError(
                f"Cannot connect to S3 bucket '{self.config.bucket}'",
                hint="Check credentials and bucket configuration",
                details=[str(e)],
            ) from e

    def upload_file(
        self,
        local_path: Path,
        remote_key: str,
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        """Upload a file to S3.

        Args:
            local_path: Local file path
            remote_key: S3 object key (without bucket)
            progress_callback: Optional callback for progress updates

        Raises:
            BackupError: If upload fails
        """
        if not local_path.exists():
            raise BackupError(f"File not found: {local_path}")

        file_size = local_path.stat().st_size

        if self.ctx.dry_run:
            console.dry_run(f"Would upload {local_path} to s3://{self.config.bucket}/{remote_key}")
            return

        try:
            # Create progress callback wrapper
            callback = None
            if progress_callback:
                bytes_transferred = [0]

                def _callback(bytes_amount):
                    bytes_transferred[0] += bytes_amount
                    progress_callback(bytes_transferred[0], file_size)

                callback = _callback

            self.client.upload_file(
                str(local_path),
                self.config.bucket,
                remote_key,
                Callback=callback,
            )

            if self.ctx.is_verbose:
                console.verbose(f"Uploaded to s3://{self.config.bucket}/{remote_key}")

        except Exception as e:
            raise BackupError(
                f"Failed to upload {local_path.name} to S3",
                details=[str(e)],
            ) from e

    def download_file(
        self,
        remote_key: str,
        local_path: Path,
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        """Download a file from S3.

        Args:
            remote_key: S3 object key (without bucket)
            local_path: Local destination path
            progress_callback: Optional callback for progress updates

        Raises:
            BackupError: If download fails
        """
        if self.ctx.dry_run:
            console.dry_run(
                f"Would download s3://{self.config.bucket}/{remote_key} to {local_path}"
            )
            return

        try:
            # Get file size first
            response = self.client.head_object(Bucket=self.config.bucket, Key=remote_key)
            file_size = response["ContentLength"]

            # Create progress callback wrapper
            callback = None
            if progress_callback:
                bytes_transferred = [0]

                def _callback(bytes_amount):
                    bytes_transferred[0] += bytes_amount
                    progress_callback(bytes_transferred[0], file_size)

                callback = _callback

            # Ensure parent directory exists
            local_path.parent.mkdir(parents=True, exist_ok=True)

            self.client.download_file(
                self.config.bucket,
                remote_key,
                str(local_path),
                Callback=callback,
            )

            if self.ctx.is_verbose:
                console.verbose(f"Downloaded to {local_path}")

        except self.client.exceptions.NoSuchKey as e:
            raise BackupError(
                f"Object not found: s3://{self.config.bucket}/{remote_key}",
                hint="Use 'sm postgres backup list' to see available exports",
            ) from e
        except Exception as e:
            raise BackupError(
                f"Failed to download from S3: {remote_key}",
                details=[str(e)],
            ) from e

    def list_objects(
        self,
        prefix: str,
        *,
        recursive: bool = True,
        max_keys: int = 1000,
    ) -> Iterator[S3ObjectInfo]:
        """List objects under a prefix.

        Args:
            prefix: S3 key prefix
            recursive: Include nested objects
            max_keys: Maximum objects to return

        Yields:
            S3ObjectInfo for each matching object
        """
        if self.ctx.dry_run:
            console.dry_run(f"Would list objects under s3://{self.config.bucket}/{prefix}")
            return

        try:
            paginator = self.client.get_paginator("list_objects_v2")

            kwargs = {
                "Bucket": self.config.bucket,
                "Prefix": prefix,
                "MaxKeys": max_keys,
            }

            if not recursive:
                kwargs["Delimiter"] = "/"

            for page in paginator.paginate(**kwargs):
                for obj in page.get("Contents", []):
                    yield S3ObjectInfo(
                        key=obj["Key"],
                        size=obj["Size"],
                        last_modified=obj["LastModified"],
                        etag=obj["ETag"].strip('"'),
                    )

        except Exception as e:
            raise BackupError(
                f"Failed to list objects: {prefix}",
                details=[str(e)],
            ) from e

    def list_prefixes(self, prefix: str) -> Iterator[str]:
        """List common prefixes (like directories) under a prefix.

        Args:
            prefix: S3 key prefix

        Yields:
            Common prefix strings
        """
        if self.ctx.dry_run:
            console.dry_run(f"Would list prefixes under s3://{self.config.bucket}/{prefix}")
            return

        try:
            paginator = self.client.get_paginator("list_objects_v2")

            for page in paginator.paginate(
                Bucket=self.config.bucket,
                Prefix=prefix,
                Delimiter="/",
            ):
                for common_prefix in page.get("CommonPrefixes", []):
                    yield common_prefix["Prefix"]

        except Exception as e:
            raise BackupError(
                f"Failed to list prefixes: {prefix}",
                details=[str(e)],
            ) from e

    def delete_object(self, key: str) -> None:
        """Delete an object from S3.

        Args:
            key: S3 object key

        Raises:
            BackupError: If deletion fails
        """
        if self.ctx.dry_run:
            console.dry_run(f"Would delete s3://{self.config.bucket}/{key}")
            return

        try:
            self.client.delete_object(Bucket=self.config.bucket, Key=key)

            if self.ctx.is_verbose:
                console.verbose(f"Deleted s3://{self.config.bucket}/{key}")

        except Exception as e:
            raise BackupError(
                f"Failed to delete object: {key}",
                details=[str(e)],
            ) from e

    def delete_prefix(self, prefix: str) -> int:
        """Delete all objects under a prefix.

        Args:
            prefix: S3 key prefix

        Returns:
            Number of objects deleted

        Raises:
            BackupError: If deletion fails
        """
        if self.ctx.dry_run:
            objects = list(self.list_objects(prefix))
            console.dry_run(f"Would delete {len(objects)} objects under {prefix}")
            return len(objects)

        deleted_count = 0
        try:
            # List and delete in batches of 1000
            objects_to_delete = []

            for obj in self.list_objects(prefix):
                objects_to_delete.append({"Key": obj.key})

                if len(objects_to_delete) >= 1000:
                    self.client.delete_objects(
                        Bucket=self.config.bucket,
                        Delete={"Objects": objects_to_delete},
                    )
                    deleted_count += len(objects_to_delete)
                    objects_to_delete = []

            # Delete remaining objects
            if objects_to_delete:
                self.client.delete_objects(
                    Bucket=self.config.bucket,
                    Delete={"Objects": objects_to_delete},
                )
                deleted_count += len(objects_to_delete)

            return deleted_count

        except Exception as e:
            raise BackupError(
                f"Failed to delete objects under {prefix}",
                details=[str(e)],
            ) from e

    def object_exists(self, key: str) -> bool:
        """Check if an object exists.

        Args:
            key: S3 object key

        Returns:
            True if object exists
        """
        if self.ctx.dry_run:
            console.dry_run(f"Would check if s3://{self.config.bucket}/{key} exists")
            return True

        try:
            self.client.head_object(Bucket=self.config.bucket, Key=key)
            return True
        except Exception:
            return False

    def get_object_size(self, key: str) -> int:
        """Get object size in bytes.

        Args:
            key: S3 object key

        Returns:
            Object size in bytes

        Raises:
            BackupError: If object not found
        """
        if self.ctx.dry_run:
            console.dry_run(f"Would get size of s3://{self.config.bucket}/{key}")
            return 0

        try:
            response = self.client.head_object(Bucket=self.config.bucket, Key=key)
            return response["ContentLength"]
        except self.client.exceptions.NoSuchKey as e:
            raise BackupError(f"Object not found: {key}") from e
        except Exception as e:
            raise BackupError(
                f"Failed to get object size: {key}",
                details=[str(e)],
            ) from e

    def download_json(self, key: str) -> dict:
        """Download and parse a JSON file.

        Args:
            key: S3 object key

        Returns:
            Parsed JSON data

        Raises:
            BackupError: If download or parse fails
        """
        if self.ctx.dry_run:
            console.dry_run(f"Would download JSON from s3://{self.config.bucket}/{key}")
            return {}

        try:
            response = self.client.get_object(Bucket=self.config.bucket, Key=key)
            content = response["Body"].read().decode("utf-8")
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise BackupError(
                f"Invalid JSON in {key}",
                details=[str(e)],
            ) from e
        except Exception as e:
            raise BackupError(
                f"Failed to download JSON: {key}",
                details=[str(e)],
            ) from e

    def upload_json(self, key: str, data: dict) -> None:
        """Upload a dict as JSON.

        Args:
            key: S3 object key
            data: Data to serialize as JSON

        Raises:
            BackupError: If upload fails
        """
        if self.ctx.dry_run:
            console.dry_run(f"Would upload JSON to s3://{self.config.bucket}/{key}")
            return

        try:
            content = json.dumps(data, indent=2, default=str)
            self.client.put_object(
                Bucket=self.config.bucket,
                Key=key,
                Body=content.encode("utf-8"),
                ContentType="application/json",
            )

            if self.ctx.is_verbose:
                console.verbose(f"Uploaded JSON to s3://{self.config.bucket}/{key}")

        except Exception as e:
            raise BackupError(
                f"Failed to upload JSON to {key}",
                details=[str(e)],
            ) from e

    def get_export_path(self, hostname: str, timestamp: str) -> str:
        """Get the S3 path for an export.

        Args:
            hostname: Server hostname
            timestamp: Export timestamp (YYYYMMDD_HHMMSS format)

        Returns:
            S3 key prefix for the export
        """
        # Use /pg-exports/ prefix to avoid conflicts with pgBackRest
        return f"pg-exports/{hostname}/{timestamp}/"

    def build_s3_uri(self, key: str) -> str:
        """Build full S3 URI for display.

        Args:
            key: S3 object key

        Returns:
            Full S3 URI (s3://bucket/key)
        """
        return f"s3://{self.config.bucket}/{key}"


def calculate_file_checksum(file_path: Path) -> str:
    """Calculate SHA256 checksum of a file.

    Args:
        file_path: Path to file

    Returns:
        SHA256 checksum as hex string with sha256: prefix
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return f"sha256:{sha256_hash.hexdigest()}"


def verify_file_checksum(file_path: Path, expected_checksum: str) -> bool:
    """Verify a file's checksum.

    Args:
        file_path: Path to file
        expected_checksum: Expected checksum (with sha256: prefix)

    Returns:
        True if checksum matches
    """
    actual = calculate_file_checksum(file_path)
    return actual == expected_checksum
