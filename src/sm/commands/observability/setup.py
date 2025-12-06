"""Observability setup command implementation.

This module implements the `sm observability setup` command which:
- Downloads and installs OpenTelemetry Collector (contrib)
- Configures host metrics collection (CPU, memory, disk, network)
- Configures log collection (fail2ban, auth, audit logs)
- Exports to SigNoz or other OTLP-compatible endpoints
"""

import os
import platform
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Optional

import typer
from jinja2 import Environment, PackageLoader, select_autoescape

from sm.core.context import ExecutionContext
from sm.core.output import console
from sm.core.executor import RollbackStack
from sm.core.exceptions import SMError, ExecutionError, PrerequisiteError
from sm.services.systemd import SystemdService

# Jinja2 environment for templates
jinja_env = Environment(
    loader=PackageLoader("sm", "templates"),
    autoescape=select_autoescape(),
    trim_blocks=True,
    lstrip_blocks=True,
)

# Default settings
DEFAULT_OTEL_VERSION = "0.104.0"
DEFAULT_INSTALL_DIR = "/opt/otel-host"
DEFAULT_SERVICE_NAME = "otel-host-metrics"
DEFAULT_COLLECTION_INTERVAL = "10s"


class ObservabilitySetup:
    """Handles OpenTelemetry Collector installation and configuration."""

    def __init__(
        self,
        ctx: ExecutionContext,
        otlp_endpoint: str,
        otel_version: str = DEFAULT_OTEL_VERSION,
        install_dir: str = DEFAULT_INSTALL_DIR,
        service_name: str = DEFAULT_SERVICE_NAME,
        collection_interval: str = DEFAULT_COLLECTION_INTERVAL,
        collect_logs: bool = True,
        enable_cloud_detection: bool = True,
    ):
        self.ctx = ctx
        self.otlp_endpoint = otlp_endpoint
        self.otel_version = otel_version
        self.install_dir = Path(install_dir)
        self.service_name = service_name
        self.collection_interval = collection_interval
        self.collect_logs = collect_logs
        self.enable_cloud_detection = enable_cloud_detection
        self.rollback = RollbackStack()

    def _get_download_url(self) -> str:
        """Get the download URL for OTEL collector based on architecture."""
        arch = platform.machine()

        # Normalize architecture name
        if arch in ("x86_64", "amd64"):
            arch_name = "amd64"
        elif arch in ("aarch64", "arm64"):
            arch_name = "arm64"
        else:
            raise PrerequisiteError(
                message=f"Unsupported architecture: {arch}",
                hint="Only x86_64/amd64 and aarch64/arm64 are supported",
            )

        return (
            f"https://github.com/open-telemetry/opentelemetry-collector-releases/"
            f"releases/download/v{self.otel_version}/"
            f"otelcol-contrib_{self.otel_version}_linux_{arch_name}.tar.gz"
        )

    def install_prerequisites(self) -> None:
        """Install prerequisite packages via apt."""
        packages = ["curl", "wget", "jq", "ca-certificates", "net-tools", "gnupg"]

        self.ctx.console.step("Installing prerequisite packages")

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would install: {', '.join(packages)}")
            return

        result = subprocess.run(
            ["apt-get", "update", "-y"],
            capture_output=True,
            text=True,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        if result.returncode != 0:
            raise ExecutionError(
                message="Failed to update apt cache",
                command="apt-get update",
                return_code=result.returncode,
                stderr=result.stderr,
            )

        result = subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends"] + packages,
            capture_output=True,
            text=True,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        if result.returncode != 0:
            raise ExecutionError(
                message="Failed to install prerequisite packages",
                command="apt-get install",
                return_code=result.returncode,
                stderr=result.stderr,
            )

        self.ctx.console.success("Prerequisite packages installed")

    def download_otel_collector(self) -> None:
        """Download and extract OpenTelemetry Collector."""
        self.ctx.console.step(f"Installing OpenTelemetry Collector v{self.otel_version}")

        otelcol_binary = self.install_dir / "otelcol"
        download_url = self._get_download_url()

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would download from: {download_url}")
            self.ctx.console.info(f"Would install to: {self.install_dir}")
            return

        # Create install directory
        dir_existed = self.install_dir.exists()
        self.install_dir.mkdir(parents=True, exist_ok=True)

        # Add rollback to remove install directory if we created it
        if not dir_existed:
            install_dir_str = str(self.install_dir)
            self.rollback.push(
                lambda: shutil.rmtree(install_dir_str, ignore_errors=True),
                f"Remove install directory {self.install_dir}",
            )

        # Check if binary already exists
        if otelcol_binary.exists():
            self.ctx.console.warn(f"otelcol binary already exists at {otelcol_binary}")
            self.ctx.console.info("Skipping download")
            return

        # Download tarball
        tarball_path = self.install_dir / "otelcol.tar.gz"
        self.ctx.console.info(f"Downloading from {download_url}...")

        try:
            urllib.request.urlretrieve(download_url, tarball_path)
        except Exception as e:
            raise ExecutionError(
                message="Failed to download OpenTelemetry Collector",
                stderr=str(e),
                hint="Check network connectivity and OTEL version",
            )

        # Verify download
        if not tarball_path.exists() or tarball_path.stat().st_size == 0:
            raise ExecutionError(
                message="Downloaded file is empty or missing",
                hint="Check the download URL and try again",
            )

        # Extract tarball
        self.ctx.console.info("Extracting...")
        result = subprocess.run(
            ["tar", "-xvf", str(tarball_path), "-C", str(self.install_dir)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ExecutionError(
                message="Failed to extract tarball",
                command="tar -xvf",
                return_code=result.returncode,
                stderr=result.stderr,
            )

        # Rename binary (contrib builds use different naming)
        contrib_binary = self.install_dir / "otelcol-contrib"
        if contrib_binary.exists():
            contrib_binary.rename(otelcol_binary)

        # Make executable
        otelcol_binary.chmod(0o755)

        # Cleanup tarball
        tarball_path.unlink()

        self.ctx.console.success(f"OpenTelemetry Collector installed to {self.install_dir}")

    def configure_otel_collector(self) -> None:
        """Generate OpenTelemetry Collector configuration."""
        self.ctx.console.step("Configuring OpenTelemetry Collector")

        config_path = self.install_dir / "config.yaml"

        # Render template
        template = jinja_env.get_template("otel/config.yaml.j2")
        content = template.render(
            otlp_endpoint=self.otlp_endpoint,
            collection_interval=self.collection_interval,
            collect_logs=self.collect_logs,
            enable_cloud_detection=self.enable_cloud_detection,
        )

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would create {config_path}")
            self.ctx.console.code(content, language="yaml", title="config.yaml")
            return

        # Backup if exists
        if config_path.exists():
            backup_path = config_path.with_suffix(".yaml.bak")
            import shutil
            shutil.copy2(config_path, backup_path)
            self.rollback.push(
                lambda: shutil.move(str(backup_path), str(config_path)),
                f"Restore {config_path} from backup",
            )

        # Write config
        config_path.write_text(content)
        self.ctx.console.success(f"Configuration written to {config_path}")

    def create_systemd_service(self) -> None:
        """Create and enable systemd service for OTEL collector."""
        self.ctx.console.step(f"Creating systemd service: {self.service_name}")

        service_path = Path(f"/etc/systemd/system/{self.service_name}.service")

        # Render template
        template = jinja_env.get_template("otel/systemd.service.j2")
        content = template.render(install_dir=str(self.install_dir))

        if self.ctx.dry_run:
            self.ctx.console.info(f"Would create {service_path}")
            self.ctx.console.code(content, language="ini", title=f"{self.service_name}.service")
            return

        # Write service file
        service_path.write_text(content)
        self.ctx.console.info(f"Created {service_path}")

        # Add rollback to remove service file
        service_path_str = str(service_path)
        self.rollback.push(
            lambda: Path(service_path_str).unlink(missing_ok=True),
            f"Remove service file {service_path}",
        )

        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

        # Enable and start service
        otel_service = SystemdService(self.service_name, self.ctx)
        otel_service.enable()
        otel_service.restart()

        self.ctx.console.success(f"Service {self.service_name} is running")


def run_observability_setup(
    ctx: ExecutionContext,
    otlp_endpoint: str,
    otel_version: str = DEFAULT_OTEL_VERSION,
    install_dir: str = DEFAULT_INSTALL_DIR,
    service_name: str = DEFAULT_SERVICE_NAME,
    collection_interval: str = DEFAULT_COLLECTION_INTERVAL,
    collect_logs: bool = True,
    enable_cloud_detection: bool = True,
) -> None:
    """Run observability setup operations.

    Args:
        ctx: Execution context
        otlp_endpoint: OTLP HTTP endpoint (e.g., http://signoz:4318)
        otel_version: OpenTelemetry Collector version
        install_dir: Installation directory
        service_name: Systemd service name
        collection_interval: Metrics collection interval
        collect_logs: Whether to collect logs (fail2ban, auth, audit)
        enable_cloud_detection: Enable cloud provider detection (GCP, EC2)
    """
    setup = ObservabilitySetup(
        ctx=ctx,
        otlp_endpoint=otlp_endpoint,
        otel_version=otel_version,
        install_dir=install_dir,
        service_name=service_name,
        collection_interval=collection_interval,
        collect_logs=collect_logs,
        enable_cloud_detection=enable_cloud_detection,
    )

    try:
        # Install prerequisites
        setup.install_prerequisites()

        # Download and install OTEL collector
        setup.download_otel_collector()

        # Configure collector
        setup.configure_otel_collector()

        # Create systemd service
        setup.create_systemd_service()

        # Summary
        ctx.console.print()
        ctx.console.success("Observability setup complete!")
        ctx.console.print()

        ctx.console.summary("OpenTelemetry Collector", {
            "Version": otel_version,
            "Install directory": install_dir,
            "Service name": service_name,
            "OTLP endpoint": otlp_endpoint,
            "Collect metrics": "Yes (CPU, memory, disk, network, etc.)",
            "Collect logs": "Yes (fail2ban, auth, audit)" if collect_logs else "No",
        })

    except SMError:
        # Rollback on error
        if setup.rollback.has_items():
            ctx.console.warn("Rolling back changes...")
            setup.rollback.rollback_all()
        raise
    except Exception as e:
        # Also rollback on unexpected errors
        if setup.rollback.has_items():
            ctx.console.warn("Unexpected error, rolling back changes...")
            setup.rollback.rollback_all()
        raise SMError(
            message="Observability setup failed",
            details=[str(e)],
            hint="Check the error message and try again",
        ) from e
