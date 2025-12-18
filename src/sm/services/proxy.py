"""Reverse proxy service abstraction.

Provides a secure interface for managing OpenResty-based reverse proxy
with API key authentication for HTTP and gRPC endpoints.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, PackageLoader, select_autoescape

from sm.core.config import ProxyConfig, ProxyEndpoint
from sm.core.context import ExecutionContext
from sm.core.exceptions import ExecutionError, ProxyError
from sm.core.executor import CommandExecutor, RollbackStack

# Configuration paths
PROXY_CONFIG_PATH = Path("/etc/sm/proxy.yaml")
PROXY_KEYS_PATH = Path("/etc/sm/proxy-keys.yaml")
OPENRESTY_CONF_DIR = Path("/etc/openresty")
OPENRESTY_LUA_DIR = Path("/etc/openresty/lua")
PROXY_LOG_DIR = Path("/var/log/sm")


@dataclass
class ProxyKey:
    """Information about a proxy API key."""

    name: str
    key: str
    key_prefix: str  # First 8 chars for identification
    key_hash: str  # SHA256 for validation
    endpoints: list[str]  # Endpoint names or ["*"]
    rate_limit: int | None = None  # Requests per minute
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    rotated_at: datetime | None = None
    expires_at: datetime | None = None
    enabled: bool = True


@dataclass
class EndpointStatus:
    """Status of a proxy endpoint."""

    name: str
    listen_port: int
    upstream: str
    protocol: str
    require_auth: bool
    is_healthy: bool = False


class ProxyService:
    """Safe interface for reverse proxy operations.

    All operations:
    - Respect dry-run mode
    - Use OpenResty (nginx + Lua) for execution
    - Log to audit trail
    - Support rollback
    """

    def __init__(
        self,
        ctx: ExecutionContext,
        executor: CommandExecutor,
    ) -> None:
        """Initialize proxy service.

        Args:
            ctx: Execution context
            executor: Command executor
        """
        self.ctx = ctx
        self.executor = executor
        self.config_path = PROXY_CONFIG_PATH
        self.keys_path = PROXY_KEYS_PATH
        self.nginx_conf_dir = OPENRESTY_CONF_DIR
        self.lua_dir = OPENRESTY_LUA_DIR
        self.log_dir = PROXY_LOG_DIR

        # Setup Jinja2 environment
        self._jinja_env = Environment(
            loader=PackageLoader("sm", "templates"),
            autoescape=select_autoescape(),
        )

    # =========================================================================
    # Installation
    # =========================================================================

    def is_installed(self) -> bool:
        """Check if OpenResty is installed.

        Returns:
            True if installed
        """
        result = self.executor.run(
            ["which", "openresty"],
            check=False,
        )
        return result.success

    def detect_version(self) -> str | None:
        """Detect installed OpenResty version.

        Returns:
            Version string or None
        """
        if not self.is_installed():
            return None

        result = self.executor.run(
            ["openresty", "-v"],
            check=False,
        )
        if result.success:
            # Parse: openresty/1.25.3.1
            for line in (result.stderr or result.stdout).splitlines():
                if "openresty/" in line.lower():
                    return line.split("/")[-1].split()[0]
        return None

    def install(
        self,
        *,
        rollback: RollbackStack | None = None,
    ) -> None:
        """Install OpenResty from official repository.

        Args:
            rollback: Rollback stack for cleanup on failure

        Raises:
            ProxyError: If installation fails
        """
        if self.is_installed():
            version = self.detect_version()
            self.ctx.console.info(f"OpenResty {version} already installed")
            return

        self.ctx.console.step("Installing OpenResty")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Would install OpenResty")
            return

        # Install dependencies
        self.executor.run(
            ["apt-get", "update"],
            check=True,
        )

        self.executor.run(
            ["apt-get", "install", "-y", "--no-install-recommends",
             "wget", "gnupg", "ca-certificates", "lsb-release"],
            check=True,
        )

        # Detect distribution and codename
        result = self.executor.run(
            ["lsb_release", "-si"],
            check=True,
        )
        distro = result.stdout.strip().lower()

        result = self.executor.run(
            ["lsb_release", "-cs"],
            check=True,
        )
        codename = result.stdout.strip()

        # Detect architecture
        arch_result = self.executor.run(["dpkg", "--print-architecture"], check=True)
        arch = arch_result.stdout.strip()

        self.ctx.console.debug(f"Detected distro: {distro}, codename: {codename}, arch: {arch}")

        # Supported codenames by OpenResty
        supported_ubuntu = {"focal", "jammy", "noble"}  # 20.04, 22.04, 24.04
        supported_debian = {"bullseye", "bookworm"}  # 11, 12

        # Determine repository URL based on distribution and architecture
        # OpenResty uses http:// and has separate arm64 repos
        if distro == "debian":
            if arch == "arm64":
                repo_url = "http://openresty.org/package/arm64/debian"
            else:
                repo_url = "http://openresty.org/package/debian"
            component = "openresty"  # Debian uses 'openresty' component
            if codename not in supported_debian:
                self.ctx.console.warn(
                    f"Codename '{codename}' may not be supported by OpenResty. "
                    f"Supported: {', '.join(sorted(supported_debian))}"
                )
        else:
            # Default to Ubuntu (also works for Ubuntu derivatives)
            if arch == "arm64":
                repo_url = "http://openresty.org/package/arm64/ubuntu"
            else:
                repo_url = "http://openresty.org/package/ubuntu"
            component = "main"  # Ubuntu uses 'main' component
            if codename not in supported_ubuntu:
                self.ctx.console.warn(
                    f"Codename '{codename}' may not be supported by OpenResty. "
                    f"Supported: {', '.join(sorted(supported_ubuntu))}"
                )

        # Import GPG key - use trusted.gpg.d for broader compatibility
        keyring_dir = Path("/etc/apt/trusted.gpg.d")
        keyring_dir.mkdir(parents=True, exist_ok=True)
        keyring_file = keyring_dir / "openresty.gpg"

        # Remove existing keyring file if present (from previous failed attempts)
        if keyring_file.exists():
            keyring_file.unlink()

        # Download and dearmor the GPG key
        self.executor.run(
            ["bash", "-c",
             f"wget -qO - https://openresty.org/package/pubkey.gpg | "
             f"gpg --dearmor -o {keyring_file}"],
            check=True,
        )

        # Add repository (no signed-by needed when using trusted.gpg.d)
        repo_line = f"deb {repo_url} {codename} {component}"
        repo_file = Path("/etc/apt/sources.list.d/openresty.list")

        self._write_file_atomic(repo_file, repo_line + "\n")

        # Update and install
        update_result = self.executor.run(["apt-get", "update"], check=True)

        # Check for repository errors in apt-get update output
        if update_result.stderr and "404" in update_result.stderr:
            self.ctx.console.warn(
                f"Repository may not exist for {distro}/{codename}. "
                "Check https://openresty.org/en/linux-packages.html for supported versions."
            )

        try:
            self.executor.run(["apt-get", "install", "-y", "openresty"], check=True)
        except ExecutionError as e:
            # Provide more helpful error message
            raise ProxyError(
                f"Failed to install OpenResty for {distro}/{codename} ({arch})",
                hint=(
                    f"OpenResty may not support '{codename}'. "
                    "Check https://openresty.org/en/linux-packages.html for supported versions."
                ),
                details=[
                    f"Distribution: {distro}",
                    f"Codename: {codename}",
                    f"Architecture: {arch}",
                    f"Repository: {repo_url} {codename} {component}",
                    e.stderr or "No error output",
                ],
            ) from e

        if rollback:
            rollback.add(
                "Uninstall OpenResty",
                lambda: self.uninstall(),
            )

        # Create directories
        self.lua_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.ctx.console.success("OpenResty installed")

    def uninstall(self) -> None:
        """Uninstall OpenResty.

        Raises:
            ProxyError: If uninstallation fails
        """
        if not self.is_installed():
            self.ctx.console.info("OpenResty not installed")
            return

        self.ctx.console.step("Uninstalling OpenResty")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Would uninstall OpenResty")
            return

        # Stop service first
        self.executor.run(["systemctl", "stop", "openresty"], check=False)

        # Remove package
        self.executor.run(
            ["apt-get", "remove", "-y", "--purge", "openresty"],
            check=True,
        )

        # Clean up repository and keyring
        repo_file = Path("/etc/apt/sources.list.d/openresty.list")
        keyring_file = Path("/etc/apt/keyrings/openresty.gpg")

        if repo_file.exists():
            repo_file.unlink()
        if keyring_file.exists():
            keyring_file.unlink()

        self.ctx.console.success("OpenResty uninstalled")

    # =========================================================================
    # Service Management
    # =========================================================================

    def is_running(self) -> bool:
        """Check if OpenResty is running.

        Returns:
            True if running
        """
        if self.ctx.dry_run:
            return True

        result = self.executor.run(
            ["systemctl", "is-active", "openresty"],
            check=False,
        )
        return result.success and "active" in result.stdout

    def start(self) -> None:
        """Start the OpenResty service."""
        self.ctx.console.step("Starting OpenResty")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Would start OpenResty")
            return

        self.executor.run(["systemctl", "start", "openresty"], check=True)
        self.executor.run(["systemctl", "enable", "openresty"], check=True)
        self.ctx.console.success("OpenResty started")

    def stop(self) -> None:
        """Stop the OpenResty service."""
        self.ctx.console.step("Stopping OpenResty")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Would stop OpenResty")
            return

        self.executor.run(["systemctl", "stop", "openresty"], check=True)
        self.ctx.console.success("OpenResty stopped")

    def reload(self) -> None:
        """Reload OpenResty configuration.

        Raises:
            ProxyError: If config is invalid
        """
        self.ctx.console.step("Reloading OpenResty configuration")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Would reload OpenResty")
            return

        # Test configuration first
        result = self.executor.run(
            ["openresty", "-t"],
            check=False,
        )

        if not result.success:
            raise ProxyError(
                "Nginx configuration is invalid",
                hint="Check configuration with: openresty -t",
                details=[result.stderr] if result.stderr else None,
            )

        self.executor.run(["systemctl", "reload", "openresty"], check=True)
        self.ctx.console.success("OpenResty reloaded")

    # =========================================================================
    # Configuration Management
    # =========================================================================

    def load_config(self) -> dict[str, Any]:
        """Load proxy configuration from YAML.

        Returns:
            Configuration dictionary
        """
        if not self.config_path.exists():
            return {"proxy": {}, "endpoints": []}

        with open(self.config_path) as f:
            return yaml.safe_load(f) or {"proxy": {}, "endpoints": []}

    def save_config(self, config: dict[str, Any]) -> None:
        """Save proxy configuration to YAML.

        Args:
            config: Configuration dictionary
        """
        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would save config to {self.config_path}")
            return

        self._write_file_atomic(
            self.config_path,
            yaml.dump(config, default_flow_style=False, sort_keys=False),
            mode=0o644,
        )

    def generate_nginx_config(self) -> None:
        """Generate nginx.conf from proxy configuration.

        Raises:
            ProxyError: If template rendering fails
        """
        self.ctx.console.step("Generating nginx configuration")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Would generate nginx.conf")
            return

        config = self.load_config()
        proxy_settings = config.get("proxy", {})
        endpoints = config.get("endpoints", [])

        template = self._jinja_env.get_template("proxy/nginx.conf.j2")
        content = template.render(
            worker_processes=proxy_settings.get("worker_processes", "auto"),
            worker_connections=proxy_settings.get("worker_connections", 4096),
            client_max_body_size=proxy_settings.get("client_max_body_size", "10m"),
            proxy_connect_timeout=proxy_settings.get("proxy_connect_timeout", 5),
            proxy_read_timeout=proxy_settings.get("proxy_read_timeout", 60),
            endpoints=endpoints,
        )

        nginx_conf = self.nginx_conf_dir / "nginx.conf"
        self._write_file_atomic(nginx_conf, content)

        self.ctx.console.success("nginx.conf generated")

    def generate_lua_scripts(self) -> None:
        """Generate Lua authentication and init scripts.

        Raises:
            ProxyError: If template rendering fails
        """
        self.ctx.console.step("Generating Lua scripts")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg("Would generate Lua scripts")
            return

        # Ensure directory exists
        self.lua_dir.mkdir(parents=True, exist_ok=True)

        # Generate auth.lua
        auth_template = self._jinja_env.get_template("proxy/auth.lua.j2")
        auth_content = auth_template.render()
        self._write_file_atomic(self.lua_dir / "auth.lua", auth_content)

        # Generate init.lua (loads keys into shared dict)
        init_template = self._jinja_env.get_template("proxy/init.lua.j2")
        keys = self._load_keys_for_nginx()
        init_content = init_template.render(keys=json.dumps(keys))
        self._write_file_atomic(self.lua_dir / "init.lua", init_content)

        self.ctx.console.success("Lua scripts generated")

    # =========================================================================
    # Endpoint Management
    # =========================================================================

    def add_endpoint(
        self,
        endpoint: ProxyEndpoint,
        *,
        rollback: RollbackStack | None = None,
    ) -> None:
        """Add a new proxy endpoint.

        Args:
            endpoint: Endpoint configuration
            rollback: Rollback stack for cleanup on failure

        Raises:
            ProxyError: If endpoint already exists or creation fails
        """
        config = self.load_config()
        endpoints = config.get("endpoints", [])

        # Check for duplicate name or port
        for ep in endpoints:
            if ep["name"] == endpoint.name:
                raise ProxyError(
                    f"Endpoint '{endpoint.name}' already exists",
                    hint=(
                        f"Use 'sm proxy endpoint remove --name {endpoint.name}' "
                        "to remove it first"
                    ),
                )
            if ep["listen_port"] == endpoint.listen_port:
                raise ProxyError(
                    f"Port {endpoint.listen_port} already in use by endpoint '{ep['name']}'",
                    hint="Choose a different port",
                )

        self.ctx.console.step(f"Adding endpoint '{endpoint.name}'")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would add endpoint: {endpoint.name}")
            return

        # Add endpoint to config
        endpoints.append({
            "name": endpoint.name,
            "listen_port": endpoint.listen_port,
            "upstream": endpoint.upstream,
            "protocol": endpoint.protocol,
            "require_auth": endpoint.require_auth,
            "allowed_methods": endpoint.allowed_methods,
            "health_check_path": endpoint.health_check_path,
        })
        config["endpoints"] = endpoints
        self.save_config(config)

        if rollback:
            # Capture endpoint name in closure for rollback
            def rollback_remove(n: str = endpoint.name) -> None:
                self.remove_endpoint(n)

            rollback.add(f"Remove endpoint '{endpoint.name}'", rollback_remove)

        # Regenerate and reload
        self.generate_nginx_config()
        if self.is_running():
            self.reload()

        self.ctx.console.success(f"Endpoint '{endpoint.name}' added on port {endpoint.listen_port}")

    def remove_endpoint(self, name: str) -> None:
        """Remove a proxy endpoint.

        Args:
            name: Endpoint name

        Raises:
            ProxyError: If endpoint doesn't exist
        """
        config = self.load_config()
        endpoints = config.get("endpoints", [])

        # Find and remove endpoint
        new_endpoints = [ep for ep in endpoints if ep["name"] != name]

        if len(new_endpoints) == len(endpoints):
            raise ProxyError(
                f"Endpoint '{name}' not found",
                hint="Use 'sm proxy endpoint list' to see available endpoints",
            )

        self.ctx.console.step(f"Removing endpoint '{name}'")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would remove endpoint: {name}")
            return

        config["endpoints"] = new_endpoints
        self.save_config(config)

        # Regenerate and reload
        self.generate_nginx_config()
        if self.is_running():
            self.reload()

        self.ctx.console.success(f"Endpoint '{name}' removed")

    def list_endpoints(self) -> list[EndpointStatus]:
        """List all configured endpoints.

        Returns:
            List of EndpointStatus objects
        """
        config = self.load_config()
        endpoints = config.get("endpoints", [])

        result = []
        for ep in endpoints:
            status = EndpointStatus(
                name=ep["name"],
                listen_port=ep["listen_port"],
                upstream=ep["upstream"],
                protocol=ep.get("protocol", "http"),
                require_auth=ep.get("require_auth", True),
                is_healthy=self._check_endpoint_health(ep),
            )
            result.append(status)

        return result

    def _check_endpoint_health(self, endpoint: dict[str, Any]) -> bool:
        """Check if upstream is healthy.

        Args:
            endpoint: Endpoint configuration

        Returns:
            True if healthy
        """
        if self.ctx.dry_run:
            return True

        # Try to connect to upstream
        upstream = endpoint.get("upstream", "")
        if ":" not in upstream:
            return False

        host, port = upstream.rsplit(":", 1)
        result = self.executor.run(
            ["nc", "-z", "-w", "2", host, port],
            check=False,
        )
        return result.success

    # =========================================================================
    # API Key Management
    # =========================================================================

    def _load_keys(self) -> list[dict[str, Any]]:
        """Load API keys from YAML file.

        Returns:
            List of key dictionaries
        """
        if not self.keys_path.exists():
            return []

        with open(self.keys_path) as f:
            data: dict[str, Any] = yaml.safe_load(f) or {}
            keys: list[dict[str, Any]] = data.get("keys", [])
            return keys

    def _save_keys(self, keys: list[dict[str, Any]]) -> None:
        """Save API keys to YAML file with secure permissions.

        Args:
            keys: List of key dictionaries
        """
        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would save keys to {self.keys_path}")
            return

        content = yaml.dump({"keys": keys}, default_flow_style=False, sort_keys=False)
        self._write_file_atomic(self.keys_path, content, mode=0o600)

    def _load_keys_for_nginx(self) -> dict[str, Any]:
        """Load keys in format for nginx shared dict.

        Returns:
            Dict mapping key -> key data for auth
        """
        keys = self._load_keys()
        result = {}

        for key_data in keys:
            if not key_data.get("enabled", True):
                continue

            result[key_data["key"]] = {
                "name": key_data["name"],
                "endpoints": key_data.get("endpoints", ["*"]),
                "rate_limit": key_data.get("rate_limit"),
                "expires_at": key_data.get("expires_at"),
                "enabled": key_data.get("enabled", True),
            }

        return result

    def _generate_api_key(self) -> str:
        """Generate a cryptographically secure API key.

        Returns:
            API key string (sk_live_...)
        """
        # 32 bytes = 256 bits of entropy
        random_part = secrets.token_urlsafe(32)
        return f"sk_live_{random_part}"

    def _hash_key(self, key: str) -> str:
        """Create SHA256 hash of key.

        Args:
            key: API key

        Returns:
            SHA256 hash string
        """
        return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"

    def create_key(
        self,
        name: str,
        endpoints: list[str] | None = None,
        rate_limit: int | None = None,
        expires_at: datetime | None = None,
        *,
        rollback: RollbackStack | None = None,
    ) -> str:
        """Create a new API key.

        Args:
            name: Key name for identification
            endpoints: List of endpoint names or ["*"] for all
            rate_limit: Requests per minute limit
            expires_at: Optional expiration time
            rollback: Rollback stack for cleanup on failure

        Returns:
            The generated API key (only returned once!)

        Raises:
            ProxyError: If key name already exists
        """
        keys = self._load_keys()

        # Check for duplicate name
        for key_data in keys:
            if key_data["name"] == name:
                raise ProxyError(
                    f"API key '{name}' already exists",
                    hint=f"Use 'sm proxy key rotate --name {name}' to rotate it",
                )

        self.ctx.console.step(f"Creating API key '{name}'")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would create API key: {name}")
            return "sk_live_DRY_RUN_KEY"

        # Generate key
        api_key = self._generate_api_key()
        key_hash = self._hash_key(api_key)
        key_prefix = api_key[:16]  # sk_live_ + first 8 chars

        # Create key entry
        key_entry = {
            "name": name,
            "key": api_key,
            "key_prefix": key_prefix,
            "key_hash": key_hash,
            "endpoints": endpoints or ["*"],
            "rate_limit": rate_limit,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "rotated_at": None,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "enabled": True,
        }

        keys.append(key_entry)
        self._save_keys(keys)

        if rollback:
            # Capture key name in closure for rollback
            def rollback_revoke(n: str = name) -> None:
                self.revoke_key(n)

            rollback.add(f"Revoke API key '{name}'", rollback_revoke)

        # Update nginx shared dict
        self.generate_lua_scripts()
        if self.is_running():
            self.reload()

        self.ctx.console.success(f"API key '{name}' created")

        return api_key

    def rotate_key(self, name: str) -> str:
        """Rotate an existing API key.

        Args:
            name: Key name

        Returns:
            The new API key

        Raises:
            ProxyError: If key doesn't exist
        """
        keys = self._load_keys()

        # Find key
        key_index = None
        for i, key_data in enumerate(keys):
            if key_data["name"] == name:
                key_index = i
                break

        if key_index is None:
            raise ProxyError(
                f"API key '{name}' not found",
                hint="Use 'sm proxy key list' to see available keys",
            )

        self.ctx.console.step(f"Rotating API key '{name}'")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would rotate API key: {name}")
            return "sk_live_DRY_RUN_KEY"

        # Generate new key
        new_api_key = self._generate_api_key()
        new_hash = self._hash_key(new_api_key)
        new_prefix = new_api_key[:16]

        # Update key entry
        keys[key_index]["key"] = new_api_key
        keys[key_index]["key_hash"] = new_hash
        keys[key_index]["key_prefix"] = new_prefix
        keys[key_index]["rotated_at"] = datetime.now(timezone.utc).isoformat()

        self._save_keys(keys)

        # Update nginx shared dict
        self.generate_lua_scripts()
        if self.is_running():
            self.reload()

        self.ctx.console.success(f"API key '{name}' rotated")

        return new_api_key

    def revoke_key(self, name: str) -> None:
        """Revoke (disable) an API key.

        Args:
            name: Key name

        Raises:
            ProxyError: If key doesn't exist
        """
        keys = self._load_keys()

        # Find key
        key_index = None
        for i, key_data in enumerate(keys):
            if key_data["name"] == name:
                key_index = i
                break

        if key_index is None:
            raise ProxyError(
                f"API key '{name}' not found",
                hint="Use 'sm proxy key list' to see available keys",
            )

        self.ctx.console.step(f"Revoking API key '{name}'")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would revoke API key: {name}")
            return

        # Disable key (keep for audit trail)
        keys[key_index]["enabled"] = False

        self._save_keys(keys)

        # Update nginx shared dict
        self.generate_lua_scripts()
        if self.is_running():
            self.reload()

        self.ctx.console.success(f"API key '{name}' revoked")

    def delete_key(self, name: str) -> None:
        """Permanently delete an API key.

        Args:
            name: Key name

        Raises:
            ProxyError: If key doesn't exist
        """
        keys = self._load_keys()

        new_keys = [k for k in keys if k["name"] != name]

        if len(new_keys) == len(keys):
            raise ProxyError(
                f"API key '{name}' not found",
                hint="Use 'sm proxy key list' to see available keys",
            )

        self.ctx.console.step(f"Deleting API key '{name}'")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Would delete API key: {name}")
            return

        self._save_keys(new_keys)

        # Update nginx shared dict
        self.generate_lua_scripts()
        if self.is_running():
            self.reload()

        self.ctx.console.success(f"API key '{name}' deleted")

    def list_keys(self, include_disabled: bool = False) -> list[ProxyKey]:
        """List all API keys (without exposing actual keys).

        Args:
            include_disabled: Include revoked/disabled keys

        Returns:
            List of ProxyKey objects (keys masked)
        """
        keys = self._load_keys()
        result = []

        for key_data in keys:
            if not include_disabled and not key_data.get("enabled", True):
                continue

            # Parse datetime fields
            created_at = (
                datetime.fromisoformat(key_data["created_at"])
                if key_data.get("created_at")
                else datetime.now(timezone.utc)
            )
            rotated_at = (
                datetime.fromisoformat(key_data["rotated_at"])
                if key_data.get("rotated_at")
                else None
            )
            expires_at = (
                datetime.fromisoformat(key_data["expires_at"])
                if key_data.get("expires_at")
                else None
            )

            result.append(ProxyKey(
                name=key_data["name"],
                key="***REDACTED***",  # Never expose in listings
                key_prefix=key_data.get("key_prefix", ""),
                key_hash=key_data.get("key_hash", ""),
                endpoints=key_data.get("endpoints", ["*"]),
                rate_limit=key_data.get("rate_limit"),
                created_at=created_at,
                rotated_at=rotated_at,
                expires_at=expires_at,
                enabled=key_data.get("enabled", True),
            ))

        return result

    def show_key(self, name: str) -> ProxyKey:
        """Show full details of a single key including the actual key.

        Args:
            name: Key name

        Returns:
            ProxyKey with actual key value

        Raises:
            ProxyError: If key doesn't exist
        """
        keys = self._load_keys()

        for key_data in keys:
            if key_data["name"] == name:
                # Parse datetime fields
                created_at = (
                    datetime.fromisoformat(key_data["created_at"])
                    if key_data.get("created_at")
                    else datetime.now(timezone.utc)
                )
                rotated_at = (
                    datetime.fromisoformat(key_data["rotated_at"])
                    if key_data.get("rotated_at")
                    else None
                )
                expires_at = (
                    datetime.fromisoformat(key_data["expires_at"])
                    if key_data.get("expires_at")
                    else None
                )

                return ProxyKey(
                    name=key_data["name"],
                    key=key_data["key"],  # Actual key for show command only
                    key_prefix=key_data.get("key_prefix", ""),
                    key_hash=key_data.get("key_hash", ""),
                    endpoints=key_data.get("endpoints", ["*"]),
                    rate_limit=key_data.get("rate_limit"),
                    created_at=created_at,
                    rotated_at=rotated_at,
                    expires_at=expires_at,
                    enabled=key_data.get("enabled", True),
                )

        raise ProxyError(
            f"API key '{name}' not found",
            hint="Use 'sm proxy key list' to see available keys",
        )

    # =========================================================================
    # Setup
    # =========================================================================

    def setup(
        self,
        config: ProxyConfig | None = None,
        *,
        rollback: RollbackStack | None = None,
    ) -> None:
        """Full setup: install, configure, and start proxy.

        Args:
            config: Optional proxy configuration
            rollback: Rollback stack for cleanup on failure
        """
        self.ctx.console.step("Setting up reverse proxy")

        # Install OpenResty
        self.install(rollback=rollback)

        # Initialize config file if needed
        if not self.config_path.exists():
            initial_config = {
                "proxy": {
                    "enabled": True,
                    "bind_address": config.bind_address if config else "0.0.0.0",
                    "worker_processes": config.worker_processes if config else "auto",
                    "worker_connections": config.worker_connections if config else 4096,
                    "client_max_body_size": config.client_max_body_size if config else "10m",
                    "proxy_connect_timeout": config.proxy_connect_timeout if config else 5,
                    "proxy_read_timeout": config.proxy_read_timeout if config else 60,
                    "rate_limit": {
                        "enabled": (
                            config.rate_limit.enabled if config else True
                        ),
                        "default_requests_per_minute": (
                            config.rate_limit.default_requests_per_minute
                            if config
                            else 1000
                        ),
                        "burst": config.rate_limit.burst if config else 100,
                    },
                },
                "endpoints": [],
            }
            self.save_config(initial_config)

        # Initialize keys file if needed
        if not self.keys_path.exists():
            self._save_keys([])

        # Generate configs
        self.generate_nginx_config()
        self.generate_lua_scripts()

        # Start service
        if not self.ctx.dry_run:
            self.start()

        self.ctx.console.success("Reverse proxy setup complete")

    # =========================================================================
    # Utilities
    # =========================================================================

    def _write_file_atomic(
        self,
        path: Path,
        content: str,
        mode: int = 0o644,
    ) -> None:
        """Write file atomically using temp file + rename.

        Args:
            path: Target file path
            content: File content
            mode: File permissions
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        # Write to temp file in same directory (same filesystem for atomic rename)
        fd, temp_path = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            os.write(fd, content.encode())
            os.fchmod(fd, mode)
            os.close(fd)
            os.rename(temp_path, path)
        except Exception:
            os.close(fd)
            os.unlink(temp_path)
            raise
