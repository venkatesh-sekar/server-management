"""MongoDB setup command.

Installs and configures MongoDB 7.0 with:
- Official MongoDB repository
- Security-hardened configuration
- Admin user creation
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer
from jinja2 import Environment, PackageLoader, select_autoescape

from sm.core import (
    console,
    ExecutionContext,
    create_context,
    CommandExecutor,
    get_credential_manager,
    get_audit_logger,
    AuditEventType,
    require_root,
    run_preflight_checks,
    MongoDBError,
)
from sm.services.mongodb import MongoDBService
from sm.services.systemd import SystemdService


# Constants
MONGODB_REPO_KEY_URL = "https://pgp.mongodb.com/server-7.0.asc"
MONGODB_KEYRING = Path("/usr/share/keyrings/mongodb-server-7.0.gpg")
MONGODB_REPO_LIST = Path("/etc/apt/sources.list.d/mongodb-org-7.0.list")


def _mongodb_repo_exists() -> bool:
    """Check if MongoDB repository is already configured.

    Returns:
        True if the MongoDB repository list file exists
    """
    return MONGODB_REPO_LIST.exists()


def get_jinja_env() -> Environment:
    """Get Jinja2 environment for templates."""
    return Environment(
        loader=PackageLoader("sm", "templates"),
        autoescape=select_autoescape(),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _get_system_memory_gb() -> float:
    """Get total system memory in GB."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    # Value is in kB
                    kb = int(line.split()[1])
                    return kb / (1024 * 1024)
    except Exception:
        pass
    return 4.0  # Default to 4GB if detection fails


def setup_mongodb(
    ctx: ExecutionContext,
    executor: CommandExecutor,
    systemd: SystemdService,
) -> str:
    """Install and configure MongoDB 7.0.

    Args:
        ctx: Execution context
        executor: Command executor
        systemd: Systemd service

    Returns:
        Admin password
    """
    jinja = get_jinja_env()
    creds = get_credential_manager()

    console.step("Installing MongoDB 7.0 from official repository")

    if not ctx.dry_run:
        # Check if MongoDB repository is already configured (idempotency)
        if _mongodb_repo_exists():
            console.info("MongoDB repository already configured")
        else:
            # Get distro codename
            result = executor.run(["lsb_release", "-cs"], description="Get distro codename")
            codename = result.stdout.strip()

            # Import MongoDB GPG key
            console.step("Adding MongoDB repository")
            executor.run(
                ["curl", "-fsSL", MONGODB_REPO_KEY_URL, "-o", "/tmp/mongodb.asc"],
                description="Download MongoDB key",
            )
            executor.run(
                ["gpg", "--dearmor", "--yes", "-o", str(MONGODB_KEYRING), "/tmp/mongodb.asc"],
                description="Install MongoDB keyring",
            )

            # Add repository
            repo_line = (
                f"deb [signed-by={MONGODB_KEYRING}] "
                f"https://repo.mongodb.org/apt/ubuntu {codename}/mongodb-org/7.0 multiverse"
            )
            executor.write_file(
                MONGODB_REPO_LIST,
                repo_line + "\n",
                description="Add MongoDB repository",
            )

            # Update after adding new repository
            executor.run(["apt-get", "update", "-y"], description="Update package lists")

        # Install MongoDB (apt will skip if already installed)
        executor.apt_install(
            ["mongodb-org", "mongodb-database-tools"],
            description="Install MongoDB and database tools",
        )
    else:
        console.dry_run_msg("Install mongodb-org, mongodb-database-tools")

    # Calculate WiredTiger cache size (50% of RAM, max 4GB for standalone)
    total_ram_gb = _get_system_memory_gb()
    cache_size_gb = min(total_ram_gb * 0.5, 4)

    console.info(f"Detected: {total_ram_gb:.1f}GB RAM")
    console.info(f"Setting WiredTiger cache: {cache_size_gb:.1f}GB")

    # Generate MongoDB configuration
    config_content = jinja.get_template("mongodb/mongod.conf.j2").render(
        data_dir="/var/lib/mongodb",
        port=27017,
        bind_ip="127.0.0.1",
        cache_size_gb=round(cache_size_gb, 1),
        max_connections=1000,
        auth_enabled=False,  # Temporarily disabled for initial setup
    )

    # Write temporary config without auth
    mongod_conf = Path("/etc/mongod.conf")
    executor.write_file(
        mongod_conf,
        config_content,
        description="Write mongod.conf (auth disabled for setup)",
        permissions=0o644,
    )

    # Start MongoDB without auth first to create admin user
    console.step("Starting MongoDB for initial configuration")
    systemd.restart("mongod.service")
    systemd.enable("mongod.service")

    # Wait for MongoDB to be ready
    if not ctx.dry_run:
        console.step("Waiting for MongoDB to be ready")
        for i in range(30):
            try:
                result = executor.run(
                    ["mongosh", "mongodb://127.0.0.1:27017/admin",
                     "--quiet", "--eval", "db.adminCommand('ping')"],
                    check=False,
                )
                if result.success:
                    console.success("MongoDB is ready")
                    break
            except Exception:
                pass
            time.sleep(1)
        else:
            raise MongoDBError(
                "MongoDB failed to start within 30 seconds",
                hint="Check logs with: journalctl -u mongod.service",
            )

    # Create admin user
    console.step("Creating admin user")
    admin_pass, generated = creds.ensure_password("admin", "_mongodb", dry_run=ctx.dry_run)

    if not ctx.dry_run:
        # Create admin user with root role
        admin_js = f"""
        db.getSiblingDB('admin').createUser({{
            user: 'admin',
            pwd: '{admin_pass}',
            roles: [
                {{ role: 'root', db: 'admin' }}
            ],
            mechanisms: ['SCRAM-SHA-256']
        }})
        """

        result = executor.run(
            ["mongosh", "mongodb://127.0.0.1:27017/admin",
             "--quiet", "--eval", admin_js],
            sensitive=True,
            check=False,
        )

        if not result.success and "already exists" not in result.stderr:
            raise MongoDBError(
                "Failed to create admin user",
                details=[result.stderr] if result.stderr else None,
            )

    if generated:
        creds.store_password(admin_pass, "admin", "_mongodb", dry_run=ctx.dry_run)
        console.success("Generated and stored new admin password")
    else:
        console.info("Using existing admin password")

    # Re-enable authorization
    console.step("Enabling authorization")
    config_content_auth = jinja.get_template("mongodb/mongod.conf.j2").render(
        data_dir="/var/lib/mongodb",
        port=27017,
        bind_ip="127.0.0.1",
        cache_size_gb=round(cache_size_gb, 1),
        max_connections=1000,
        auth_enabled=True,  # Now enable auth
    )

    executor.write_file(
        mongod_conf,
        config_content_auth,
        description="Write mongod.conf (auth enabled)",
        permissions=0o644,
    )

    # Restart with auth enabled
    systemd.restart("mongod.service")

    # Verify auth is working
    if not ctx.dry_run:
        console.step("Verifying authentication")
        time.sleep(2)  # Wait for restart

        mongo = MongoDBService(ctx, executor)
        mongo.set_admin_credentials("admin", admin_pass)

        if not mongo.is_running():
            raise MongoDBError(
                "MongoDB failed to restart with authentication enabled",
                hint="Check logs with: journalctl -u mongod.service",
            )

        console.success("MongoDB authentication verified")

    return admin_pass


def run_setup(
    ctx: ExecutionContext,
) -> None:
    """Run the full MongoDB setup."""
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    creds = get_credential_manager()
    audit = get_audit_logger()

    try:
        admin_pass = setup_mongodb(ctx, executor, systemd)

        audit.log_success(
            AuditEventType.CONFIG_MODIFY,
            "mongodb",
            "mongodb-7.0",
            message="MongoDB setup completed",
        )

        # Summary
        console.print()
        console.print("[bold green]MongoDB Setup Complete[/bold green]")
        console.print()
        console.summary(
            "Installation Summary",
            {
                "MongoDB version": "7.0",
                "Port": "27017 (localhost only)",
                "Admin user": "admin",
                "Password file": str(creds.get_password_path("admin", "_mongodb")),
            },
        )

        console.print()
        console.warn("IMPORTANT: Configure your firewall!")
        console.print("  - MongoDB is only listening on localhost (127.0.0.1)")
        console.print("  - DO NOT expose port 27017 to the internet")
        console.print()
        console.print("Next steps:")
        console.print("  - Create a database: sm mongodb db create-with-user -d myapp")
        console.print("  - List databases: sm mongodb db list")

    except MongoDBError as e:
        audit.log_failure(
            AuditEventType.CONFIG_MODIFY,
            "mongodb",
            "mongodb-7.0",
            str(e),
        )
        raise
