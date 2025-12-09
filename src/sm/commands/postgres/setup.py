"""PostgreSQL setup command.

Installs and configures PostgreSQL with:
- PostgreSQL from PGDG repository
- PgBouncer connection pooler
- pgBackRest with S3/B2 backups
- Secure defaults and PITR support
"""

from pathlib import Path
from typing import Optional

import typer
from jinja2 import Environment, PackageLoader, select_autoescape

from sm.core import (
    console,
    ExecutionContext,
    create_context,
    CommandExecutor,
    CredentialManager,
    get_credential_manager,
    get_audit_logger,
    AuditEventType,
    AuditResult,
    require_root,
    run_preflight_checks,
    DangerLevel,
    ValidationError,
    PostgresError,
    ConfigurationError,
)
from sm.core.validation import validate_path
from sm.services.systemd import SystemdService
from sm.services.tuning import PostgresTuningService, WorkloadProfile


# Constants
PGDG_KEY_URL = "https://www.postgresql.org/media/keys/ACCC4CF8.asc"
PGDG_KEYRING = Path("/usr/share/keyrings/postgresql.gpg")
PGDG_LIST = Path("/etc/apt/sources.list.d/pgdg.list")


def _pgdg_repo_exists() -> bool:
    """Check if PGDG repository is already configured.

    Returns:
        True if the PGDG repository list file exists
    """
    return PGDG_LIST.exists()


def get_jinja_env() -> Environment:
    """Get Jinja2 environment for templates."""
    return Environment(
        loader=PackageLoader("sm", "templates"),
        autoescape=select_autoescape(),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def setup_postgres(
    ctx: ExecutionContext,
    executor: CommandExecutor,
    systemd: SystemdService,
    version: str,
    creds: CredentialManager,
) -> str:
    """Install and configure PostgreSQL.

    Returns:
        Superuser password
    """
    jinja = get_jinja_env()

    # Install packages
    console.step("Installing PostgreSQL from PGDG repository")

    if not ctx.dry_run:
        # Check if PGDG repository is already configured (idempotency)
        if _pgdg_repo_exists():
            console.info("PGDG repository already configured")
        else:
            # Get distro codename
            result = executor.run(["lsb_release", "-cs"], description="Get distro codename")
            codename = result.stdout.strip()

            # Import PGDG key
            console.step("Adding PGDG repository")
            executor.run(
                ["curl", "-fsSL", PGDG_KEY_URL, "-o", "/tmp/pgdg.asc"],
                description="Download PGDG key",
            )
            executor.run(
                ["gpg", "--dearmor", "-o", str(PGDG_KEYRING), "/tmp/pgdg.asc"],
                description="Install PGDG keyring",
            )

            # Add repository
            repo_line = f"deb [signed-by={PGDG_KEYRING}] http://apt.postgresql.org/pub/repos/apt {codename}-pgdg main"
            executor.write_file(
                PGDG_LIST,
                repo_line + "\n",
                description="Add PGDG repository",
            )

            # Update after adding new repository
            executor.run(["apt-get", "update", "-y"], description="Update package lists")

        # Install packages (apt will skip if already installed)
        executor.apt_install(
            [f"postgresql-{version}", "pgbouncer", "pgbackrest"],
            description="Install PostgreSQL, PgBouncer, pgBackRest",
        )
    else:
        console.dry_run_msg(f"Install postgresql-{version}, pgbouncer, pgbackrest")

    # Get tuning parameters using enhanced detection
    console.step("Detecting system resources for tuning")
    tuning_service = PostgresTuningService(ctx, executor)
    system_info = tuning_service.detect_system_info(version)

    console.info(f"Detected: {system_info.memory_mb}MB RAM, "
                 f"{system_info.cpu_count} CPUs, {system_info.disk_type.upper()}")

    # Calculate recommendations using MIXED profile by default for new installs
    recommendation = tuning_service.calculate_recommendations(
        system_info,
        WorkloadProfile.MIXED,
        {},  # No current config during fresh setup
    )

    # Display key settings
    console.info("Applying tuning (MIXED workload profile):")
    for param in recommendation.parameters[:4]:  # Show first 4 params
        console.info(f"  {param.name} = {param.recommended_value}")

    # Write tuning config
    pg_conf_dir = Path(f"/etc/postgresql/{version}/main")
    conf_d = pg_conf_dir / "conf.d"

    if not ctx.dry_run:
        conf_d.mkdir(parents=True, exist_ok=True)

    tuning_conf = tuning_service.generate_config(recommendation)
    executor.write_file(
        conf_d / "99-tuning.conf",
        tuning_conf,
        description="Write PostgreSQL tuning config",
        owner="postgres",
        group="postgres",
        permissions=0o640,
    )

    # Configure listen_addresses (localhost only, PgBouncer handles external)
    console.step("Configuring PostgreSQL for local-only access")
    if not ctx.dry_run:
        pg_conf = pg_conf_dir / "postgresql.conf"
        if pg_conf.exists():
            content = pg_conf.read_text()
            import re
            content = re.sub(
                r"^#?listen_addresses.*$",
                "listen_addresses = '127.0.0.1'",
                content,
                flags=re.MULTILINE,
            )
            executor.write_file(pg_conf, content, description="Set listen_addresses")

    # Write pg_hba.conf
    pg_hba = jinja.get_template("postgresql/pg_hba.conf.j2").render()
    executor.write_file(
        pg_conf_dir / "pg_hba.conf",
        pg_hba,
        description="Write pg_hba.conf",
        owner="postgres",
        group="postgres",
        permissions=0o640,
    )

    # Start PostgreSQL
    systemd.restart(f"postgresql@{version}-main.service")
    systemd.enable(f"postgresql@{version}-main.service")

    # Set superuser password
    console.step("Setting postgres superuser password")
    superuser_pass, generated = creds.ensure_password("postgres", "_system", dry_run=ctx.dry_run)

    if not ctx.dry_run:
        # Use unique dollar-quote tag to safely embed password
        import secrets
        tag = f"p{secrets.token_hex(4)}"
        executor.run_sql(
            f"""
            SET password_encryption = 'scram-sha-256';
            ALTER USER postgres WITH PASSWORD ${tag}${superuser_pass}${tag}$;
            """,
            description="Set postgres password",
        )

    if generated:
        creds.store_password(superuser_pass, "postgres", "_system", dry_run=ctx.dry_run)
        console.success("Generated and stored new postgres password")
    else:
        console.info("Using existing postgres password")

    return superuser_pass


def setup_pgbouncer(
    ctx: ExecutionContext,
    executor: CommandExecutor,
    systemd: SystemdService,
    pg_password: str,
    config: dict,
) -> None:
    """Configure PgBouncer."""
    jinja = get_jinja_env()

    console.step("Configuring PgBouncer")

    # Get service user
    svc_user, svc_group = systemd.get_service_user("pgbouncer.service")
    console.debug(f"PgBouncer runs as {svc_user}:{svc_group}")

    # Ensure directories
    pgb_dir = Path("/etc/pgbouncer")
    run_dir = Path("/run/pgbouncer")

    if not ctx.dry_run:
        pgb_dir.mkdir(parents=True, exist_ok=True)
        run_dir.mkdir(parents=True, exist_ok=True)
        import os
        import pwd
        import grp
        try:
            uid = pwd.getpwnam(svc_user).pw_uid
            gid = grp.getgrnam(svc_group).gr_gid
            os.chown(run_dir, uid, gid)
        except KeyError as e:
            console.warn(f"Could not find user/group for PgBouncer: {e}")
            console.hint("PgBouncer may have permission issues at runtime")
        except OSError as e:
            console.warn(f"Could not set ownership on {run_dir}: {e}")

    # Write userlist.txt
    userlist = f'"postgres" "{pg_password}"\n'
    executor.write_file(
        pgb_dir / "userlist.txt",
        userlist,
        description="Write PgBouncer userlist",
        owner=svc_user,
        group=svc_group,
        permissions=0o640,
    )

    # Write pgbouncer.ini
    ini_content = jinja.get_template("pgbouncer/pgbouncer.ini.j2").render(
        pg_host="127.0.0.1",
        pg_port=5432,
        listen_port=config.get("port", 6432),
        listen_addr="0.0.0.0",
        auth_file="/etc/pgbouncer/userlist.txt",
        pid_file="/run/pgbouncer/pgbouncer.pid",
        admin_users=["postgres"],
        stats_users=["postgres"],
        pool_mode=config.get("pool_mode", "transaction"),
        max_client_conn=config.get("max_client_conn", 1000),
        default_pool_size=config.get("default_pool_size", 20),
        min_pool_size=config.get("min_pool_size", 5),
        reserve_pool_size=config.get("reserve_pool_size", 5),
    )
    executor.write_file(
        pgb_dir / "pgbouncer.ini",
        ini_content,
        description="Write PgBouncer config",
        owner=svc_user,
        group=svc_group,
        permissions=0o640,
    )

    # Restart and enable
    systemd.restart("pgbouncer.service")
    systemd.enable("pgbouncer.service")

    console.success("PgBouncer configured on port 6432")


def setup_pgbackrest(
    ctx: ExecutionContext,
    executor: CommandExecutor,
    version: str,
    backup_config: dict,
) -> None:
    """Configure pgBackRest for S3/B2 backups."""
    jinja = get_jinja_env()

    console.step("Configuring pgBackRest")

    # Create directories
    dirs = [
        Path("/etc/pgbackrest"),
        Path("/etc/pgbackrest/conf.d"),
        Path("/var/lib/pgbackrest"),
        Path("/var/log/pgbackrest"),
    ]

    if not ctx.dry_run:
        import os
        import pwd
        import grp

        # Get postgres user/group once
        try:
            uid = pwd.getpwnam("postgres").pw_uid
            gid = grp.getgrnam("postgres").gr_gid
        except KeyError as e:
            console.warn(f"Could not find postgres user/group: {e}")
            console.hint("pgBackRest may have permission issues")
            uid = None
            gid = None

        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
            if uid is not None and gid is not None:
                try:
                    os.chown(d, uid, gid)
                    os.chmod(d, 0o750)
                except OSError as e:
                    console.warn(f"Could not set permissions on {d}: {e}")

    # Store passphrase securely
    pass_file = Path("/etc/pgbackrest/repo1.pass")
    executor.write_file(
        pass_file,
        backup_config["passphrase"] + "\n",
        description="Store pgBackRest passphrase",
        owner="postgres",
        group="postgres",
        permissions=0o600,
    )

    # Write main config
    conf_content = jinja.get_template("pgbackrest/pgbackrest.conf.j2").render(
        repo_path=backup_config.get("repo_path", "/pgbackrest"),
        s3_bucket=backup_config["s3_bucket"],
        s3_endpoint=backup_config["s3_endpoint"],
        s3_region=backup_config["s3_region"],
        s3_key=backup_config["s3_key"],
        s3_secret=backup_config["s3_secret"],
        process_max=4,
        retention_full=53,  # 1 year of weekly
        retention_archive=60,
        passphrase_file=str(pass_file),
        stanza="main",
        pg_data_path=f"/var/lib/postgresql/{version}/main",
    )
    executor.write_file(
        Path("/etc/pgbackrest/pgbackrest.conf"),
        conf_content,
        description="Write pgBackRest config",
        owner="postgres",
        group="postgres",
        permissions=0o600,
    )

    # Write archive config for PostgreSQL
    pg_conf_dir = Path(f"/etc/postgresql/{version}/main/conf.d")
    archive_conf = jinja.get_template("postgresql/pgbackrest.conf.j2").render(stanza="main")
    executor.write_file(
        pg_conf_dir / "98-pgbackrest.conf",
        archive_conf,
        description="Write PostgreSQL archive config",
        owner="postgres",
        group="postgres",
        permissions=0o640,
    )

    # Write backup wrapper script
    script_content = jinja.get_template("pgbackrest/backup-script.sh.j2").render(stanza="main")
    executor.write_file(
        Path("/usr/local/sbin/pgbackrest-run.sh"),
        script_content,
        description="Write backup script",
        owner="postgres",
        group="postgres",
        permissions=0o750,
    )

    # Write cron schedule
    cron_content = jinja.get_template("pgbackrest/cron.j2").render()
    executor.write_file(
        Path("/etc/cron.d/pgbackrest-schedule"),
        cron_content,
        description="Write backup cron schedule",
        permissions=0o644,
    )

    console.success("pgBackRest configured")


def setup_stanza(
    ctx: ExecutionContext,
    executor: CommandExecutor,
    systemd: SystemdService,
    version: str,
) -> None:
    """Create pgBackRest stanza and run initial backup."""
    console.step("Creating pgBackRest stanza")

    if ctx.dry_run:
        console.dry_run_msg("Create stanza 'main' and run initial backup")
        return

    # Restart PostgreSQL to pick up archive config
    systemd.restart(f"postgresql@{version}-main.service")

    # Check if stanza exists
    result = executor.run(
        ["sudo", "-u", "postgres", "pgbackrest", "--stanza=main", "check"],
        check=False,
    )

    if result.success:
        console.info("Stanza 'main' already exists")
    else:
        # Create stanza
        executor.run(
            ["sudo", "-u", "postgres", "pgbackrest", "--stanza=main", "stanza-create"],
            description="Create pgBackRest stanza",
        )
        # Verify
        executor.run(
            ["sudo", "-u", "postgres", "pgbackrest", "--stanza=main", "check"],
            description="Verify stanza",
        )

    # Check for existing backup
    result = executor.run(
        ["sudo", "-u", "postgres", "pgbackrest", "--stanza=main", "info"],
        check=False,
    )

    if "backup:full" in result.stdout:
        console.info("Full backup already exists")
    else:
        console.step("Running initial full backup (this may take time)")
        executor.run(
            ["sudo", "-u", "postgres", "pgbackrest", "--stanza=main", "--type=full", "backup"],
            description="Initial full backup",
            timeout=3600,  # 1 hour timeout
        )


def run_setup(
    ctx: ExecutionContext,
    pg_version: str,
    pgbouncer_config: dict,
    backup_config: Optional[dict],
    skip_backup: bool,
) -> None:
    """Run the full PostgreSQL setup."""
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    creds = get_credential_manager()
    audit = get_audit_logger()

    try:
        # Install and configure PostgreSQL
        pg_password = setup_postgres(ctx, executor, systemd, pg_version, creds)

        # Configure PgBouncer
        setup_pgbouncer(ctx, executor, systemd, pg_password, pgbouncer_config)

        # Configure backups if enabled
        if not skip_backup and backup_config:
            setup_pgbackrest(ctx, executor, pg_version, backup_config)
            setup_stanza(ctx, executor, systemd, pg_version)

        # Verify PostgreSQL is running and accessible
        console.step("Verifying PostgreSQL installation")
        if not ctx.dry_run:
            result = executor.run(
                ["pg_isready", "-h", "127.0.0.1", "-p", "5432"],
                check=False,
                description="Check PostgreSQL is accepting connections",
            )
            if result.success:
                console.success("PostgreSQL is running and accepting connections")
            else:
                console.warn("PostgreSQL may not be fully ready yet")
                console.hint("Wait a moment and check with: pg_isready -h 127.0.0.1")

            # Verify PgBouncer
            pgb_port = pgbouncer_config.get("port", 6432)
            result = executor.run(
                ["pg_isready", "-h", "127.0.0.1", "-p", str(pgb_port)],
                check=False,
                description="Check PgBouncer is accepting connections",
            )
            if result.success:
                console.success(f"PgBouncer is running on port {pgb_port}")
            else:
                console.warn("PgBouncer may not be fully ready yet")
                console.hint(f"Check with: pg_isready -h 127.0.0.1 -p {pgb_port}")
        else:
            console.dry_run_msg("Would verify PostgreSQL and PgBouncer are running")

        # Log success
        audit.log_success(
            AuditEventType.CONFIG_MODIFY,
            "postgresql",
            f"postgresql-{pg_version}",
            message="PostgreSQL setup completed",
        )

        # Summary
        console.print()
        console.print("[bold green]PostgreSQL Setup Complete[/bold green]")
        console.print()
        console.summary(
            "Installation Summary",
            {
                "PostgreSQL version": pg_version,
                "PostgreSQL port": "5432 (localhost only)",
                "PgBouncer port": str(pgbouncer_config.get("port", 6432)),
                "Backups": "Enabled" if (not skip_backup and backup_config) else "Disabled",
                "Password file": str(creds.get_password_path("postgres", "_system")),
            },
        )

        console.print()
        console.warn("IMPORTANT: Configure your firewall!")
        console.print("  - Allow port 22/tcp (SSH) from your IP only")
        console.print("  - Allow port 6432/tcp (PgBouncer) from your application servers")
        console.print("  - DO NOT expose port 5432 to the internet")

    except Exception as e:
        audit.log_failure(
            AuditEventType.CONFIG_MODIFY,
            "postgresql",
            f"postgresql-{pg_version}",
            str(e),
        )
        raise


# Command is registered in cli.py but we define the function here
def postgres_setup_command(
    version: str = "18",
    pgbouncer_config: Optional[dict] = None,
    backup_config: Optional[dict] = None,
    skip_backup: bool = False,
    dry_run: bool = False,
    force: bool = False,
    yes: bool = False,
    verbose: int = 0,
) -> None:
    """PostgreSQL setup implementation."""
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)

    # Default configs
    if pgbouncer_config is None:
        pgbouncer_config = {"port": 6432, "pool_mode": "transaction"}

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    run_setup(ctx, version, pgbouncer_config, backup_config, skip_backup)
