"""PostgreSQL migration commands.

Commands:
- sm postgres migrate database  # Migrate single database between hosts
- sm postgres migrate cluster   # Migrate entire cluster
"""

import subprocess
import tempfile
from pathlib import Path

import typer

from sm.core import (
    AppConfig,
    AuditEventType,
    BackupError,
    CommandExecutor,
    ConfigurationError,
    ExecutionContext,
    ExecutionError,
    PrerequisiteError,
    SafetyError,
    SMError,
    ValidationError,
    console,
    create_context,
    get_audit_logger,
    require_force,
    require_root,
    run_preflight_checks,
)
from sm.core.validation import validate_identifier
from sm.services.pgdump import PgDumpService
from sm.services.s3 import S3Config, S3Service, verify_file_checksum

app = typer.Typer(
    name="migrate",
    help="PostgreSQL cross-host migration.",
    no_args_is_help=True,
)


def _get_s3_config(app_config: AppConfig) -> S3Config:
    """Create S3 config from app config."""
    if not app_config.has_backup_credentials():
        raise ConfigurationError(
            "S3 credentials not configured",
            hint="Set SM_B2_KEY, SM_B2_SECRET environment variables",
        )

    return S3Config(
        endpoint=app_config.backup.s3_endpoint or "",
        region=app_config.backup.s3_region or "",
        bucket=app_config.backup.s3_bucket or "",
        access_key=app_config.secrets.sm_b2_key or "",
        secret_key=app_config.secrets.sm_b2_secret or "",
    )


def _confirm_pg_credentials(
    app_config: AppConfig,
    skip_confirm: bool = False,
) -> tuple[str, int, str]:
    """Confirm PostgreSQL connection credentials with auto-filled defaults.

    Args:
        app_config: Application configuration
        skip_confirm: If True, return defaults without prompting

    Returns:
        Tuple of (host, port, pg_user)
    """
    # Auto-fill from config (which reads env vars)
    default_host = app_config.postgres.host
    default_port = app_config.postgres.port
    default_user = app_config.postgres.pg_user

    if skip_confirm:
        return default_host, default_port, default_user

    console.print("-> Confirm database connection:")

    # Interactive prompts with defaults
    host_input = console.input(f"  Host [[cyan]{default_host}[/cyan]]: ").strip()
    host = host_input if host_input else default_host

    port_input = console.input(f"  Port [[cyan]{default_port}[/cyan]]: ").strip()
    try:
        port = int(port_input) if port_input else default_port
    except ValueError:
        console.warn(f"Invalid port '{port_input}', using default {default_port}")
        port = default_port

    user_input = console.input(f"  Username [[cyan]{default_user}[/cyan]]: ").strip()
    user = user_input if user_input else default_user

    return host, port, user


def _run_remote_command(
    host: str,
    command: str,
    *,
    user: str = "root",
    check: bool = True,
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    """Run a command on a remote host via SSH.

    Args:
        host: Remote hostname
        command: Command to run
        user: SSH user
        check: Raise on non-zero exit
        timeout: Command timeout in seconds

    Returns:
        CompletedProcess result

    Raises:
        ExecutionError: If command fails
    """
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        f"{user}@{host}",
        command,
    ]

    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if check and result.returncode != 0:
            raise ExecutionError(
                f"Remote command failed on {host}",
                command=command,
                return_code=result.returncode,
                stderr=result.stderr,
            )

        return result

    except subprocess.TimeoutExpired as e:
        raise ExecutionError(
            f"Remote command timed out on {host}",
            command=command,
            hint=f"Increase timeout or check connectivity to {host}",
        ) from e
    except FileNotFoundError as e:
        raise PrerequisiteError(
            "SSH client not found",
            hint="Install openssh-client package",
        ) from e


def _check_remote_sm_installed(host: str, user: str = "root") -> bool:
    """Check if sm CLI is installed on remote host."""
    result = _run_remote_command(host, "which sm", user=user, check=False)
    return result.returncode == 0


@app.command("database")
@require_root
def migrate_database(
    database: str = typer.Option(
        ..., "--database", "-d",
        help="Database to migrate",
    ),
    source_host: str = typer.Option(
        ..., "--source-host",
        help="Source PostgreSQL host",
    ),
    target_database: str | None = typer.Option(
        None, "--target-database", "-t",
        help="Target database name (default: same as source)",
    ),
    source_port: int = typer.Option(5432, "--source-port"),
    source_user: str = typer.Option("postgres", "--source-user"),
    ssh_user: str = typer.Option("root", "--ssh-user", help="SSH user for remote commands"),
    via_s3: bool = typer.Option(
        True, "--via-s3/--direct",
        help="Route through S3 (safer) or direct pipe",
    ),
    compression: int = typer.Option(
        6, "--compression", "-z",
        help="Compression level (0-9)",
        min=0, max=9,
    ),
    jobs: int = typer.Option(
        4, "--jobs", "-j",
        help="Parallel jobs for dump/restore",
        min=1, max=16,
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite",
        help="Drop and recreate if target exists (creates safety backup first)",
    ),
    skip_safety_backup: bool = typer.Option(
        False, "--skip-safety-backup",
        help="Skip creating safety backup before overwrite (NOT recommended)",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", "-f", help="Required if --overwrite"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Migrate a database from another host.

    Supports two modes:
    - Via S3 (default): Export on source -> Upload S3 -> Download -> Import (safer)
    - Direct: pg_dump | pg_restore via SSH pipe (faster, requires connectivity)

    Examples:

        # Migrate via S3 (recommended for production)
        sm postgres migrate database -d myapp --source-host db-prod-01

        # Direct pipe (faster but requires connectivity)
        sm postgres migrate database -d myapp --source-host db-prod-01 --direct

        # With different target name
        sm postgres migrate database -d myapp --source-host db-prod-01 -t myapp_migrated

        # Overwrite existing
        sm postgres migrate database -d myapp --source-host db-prod-01 --overwrite --force
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    app_config = AppConfig()

    # Validate names
    try:
        validate_identifier(database, "database")
        if target_database:
            validate_identifier(target_database, "target database")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3) from None

    # Check overwrite requires force
    if overwrite and not force:
        raise SafetyError(
            "Overwrite requires --force flag",
            required_flags=["--force"],
        )

    # Check skip_safety_backup requires force
    if skip_safety_backup and not force:
        raise SafetyError(
            "--skip-safety-backup requires --force flag",
            required_flags=["--force"],
        )

    target_db = target_database or database

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Confirm database credentials (auto-filled, user can override)
    pg_host, pg_port, pg_user = _confirm_pg_credentials(app_config, skip_confirm=yes)

    # Get local services
    executor = CommandExecutor(ctx)
    pgdump = PgDumpService(
        ctx, executor,
        pg_host=pg_host,
        pg_port=pg_port,
        pg_user=pg_user,
    )

    # Check local pg_restore is available
    available, missing = pgdump.check_commands_available()
    if not available:
        raise PrerequisiteError(
            f"Required commands not found: {', '.join(missing)}",
            hint="Install postgresql-client package",
        )

    # Check PostgreSQL is running locally
    from sm.services.postgresql import PostgreSQLService
    pg = PostgreSQLService(ctx, executor)
    if not dry_run and not pg.is_running():
        raise PrerequisiteError(
            "PostgreSQL is not running on this host",
            hint="Start PostgreSQL with: systemctl start postgresql",
        )

    # Check target database and get size info for better messaging
    target_exists = not dry_run and pgdump.database_exists(target_db)
    target_size_info = None
    if target_exists:
        existing_dbs = pgdump.list_databases(exclude_system=False)
        target_size_info = next((db for db in existing_dbs if db.name == target_db), None)

        if not overwrite:
            console.print()
            console.print(f"[bold red]ERROR: Target database '{target_db}' already exists![/bold red]")
            if target_size_info:
                console.print(f"  Size: {target_size_info.size_pretty}")
            console.print()
            console.print("Options:")
            console.print(f"  1. Use --overwrite --force to replace it (creates safety backup)")
            console.print(f"  2. Use --target-database to migrate to a different name")
            console.print(f"     Example: --target-database {target_db}_migrated")
            raise typer.Exit(4)

    # Test SSH connectivity
    console.step(f"Testing SSH connectivity to {source_host}...")
    try:
        _run_remote_command(source_host, "echo ok", user=ssh_user)
        console.success("SSH connection OK")
    except ExecutionError as e:
        console.error(f"Cannot connect to {source_host}")
        console.print(f"  {e}")
        raise typer.Exit(5) from None

    # Show configuration
    console.print()
    console.print("[bold]Migration Configuration[/bold]")
    console.print(f"  Source Host:    {source_host}")
    console.print(f"  Source DB:      {database}")
    console.print(f"  Target DB:      {target_db}")
    console.print(f"  Method:         {'Via S3' if via_s3 else 'Direct pipe'}")
    console.print(f"  Compression:    {compression}")
    console.print(f"  Jobs:           {jobs}")

    if target_exists and overwrite:
        console.print()
        console.print("[bold yellow]⚠️  WARNING: Target database exists and will be REPLACED![/bold yellow]")
        if target_size_info:
            console.print(f"  Existing database size: {target_size_info.size_pretty}")
        if not skip_safety_backup:
            console.print("  A safety backup will be created before dropping.")
        else:
            console.print("[bold red]  ⚠️  Safety backup is DISABLED - data cannot be recovered![/bold red]")
    console.print()

    if not yes and not dry_run:
        if not console.confirm("Proceed with migration?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        if via_s3:
            _migrate_via_s3(
                ctx=ctx,
                app_config=app_config,
                source_host=source_host,
                database=database,
                target_db=target_db,
                source_port=source_port,
                source_user=source_user,
                ssh_user=ssh_user,
                compression=compression,
                jobs=jobs,
                overwrite=overwrite,
                skip_safety_backup=skip_safety_backup,
                pgdump=pgdump,
            )
        else:
            _migrate_direct(
                ctx=ctx,
                executor=executor,
                source_host=source_host,
                database=database,
                target_db=target_db,
                source_port=source_port,
                source_user=source_user,
                ssh_user=ssh_user,
                compression=compression,
                jobs=jobs,
                overwrite=overwrite,
                skip_safety_backup=skip_safety_backup,
                pgdump=pgdump,
            )

        console.print()
        console.success(f"Migration completed: {database} -> {target_db}")

        # Log audit event
        audit.log_success(
            AuditEventType.MIGRATE_DATABASE,
            target_type="database",
            target_name=target_db,
            message=f"Migrated from {source_host}:{database}",
        )

    except (BackupError, ExecutionError) as e:
        audit.log_failure(
            AuditEventType.MIGRATE_DATABASE,
            target_type="database",
            target_name=target_db,
            error=str(e),
        )
        console.error(str(e))
        raise typer.Exit(12) from None


def _migrate_via_s3(
    ctx: ExecutionContext,
    app_config: AppConfig,
    source_host: str,
    database: str,
    target_db: str,
    source_port: int,
    source_user: str,
    ssh_user: str,
    compression: int,
    jobs: int,
    overwrite: bool,
    skip_safety_backup: bool,
    pgdump: PgDumpService,
) -> None:
    """Migrate via S3 intermediate storage."""
    from sm.services.pgdump import format_bytes

    # Get S3 config
    s3_config = _get_s3_config(app_config)
    s3 = S3Service(ctx, s3_config)

    # Test S3 connectivity
    console.step("Testing S3 connectivity...")
    s3.test_connectivity()
    console.success("S3 connection OK")

    # Check if sm is installed on source
    if not _check_remote_sm_installed(source_host, ssh_user):
        raise PrerequisiteError(
            f"sm CLI is not installed on {source_host}",
            hint=f"Install sm on {source_host} first, or use --direct mode",
        )

    # Step 1: Export on source host
    console.step(f"Exporting database on {source_host}...")

    # Run export command on source
    export_cmd = f"sm postgres backup export -d {database} -z {compression} -j {jobs} -y"
    result = _run_remote_command(source_host, export_cmd, user=ssh_user, timeout=7200)

    # Parse the output to get the S3 path
    # Look for "Export completed: s3://..." in output
    export_path = None
    for line in result.stdout.split("\n"):
        if "Export completed:" in line:
            # Extract path from: "Export completed: s3://bucket/pg-exports/host/timestamp/"
            parts = line.split("Export completed:")
            if len(parts) > 1:
                export_path = parts[1].strip()
                break

    if not export_path:
        stdout_excerpt = (
            result.stdout[-500:] if len(result.stdout) > 500 else result.stdout
        )
        raise BackupError(
            "Could not determine export path from remote output",
            details=[stdout_excerpt],
        )

    console.success(f"Remote export completed: {export_path}")

    # Step 2: Download and restore locally
    # Parse the S3 path to get the key
    # s3://bucket/pg-exports/host/timestamp/ -> pg-exports/host/timestamp
    s3_prefix = export_path.replace(f"s3://{s3_config.bucket}/", "").rstrip("/")
    dump_key = f"{s3_prefix}/{database}.dump"
    manifest_key = f"{s3_prefix}/manifest.json"

    # Create temp directory
    with tempfile.TemporaryDirectory(prefix="sm-migrate-") as temp_dir:
        temp_path = Path(temp_dir)

        # Download dump
        console.step("Downloading dump file...")
        local_dump = temp_path / f"{database}.dump"
        s3.download_file(dump_key, local_dump)

        # Get manifest for checksum
        manifest = s3.download_json(manifest_key)
        db_info = next((db for db in manifest.get("databases", []) if db["name"] == database), None)
        expected_checksum = db_info.get("checksum") if db_info else None

        # Verify checksum
        if expected_checksum:
            console.step("Verifying checksum...")
            if not verify_file_checksum(local_dump, expected_checksum):
                raise BackupError("Checksum verification failed. The dump file may be corrupted.")
            console.success("Checksum OK")

        # Create safety backup before overwrite
        safety_backup_path = None
        if overwrite and pgdump.database_exists(target_db) and not skip_safety_backup:
            from datetime import datetime as dt
            safety_backup_path = temp_path / f"safety_backup_{target_db}_{dt.now():%Y%m%d_%H%M%S}.dump"
            console.step(f"Creating safety backup of '{target_db}'...")
            console.print(f"  Safety backup: {safety_backup_path}")
            try:
                pgdump.dump_database(target_db, safety_backup_path, compression_level=6, jobs=jobs)
                console.success(f"Safety backup created: {format_bytes(safety_backup_path.stat().st_size)}")
            except BackupError as e:
                console.error(f"Failed to create safety backup: {e}")
                console.print()
                console.print("[bold red]Cannot proceed without safety backup.[/bold red]")
                console.print("Use --skip-safety-backup --force if you want to proceed anyway (DANGEROUS)")
                raise

        # Drop existing if overwrite
        if overwrite and pgdump.database_exists(target_db):
            console.step(f"Dropping existing database '{target_db}'...")
            pgdump.drop_database(target_db, force=True)

        # Restore
        console.step(f"Restoring to '{target_db}'...")
        try:
            pgdump.restore_database(
                local_dump,
                target_db,
                create=True,
                jobs=jobs,
            )
        except BackupError as e:
            # If restore failed and we have a safety backup, show recovery instructions
            if safety_backup_path and safety_backup_path.exists():
                console.print()
                console.print("[bold yellow]Recovery Instructions:[/bold yellow]")
                console.print(f"  A safety backup exists at: {safety_backup_path}")
                console.print(f"  To restore it, run:")
                console.print(f"    pg_restore -h {app_config.postgres.host} -p {app_config.postgres.port} \\")
                console.print(f"      -U postgres -d postgres -C {safety_backup_path}")
                console.print()
                console.print("[bold]⚠️  Copy the safety backup NOW - it will be deleted when this command exits![/bold]")
            raise


def _migrate_direct(
    ctx: ExecutionContext,
    executor: CommandExecutor,
    source_host: str,
    database: str,
    target_db: str,
    source_port: int,
    source_user: str,
    ssh_user: str,
    compression: int,
    jobs: int,
    overwrite: bool,
    skip_safety_backup: bool,
    pgdump: PgDumpService,
) -> None:
    """Migrate via direct SSH pipe."""
    from sm.services.pgdump import format_bytes

    if ctx.dry_run:
        console.dry_run_msg("Would run: pg_dump | ssh | pg_restore pipeline")
        return

    # Create safety backup before overwrite
    safety_backup_path = None
    if overwrite and pgdump.database_exists(target_db) and not skip_safety_backup:
        import tempfile
        from datetime import datetime as dt
        # Create a temp file for safety backup (not in temp dir so it survives)
        safety_dir = Path(tempfile.gettempdir())
        safety_backup_path = safety_dir / f"safety_backup_{target_db}_{dt.now():%Y%m%d_%H%M%S}.dump"
        console.step(f"Creating safety backup of '{target_db}'...")
        console.print(f"  Safety backup: {safety_backup_path}")
        try:
            pgdump.dump_database(target_db, safety_backup_path, compression_level=6, jobs=jobs)
            console.success(f"Safety backup created: {format_bytes(safety_backup_path.stat().st_size)}")
        except BackupError as e:
            console.error(f"Failed to create safety backup: {e}")
            console.print()
            console.print("[bold red]Cannot proceed without safety backup.[/bold red]")
            console.print("Use --skip-safety-backup --force if you want to proceed anyway (DANGEROUS)")
            raise

    # Drop existing if overwrite
    if overwrite and pgdump.database_exists(target_db):
        console.step(f"Dropping existing database '{target_db}'...")
        pgdump.drop_database(target_db, force=True)

    # Create target database
    if not pgdump.database_exists(target_db):
        console.step(f"Creating database '{target_db}'...")
        executor.run(
            ["psql", "-c", f'CREATE DATABASE "{target_db}";'],
            description=f"Create database {target_db}",
            check=True,
            as_user="postgres",
        )

    # Build the pipeline command
    # pg_dump on remote | pg_restore locally
    console.step("Running migration pipeline...")

    dump_cmd = (
        f"pg_dump -h {source_host} -p {source_port} -U {source_user} "
        f"-d {database} -Fc -Z{compression}"
    )
    restore_cmd = f"pg_restore -d {target_db} -j {jobs}"

    # Use ssh to run pg_dump on source and pipe to local pg_restore
    pipeline = (
        f"ssh {ssh_user}@{source_host} 'PGPASSWORD= {dump_cmd}' | "
        f"sudo -u postgres {restore_cmd}"
    )

    try:
        # Shell required for pipe operation between remote pg_dump and local pg_restore
        result = subprocess.run(  # noqa: S602
            pipeline,
            shell=True,
            capture_output=True,
            text=True,
            timeout=7200,  # 2 hour timeout
        )

        # pg_restore often returns non-zero for warnings
        if result.returncode != 0:
            stderr_lower = result.stderr.lower()
            if "error:" in stderr_lower or "fatal:" in stderr_lower:
                raise ExecutionError(
                    "Migration pipeline failed",
                    stderr=result.stderr,
                )
            else:
                console.warn("Migration completed with warnings")
                if ctx.is_verbose and result.stderr:
                    console.verbose(result.stderr)

    except subprocess.TimeoutExpired as e:
        raise ExecutionError(
            "Migration pipeline timed out",
            hint="Database may be too large for direct migration. Try --via-s3",
        ) from e


@app.command("cluster")
@require_root
@require_force("Cluster migration is a major operation")
def migrate_cluster(
    source_host: str = typer.Option(
        ..., "--source-host",
        help="Source PostgreSQL host",
    ),
    ssh_user: str = typer.Option("root", "--ssh-user", help="SSH user for remote commands"),
    include_globals: bool = typer.Option(
        True, "--globals/--no-globals",
        help="Include roles and tablespaces",
    ),
    exclude_databases: list[str] | None = typer.Option(
        None, "--exclude",
        help="Databases to exclude from migration",
    ),
    skip_existing: bool = typer.Option(
        False, "--skip-existing",
        help="Skip databases that already exist locally (default: error)",
    ),
    overwrite_existing: bool = typer.Option(
        False, "--overwrite-existing",
        help="Overwrite databases that already exist locally (creates safety backup)",
    ),
    compression: int = typer.Option(
        6, "--compression", "-z",
        help="Compression level (0-9)",
        min=0, max=9,
    ),
    jobs: int = typer.Option(
        4, "--jobs", "-j",
        help="Parallel jobs for dump/restore",
        min=1, max=16,
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", "-f", help="Required for this operation"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Migrate entire PostgreSQL cluster from another host.

    Migrates all databases, roles, and global objects.
    Uses S3 as intermediate storage.

    Default excludes: template0, template1

    Example:

        sm postgres migrate cluster --source-host db-prod-01 --force
        sm postgres migrate cluster --source-host db-prod-01 --exclude analytics --force
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    app_config = AppConfig()

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Confirm database credentials (auto-filled, user can override)
    pg_host, pg_port, pg_user = _confirm_pg_credentials(app_config, skip_confirm=yes)

    # Get services
    executor = CommandExecutor(ctx)
    pgdump = PgDumpService(
        ctx, executor,
        pg_host=pg_host,
        pg_port=pg_port,
        pg_user=pg_user,
    )

    # Check pg_restore is available
    available, missing = pgdump.check_commands_available()
    if not available:
        raise PrerequisiteError(
            f"Required commands not found: {', '.join(missing)}",
            hint="Install postgresql-client package",
        )

    # Check PostgreSQL is running locally
    from sm.services.postgresql import PostgreSQLService
    pg = PostgreSQLService(ctx, executor)
    if not dry_run and not pg.is_running():
        raise PrerequisiteError(
            "PostgreSQL is not running on this host",
            hint="Start PostgreSQL with: systemctl start postgresql",
        )

    # Test SSH connectivity
    console.step(f"Testing SSH connectivity to {source_host}...")
    try:
        _run_remote_command(source_host, "echo ok", user=ssh_user)
        console.success("SSH connection OK")
    except ExecutionError as e:
        console.error(f"Cannot connect to {source_host}")
        raise typer.Exit(5) from e

    # Check sm installed on source
    if not _check_remote_sm_installed(source_host, ssh_user):
        raise PrerequisiteError(
            f"sm CLI is not installed on {source_host}",
            hint=f"Install sm on {source_host} first",
        )

    # Get S3 config
    try:
        s3_config = _get_s3_config(app_config)
        s3 = S3Service(ctx, s3_config)
        s3.test_connectivity()
    except (ConfigurationError, BackupError) as e:
        console.error(str(e))
        raise typer.Exit(2) from None

    # Get database list from source
    console.step("Fetching database list from source...")
    db_query = (
        "psql -t -A -c \"SELECT datname FROM pg_database "
        "WHERE datistemplate = false AND datname != 'postgres' ORDER BY datname;\""
    )
    result = _run_remote_command(source_host, db_query, user=ssh_user)
    source_databases = [db.strip() for db in result.stdout.strip().split("\n") if db.strip()]

    # Apply exclusions
    default_exclude = {"template0", "template1"}
    if exclude_databases:
        default_exclude.update(exclude_databases)
    databases_to_migrate = [db for db in source_databases if db not in default_exclude]

    if not databases_to_migrate:
        console.warn("No databases to migrate")
        raise typer.Exit(0)

    # Check for existing databases locally
    local_dbs = pgdump.list_databases(exclude_system=False)
    local_db_names = {db.name for db in local_dbs}
    existing_conflicts = [db for db in databases_to_migrate if db in local_db_names]

    if existing_conflicts and not skip_existing and not overwrite_existing:
        console.print()
        console.print("[bold red]ERROR: Some databases already exist locally![/bold red]")
        console.print()
        for db in existing_conflicts:
            db_info = next((d for d in local_dbs if d.name == db), None)
            size_str = f" ({db_info.size_pretty})" if db_info else ""
            console.print(f"  - {db}{size_str}")
        console.print()
        console.print("Options:")
        console.print("  1. Use --skip-existing to skip these databases")
        console.print("  2. Use --overwrite-existing --force to overwrite them (creates safety backup)")
        console.print("  3. Use --exclude <db> to exclude specific databases")
        raise typer.Exit(4)

    # Validate conflicting options
    if skip_existing and overwrite_existing:
        console.error("Cannot use both --skip-existing and --overwrite-existing")
        raise typer.Exit(3)

    # Show configuration
    console.print()
    console.print("[bold]Cluster Migration Configuration[/bold]")
    console.print(f"  Source Host:    {source_host}")
    console.print(f"  Databases:      {len(databases_to_migrate)} total")
    console.print(f"  Include Globals: {'Yes' if include_globals else 'No'}")
    console.print(f"  Compression:    {compression}")
    if existing_conflicts:
        if skip_existing:
            console.print(f"  Existing DBs:   Will SKIP {len(existing_conflicts)} existing")
        elif overwrite_existing:
            console.print(f"  Existing DBs:   Will OVERWRITE {len(existing_conflicts)} existing (with safety backup)")
    console.print()

    console.print("[bold yellow]Databases to migrate:[/bold yellow]")
    for db in databases_to_migrate:
        if db in existing_conflicts:
            if skip_existing:
                console.print(f"  - {db} [yellow](SKIP - exists)[/yellow]")
            elif overwrite_existing:
                console.print(f"  - {db} [red](OVERWRITE - exists)[/red]")
        else:
            console.print(f"  - {db}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm("Proceed with cluster migration?", default=False):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        # Step 1: Export all databases on source
        console.step(f"Exporting all databases on {source_host}...")
        export_cmd = f"sm postgres backup export -z {compression} -j {jobs} -y"
        if exclude_databases:
            for db in exclude_databases:
                export_cmd += f" -e {db}"

        result = _run_remote_command(source_host, export_cmd, user=ssh_user, timeout=14400)

        # Parse export path
        export_path = None
        for line in result.stdout.split("\n"):
            if "Export completed:" in line:
                parts = line.split("Export completed:")
                if len(parts) > 1:
                    export_path = parts[1].strip()
                    break

        if not export_path:
            raise BackupError("Could not determine export path")

        console.success(f"Remote export completed: {export_path}")

        # Step 2: Download and restore each database
        s3_prefix = export_path.replace(f"s3://{s3_config.bucket}/", "").rstrip("/")

        with tempfile.TemporaryDirectory(prefix="sm-migrate-cluster-") as temp_dir:
            temp_path = Path(temp_dir)

            # Restore globals first if requested
            if include_globals:
                globals_key = f"{s3_prefix}/globals.sql"
                if s3.object_exists(globals_key):
                    console.step("Restoring global objects...")
                    local_globals = temp_path / "globals.sql"
                    s3.download_file(globals_key, local_globals)
                    pgdump.restore_globals(local_globals)

            # Track progress
            migrated = []
            skipped = []
            failed = []

            # Restore each database
            for db_name in databases_to_migrate:
                console.step(f"Migrating database '{db_name}'...")

                dump_key = f"{s3_prefix}/{db_name}.dump"
                if not s3.object_exists(dump_key):
                    console.warn(f"  Skipping {db_name}: dump file not found in export")
                    skipped.append((db_name, "not in export"))
                    continue

                # Download
                local_dump = temp_path / f"{db_name}.dump"
                s3.download_file(dump_key, local_dump)

                # Handle existing database
                if pgdump.database_exists(db_name):
                    if skip_existing:
                        console.warn(f"  Skipping {db_name}: already exists locally")
                        skipped.append((db_name, "exists locally"))
                        local_dump.unlink()
                        continue
                    elif overwrite_existing:
                        # Create safety backup
                        from datetime import datetime as dt
                        from sm.services.pgdump import format_bytes
                        safety_backup = temp_path / f"safety_{db_name}_{dt.now():%Y%m%d_%H%M%S}.dump"
                        console.print(f"  Creating safety backup of '{db_name}'...")
                        try:
                            pgdump.dump_database(db_name, safety_backup, compression_level=6, jobs=jobs)
                            console.print(f"  Safety backup: {safety_backup} ({format_bytes(safety_backup.stat().st_size)})")
                        except BackupError as e:
                            console.error(f"  Failed to create safety backup for {db_name}: {e}")
                            console.warn(f"  Skipping {db_name} for safety")
                            skipped.append((db_name, "safety backup failed"))
                            local_dump.unlink()
                            continue
                        # Drop existing
                        console.print(f"  Dropping existing database '{db_name}'...")
                        pgdump.drop_database(db_name, force=True)

                # Restore
                try:
                    pgdump.restore_database(
                        local_dump,
                        db_name,
                        create=True,
                        jobs=jobs,
                    )
                    console.success(f"  Migrated {db_name}")
                    migrated.append(db_name)
                except BackupError as e:
                    console.error(f"  Failed to migrate {db_name}: {e}")
                    failed.append((db_name, str(e)))

                # Clean up dump file to save space
                local_dump.unlink()

        # Print summary
        console.print()
        console.print("[bold]Migration Summary[/bold]")
        console.print(f"  Migrated:  {len(migrated)}")
        console.print(f"  Skipped:   {len(skipped)}")
        console.print(f"  Failed:    {len(failed)}")

        if migrated:
            console.print()
            console.print("[green]Successfully migrated:[/green]")
            for db in migrated:
                console.print(f"  ✓ {db}")

        if skipped:
            console.print()
            console.print("[yellow]Skipped:[/yellow]")
            for db, reason in skipped:
                console.print(f"  - {db}: {reason}")

        if failed:
            console.print()
            console.print("[red]Failed:[/red]")
            for db, error in failed:
                console.print(f"  ✗ {db}: {error}")

        console.print()
        if failed:
            console.warn(f"Cluster migration completed with {len(failed)} failures")
        else:
            console.success(f"Cluster migration completed: {len(migrated)} databases migrated")

        # Log audit event
        audit.log_success(
            AuditEventType.MIGRATE_CLUSTER,
            target_type="cluster",
            target_name=source_host,
            message=f"Migrated {len(migrated)} databases, skipped {len(skipped)}, failed {len(failed)}",
        )

    except (BackupError, ExecutionError) as e:
        audit.log_failure(
            AuditEventType.MIGRATE_CLUSTER,
            target_type="cluster",
            target_name=source_host,
            error=str(e),
        )
        console.error(str(e))
        raise typer.Exit(12) from None


@app.command("wizard")
def migrate_wizard_cmd(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Interactive migration wizard using S3 for coordination.

    Migrate a PostgreSQL database between two hosts without SSH.
    Uses S3 as intermediate storage and coordination mechanism.

    Run on BOTH the source and target hosts - uses a shared session code
    to coordinate the migration.

    \b
    How it works:
      1. Run wizard on TARGET host - creates a session code
      2. Run wizard on SOURCE host - enter the code
      3. SOURCE exports database to S3
      4. TARGET auto-detects and imports

    \b
    Examples:
        # On target host (creates session)
        sm postgres migrate wizard

        # On source host (joins with code)
        sm postgres migrate wizard
    """
    from sm.commands.postgres.migrate_wizard import MigrationWizard

    try:
        wizard = MigrationWizard(
            dry_run=dry_run,
            verbose=verbose,
        )
        wizard.run()
    except SMError as e:
        console.error(str(e))
        if e.hint:
            console.hint(e.hint)
        raise typer.Exit(e.exit_code) from None
