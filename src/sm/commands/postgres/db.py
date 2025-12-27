"""PostgreSQL database management commands.

Commands:
- sm postgres db create
- sm postgres db create-with-user
- sm postgres db list
- sm postgres db grant
- sm postgres db drop
- sm postgres db reset
"""

from enum import Enum
from typing import Optional

import typer
from rich.table import Table

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
    require_force,
    run_preflight_checks,
    check_not_protected_database,
    DangerLevel,
    ValidationError,
    PostgresError,
)
from sm.core.validation import validate_identifier
from sm.services.postgresql import PostgreSQLService
from sm.services.pgbouncer import PgBouncerService
from sm.services.systemd import SystemdService
from sm.commands.postgres.ownership import ownership_command, transfer_ownership_command


class AccessLevel(str, Enum):
    """Database access levels."""
    READONLY = "readonly"
    READWRITE = "readwrite"


app = typer.Typer(
    name="db",
    help="PostgreSQL database management.",
    no_args_is_help=True,
)


def _get_services(ctx: ExecutionContext) -> tuple[CommandExecutor, PostgreSQLService, PgBouncerService]:
    """Create service instances."""
    executor = CommandExecutor(ctx)
    systemd = SystemdService(ctx, executor)
    pg = PostgreSQLService(ctx, executor)
    pgb = PgBouncerService(ctx, executor, systemd)
    return executor, pg, pgb


@app.command("create")
@require_root
def create_database(
    name: str = typer.Option(
        ..., "--database", "-d",
        help="Database name",
    ),
    owner: Optional[str] = typer.Option(
        None, "--owner", "-o",
        help="Owner username (existing user)",
    ),
    with_pgvector: bool = typer.Option(
        False, "--with-pgvector",
        help="Enable pgvector extension for vector similarity search",
    ),
    skip_pgbouncer: bool = typer.Option(
        False, "--skip-pgbouncer",
        help="Skip PgBouncer configuration",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow updating existing database"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Create a PostgreSQL database.

    Creates a new database, optionally assigning an existing user as owner.

    Examples:

        sm postgres db create -d myapp

        sm postgres db create -d myapp -o existing_user

        sm postgres db create -d embeddings --with-pgvector
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()

    # Validate
    try:
        validate_identifier(name, "database")
        if owner:
            validate_identifier(owner, "owner")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, pg, pgb = _get_services(ctx)

    # Check if database exists
    if pg.database_exists(name) and not force:
        console.error(f"Database '{name}' already exists. Use --force to update.")
        raise typer.Exit(1)

    # Check owner exists
    if owner and not pg.user_exists(owner):
        console.error(f"Owner '{owner}' does not exist. Create the user first.")
        raise typer.Exit(1)

    # Confirmation
    console.print()
    console.print("[bold]Configuration[/bold]")
    console.print(f"  Database:  {name}")
    console.print(f"  Owner:     {owner or 'postgres (default)'}")
    console.print(f"  pgvector:  {'Enabled' if with_pgvector else 'Disabled'}")
    console.print(f"  PgBouncer: {'Skipped' if skip_pgbouncer else 'Enabled'}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"Create database '{name}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        with executor.transaction() as rollback:
            # Create database
            pg.create_database(name, owner=owner, rollback=rollback)

            # Harden if owner specified
            if owner:
                pg.harden_database(name, owner)

            # Enable pgvector if requested
            if with_pgvector:
                pg.install_extension_package("vector")
                pg.enable_extension(name, "vector", rollback=rollback)

            # Update PgBouncer
            if not skip_pgbouncer and pgb.is_installed():
                pgb.add_database(name)
                pgb.reload()

            rollback.commit()

        # Log success
        audit.log_success(
            AuditEventType.DATABASE_CREATE,
            "database",
            name,
            message=f"Database created with owner {owner or 'postgres'}"
                    + (", pgvector enabled" if with_pgvector else ""),
        )

        # Summary
        summary_data = {
            "Database": name,
            "Owner": owner or "postgres",
        }
        if with_pgvector:
            summary_data["pgvector"] = "Enabled"

        console.print()
        console.summary(
            "Database Created",
            summary_data,
        )

    except PostgresError as e:
        audit.log_failure(AuditEventType.DATABASE_CREATE, "database", name, str(e))
        console.error(str(e))
        raise typer.Exit(10)


@app.command("create-with-user")
@require_root
def create_database_with_user(
    database: str = typer.Option(
        ..., "--database", "-d",
        help="Database name",
    ),
    username: Optional[str] = typer.Option(
        None, "--user", "-u",
        help="Username (default: <database>_user)",
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p",
        help="Password (auto-generated if not provided)",
        hide_input=True,
    ),
    with_pgvector: bool = typer.Option(
        False, "--with-pgvector",
        help="Enable pgvector extension for vector similarity search",
    ),
    skip_pgbouncer: bool = typer.Option(
        False, "--skip-pgbouncer",
        help="Skip PgBouncer configuration",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow updating existing resources"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Create a database with a new owner user.

    This is the most common operation - creates a database and a user
    with full ownership. The database is hardened with minimal public
    privileges.

    Examples:

        sm postgres db create-with-user -d myapp

        sm postgres db create-with-user -d myapp -u myapp_admin

        sm postgres db create-with-user -d myapp --with-pgvector

        sm postgres db create-with-user -d myapp --dry-run
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    creds = get_credential_manager()

    # Default username
    if not username:
        username = f"{database}_user"

    # Validate
    try:
        validate_identifier(database, "database")
        validate_identifier(username, "username")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, pg, pgb = _get_services(ctx)

    # Check if already exists
    if pg.database_exists(database) and not force:
        console.error(f"Database '{database}' already exists. Use --force to update.")
        raise typer.Exit(1)

    # Ensure password
    if password:
        final_password = password
        generated = False
    else:
        final_password, generated = creds.ensure_password(username, database, dry_run=dry_run)
        if generated:
            console.info("Generated new secure password")

    # Confirmation
    console.print()
    console.print("[bold]Configuration[/bold]")
    console.print(f"  Database:  {database}")
    console.print(f"  User:      {username} (owner)")
    console.print(f"  pgvector:  {'Enabled' if with_pgvector else 'Disabled'}")
    console.print(f"  PgBouncer: {'Skipped' if skip_pgbouncer else 'Enabled'}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"Create database '{database}' with owner '{username}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        with executor.transaction() as rollback:
            # Create user first
            pg.create_user(username, final_password, rollback=rollback)

            # Create database
            pg.create_database(database, owner=username, rollback=rollback)

            # Harden database
            pg.harden_database(database, username)

            # Enable pgvector if requested
            if with_pgvector:
                pg.install_extension_package("vector")
                pg.enable_extension(database, "vector", rollback=rollback)

            # Verify connection
            pg.verify_connection(database, username, final_password)

            # Update PgBouncer
            if not skip_pgbouncer and pgb.is_installed():
                scram_hash = pg.get_scram_hash(username)
                if scram_hash:
                    pgb.update_userlist(username, scram_hash)
                pgb.add_database(database)
                pgb.reload()

            rollback.commit()

        # Store password
        if not dry_run:
            creds.store_password(final_password, username, database)

        # Log success
        audit.log_success(
            AuditEventType.DATABASE_CREATE,
            "database",
            database,
            message=f"Database created with owner {username}"
                    + (", pgvector enabled" if with_pgvector else ""),
        )

        # Summary
        pass_file = creds.get_password_path(username, database)
        summary_data = {
            "Database": database,
            "User": f"{username} (owner)",
            "Password file": str(pass_file),
            "Direct connection": f"postgresql://{username}:***@127.0.0.1:5432/{database}",
        }
        if with_pgvector:
            summary_data["pgvector"] = "Enabled"

        console.print()
        console.summary(
            "Database and User Created",
            summary_data,
        )

        if not skip_pgbouncer and pgb.is_installed():
            console.print(f"  PgBouncer: postgresql://{username}:***@127.0.0.1:6432/{database}")

    except PostgresError as e:
        audit.log_failure(AuditEventType.DATABASE_CREATE, "database", database, str(e))
        console.error(str(e))
        raise typer.Exit(10)


@app.command("list")
@require_root
def list_databases(
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """List all PostgreSQL databases.

    Shows all databases with their owners, sizes, and tablespaces.

    Example:

        sm postgres db list
    """
    ctx = create_context(verbose=verbose)

    # Get services
    executor, pg, _ = _get_services(ctx)

    databases = pg.list_databases()

    if not databases:
        console.info("No databases found")
        return

    # Build table
    table = Table(title="PostgreSQL Databases", show_header=True)
    table.add_column("Database", style="cyan")
    table.add_column("Owner")
    table.add_column("Encoding")
    table.add_column("Size", justify="right")
    table.add_column("Tablespace")

    for db in databases:
        table.add_row(
            db.name,
            db.owner,
            db.encoding,
            db.size,
            db.tablespace,
        )

    console.print(table)


@app.command("grant")
@require_root
def grant_access(
    database: str = typer.Option(
        ..., "--database", "-d",
        help="Database name",
    ),
    username: str = typer.Option(
        ..., "--user", "-u",
        help="Username to grant access",
    ),
    access: AccessLevel = typer.Option(
        AccessLevel.READONLY, "--access", "-a",
        help="Access level",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Grant a user access to a database.

    Grants either read-only (SELECT) or read-write (SELECT/INSERT/UPDATE/DELETE)
    access to all tables in the database.

    Examples:

        sm postgres db grant -d myapp -u reader --access readonly

        sm postgres db grant -d myapp -u writer --access readwrite
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
    audit = get_audit_logger()

    # Validate
    try:
        validate_identifier(database, "database")
        validate_identifier(username, "username")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, pg, _ = _get_services(ctx)

    # Check database exists
    if not pg.database_exists(database):
        console.error(f"Database '{database}' does not exist")
        raise typer.Exit(1)

    # Check user exists
    if not pg.user_exists(username):
        console.error(f"User '{username}' does not exist")
        raise typer.Exit(1)

    # Confirmation
    console.print()
    console.print("[bold]Grant Configuration[/bold]")
    console.print(f"  Database: {database}")
    console.print(f"  User:     {username}")
    console.print(f"  Access:   {access.value}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"Grant {access.value} access on '{database}' to '{username}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        if access == AccessLevel.READONLY:
            pg.grant_readonly(database, username)
        else:
            pg.grant_readwrite(database, username)

        # Log success
        audit.log_success(
            AuditEventType.USER_GRANT,
            "database",
            database,
            message=f"Granted {access.value} access to {username}",
        )

        console.print()
        console.summary(
            "Access Granted",
            {
                "Database": database,
                "User": username,
                "Access": access.value,
            },
        )

    except PostgresError as e:
        audit.log_failure(AuditEventType.USER_GRANT, "database", database, str(e))
        console.error(str(e))
        raise typer.Exit(10)


@app.command("create-readonly-user")
@require_root
def create_readonly_user(
    database: str = typer.Option(
        ..., "--database", "-d",
        help="Database name (must exist)",
    ),
    username: Optional[str] = typer.Option(
        None, "--user", "-u",
        help="Username (default: <database>_readonly)",
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p",
        help="Password (auto-generated if not provided)",
        hide_input=True,
    ),
    skip_pgbouncer: bool = typer.Option(
        False, "--skip-pgbouncer",
        help="Skip PgBouncer configuration",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Create a read-only user for an existing database.

    Creates a new user with SELECT-only access to all tables.
    Useful for analytics, reporting, or read replicas.

    Examples:

        sm postgres db create-readonly-user -d myapp

        sm postgres db create-readonly-user -d myapp -u analytics
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    creds = get_credential_manager()

    # Default username
    if not username:
        username = f"{database}_readonly"

    # Validate
    try:
        validate_identifier(database, "database")
        validate_identifier(username, "username")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, pg, pgb = _get_services(ctx)

    # Check database exists
    if not pg.database_exists(database):
        console.error(f"Database '{database}' does not exist")
        raise typer.Exit(1)

    # Check if user already exists (idempotency)
    user_exists = pg.user_exists(username)

    if user_exists:
        console.info(f"User '{username}' already exists")
        console.info("Ensuring read-only grants are correct...")

        try:
            # Just ensure grants are correct
            pg.grant_readonly(database, username)

            # Update PgBouncer if needed
            if not skip_pgbouncer and pgb.is_installed():
                scram_hash = pg.get_scram_hash(username)
                if scram_hash:
                    pgb.update_userlist(username, scram_hash)
                pgb.reload()

            # Log success
            audit.log_success(
                AuditEventType.USER_GRANT,
                "user",
                username,
                message=f"Read-only grants verified for {database} (user already exists)",
            )

            console.print()
            console.summary(
                "Read-Only Access Verified",
                {
                    "Database": database,
                    "User": f"{username} (read-only)",
                    "Status": "User exists, grants verified",
                },
            )
            return

        except PostgresError as e:
            audit.log_failure(AuditEventType.USER_GRANT, "user", username, str(e))
            console.error(str(e))
            raise typer.Exit(10)

    # User doesn't exist - proceed with creation
    # Ensure password
    if password:
        final_password = password
    else:
        final_password, _ = creds.ensure_password(username, database, dry_run=dry_run)

    # Confirmation
    console.print()
    console.print("[bold]Configuration[/bold]")
    console.print(f"  Database:  {database}")
    console.print(f"  User:      {username} (read-only)")
    console.print(f"  PgBouncer: {'Skipped' if skip_pgbouncer else 'Enabled'}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"Create read-only user '{username}' for '{database}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        with executor.transaction() as rollback:
            # Create user
            pg.create_user(username, final_password, rollback=rollback)

            # Grant read-only access
            pg.grant_readonly(database, username)

            # Verify connection
            pg.verify_connection(database, username, final_password)

            # Update PgBouncer
            if not skip_pgbouncer and pgb.is_installed():
                scram_hash = pg.get_scram_hash(username)
                if scram_hash:
                    pgb.update_userlist(username, scram_hash)
                pgb.reload()

            rollback.commit()

        # Store password
        if not dry_run:
            creds.store_password(final_password, username, database)

        # Log success
        audit.log_success(
            AuditEventType.USER_CREATE,
            "user",
            username,
            message=f"Read-only user created for {database}",
        )

        # Summary
        pass_file = creds.get_password_path(username, database)
        console.print()
        console.summary(
            "Read-Only User Created",
            {
                "Database": database,
                "User": f"{username} (read-only)",
                "Password file": str(pass_file),
            },
        )

    except PostgresError as e:
        audit.log_failure(AuditEventType.USER_CREATE, "user", username, str(e))
        console.error(str(e))
        raise typer.Exit(10)


@app.command("drop")
@require_root
@require_force("Dropping databases permanently deletes all data")
def drop_database(
    name: str = typer.Option(
        ..., "--database", "-d",
        help="Database name to drop",
    ),
    confirm_name: Optional[str] = typer.Option(
        None, "--confirm-name",
        help="Confirm database name (required)",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow dangerous operations"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Drop a PostgreSQL database.

    CRITICAL: This permanently deletes all data in the database!

    Requires --force AND --confirm-name=<database> for safety.

    Example:

        sm postgres db drop -d testdb --force --confirm-name=testdb
    """
    ctx = create_context(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
        confirm_name=confirm_name,
    )
    audit = get_audit_logger()

    # Validate
    try:
        validate_identifier(name, "database")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Check confirm-name matches
    if confirm_name != name:
        console.error(f"--confirm-name must match database name '{name}'")
        console.error(f"Use: --confirm-name={name}")
        raise typer.Exit(4)

    # Check protected database
    try:
        check_not_protected_database(name)
    except Exception as e:
        console.error(str(e))
        audit.log_blocked("drop_database", str(e), "database", name)
        raise typer.Exit(4)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, pg, pgb = _get_services(ctx)

    # Check database exists
    if not pg.database_exists(name):
        console.info(f"Database '{name}' does not exist")
        return

    # Confirmation
    console.print()
    console.print("[bold red]⚠️  CRITICAL: Database Deletion[/bold red]")
    console.print(f"  Database: {name}")
    console.print()
    console.print("[red]This will PERMANENTLY DELETE all data![/red]")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"[red]Drop database '{name}'?[/red]", default=False):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        # Remove from PgBouncer first
        if pgb.is_installed():
            pgb.remove_database(name)
            pgb.reload()

        # Drop database
        pg.drop_database(name, force=True)

        # Log success
        audit.log_success(
            AuditEventType.DATABASE_DROP,
            "database",
            name,
        )

        console.print()
        console.success(f"Database '{name}' dropped")

    except PostgresError as e:
        audit.log_failure(AuditEventType.DATABASE_DROP, "database", name, str(e))
        console.error(str(e))
        raise typer.Exit(10)


@app.command("reset")
@require_root
@require_force("Resetting databases permanently deletes all data including tables, views, functions, and triggers")
def reset_database(
    name: str = typer.Option(
        ..., "--database", "-d",
        help="Database name to reset",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow dangerous operations"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Reset a PostgreSQL database by dropping ALL objects.

    CRITICAL: This permanently deletes ALL data, tables, views, functions,
    triggers, sequences, types, indexes, and extensions. The database name
    and user permissions are preserved.

    Requires interactive confirmation where you must TYPE the database name.
    This cannot be automated - it requires manual human input.

    No backup is created - ensure you have your own backup before proceeding.

    Example:

        sm postgres db reset -d testdb --force

        # Preview what would be dropped

        sm postgres db reset -d testdb --dry-run
    """
    ctx = create_context(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
    )
    audit = get_audit_logger()

    # Validate database name
    try:
        validate_identifier(name, "database")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Safety check: protected database
    try:
        check_not_protected_database(name)
    except Exception as e:
        console.error(str(e))
        audit.log_blocked("reset_database", str(e), "database", name)
        raise typer.Exit(4)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, pg, pgb = _get_services(ctx)

    # Check database exists
    if not pg.database_exists(name):
        console.error(f"Database '{name}' does not exist")
        raise typer.Exit(1)

    # Get object details for display
    details = pg._get_object_details(name) if not dry_run else {}
    total_objects = sum(len(v) for v in details.values()) if details else 0

    # Display warning and summary
    console.print()
    console.print("[bold red]" + "=" * 60 + "[/bold red]")
    console.print("[bold red]  CRITICAL: DATABASE RESET OPERATION[/bold red]")
    console.print("[bold red]" + "=" * 60 + "[/bold red]")
    console.print()
    console.print(f"  Database: [bold]{name}[/bold]")
    console.print()

    # Helper to display objects with names
    def _display_objects(label: str, items: list[str]) -> None:
        console.print(f"  [bold]{label}[/bold] ({len(items)}):")
        for item in items:
            console.print(f"    [red]-[/red] {item}")
        console.print()

    if details:
        console.print("[bold]Objects to be PERMANENTLY DELETED:[/bold]")
        console.print()
        if details.get("tables"):
            _display_objects("Tables", details["tables"])
        if details.get("views"):
            _display_objects("Views", details["views"])
        if details.get("materialized_views"):
            _display_objects("Materialized Views", details["materialized_views"])
        if details.get("indexes"):
            _display_objects("Indexes", details["indexes"])
        if details.get("sequences"):
            _display_objects("Sequences", details["sequences"])
        if details.get("functions"):
            _display_objects("Functions", details["functions"])
        if details.get("triggers"):
            _display_objects("Triggers", details["triggers"])
        if details.get("types"):
            _display_objects("Custom Types", details["types"])
        if details.get("extensions"):
            _display_objects("Extensions", details["extensions"])
        console.print(f"[bold red]TOTAL: {total_objects} objects will be deleted[/bold red]")
    elif not dry_run:
        console.print("  [dim]No objects found in database (may already be empty)[/dim]")

    console.print()
    console.print("[bold yellow]WARNING: No backup will be created![/bold yellow]")
    console.print("[yellow]Ensure you have your own backup before proceeding.[/yellow]")
    console.print()
    console.print("[bold red]" + "=" * 60 + "[/bold red]")
    console.print()

    # Safety check: Interactive confirmation requiring exact name
    if not yes and not dry_run:
        if not console.confirm_critical(
            operation=f"reset database '{name}' (DELETE ALL {total_objects} OBJECTS)",
            resource_name=name,
        ):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        # Execute reset
        pg.reset_database(name, force=True)

        # Log success
        audit.log_success(
            AuditEventType.DATABASE_MODIFY,
            "database",
            name,
            message=f"Database reset: {total_objects} objects dropped",
        )

        # Summary
        console.print()
        console.success(f"Database '{name}' reset successfully")
        console.print(f"  Objects dropped: {total_objects}")
        console.print(f"  Status: All schemas recreated empty")

    except PostgresError as e:
        audit.log_failure(AuditEventType.DATABASE_MODIFY, "database", name, str(e))
        console.error(str(e))
        raise typer.Exit(10)


# Register ownership commands
app.command("ownership")(ownership_command)
app.command("transfer-ownership")(transfer_ownership_command)
