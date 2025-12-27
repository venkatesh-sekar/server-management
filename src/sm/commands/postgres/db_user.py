"""PostgreSQL database + user combo operations.

Commands:
- sm postgres db-user create         # Create database with owner user
- sm postgres db-user grant          # Grant user access to database
- sm postgres db-user grant-readonly # Create/grant readonly user for database
"""

from enum import Enum

import typer

from sm.core import (
    AuditEventType,
    CommandExecutor,
    ExecutionContext,
    PostgresError,
    ValidationError,
    console,
    create_context,
    get_audit_logger,
    get_credential_manager,
    require_root,
    run_preflight_checks,
)
from sm.core.validation import validate_identifier
from sm.services.pgbouncer import PgBouncerService
from sm.services.postgresql import PostgreSQLService
from sm.services.systemd import SystemdService


class AccessLevel(str, Enum):
    """Database access levels."""
    READONLY = "readonly"
    READWRITE = "readwrite"


app = typer.Typer(
    name="db-user",
    help="PostgreSQL database + user combo operations.",
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
def create_database_with_user(
    database: str = typer.Option(
        ..., "--database", "-d",
        help="Database name",
    ),
    username: str | None = typer.Option(
        None, "--user", "-u",
        help="Username (default: <database>_user)",
    ),
    password: str | None = typer.Option(
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

        sm postgres db-user create -d myapp

        sm postgres db-user create -d myapp -u myapp_admin

        sm postgres db-user create -d myapp --with-pgvector

        sm postgres db-user create -d myapp --dry-run
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

        sm postgres db-user grant -d myapp -u reader --access readonly

        sm postgres db-user grant -d myapp -u writer --access readwrite
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


@app.command("grant-readonly")
@require_root
def grant_readonly_user(
    database: str = typer.Option(
        ..., "--database", "-d",
        help="Database name (must exist)",
    ),
    username: str | None = typer.Option(
        None, "--user", "-u",
        help="Username (default: <database>_readonly)",
    ),
    password: str | None = typer.Option(
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

    If the user already exists, grants/verifies read-only access.

    Examples:

        sm postgres db-user grant-readonly -d myapp

        sm postgres db-user grant-readonly -d myapp -u analytics
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
