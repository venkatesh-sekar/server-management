"""MongoDB database management commands.

Commands:
- sm mongodb db create
- sm mongodb db create-with-user
- sm mongodb db list
- sm mongodb db drop
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.table import Table

from sm.core import (
    console,
    create_context,
    CommandExecutor,
    get_credential_manager,
    get_audit_logger,
    AuditEventType,
    require_root,
    require_force,
    run_preflight_checks,
    ValidationError,
    MongoDBError,
)
from sm.core.validation import validate_identifier
from sm.services.mongodb import MongoDBService
from sm.services.mongodump import format_bytes


app = typer.Typer(
    name="db",
    help="MongoDB database management.",
    no_args_is_help=True,
)


# Protected system databases
PROTECTED_DATABASES = {"admin", "config", "local"}


def _get_services(ctx):
    """Create service instances and load credentials."""
    executor = CommandExecutor(ctx)
    mongo = MongoDBService(ctx, executor)

    # Load admin credentials
    creds = get_credential_manager()
    admin_pass = creds.get_password("admin", "_mongodb")
    if admin_pass:
        mongo.set_admin_credentials("admin", admin_pass)

    return executor, mongo


@app.command("create")
@require_root
def create_database(
    name: str = typer.Option(
        ..., "--database", "-d",
        help="Database name",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Create a MongoDB database.

    Creates a new empty database.

    Examples:

        sm mongodb db create -d myapp
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
    audit = get_audit_logger()

    # Validate
    try:
        validate_identifier(name, "database")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, mongo = _get_services(ctx)

    # Check if database exists
    if mongo.database_exists(name):
        console.info(f"Database '{name}' already exists")
        return

    # Confirmation
    console.print()
    console.print("[bold]Configuration[/bold]")
    console.print(f"  Database: {name}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"Create database '{name}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        with executor.transaction() as rollback:
            mongo.create_database(name, rollback=rollback)
            rollback.commit()

        audit.log_success(
            AuditEventType.DATABASE_CREATE,
            "database",
            name,
        )

    except MongoDBError as e:
        audit.log_failure(AuditEventType.DATABASE_CREATE, "database", name, str(e))
        console.error(str(e))
        raise typer.Exit(16)


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
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Create a database with a new owner user.

    This is the recommended way to create databases. It:
    - Creates a new user with dbOwner role on the database
    - Creates the database
    - Auto-generates a secure password
    - Stores the password securely

    Examples:

        sm mongodb db create-with-user -d myapp

        sm mongodb db create-with-user -d myapp -u custom_user
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
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
    executor, mongo = _get_services(ctx)

    # Ensure password
    if password:
        final_password = password
    else:
        final_password, _ = creds.ensure_password(username, database, dry_run=dry_run)

    # Confirmation
    console.print()
    console.print("[bold]Configuration[/bold]")
    console.print(f"  Database: {database}")
    console.print(f"  User:     {username} (dbOwner)")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"Create database '{database}' with user '{username}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        with executor.transaction() as rollback:
            # Create user with dbOwner role on the target database
            mongo.create_user(
                username,
                final_password,
                database="admin",  # Auth database
                roles=[{"role": "dbOwner", "db": database}],
                rollback=rollback,
            )

            # Create database
            mongo.create_database(database, rollback=rollback)

            # Verify connection
            mongo.verify_connection(database, username, final_password)

            rollback.commit()

        # Store password
        if not dry_run:
            creds.store_password(final_password, username, database)

        audit.log_success(
            AuditEventType.DATABASE_CREATE,
            "database",
            database,
            message=f"Database created with owner {username}",
        )

        pass_file = creds.get_password_path(username, database)
        console.print()
        console.summary(
            "Database and User Created",
            {
                "Database": database,
                "User": f"{username} (dbOwner)",
                "Password file": str(pass_file),
                "Connection": f"mongodb://{username}:***@127.0.0.1:27017/{database}?authSource=admin",
            },
            success=True,
        )

    except MongoDBError as e:
        audit.log_failure(AuditEventType.DATABASE_CREATE, "database", database, str(e))
        console.error(str(e))
        raise typer.Exit(16)


@app.command("list")
@require_root
def list_databases(
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """List all MongoDB databases.

    Shows database names and sizes.

    Examples:

        sm mongodb db list
    """
    ctx = create_context(verbose=verbose)
    executor, mongo = _get_services(ctx)

    databases = mongo.list_databases()

    if not databases:
        console.info("No user databases found")
        return

    table = Table(title="MongoDB Databases", show_header=True)
    table.add_column("Database", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Empty")

    for db in databases:
        size_str = format_bytes(db.size_on_disk)
        table.add_row(
            db.name,
            size_str,
            "Yes" if db.is_empty else "No",
        )

    console.print(table)


@app.command("drop")
@require_root
@require_force("Dropping databases permanently deletes all data")
def drop_database(
    name: str = typer.Option(
        ..., "--database", "-d",
        help="Database name",
    ),
    confirm_name: Optional[str] = typer.Option(
        None, "--confirm-name",
        help="Confirm database name to drop",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow dangerous operation"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Drop a MongoDB database.

    WARNING: This permanently deletes all data in the database!

    Requires --force and --confirm-name for safety.

    Examples:

        sm mongodb db drop -d testdb --force --confirm-name=testdb
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()

    # Validate
    try:
        validate_identifier(name, "database")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Require --confirm-name
    if confirm_name != name:
        console.error(f"--confirm-name must match database name '{name}'")
        raise typer.Exit(4)

    # Protect system databases
    if name in PROTECTED_DATABASES:
        console.error(f"Cannot drop system database '{name}'")
        raise typer.Exit(4)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, mongo = _get_services(ctx)

    # Check if database exists
    if not mongo.database_exists(name):
        console.info(f"Database '{name}' does not exist")
        return

    # Serious warning
    console.print()
    console.print("[bold red]CRITICAL: Database Deletion[/bold red]")
    console.print(f"  Database: {name}")
    console.print("[red]This will PERMANENTLY DELETE all data![/red]")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"[red]Drop database '{name}'?[/red]", default=False):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        mongo.drop_database(name)

        audit.log_success(AuditEventType.DATABASE_DROP, "database", name)
        console.success(f"Database '{name}' dropped")

    except MongoDBError as e:
        audit.log_failure(AuditEventType.DATABASE_DROP, "database", name, str(e))
        console.error(str(e))
        raise typer.Exit(16)
