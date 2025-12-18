"""MongoDB user management commands.

Commands:
- sm mongodb user create
- sm mongodb user list
- sm mongodb user rotate-password
- sm mongodb user delete
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


app = typer.Typer(
    name="user",
    help="MongoDB user management.",
    no_args_is_help=True,
)


# Protected users
PROTECTED_USERS = {"admin"}


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
def create_user(
    username: str = typer.Option(
        ..., "--user", "-u",
        help="Username",
    ),
    database: str = typer.Option(
        "admin", "--database", "-d",
        help="Authentication database",
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p",
        help="Password (auto-generated if not provided)",
        hide_input=True,
    ),
    role: Optional[str] = typer.Option(
        None, "--role", "-r",
        help="Role to grant (e.g., readWrite, dbOwner)",
    ),
    role_db: Optional[str] = typer.Option(
        None, "--role-db",
        help="Database for the role (defaults to --database)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Create a MongoDB user.

    Creates a user with SCRAM-SHA-256 authentication.

    Examples:

        sm mongodb user create -u myuser

        sm mongodb user create -u appuser -r readWrite --role-db myapp
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    creds = get_credential_manager()

    # Validate
    try:
        validate_identifier(username, "username")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, mongo = _get_services(ctx)

    # Build roles
    roles = []
    if role:
        roles.append({"role": role, "db": role_db or database})

    # Ensure password
    if password:
        final_password = password
    else:
        final_password, _ = creds.ensure_password(username, database, dry_run=dry_run)

    # Confirmation
    roles_display = ", ".join(f"{r['role']}@{r['db']}" for r in roles) if roles else "None"
    console.print()
    console.print("[bold]Configuration[/bold]")
    console.print(f"  User:     {username}")
    console.print(f"  Auth DB:  {database}")
    console.print(f"  Roles:    {roles_display}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"Create user '{username}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        with executor.transaction() as rollback:
            mongo.create_user(
                username,
                final_password,
                database=database,
                roles=roles,
                rollback=rollback,
            )
            rollback.commit()

        if not dry_run:
            creds.store_password(final_password, username, database)

        audit.log_success(AuditEventType.USER_CREATE, "user", username)

        console.print()
        console.summary(
            "User Created",
            {
                "User": username,
                "Auth DB": database,
                "Roles": roles_display,
                "Password file": str(creds.get_password_path(username, database)),
            },
        )

    except MongoDBError as e:
        audit.log_failure(AuditEventType.USER_CREATE, "user", username, str(e))
        console.error(str(e))
        raise typer.Exit(16)


@app.command("list")
@require_root
def list_users(
    database: str = typer.Option(
        "admin", "--database", "-d",
        help="Authentication database",
    ),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """List MongoDB users.

    Shows users in the specified authentication database.

    Examples:

        sm mongodb user list

        sm mongodb user list -d myapp
    """
    ctx = create_context(verbose=verbose)
    executor, mongo = _get_services(ctx)

    users = mongo.list_users(database)

    if not users:
        console.info(f"No users found in database '{database}'")
        return

    table = Table(title=f"MongoDB Users (auth db: {database})", show_header=True)
    table.add_column("Username", style="cyan")
    table.add_column("Auth DB")
    table.add_column("Roles")

    for user in users:
        roles_str = ", ".join(f"{r['role']}@{r['db']}" for r in user.roles) or "-"
        table.add_row(user.name, user.database, roles_str)

    console.print(table)


@app.command("rotate-password")
@require_root
def rotate_password(
    username: str = typer.Option(
        ..., "--user", "-u",
        help="Username",
    ),
    database: str = typer.Option(
        "admin", "--database", "-d",
        help="Authentication database",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Rotate password for a MongoDB user.

    Generates a new secure password and updates the user.

    Examples:

        sm mongodb user rotate-password -u myuser

        sm mongodb user rotate-password -u appuser -d myapp
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    creds = get_credential_manager()

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, mongo = _get_services(ctx)

    # Check user exists
    if not mongo.user_exists(username, database):
        console.error(f"User '{username}' does not exist in database '{database}'")
        raise typer.Exit(1)

    # Confirmation
    if not yes and not dry_run:
        if not console.confirm(f"Rotate password for '{username}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        new_password, backup_path = creds.rotate_password(username, database, dry_run=dry_run)

        if backup_path:
            console.info(f"Previous password backed up to: {backup_path}")

        mongo.rotate_password(username, new_password, database)

        audit.log_success(AuditEventType.PASSWORD_ROTATE, "user", username)

        console.print()
        console.summary(
            "Password Rotated",
            {
                "User": username,
                "Auth DB": database,
                "Password file": str(creds.get_password_path(username, database)),
            },
        )

    except MongoDBError as e:
        audit.log_failure(AuditEventType.PASSWORD_ROTATE, "user", username, str(e))
        console.error(str(e))
        raise typer.Exit(16)


@app.command("delete")
@require_root
@require_force("Deleting users is a dangerous operation")
def delete_user(
    username: str = typer.Option(
        ..., "--user", "-u",
        help="Username",
    ),
    database: str = typer.Option(
        "admin", "--database", "-d",
        help="Authentication database",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow dangerous operation"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Delete a MongoDB user.

    Requires --force flag for safety.

    Examples:

        sm mongodb user delete -u olduser --force
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbose=verbose)
    audit = get_audit_logger()
    creds = get_credential_manager()

    # Protect admin user
    if username in PROTECTED_USERS:
        console.error(f"Cannot delete protected user '{username}'")
        raise typer.Exit(4)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, mongo = _get_services(ctx)

    # Check user exists
    if not mongo.user_exists(username, database):
        console.info(f"User '{username}' does not exist")
        return

    # Serious warning
    console.print()
    console.print("[bold red]DANGER: User Deletion[/bold red]")
    console.print(f"  User: {username}")
    console.print(f"  Auth DB: {database}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"[red]Delete user '{username}'?[/red]", default=False):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        mongo.drop_user(username, database)
        creds.delete_password(username, database, secure=True, dry_run=dry_run)

        audit.log_success(AuditEventType.USER_DELETE, "user", username)
        console.success(f"User '{username}' deleted")

    except MongoDBError as e:
        audit.log_failure(AuditEventType.USER_DELETE, "user", username, str(e))
        console.error(str(e))
        raise typer.Exit(16)
