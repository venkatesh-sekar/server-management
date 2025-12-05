"""PostgreSQL user management commands.

Commands:
- sm postgres user create
- sm postgres user list
- sm postgres user rotate-password
- sm postgres user delete
"""

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
    check_not_protected_user,
    DangerLevel,
    ValidationError,
    PostgresError,
)
from sm.core.validation import validate_identifier
from sm.services.postgresql import PostgreSQLService
from sm.services.pgbouncer import PgBouncerService
from sm.services.systemd import SystemdService


app = typer.Typer(
    name="user",
    help="PostgreSQL user management.",
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
def create_user(
    username: str = typer.Option(
        ..., "--user", "-u",
        help="Username to create",
    ),
    database: Optional[str] = typer.Option(
        None, "--database", "-d",
        help="Database name (for password file organization)",
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p",
        help="Password (auto-generated if not provided)",
        hide_input=True,
    ),
    superuser: bool = typer.Option(
        False, "--superuser",
        help="Grant superuser privileges (DANGEROUS)",
    ),
    createdb: bool = typer.Option(
        False, "--createdb",
        help="Allow creating databases",
    ),
    skip_pgbouncer: bool = typer.Option(
        False, "--skip-pgbouncer",
        help="Skip PgBouncer configuration",
    ),
    # Global options from context
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow dangerous operations"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Create a new PostgreSQL user.

    Creates a user with SCRAM-SHA-256 authentication and optionally
    configures PgBouncer.

    Examples:

        sm postgres user create -u myapp_user

        sm postgres user create -u admin --superuser --force

        sm postgres user create -u service -d myapp --skip-pgbouncer
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbosity=verbose)
    audit = get_audit_logger()
    creds = get_credential_manager()

    # Validate
    try:
        validate_identifier(username, "username")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Safety check for superuser
    if superuser and not force:
        console.error("Creating superuser requires --force flag")
        raise typer.Exit(4)

    # Run preflight checks
    run_preflight_checks(ctx)

    # Get services
    executor, pg, pgb = _get_services(ctx)

    # Check if user exists
    if pg.user_exists(username) and not force:
        console.error(f"User '{username}' already exists. Use --force to update.")
        raise typer.Exit(1)

    # Confirmation
    console.print()
    console.print("[bold]Configuration[/bold]")
    console.print(f"  User:       {username}")
    console.print(f"  Superuser:  {'Yes' if superuser else 'No'}")
    console.print(f"  CreateDB:   {'Yes' if createdb else 'No'}")
    console.print(f"  PgBouncer:  {'Skipped' if skip_pgbouncer else 'Enabled'}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"Create user '{username}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    # Ensure password
    if password:
        final_password = password
        generated = False
    else:
        final_password, generated = creds.ensure_password(username, database, dry_run=dry_run)
        if generated:
            console.info("Generated new secure password")

    try:
        # Create user
        with executor.transaction() as rollback:
            pg.create_user(
                username,
                final_password,
                superuser=superuser,
                createdb=createdb,
                rollback=rollback,
            )

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
            message=f"User created with {'superuser' if superuser else 'normal'} privileges",
        )

        # Summary
        console.print()
        console.summary(
            "User Created",
            {
                "User": username,
                "Password file": str(creds.get_password_path(username, database)),
            },
            success=True,
        )

        if not dry_run:
            console.print()
            console.print("[dim]Note: Use 'sm postgres grant' to grant database access[/dim]")

    except PostgresError as e:
        audit.log_failure(AuditEventType.USER_CREATE, "user", username, str(e))
        console.error(str(e))
        raise typer.Exit(10)


@app.command("list")
@require_root
def list_users(
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """List all PostgreSQL users.

    Shows all database users/roles with their privileges.

    Example:

        sm postgres user list
    """
    ctx = create_context(verbosity=verbose)

    # Get services
    executor, pg, _ = _get_services(ctx)

    users = pg.list_users()

    if not users:
        console.info("No users found")
        return

    # Build table
    table = Table(title="PostgreSQL Users", show_header=True)
    table.add_column("Username", style="cyan")
    table.add_column("Login", justify="center")
    table.add_column("Superuser", justify="center")
    table.add_column("CreateDB", justify="center")
    table.add_column("Connections")
    table.add_column("Member Of")

    for user in users:
        table.add_row(
            user.name,
            "[green]✓[/green]" if user.login else "[red]✗[/red]",
            "[yellow]✓[/yellow]" if user.superuser else "",
            "[green]✓[/green]" if user.create_db else "",
            str(user.connections) if user.connections >= 0 else "unlimited",
            ", ".join(user.roles) if user.roles else "-",
        )

    console.print(table)


@app.command("rotate-password")
@require_root
def rotate_password(
    username: str = typer.Option(
        ..., "--user", "-u",
        help="Username",
    ),
    database: Optional[str] = typer.Option(
        None, "--database", "-d",
        help="Database name (for password file organization)",
    ),
    skip_pgbouncer: bool = typer.Option(
        False, "--skip-pgbouncer",
        help="Skip PgBouncer configuration update",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow dangerous operations"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Rotate password for a PostgreSQL user.

    Generates a new secure password, updates PostgreSQL and PgBouncer,
    and stores the new password in the secure credential store.

    Example:

        sm postgres user rotate-password -u myapp_user

        sm postgres user rotate-password -u myapp_user -d myapp
    """
    ctx = create_context(dry_run=dry_run, force=force, yes=yes, verbosity=verbose)
    audit = get_audit_logger()
    creds = get_credential_manager()

    # Validate
    try:
        validate_identifier(username, "username")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Run preflight checks
    run_preflight_checks(ctx)

    # Get services
    executor, pg, pgb = _get_services(ctx)

    # Check user exists
    if not pg.user_exists(username):
        console.error(f"User '{username}' does not exist")
        raise typer.Exit(1)

    # Confirmation
    console.print()
    console.print("[bold]Password Rotation[/bold]")
    console.print(f"  User:      {username}")
    console.print(f"  PgBouncer: {'Skipped' if skip_pgbouncer else 'Enabled'}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"Rotate password for '{username}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        # Rotate password
        new_password, backup_path = creds.rotate_password(username, database, dry_run=dry_run)

        if backup_path:
            console.info(f"Previous password backed up to: {backup_path}")

        # Update PostgreSQL
        pg.rotate_password(username, new_password)

        # Update PgBouncer
        if not skip_pgbouncer and pgb.is_installed():
            scram_hash = pg.get_scram_hash(username)
            if scram_hash:
                pgb.update_userlist(username, scram_hash)
                pgb.reload()

        # Log success
        audit.log_success(
            AuditEventType.PASSWORD_ROTATE,
            "user",
            username,
        )

        # Summary
        console.print()
        console.summary(
            "Password Rotated",
            {
                "User": username,
                "Password file": str(creds.get_password_path(username, database)),
            },
            success=True,
        )

    except PostgresError as e:
        audit.log_failure(AuditEventType.PASSWORD_ROTATE, "user", username, str(e))
        console.error(str(e))
        raise typer.Exit(10)


@app.command("delete")
@require_root
@require_force(DangerLevel.DANGEROUS)
def delete_user(
    username: str = typer.Option(
        ..., "--user", "-u",
        help="Username to delete",
    ),
    confirm_name: Optional[str] = typer.Option(
        None, "--confirm-name",
        help="Confirm username to delete (required for protected users)",
    ),
    skip_pgbouncer: bool = typer.Option(
        False, "--skip-pgbouncer",
        help="Skip PgBouncer cleanup",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    force: bool = typer.Option(False, "--force", help="Allow dangerous operations"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Delete a PostgreSQL user.

    DANGEROUS: This permanently removes the user from PostgreSQL.

    Example:

        sm postgres user delete -u old_user --force

        sm postgres user delete -u admin --force --confirm-name=admin
    """
    ctx = create_context(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbosity=verbose,
        confirm_name=confirm_name,
    )
    audit = get_audit_logger()
    creds = get_credential_manager()

    # Validate
    try:
        validate_identifier(username, "username")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Check protected user
    try:
        check_not_protected_user(username, ctx)
    except Exception as e:
        console.error(str(e))
        audit.log_blocked("delete_user", str(e), "user", username)
        raise typer.Exit(4)

    # Run preflight checks
    run_preflight_checks(ctx)

    # Get services
    executor, pg, pgb = _get_services(ctx)

    # Check user exists
    if not pg.user_exists(username):
        console.info(f"User '{username}' does not exist")
        return

    # Confirmation
    console.print()
    console.print("[bold red]⚠️  DANGER: User Deletion[/bold red]")
    console.print(f"  User: {username}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"[red]Delete user '{username}'?[/red]", default=False):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        # Remove from PgBouncer first
        if not skip_pgbouncer and pgb.is_installed():
            pgb.remove_from_userlist(username)
            pgb.reload()

        # Drop user
        pg.drop_user(username)

        # Delete credential file
        creds.delete_password(username, secure=True, dry_run=dry_run)

        # Log success
        audit.log_success(
            AuditEventType.USER_DELETE,
            "user",
            username,
        )

        console.print()
        console.success(f"User '{username}' deleted")

    except PostgresError as e:
        audit.log_failure(AuditEventType.USER_DELETE, "user", username, str(e))
        console.error(str(e))
        raise typer.Exit(10)
