"""PostgreSQL extension management commands.

Commands:
- sm postgres extension enable
- sm postgres extension list
"""

import typer
from rich.table import Table

from sm.core import (
    console,
    ExecutionContext,
    create_context,
    CommandExecutor,
    get_audit_logger,
    AuditEventType,
    require_root,
    run_preflight_checks,
    PostgresError,
)
from sm.core.validation import validate_identifier
from sm.services.postgresql import PostgreSQLService, EXTENSION_PACKAGES
from sm.services.systemd import SystemdService


app = typer.Typer(
    name="extension",
    help="PostgreSQL extension management.",
    no_args_is_help=True,
)


def _get_services(ctx: ExecutionContext) -> tuple[CommandExecutor, PostgreSQLService]:
    """Create service instances."""
    executor = CommandExecutor(ctx)
    pg = PostgreSQLService(ctx, executor)
    return executor, pg


@app.command("enable")
@require_root
def enable_extension(
    database: str = typer.Option(
        ..., "--database", "-d",
        help="Database name",
    ),
    extension: str = typer.Option(
        "vector", "--extension", "-e",
        help=f"Extension name (supported: {', '.join(sorted(EXTENSION_PACKAGES.keys()))})",
    ),
    schema: str = typer.Option(
        "public", "--schema", "-s",
        help="Schema to install the extension into",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmations"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Enable an extension on a database.

    Installs the required system package and enables the extension.

    Examples:

        sm postgres extension enable -d myapp

        sm postgres extension enable -d myapp -e vector

        sm postgres extension enable -d myapp --dry-run
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
    audit = get_audit_logger()

    # Validate
    try:
        validate_identifier(database, "database")
    except Exception as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, pg = _get_services(ctx)

    # Check database exists
    if not pg.database_exists(database):
        console.error(f"Database '{database}' does not exist")
        raise typer.Exit(1)

    # Check if extension is already enabled
    if pg.extension_exists(database, extension):
        console.info(f"Extension '{extension}' already enabled on '{database}'")
        return

    # Confirmation
    console.print()
    console.print("[bold]Configuration[/bold]")
    console.print(f"  Database:  {database}")
    console.print(f"  Extension: {extension}")
    console.print(f"  Schema:    {schema}")
    console.print()

    if not yes and not dry_run:
        if not console.confirm(f"Enable extension '{extension}' on '{database}'?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        with executor.transaction() as rollback:
            # Install the extension package
            pg.install_extension_package(extension)

            # Enable the extension
            pg.enable_extension(database, extension, schema=schema, rollback=rollback)

            rollback.commit()

        # Log success
        audit.log_success(
            AuditEventType.EXTENSION_ENABLE,
            "extension",
            f"{database}/{extension}",
            message=f"Extension '{extension}' enabled on database '{database}'",
        )

        # Summary
        console.print()
        console.summary(
            "Extension Enabled",
            {
                "Database": database,
                "Extension": extension,
                "Schema": schema,
            },
            success=True,
        )

    except PostgresError as e:
        audit.log_failure(AuditEventType.EXTENSION_ENABLE, "extension", f"{database}/{extension}", str(e))
        console.error(str(e))
        raise typer.Exit(10)


@app.command("list")
@require_root
def list_extensions(
    database: str = typer.Option(
        ..., "--database", "-d",
        help="Database name",
    ),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """List enabled extensions on a database.

    Shows all installed extensions with their versions and schemas.

    Example:

        sm postgres extension list -d myapp
    """
    ctx = create_context(verbose=verbose)

    # Validate
    try:
        validate_identifier(database, "database")
    except Exception as e:
        console.error(str(e))
        raise typer.Exit(3)

    # Get services
    executor, pg = _get_services(ctx)

    # Check database exists
    if not pg.database_exists(database):
        console.error(f"Database '{database}' does not exist")
        raise typer.Exit(1)

    extensions = pg.list_extensions(database)

    if not extensions:
        console.info(f"No extensions enabled on '{database}'")
        return

    # Build table
    table = Table(title=f"Extensions on '{database}'", show_header=True)
    table.add_column("Extension", style="cyan")
    table.add_column("Version")
    table.add_column("Schema")

    for ext in extensions:
        table.add_row(ext.name, ext.version, ext.schema)

    console.print(table)
