"""PostgreSQL ownership management commands.

Commands:
- sm postgres db ownership <database>  - View ownership of all objects
- sm postgres db transfer-ownership <database> --to <owner>  - Transfer ownership
"""


import typer
from rich.table import Table

from sm.core import (
    CommandExecutor,
    PostgresError,
    ValidationError,
    console,
    create_context,
    require_root,
    run_preflight_checks,
)
from sm.core.context import ExecutionContext
from sm.core.validation import validate_identifier
from sm.services.ownership import DatabaseObject, OwnershipService
from sm.services.postgresql import PostgreSQLService


def _get_services(
    ctx: ExecutionContext,
) -> tuple[CommandExecutor, PostgreSQLService, OwnershipService]:
    """Create service instances."""
    executor = CommandExecutor(ctx)
    pg = PostgreSQLService(ctx, executor)
    ownership = OwnershipService(ctx, executor)
    return executor, pg, ownership


def _parse_object_types(type_str: str | None) -> list[str] | None:
    """Parse comma-separated object types into a list."""
    if not type_str:
        return None
    return [t.strip().lower().replace(" ", "_") for t in type_str.split(",") if t.strip()]


def _interactive_select(
    objects: list[DatabaseObject],
    new_owner: str,
) -> list[DatabaseObject]:
    """Interactive multi-select for objects to transfer.

    Falls back to simple numbered selection if InquirerPy is not available.
    """
    # Filter out objects already owned by new_owner
    transferable = [obj for obj in objects if obj.owner != new_owner]

    if not transferable:
        console.info(f"All objects are already owned by '{new_owner}'")
        return []

    try:
        from InquirerPy import inquirer  # type: ignore[import-not-found]
        from InquirerPy.separator import Separator  # type: ignore[import-not-found]

        # Group by object type for better UX
        choices = []
        current_type = None

        for obj in sorted(transferable, key=lambda o: (o.object_type, o.schema, o.name)):
            if obj.object_type != current_type:
                if current_type is not None:
                    choices.append(Separator())
                current_type = obj.object_type
                choices.append(Separator(f"── {obj.object_type.upper().replace('_', ' ')}S ──"))

            label = f"{obj.display_name} [dim](owner: {obj.owner})[/dim]"
            choices.append({"name": label, "value": obj, "enabled": True})

        console.print()
        console.print(f"[bold]Select objects to transfer to '{new_owner}':[/bold]")
        console.print("[dim]Use space to toggle, enter to confirm, ctrl+c to cancel[/dim]")
        console.print()

        selected = inquirer.checkbox(
            message="",
            choices=choices,
            transformer=lambda x: f"{len(x)} selected",
            instruction="(space: toggle, a: all, n: none, enter: confirm)",
        ).execute()

        return selected if selected else []

    except ImportError:
        # Fallback to simple numbered selection
        return _simple_select(transferable, new_owner)


def _simple_select(
    objects: list[DatabaseObject],
    new_owner: str,
) -> list[DatabaseObject]:
    """Simple numbered selection fallback when InquirerPy is not available."""
    console.print()
    console.print(f"[bold]Objects available for transfer to '{new_owner}':[/bold]")
    console.print()

    # Group by type
    by_type: dict[str, list[tuple[int, DatabaseObject]]] = {}
    for i, obj in enumerate(objects, 1):
        if obj.object_type not in by_type:
            by_type[obj.object_type] = []
        by_type[obj.object_type].append((i, obj))

    for obj_type, items in sorted(by_type.items()):
        console.print(f"[bold]{obj_type.upper().replace('_', ' ')}S:[/bold]")
        for idx, obj in items:
            console.print(f"  [{idx}] {obj.display_name} (owner: {obj.owner})")
        console.print()

    console.print("Enter object numbers to transfer (comma-separated, 'all' for all, 'q' to quit):")
    selection = input("> ").strip().lower()

    if selection == "q" or not selection:
        return []

    if selection == "all":
        return objects

    # Parse selection
    selected = []
    try:
        for part in selection.split(","):
            part = part.strip()
            if "-" in part:
                # Range: 1-5
                start, end = part.split("-")
                for i in range(int(start), int(end) + 1):
                    if 1 <= i <= len(objects):
                        selected.append(objects[i - 1])
            else:
                i = int(part)
                if 1 <= i <= len(objects):
                    selected.append(objects[i - 1])
    except ValueError:
        console.error("Invalid selection format")
        return []

    return selected


@require_root
def ownership_command(
    database: str = typer.Argument(..., help="Database name"),
    # Global options
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """List all objects in a database with their owners.

    Displays a flat, grep-able list of all database objects and their owners.

    Examples:

        sm postgres db ownership mydb

        sm postgres db ownership mydb | grep -v postgres
    """
    ctx = create_context(verbose=verbose)

    # Validate
    try:
        validate_identifier(database, "database")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3) from None

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, pg, ownership = _get_services(ctx)

    # Check database exists
    if not pg.database_exists(database):
        console.error(f"Database '{database}' does not exist")
        raise typer.Exit(1)

    # List objects
    objects = ownership.list_objects(database)

    if not objects:
        console.info(f"No objects found in database '{database}'")
        return

    # Build table
    table = Table(show_header=True, header_style="bold")
    table.add_column("TYPE", style="cyan", min_width=18)
    table.add_column("SCHEMA", min_width=10)
    table.add_column("NAME", min_width=20)
    table.add_column("OWNER", style="green")

    for obj in objects:
        table.add_row(
            obj.object_type,
            obj.schema or "",
            obj.display_name if obj.signature else obj.name,
            obj.owner,
        )

    console.print(table)
    console.print()
    console.print(f"[dim]Total: {len(objects)} objects[/dim]")


@require_root
def transfer_ownership_command(
    database: str = typer.Argument(..., help="Database name"),
    to_owner: str = typer.Option(
        ..., "--to",
        help="New owner role name",
    ),
    all_objects: bool = typer.Option(
        False, "--all",
        help="Transfer all objects (skip interactive selection)",
    ),
    object_types: str | None = typer.Option(
        None, "--type", "-t",
        help="Filter by object types (comma-separated: table,sequence,function)",
    ),
    schema: str | None = typer.Option(
        None, "--schema", "-s",
        help="Filter by schema name",
    ),
    # Global options
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without executing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity"),
) -> None:
    """Transfer ownership of database objects to a new owner.

    By default, opens an interactive multi-select to choose which objects
    to transfer. Use --all to transfer all objects without interaction.

    Examples:

        # Interactive mode - select objects to transfer
        sm postgres db transfer-ownership mydb --to myapp_user

        # Transfer all objects (for scripts/automation)
        sm postgres db transfer-ownership mydb --to myapp_user --all --yes

        # Transfer only tables and sequences
        sm postgres db transfer-ownership mydb --to myapp_user --type table,sequence --all --yes

        # Transfer objects in a specific schema
        sm postgres db transfer-ownership mydb --to myapp_user --schema public --all --yes

        # Preview what would change
        sm postgres db transfer-ownership mydb --to myapp_user --all --dry-run
    """
    ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)

    # Validate inputs
    try:
        validate_identifier(database, "database")
        validate_identifier(to_owner, "owner")
    except ValidationError as e:
        console.error(str(e))
        raise typer.Exit(3) from None

    # Parse object types
    types_filter = _parse_object_types(object_types)
    schemas_filter = [schema] if schema else None

    # Run preflight checks
    run_preflight_checks(dry_run=ctx.dry_run, verbose=ctx.is_verbose)

    # Get services
    executor, pg, ownership = _get_services(ctx)

    # Check database exists
    if not pg.database_exists(database):
        console.error(f"Database '{database}' does not exist")
        raise typer.Exit(1)

    # Check new owner exists
    if not ownership.role_exists(to_owner):
        console.error(f"Role '{to_owner}' does not exist")
        console.error("Create the role first with: sm postgres user create")
        raise typer.Exit(1)

    # Get objects
    objects = ownership.list_objects(database)

    if not objects:
        console.info(f"No objects found in database '{database}'")
        return

    # Apply filters
    if types_filter:
        objects = [obj for obj in objects if obj.object_type in types_filter]

    if schemas_filter:
        objects = [
            obj for obj in objects
            if (obj.object_type == "schema" and obj.name in schemas_filter)
            or (obj.object_type != "schema" and obj.schema in schemas_filter)
        ]

    if not objects:
        console.info("No objects match the specified filters")
        return

    # Select objects to transfer
    if all_objects:
        # Non-interactive: transfer all filtered objects
        selected = [obj for obj in objects if obj.owner != to_owner]
    else:
        # Interactive selection
        selected = _interactive_select(objects, to_owner)

    if not selected:
        console.info("No objects selected for transfer")
        return

    # Show preview
    console.print()
    console.print(f"[bold]Will transfer {len(selected)} objects to '{to_owner}':[/bold]")
    console.print()

    for obj in selected:
        stmt = obj.get_alter_statement(to_owner)
        console.print(f"  [dim]{stmt}[/dim]")

    console.print()

    # Confirm
    if not yes and not dry_run:
        if not console.confirm("Proceed with ownership transfer?"):
            console.warn("Operation cancelled")
            raise typer.Exit(0)

    # Execute transfer
    try:
        statements = ownership.transfer_ownership(
            database,
            selected,
            to_owner,
            dry_run=dry_run,
        )

        if dry_run:
            console.print()
            console.info(f"[dry-run] Would transfer {len(statements)} objects to '{to_owner}'")
        else:
            console.print()
            console.success(f"Transferred ownership of {len(statements)} objects to '{to_owner}'")

    except PostgresError as e:
        console.error(str(e))
        raise typer.Exit(10) from None
