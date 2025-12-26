"""Interactive PostgreSQL migration wizard.

Provides a step-by-step guided migration between two hosts using S3
as the sole coordination mechanism. No SSH required.

Usage:
    # On TARGET host (creates session)
    sm postgres migrate wizard

    # On SOURCE host (joins with code)
    sm postgres migrate wizard
"""

import getpass
import socket
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.table import Table

from sm.core import CommandExecutor, SMError, console, create_context
from sm.core.exceptions import BackupError
from sm.services.migration_session import (
    STATUS_EXPORTED,
    STATUS_EXPORTING,
    STATUS_FAILED,
    MigrationSession,
    MigrationSessionService,
)
from sm.services.pgdump import PgDumpService
from sm.services.s3 import S3Config, S3Service, verify_file_checksum


class S3ProviderInfo(TypedDict):
    """S3 provider information."""

    name: str
    endpoint: str | None
    region: str | None


class OwnershipChoice(TypedDict):
    """Database ownership configuration."""

    mode: str  # "original", "create", "postgres"
    role_name: str | None  # Role name if mode is "create"
    role_password: str | None  # Password if mode is "create"


# S3 provider presets
S3_PROVIDERS: dict[str, S3ProviderInfo] = {
    "hetzner-fsn1": {
        "name": "Hetzner Object Storage (Falkenstein)",
        "endpoint": "fsn1.your-objectstorage.com",
        "region": "fsn1",
    },
    "hetzner-nbg1": {
        "name": "Hetzner Object Storage (Nuremberg)",
        "endpoint": "nbg1.your-objectstorage.com",
        "region": "nbg1",
    },
    "hetzner-hel1": {
        "name": "Hetzner Object Storage (Helsinki)",
        "endpoint": "hel1.your-objectstorage.com",
        "region": "hel1",
    },
    "aws-us-east-1": {
        "name": "AWS S3 (US East - N. Virginia)",
        "endpoint": "s3.us-east-1.amazonaws.com",
        "region": "us-east-1",
    },
    "aws-eu-central-1": {
        "name": "AWS S3 (EU - Frankfurt)",
        "endpoint": "s3.eu-central-1.amazonaws.com",
        "region": "eu-central-1",
    },
    "b2-us-west-004": {
        "name": "Backblaze B2 (US West - Las Vegas)",
        "endpoint": "s3.us-west-004.backblazeb2.com",
        "region": "us-west-004",
    },
    "b2-eu-central-003": {
        "name": "Backblaze B2 (EU Central - Amsterdam)",
        "endpoint": "s3.eu-central-003.backblazeb2.com",
        "region": "eu-central-003",
    },
    "custom": {
        "name": "Custom S3-compatible",
        "endpoint": None,
        "region": None,
    },
}


class MigrationWizard:
    """Interactive PostgreSQL migration wizard."""

    def __init__(
        self,
        dry_run: bool = False,
        verbose: int = 0,
    ) -> None:
        """Initialize wizard.

        Args:
            dry_run: Preview mode without executing
            verbose: Verbosity level
        """
        self.dry_run = dry_run
        self.verbose = verbose
        self.ctx = create_context(dry_run=dry_run, verbose=verbose)
        self.executor = CommandExecutor(self.ctx)

        # Will be set during flow
        self.s3_config: S3Config | None = None
        self.s3: S3Service | None = None
        self.session_service: MigrationSessionService | None = None
        self.pgdump: PgDumpService | None = None
        self.ownership: OwnershipChoice | None = None

    def run(self) -> None:
        """Run the interactive wizard."""
        try:
            self._show_welcome()

            # Step 1: Select role
            role = self._select_role()
            if role is None:
                return

            # Step 2: Collect S3 credentials
            self.s3_config = self._collect_s3_credentials()
            if self.s3_config is None:
                return

            # Initialize services
            self.s3 = S3Service(self.ctx, self.s3_config)
            self.session_service = MigrationSessionService(self.ctx, self.s3)
            self.pgdump = PgDumpService(self.ctx, self.executor)

            # Step 3: Test S3 connection
            console.step("Testing S3 connection...")
            self.s3.test_connectivity()
            console.success("S3 connection OK")
            console.print()

            # Run role-specific flow
            if role == "target":
                self._run_target_flow()
            else:
                self._run_source_flow()

        except KeyboardInterrupt:
            console.print()
            console.warn("Migration cancelled")
        except SMError as e:
            console.error(str(e))
            if e.hint:
                console.hint(e.hint)
            raise

    def _show_welcome(self) -> None:
        """Show welcome message."""
        console.print()
        console.print(
            Panel(
                "[bold]PostgreSQL Migration Wizard[/bold]\n\n"
                "Migrate a database between hosts using S3 as the bridge.\n\n"
                "  [cyan]How it works:[/cyan]\n"
                "  1. TARGET: Generate a session code\n"
                "  2. SOURCE: Join with code and export\n"
                "  3. TARGET: Auto-imports when export complete\n\n"
                "[dim]No SSH required. S3 credentials are not saved to disk.[/dim]",
                title="Welcome",
                border_style="blue",
            )
        )
        console.print()

    def _select_role(self) -> str | None:
        """Ask user if this is SOURCE or TARGET.

        Returns:
            "source" or "target", or None if cancelled
        """
        console.print("[bold]Step 1: Select Role[/bold]")
        console.print()
        console.print("  Are you running this on the:")
        console.print()
        console.print("  [1] [bold]TARGET[/bold] host  (receiving the database)")
        console.print("      [dim]Creates a new session and waits for source[/dim]")
        console.print()
        console.print("  [2] [bold]SOURCE[/bold] host  (sending the database)")
        console.print("      [dim]Joins an existing session with a code[/dim]")
        console.print()
        console.print("  [0] Cancel")
        console.print()

        while True:
            try:
                choice = console.input("[bold]Select role (1-2): [/bold]")
                choice = choice.strip()

                if choice == "0":
                    console.warn("Migration cancelled")
                    return None

                if choice == "1":
                    console.print()
                    console.print("  Selected: [bold]TARGET[/bold] (receiving)")
                    console.print()
                    return "target"

                if choice == "2":
                    console.print()
                    console.print("  Selected: [bold]SOURCE[/bold] (sending)")
                    console.print()
                    return "source"

                console.warn("Please enter 1 or 2")

            except (EOFError, KeyboardInterrupt):
                console.print()
                console.warn("Migration cancelled")
                return None

    def _collect_s3_credentials(self) -> S3Config | None:
        """Collect S3 credentials interactively.

        Returns:
            S3Config or None if cancelled
        """
        console.print("[bold]Step 2: S3 Connection[/bold]")
        console.print()
        console.print(
            "  [dim]Enter your S3 credentials. These are used only for this session.[/dim]"
        )
        console.print()

        try:
            # Provider selection
            console.print("  [bold]S3 Provider:[/bold]")
            providers = list(S3_PROVIDERS.items())
            for i, (_key, info) in enumerate(providers, 1):
                console.print(f"    [{i}] {info['name']}")

            console.print()

            # Default to Hetzner
            default_provider_idx = 1

            while True:
                prompt = (
                    f"  Select provider (1-{len(providers)}) "
                    f"[[cyan]{default_provider_idx}[/cyan]]: "
                )
                choice = console.input(prompt)
                choice = choice.strip()

                if choice == "":
                    choice = str(default_provider_idx)

                try:
                    choice_int = int(choice)
                    if 1 <= choice_int <= len(providers):
                        provider_key, provider_info = providers[choice_int - 1]
                        break
                    console.warn(f"Please enter a number between 1 and {len(providers)}")
                except ValueError:
                    console.warn("Please enter a number")

            console.print()

            # Get endpoint and region
            if provider_info["endpoint"] is None:
                # Custom provider
                console.print("  [bold]S3 Endpoint:[/bold]")
                console.print("  [dim]Example: s3.eu-central-1.amazonaws.com[/dim]")
                while True:
                    endpoint = console.input("  Endpoint: ")
                    endpoint = endpoint.strip()
                    if endpoint:
                        # Remove https:// prefix if provided
                        if endpoint.startswith("https://"):
                            endpoint = endpoint[8:]
                        if endpoint.startswith("http://"):
                            endpoint = endpoint[7:]
                        break
                    console.warn("Endpoint is required")

                console.print()
                console.print("  [bold]S3 Region:[/bold]")
                console.print("  [dim]Example: eu-central-1, us-west-2[/dim]")
                while True:
                    region = console.input("  Region: ")
                    region = region.strip()
                    if region:
                        break
                    console.warn("Region is required")
            else:
                # Non-custom providers always have endpoint and region set
                _endpoint = provider_info["endpoint"]
                _region = provider_info["region"]
                assert _endpoint is not None
                assert _region is not None
                endpoint = _endpoint
                region = _region
                console.print(f"  Endpoint: [cyan]{endpoint}[/cyan]")
                console.print(f"  Region: [cyan]{region}[/cyan]")

            console.print()

            # Bucket name
            console.print("  [bold]Bucket Name:[/bold]")
            while True:
                bucket = console.input("  Bucket: ")
                bucket = bucket.strip()
                if bucket:
                    break
                console.warn("Bucket name is required")

            console.print()

            # Access key
            console.print("  [bold]Access Key:[/bold]")
            while True:
                access_key = console.input("  Access Key: ")
                access_key = access_key.strip()
                if access_key:
                    break
                console.warn("Access key is required")

            console.print()

            # Secret key (masked)
            console.print("  [bold]Secret Key:[/bold]")
            while True:
                secret_key = getpass.getpass("  Secret Key: ")
                secret_key = secret_key.strip()
                if secret_key:
                    break
                console.warn("Secret key is required")

            console.print()

            return S3Config(
                endpoint=endpoint,
                region=region,
                bucket=bucket,
                access_key=access_key,
                secret_key=secret_key,
            )

        except (EOFError, KeyboardInterrupt):
            console.print()
            console.warn("Migration cancelled")
            return None

    # -------------------------------------------------------------------------
    # TARGET Flow
    # -------------------------------------------------------------------------

    def _run_target_flow(self) -> None:
        """Execute target host workflow."""
        # Services must be initialized before calling this method
        assert self.s3 is not None
        assert self.session_service is not None
        assert self.pgdump is not None

        # Step 3: Get database name
        database = self._prompt_target_database()
        if database is None:
            return

        # Step 4: Get ownership preference
        self.ownership = self._prompt_ownership()
        if self.ownership is None:
            return

        # Step 5: Create session
        console.step("Creating migration session...")
        session = self.session_service.create_session(database)
        console.success(f"Session created: {session.code}")
        console.print()

        # Step 6: Display session code
        self._display_session_code(session)

        # Step 7: Wait for source
        try:
            session = self._wait_for_source(session.code)
        except KeyboardInterrupt:
            console.print()
            remaining = session.time_remaining()
            console.warn(f"Cancelled. Session '{session.code}' is still available for {remaining}.")
            console.hint(f"Resume with code: {session.code}")
            return

        # Step 8: Download and import
        self._download_and_import(session)

        # Step 9: Verify
        self._verify_migration(session)

        # Step 10: Cleanup
        self._cleanup_session(session)

    def _prompt_target_database(self) -> str | None:
        """Prompt for target database name.

        Returns:
            Database name or None if cancelled
        """
        assert self.pgdump is not None

        console.print("[bold]Step 3: Target Database[/bold]")
        console.print()
        console.print("  [dim]Enter the name for the database on this host.[/dim]")
        console.print("  [dim]It will be created if it doesn't exist.[/dim]")
        console.print()

        try:
            while True:
                database = console.input("  Database name: ")
                database = database.strip()

                if not database:
                    console.warn("Database name is required")
                    continue

                # Basic validation
                if not database[0].isalpha() and database[0] != "_":
                    console.warn("Database name must start with a letter or underscore")
                    continue

                # Check if exists
                if self.pgdump.database_exists(database):
                    console.warn(f"Database '{database}' already exists")
                    overwrite = console.confirm("  Overwrite existing database?", default=False)
                    if not overwrite:
                        continue

                console.print()
                return database

        except (EOFError, KeyboardInterrupt):
            console.print()
            console.warn("Migration cancelled")
            return None

    def _prompt_ownership(self) -> OwnershipChoice | None:
        """Prompt for database ownership configuration.

        Returns:
            OwnershipChoice or None if cancelled
        """
        console.print("[bold]Step 4: Database Ownership[/bold]")
        console.print()
        console.print("  [dim]Choose who will own the database and its objects.[/dim]")
        console.print()
        console.print("  [1] [bold]postgres[/bold]  (recommended)")
        console.print("      [dim]All objects owned by postgres user[/dim]")
        console.print()
        console.print("  [2] [bold]Create new role[/bold]")
        console.print("      [dim]Create a role and assign ownership[/dim]")
        console.print()
        console.print("  [3] [bold]Keep original owners[/bold]")
        console.print("      [dim]Roles must already exist on this server[/dim]")
        console.print()
        console.print("  [0] Cancel")
        console.print()

        try:
            while True:
                choice = console.input("[bold]Select ownership (1-3): [/bold]")
                choice = choice.strip()

                if choice == "0":
                    console.warn("Migration cancelled")
                    return None

                if choice == "1":
                    console.print()
                    console.print("  Selected: [bold]postgres[/bold] will own all objects")
                    console.print()
                    return OwnershipChoice(
                        mode="postgres",
                        role_name=None,
                        role_password=None,
                    )

                if choice == "2":
                    console.print()
                    return self._prompt_create_role()

                if choice == "3":
                    console.print()
                    console.print("  Selected: [bold]Keep original owners[/bold]")
                    console.warn("Make sure the required roles exist on this server!")
                    console.print()
                    return OwnershipChoice(
                        mode="original",
                        role_name=None,
                        role_password=None,
                    )

                console.warn("Please enter 1, 2, or 3")

        except (EOFError, KeyboardInterrupt):
            console.print()
            console.warn("Migration cancelled")
            return None

    def _prompt_create_role(self) -> OwnershipChoice | None:
        """Prompt for new role details.

        Returns:
            OwnershipChoice or None if cancelled
        """
        console.print("  [bold]Create New Role[/bold]")
        console.print()

        try:
            # Role name
            while True:
                role_name = console.input("  Role name: ")
                role_name = role_name.strip()

                if not role_name:
                    console.warn("Role name is required")
                    continue

                if not role_name[0].isalpha() and role_name[0] != "_":
                    console.warn("Role name must start with a letter or underscore")
                    continue

                # Check if role exists
                if self._role_exists(role_name):
                    console.warn(f"Role '{role_name}' already exists")
                    use_existing = console.confirm("  Use existing role?", default=True)
                    if use_existing:
                        console.print()
                        console.print(f"  Selected: Use existing role [bold]{role_name}[/bold]")
                        console.print()
                        return OwnershipChoice(
                            mode="create",
                            role_name=role_name,
                            role_password=None,  # Don't change password
                        )
                    continue

                break

            # Password for the new role
            console.print()
            console.print(f"  [bold]Password for '{role_name}':[/bold]")
            console.print("  [dim]This sets the login password for the new database role.[/dim]")
            console.print("  [dim]Leave empty if this role should not have login access.[/dim]")
            console.print()

            while True:
                raw_password = getpass.getpass(f"  Password for {role_name}: ")
                role_password: str | None = raw_password.strip() if raw_password else None

                if role_password:
                    # Confirm password
                    confirm_password = getpass.getpass("  Confirm password: ")
                    if confirm_password != role_password:
                        console.warn("Passwords do not match, try again")
                        continue
                break

            console.print()
            if role_password:
                console.print(f"  Selected: Create role [bold]{role_name}[/bold] with login")
            else:
                console.print(f"  Selected: Create role [bold]{role_name}[/bold] (no login)")
            console.print()

            return OwnershipChoice(
                mode="create",
                role_name=role_name,
                role_password=role_password,
            )

        except (EOFError, KeyboardInterrupt):
            console.print()
            console.warn("Migration cancelled")
            return None

    def _role_exists(self, role_name: str) -> bool:
        """Check if a PostgreSQL role exists.

        Args:
            role_name: Role name to check

        Returns:
            True if role exists
        """
        if self.ctx.dry_run:
            return False

        # Use run_sql with format() for safe interpolation
        result = self.executor.run_sql_format(
            "SELECT 1 FROM pg_roles WHERE rolname = %L",
            database="postgres",
            as_user="postgres",
            check=False,
            role_name=role_name,
        )
        return bool(result.strip())

    def _create_role(self, role_name: str, password: str | None) -> None:
        """Create a PostgreSQL role.

        Args:
            role_name: Role name
            password: Optional password (enables LOGIN)
        """
        if self.ctx.dry_run:
            console.dry_run_msg(f"Would create role '{role_name}'")
            return

        console.step(f"Creating role '{role_name}'...")

        if password:
            # Role with login - use format() for safe interpolation
            self.executor.run_sql_format(
                "CREATE ROLE %I LOGIN PASSWORD %L",
                database="postgres",
                as_user="postgres",
                role_name=role_name,
                password=password,
            )
        else:
            # Role without login
            self.executor.run_sql_format(
                "CREATE ROLE %I",
                database="postgres",
                as_user="postgres",
                role_name=role_name,
            )

        console.success(f"Role '{role_name}' created")

    def _reassign_ownership(self, database: str, new_owner: str) -> None:
        """Reassign database and all objects to a new owner.

        Args:
            database: Database name
            new_owner: New owner role name
        """
        if self.ctx.dry_run:
            console.dry_run_msg(f"Would reassign ownership to '{new_owner}'")
            return

        console.step(f"Reassigning ownership to '{new_owner}'...")

        # Change database owner
        self.executor.run_sql_format(
            "ALTER DATABASE %I OWNER TO %I",
            database="postgres",
            as_user="postgres",
            db_name=database,
            owner=new_owner,
        )

        # Reassign all objects in the database
        self.executor.run_sql_format(
            "REASSIGN OWNED BY postgres TO %I",
            database=database,
            as_user="postgres",
            owner=new_owner,
        )

        console.success(f"Ownership reassigned to '{new_owner}'")

    def _display_session_code(self, session: MigrationSession) -> None:
        """Display the session code prominently."""
        console.print(
            Panel(
                f"[bold]Run this on the SOURCE server:[/bold]\n\n"
                f"    sm postgres migrate wizard\n\n"
                f"When prompted, enter code:\n\n"
                f"    [bold cyan]{session.code}[/bold cyan]\n\n"
                f"[dim]Database:  {session.database}[/dim]\n"
                f"[dim]Expires:   in {session.time_remaining()}[/dim]",
                title="SESSION CREATED",
                border_style="green",
            )
        )
        console.print()

    def _wait_for_source(self, code: str) -> MigrationSession:
        """Wait for source to complete export with spinner."""
        assert self.session_service is not None

        console.print("[dim]Waiting for source to export... (Ctrl+C to cancel)[/dim]")
        console.print()

        with Live(console=console._console, refresh_per_second=4) as live:
            last_status = None
            dots = 0

            while True:
                session = self.session_service.get_session(code)

                if session is None:
                    raise BackupError(f"Session '{code}' not found")

                if session.is_expired():
                    raise BackupError(
                        f"Session '{code}' has expired",
                        hint="Create a new session",
                    )

                # Update display based on status
                if session.status != last_status:
                    last_status = session.status

                    if session.status == STATUS_EXPORTING:
                        live.update(
                            Panel(
                                "[yellow]Source is exporting the database...[/yellow]",
                                title="In Progress",
                                border_style="yellow",
                            )
                        )
                    elif session.status == STATUS_EXPORTED:
                        live.update(
                            Panel(
                                "[green]Export complete! Downloading...[/green]",
                                title="Ready",
                                border_style="green",
                            )
                        )
                        console.print()
                        return session
                else:
                    # Animate waiting dots
                    dots = (dots + 1) % 4
                    dots_str = "." * dots + " " * (3 - dots)
                    live.update(
                        Panel(
                            f"[dim]Waiting for source to start{dots_str}[/dim]\n\n"
                            f"[dim]Checking every 10 seconds[/dim]",
                            title="Waiting",
                            border_style="blue",
                        )
                    )

                time.sleep(2)  # Check every 2 seconds for responsive UI

    def _download_and_import(self, session: MigrationSession) -> None:
        """Download dump from S3 and import to database."""
        assert self.s3 is not None
        assert self.pgdump is not None

        if not session.dump_key:
            raise BackupError("No dump file in session")

        # Create temp directory for download
        with tempfile.TemporaryDirectory() as tmpdir:
            dump_path = Path(tmpdir) / f"{session.database}.dump"

            # Download dump with progress
            console.step("Downloading database dump...")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
                console=console._console,
            ) as progress:
                task = progress.add_task("Downloading", total=session.dump_size or 0)

                def update_progress(transferred: int, total: int) -> None:
                    progress.update(task, completed=transferred, total=total)

                self.s3.download_file(
                    session.dump_key, dump_path, progress_callback=update_progress
                )

            console.success(f"Downloaded {self._format_size(dump_path.stat().st_size)}")

            # Verify checksum
            if session.dump_checksum:
                console.step("Verifying checksum...")
                if verify_file_checksum(dump_path, session.dump_checksum):
                    console.success("Checksum verified")
                else:
                    raise BackupError(
                        "Checksum verification failed",
                        hint="The dump file may be corrupted. Try the migration again.",
                    )

            # Handle ownership setup
            assert self.ownership is not None
            owner_role = None
            no_owner = False

            if self.ownership["mode"] == "postgres":
                no_owner = True
            elif self.ownership["mode"] == "create":
                owner_role = self.ownership["role_name"]
                # Create role if needed (has password = new role)
                if owner_role and self.ownership["role_password"] is not None:
                    if not self._role_exists(owner_role):
                        self._create_role(owner_role, self.ownership["role_password"])
            # mode == "original" uses default behavior (preserve owners)

            # Drop existing database if needed
            if self.pgdump.database_exists(session.database):
                console.step(f"Dropping existing database '{session.database}'...")
                self.executor.run_sql_format(
                    "DROP DATABASE IF EXISTS %I",
                    database="postgres",
                    as_user="postgres",
                    db_name=session.database,
                )

            # Import database
            console.step(f"Restoring to database '{session.database}'...")

            start_time = time.time()
            self.pgdump.restore_database(
                dump_path,
                session.database,
                create=True,
                jobs=4,
                no_owner=no_owner,
                owner=owner_role,
            )
            elapsed = time.time() - start_time

            console.success(f"Database restored in {self._format_duration(elapsed)}")

            # Reassign ownership if a specific owner was requested
            if owner_role:
                self._reassign_ownership(session.database, owner_role)

    def _verify_migration(self, session: MigrationSession) -> None:
        """Verify migration by comparing row counts."""
        assert self.session_service is not None

        console.print()
        console.step("Verifying migration...")

        # Get target row counts
        target_counts = self._get_row_counts(session.database)
        source_counts = session.source_row_counts

        if not source_counts:
            console.warn("Source row counts not available, skipping verification")
            return

        # Compare
        table = Table(title="Row Count Verification")
        table.add_column("Table", style="cyan")
        table.add_column("Source Rows", justify="right")
        table.add_column("Target Rows", justify="right")
        table.add_column("Status", justify="center")

        all_match = True
        total_rows = 0

        # Get all tables from both
        all_tables = sorted(set(source_counts.keys()) | set(target_counts.keys()))

        for table_name in all_tables:
            source_count = source_counts.get(table_name, 0)
            target_count = target_counts.get(table_name, 0)
            total_rows += target_count

            if source_count == target_count:
                status = "[green]OK[/green]"
            else:
                status = "[red]MISMATCH[/red]"
                all_match = False

            table.add_row(
                table_name,
                f"{source_count:,}",
                f"{target_count:,}",
                status,
            )

        console.print(table)
        console.print()

        if all_match:
            console.success(
                f"Verification passed: {len(all_tables)} tables, {total_rows:,} total rows"
            )
        else:
            console.warn("Some tables have mismatched row counts")

        # Update session with target counts
        session.target_row_counts = target_counts
        self.session_service.update_session(session)

    def _cleanup_session(self, session: MigrationSession) -> None:
        """Cleanup session files from S3."""
        assert self.session_service is not None

        console.print()
        if console.confirm("Clean up session files from S3?", default=True):
            count = self.session_service.cleanup_session(session.code)
            console.success(f"Cleaned up {count} files")

    # -------------------------------------------------------------------------
    # SOURCE Flow
    # -------------------------------------------------------------------------

    def _run_source_flow(self) -> None:
        """Execute source host workflow."""
        # Services must be initialized before calling this method
        assert self.s3 is not None
        assert self.session_service is not None
        assert self.pgdump is not None

        # Step 3: Get session code
        code = self._prompt_session_code()
        if code is None:
            return

        # Step 4: Join session
        console.step(f"Looking up session {code}...")
        session = self.session_service.get_session(code)

        if session is None:
            console.error(f"No session found with code '{code}'")
            console.hint("Check the code and try again, or create a new session on the target")
            return

        # Validate session
        self.session_service.validate_for_export(session)

        console.success(f"Found session for database '{session.database}'")
        console.print(f"  Target host: [cyan]{session.target_host}[/cyan]")
        console.print(f"  Expires: [dim]in {session.time_remaining()}[/dim]")
        console.print()

        # Step 5: Verify source database exists
        if not self.pgdump.database_exists(session.database):
            console.error(f"Database '{session.database}' not found on this host")
            console.hint("Make sure you're running this on the source server")
            return

        # Confirm
        if not console.confirm(f"Export database '{session.database}'?", default=True):
            console.warn("Migration cancelled")
            return

        # Step 6: Export and upload
        self._export_and_upload(session)

        console.print()
        console.success("Export complete!")
        console.print()
        console.print(
            Panel(
                "The target host will now automatically download and import the database.\n\n"
                "You can close this terminal.",
                title="Done",
                border_style="green",
            )
        )

    def _prompt_session_code(self) -> str | None:
        """Prompt for session code.

        Returns:
            Session code or None if cancelled
        """
        console.print("[bold]Step 3: Session Code[/bold]")
        console.print()
        console.print("  [dim]Enter the code from the target host.[/dim]")
        console.print()

        try:
            while True:
                code = console.input("  Session code: ")
                code = code.strip().upper()

                if not code:
                    console.warn("Session code is required")
                    continue

                if len(code) != 6:
                    console.warn("Session code must be 6 characters")
                    continue

                console.print()
                return code

        except (EOFError, KeyboardInterrupt):
            console.print()
            console.warn("Migration cancelled")
            return None

    def _export_and_upload(self, session: MigrationSession) -> None:
        """Export database and upload to S3."""
        assert self.s3 is not None
        assert self.session_service is not None
        assert self.pgdump is not None

        # Update session status
        session.status = STATUS_EXPORTING
        session.source_host = socket.gethostname()
        session.export_started_at = datetime.now(timezone.utc).isoformat()
        self.session_service.update_session(session)

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                dump_path = Path(tmpdir) / f"{session.database}.dump"

                # Export database
                console.step(f"Exporting database '{session.database}'...")

                start_time = time.time()
                dump_info = self.pgdump.dump_database(
                    session.database,
                    dump_path,
                    compression_level=6,
                    jobs=4,
                )
                export_elapsed = time.time() - start_time

                console.success(
                    f"Exported {self._format_size(dump_info.size_bytes)} "
                    f"in {self._format_duration(export_elapsed)}"
                )

                # Get row counts for verification
                console.step("Counting rows for verification...")
                row_counts = self._get_row_counts(session.database)
                total_rows = sum(row_counts.values())
                console.success(f"Counted {len(row_counts)} tables, {total_rows:,} total rows")

                # Upload to S3
                console.step("Uploading to S3...")
                dump_key = self.session_service.get_dump_key(session.code, session.database)

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    DownloadColumn(),
                    TransferSpeedColumn(),
                    TimeRemainingColumn(),
                    console=console._console,
                ) as progress:
                    task = progress.add_task("Uploading", total=dump_info.size_bytes)

                    def update_progress(transferred: int, total: int) -> None:
                        progress.update(task, completed=transferred, total=total)

                    self.s3.upload_file(dump_path, dump_key, progress_callback=update_progress)

                console.success("Upload complete")

                # Update session with export info
                session.status = STATUS_EXPORTED
                session.export_completed_at = datetime.now(timezone.utc).isoformat()
                session.dump_key = dump_key
                session.dump_size = dump_info.size_bytes
                session.dump_checksum = dump_info.checksum
                session.source_row_counts = row_counts
                self.session_service.update_session(session)

        except Exception as e:
            # Mark session as failed
            session.status = STATUS_FAILED
            session.error = str(e)
            self.session_service.update_session(session)
            raise

    def _get_row_counts(self, database: str) -> dict[str, int]:
        """Get row counts for all tables in database.

        Args:
            database: Database name

        Returns:
            Dict mapping table name to row count
        """
        if self.ctx.dry_run:
            return {}

        # Query to get row counts for all tables (uses | as separator)
        sql = """
        SELECT schemaname || '.' || tablename || '|' || n_live_tup
        FROM pg_stat_user_tables
        ORDER BY schemaname, tablename;
        """

        result = self.executor.run_sql(
            sql,
            database=database,
            as_user="postgres",
        )

        counts = {}
        for line in result.strip().split("\n"):
            if line and "|" in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    table_name = parts[0]
                    try:
                        count = int(parts[1])
                    except ValueError:
                        count = 0
                    counts[table_name] = count

        return counts

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def _format_size(self, size_bytes: int) -> str:
        """Format byte size as human-readable string."""
        size: float = float(size_bytes)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    def _format_duration(self, seconds: float) -> str:
        """Format duration as human-readable string."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes = int(seconds / 60)
        secs = int(seconds % 60)
        if minutes < 60:
            return f"{minutes}m {secs}s"
        hours = int(minutes / 60)
        mins = int(minutes % 60)
        return f"{hours}h {mins}m"
