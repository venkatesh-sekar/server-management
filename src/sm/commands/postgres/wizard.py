"""Interactive PostgreSQL setup wizard.

Provides a step-by-step guided setup for PostgreSQL with PgBouncer
and pgBackRest backups to Backblaze B2.
"""

import getpass
import os
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from sm.core import (
    SMError,
    console,
    create_context,
    CommandExecutor,
    get_credential_manager,
    get_audit_logger,
    AuditEventType,
)
from sm.core.validation import (
    validate_b2_bucket_name,
    validate_backup_passphrase,
    validate_path,
    ValidationError,
)
from sm.services.systemd import SystemdService


# PostgreSQL version options
PG_VERSIONS = {
    "18": {"name": "PostgreSQL 18", "status": "Latest", "recommended": True},
    "17": {"name": "PostgreSQL 17", "status": "Stable"},
    "16": {"name": "PostgreSQL 16", "status": "LTS"},
    "15": {"name": "PostgreSQL 15", "status": "Maintained"},
    "14": {"name": "PostgreSQL 14", "status": "Maintained"},
}

# PgBouncer pool mode options
POOL_MODES = {
    "transaction": {
        "name": "Transaction",
        "description": "Connection returned to pool after each transaction",
        "recommended": True,
    },
    "session": {
        "name": "Session",
        "description": "Connection held for entire client session",
    },
    "statement": {
        "name": "Statement",
        "description": "Connection returned after each statement (advanced)",
    },
}

# Backblaze B2 region options
B2_REGIONS = {
    "us-west-004": {
        "name": "US West (Las Vegas)",
        "endpoint": "s3.us-west-004.backblazeb2.com",
    },
    "us-west-002": {
        "name": "US West (Phoenix)",
        "endpoint": "s3.us-west-002.backblazeb2.com",
    },
    "us-west-001": {
        "name": "US West (Sacramento)",
        "endpoint": "s3.us-west-001.backblazeb2.com",
    },
    "us-east-005": {
        "name": "US East (New York)",
        "endpoint": "s3.us-east-005.backblazeb2.com",
    },
    "eu-central-003": {
        "name": "EU Central (Amsterdam)",
        "endpoint": "s3.eu-central-003.backblazeb2.com",
    },
}


class PostgresWizard:
    """Interactive PostgreSQL setup wizard."""

    def __init__(
        self,
        dry_run: bool = False,
        yes: bool = False,
        verbose: int = 0,
    ):
        self.dry_run = dry_run
        self.yes = yes
        self.verbose = verbose
        self.ctx = create_context(dry_run=dry_run, yes=yes, verbose=verbose)
        self.executor = CommandExecutor(self.ctx)
        self.systemd = SystemdService(self.ctx, self.executor)
        self.creds = get_credential_manager()
        self.audit = get_audit_logger()

        # Configuration to build
        self.pg_version: str = "18"
        self.pgbouncer_config: dict = {
            "port": 6432,
            "pool_mode": "transaction",
            "max_client_conn": 1000,
            "default_pool_size": 20,
        }
        self.backup_enabled: bool = True
        self.backup_config: dict = {
            "s3_endpoint": "",
            "s3_region": "",
            "s3_bucket": "",
            "repo_path": "/pgbackrest",
        }
        self.secrets: dict = {}  # B2 credentials and passphrase
        self.secrets_from_env: dict = {}  # Track which secrets came from env

    def run(self) -> None:
        """Run the interactive wizard."""
        self._check_root()
        self._show_welcome()

        # Step 1: PostgreSQL version
        if not self._configure_postgres_version():
            return

        # Step 2: PgBouncer configuration
        if not self._configure_pgbouncer():
            return

        # Step 3: Backup configuration (enable/skip)
        if not self._configure_backup():
            return

        # Step 4: B2 credentials (if backups enabled)
        if self.backup_enabled:
            if not self._configure_b2_credentials():
                return

        # Step 5: Review configuration
        if not self._review_configuration():
            return

        # Step 6: Apply
        self._apply_configuration()

    def _check_root(self) -> None:
        """Check for root privileges."""
        if os.geteuid() != 0 and not self.dry_run:
            self.ctx.console.error("This operation requires root privileges")
            self.ctx.console.hint("Run with: sudo sm postgres setup")
            raise typer.Exit(6)

    def _show_welcome(self) -> None:
        """Show welcome message."""
        self.ctx.console.print()
        self.ctx.console.print(
            Panel(
                "[bold]PostgreSQL Setup Wizard[/bold]\n\n"
                "This wizard will help you set up a production-ready PostgreSQL installation:\n\n"
                "  [cyan]1.[/cyan] PostgreSQL database server\n"
                "  [cyan]2.[/cyan] PgBouncer connection pooler\n"
                "  [cyan]3.[/cyan] pgBackRest backups to Backblaze B2\n\n"
                "[dim]All settings have sensible defaults. Press Enter to accept defaults.[/dim]",
                title="Welcome",
                border_style="blue",
            )
        )
        self.ctx.console.print()

    def _configure_postgres_version(self) -> bool:
        """Step 1: Select PostgreSQL version."""
        self.ctx.console.print("[bold]Step 1: PostgreSQL Version[/bold]")
        self.ctx.console.print()

        versions = list(PG_VERSIONS.items())
        for i, (version, info) in enumerate(versions, 1):
            marker = " [green](recommended)[/green]" if info.get("recommended") else ""
            self.ctx.console.print(f"  [{i}] {info['name']} - {info['status']}{marker}")

        self.ctx.console.print()
        self.ctx.console.print("  [0] Cancel")
        self.ctx.console.print()

        # Default is version 18 (index 1)
        default_idx = 1

        while True:
            try:
                choice = self.ctx.console.input(
                    f"[bold]Select version (1-{len(versions)}) [[cyan]{default_idx}[/cyan]]: [/bold]"
                )
                choice = choice.strip()

                if choice == "":
                    choice = str(default_idx)

                choice_int = int(choice)

                if choice_int == 0:
                    self.ctx.console.warn("Setup cancelled")
                    return False

                if 1 <= choice_int <= len(versions):
                    self.pg_version = versions[choice_int - 1][0]
                    info = versions[choice_int - 1][1]
                    self.ctx.console.print()
                    self.ctx.console.print(
                        f"  Selected: [bold]{info['name']}[/bold]"
                    )
                    self.ctx.console.print()
                    return True

                self.ctx.console.warn(f"Please enter a number between 0 and {len(versions)}")

            except ValueError:
                self.ctx.console.warn("Please enter a number")
            except (EOFError, KeyboardInterrupt):
                self.ctx.console.print()
                self.ctx.console.warn("Setup cancelled")
                return False

    def _configure_pgbouncer(self) -> bool:
        """Step 2: Configure PgBouncer."""
        self.ctx.console.print("[bold]Step 2: PgBouncer Configuration[/bold]")
        self.ctx.console.print()
        self.ctx.console.print(
            "  [dim]PgBouncer is a connection pooler that sits between your app and PostgreSQL.[/dim]"
        )
        self.ctx.console.print(
            "  [dim]Applications connect to PgBouncer instead of PostgreSQL directly.[/dim]"
        )
        self.ctx.console.print()

        # Port configuration
        default_port = 6432
        while True:
            try:
                port_input = self.ctx.console.input(
                    f"  PgBouncer port [[cyan]{default_port}[/cyan]]: "
                )
                port_input = port_input.strip()

                if port_input == "":
                    self.pgbouncer_config["port"] = default_port
                    break

                port = int(port_input)
                if 1024 <= port <= 65535:
                    if port == 5432:
                        self.ctx.console.warn(
                            "Port 5432 is used by PostgreSQL. Using a different port is recommended."
                        )
                        if not self.ctx.console.confirm("Use port 5432 anyway?", default=False):
                            continue
                    self.pgbouncer_config["port"] = port
                    break
                else:
                    self.ctx.console.warn("Port must be between 1024 and 65535")

            except ValueError:
                self.ctx.console.warn("Please enter a valid port number")
            except (EOFError, KeyboardInterrupt):
                self.ctx.console.print()
                self.ctx.console.warn("Setup cancelled")
                return False

        self.ctx.console.print()

        # Pool mode configuration
        self.ctx.console.print("  [bold]Pool Mode:[/bold]")
        modes = list(POOL_MODES.items())
        for i, (mode, info) in enumerate(modes, 1):
            marker = " [green](recommended)[/green]" if info.get("recommended") else ""
            self.ctx.console.print(f"    [{i}] {info['name']}{marker}")
            self.ctx.console.print(f"        [dim]{info['description']}[/dim]")

        self.ctx.console.print()

        # Default is transaction (index 1)
        default_mode_idx = 1

        while True:
            try:
                choice = self.ctx.console.input(
                    f"  Select pool mode (1-{len(modes)}) [[cyan]{default_mode_idx}[/cyan]]: "
                )
                choice = choice.strip()

                if choice == "":
                    choice = str(default_mode_idx)

                choice_int = int(choice)

                if 1 <= choice_int <= len(modes):
                    self.pgbouncer_config["pool_mode"] = modes[choice_int - 1][0]
                    break

                self.ctx.console.warn(f"Please enter a number between 1 and {len(modes)}")

            except ValueError:
                self.ctx.console.warn("Please enter a number")
            except (EOFError, KeyboardInterrupt):
                self.ctx.console.print()
                self.ctx.console.warn("Setup cancelled")
                return False

        self.ctx.console.print()
        self.ctx.console.print(
            f"  Selected: port [bold]{self.pgbouncer_config['port']}[/bold], "
            f"mode [bold]{self.pgbouncer_config['pool_mode']}[/bold]"
        )
        self.ctx.console.print()
        return True

    def _configure_backup(self) -> bool:
        """Step 3: Configure backup settings."""
        self.ctx.console.print("[bold]Step 3: Backup Configuration[/bold]")
        self.ctx.console.print()
        self.ctx.console.print(
            "  [dim]pgBackRest provides continuous backups with point-in-time recovery.[/dim]"
        )
        self.ctx.console.print(
            "  [dim]Backups are stored in Backblaze B2 (S3-compatible cloud storage).[/dim]"
        )
        self.ctx.console.print()

        try:
            self.backup_enabled = self.ctx.console.confirm(
                "  Enable backups to Backblaze B2?", default=True
            )
        except (EOFError, KeyboardInterrupt):
            self.ctx.console.print()
            self.ctx.console.warn("Setup cancelled")
            return False

        if not self.backup_enabled:
            self.ctx.console.print()
            self.ctx.console.warn(
                "  Backups disabled. You can configure them later with 'sm postgres backup setup'"
            )
            self.ctx.console.print()
            return True

        self.ctx.console.print()

        # B2 Bucket name
        self.ctx.console.print("  [bold]B2 Bucket Name[/bold]")
        self.ctx.console.print(
            "  [dim]Format: lowercase letters, numbers, hyphens (6-50 chars)[/dim]"
        )
        self.ctx.console.print(
            "  [dim]Example: mycompany-pg-backups[/dim]"
        )

        while True:
            try:
                bucket = self.ctx.console.input("  Bucket name: ")
                bucket = bucket.strip().lower()

                if not bucket:
                    self.ctx.console.warn("Bucket name is required")
                    continue

                # Validate bucket name using centralized validator
                try:
                    bucket = validate_b2_bucket_name(bucket)
                    self.backup_config["s3_bucket"] = bucket
                    break
                except ValidationError as e:
                    self.ctx.console.warn(str(e))
                    if e.hint:
                        self.ctx.console.hint(e.hint)
                    continue

            except (EOFError, KeyboardInterrupt):
                self.ctx.console.print()
                self.ctx.console.warn("Setup cancelled")
                return False

        self.ctx.console.print()

        # B2 Region selection
        self.ctx.console.print("  [bold]B2 Region[/bold]")
        regions = list(B2_REGIONS.items())
        for i, (region_id, info) in enumerate(regions, 1):
            self.ctx.console.print(f"    [{i}] {info['name']} ({region_id})")

        self.ctx.console.print()

        # Default is us-west-004 (index 1)
        default_region_idx = 1

        while True:
            try:
                choice = self.ctx.console.input(
                    f"  Select region (1-{len(regions)}) [[cyan]{default_region_idx}[/cyan]]: "
                )
                choice = choice.strip()

                if choice == "":
                    choice = str(default_region_idx)

                choice_int = int(choice)

                if 1 <= choice_int <= len(regions):
                    region_id, region_info = regions[choice_int - 1]
                    self.backup_config["s3_region"] = region_id
                    self.backup_config["s3_endpoint"] = region_info["endpoint"]
                    break

                self.ctx.console.warn(f"Please enter a number between 1 and {len(regions)}")

            except ValueError:
                self.ctx.console.warn("Please enter a number")
            except (EOFError, KeyboardInterrupt):
                self.ctx.console.print()
                self.ctx.console.warn("Setup cancelled")
                return False

        self.ctx.console.print()

        # Repository path
        default_repo_path = "/pgbackrest"
        self.ctx.console.print("  [bold]Repository Path[/bold]")
        self.ctx.console.print(
            "  [dim]Path inside the bucket where backups will be stored.[/dim]"
        )

        while True:
            try:
                repo_path = self.ctx.console.input(
                    f"  Repository path [[cyan]{default_repo_path}[/cyan]]: "
                )
                repo_path = repo_path.strip()

                if repo_path == "":
                    repo_path = default_repo_path

                if not repo_path.startswith("/"):
                    repo_path = "/" + repo_path

                # Validate path for dangerous characters
                try:
                    repo_path = validate_path(repo_path, must_be_absolute=True)
                    self.backup_config["repo_path"] = repo_path
                    break
                except ValidationError as e:
                    self.ctx.console.warn(str(e))
                    if e.hint:
                        self.ctx.console.hint(e.hint)
                    continue

            except (EOFError, KeyboardInterrupt):
                self.ctx.console.print()
                self.ctx.console.warn("Setup cancelled")
                return False

        # Show full path preview
        full_path = f"s3://{self.backup_config['s3_bucket']}{self.backup_config['repo_path']}/"
        self.ctx.console.print()
        self.ctx.console.print(f"  Full backup path: [cyan]{full_path}[/cyan]")
        self.ctx.console.print()

        return True

    def _configure_b2_credentials(self) -> bool:
        """Step 4: Collect B2 credentials and passphrase."""
        self.ctx.console.print("[bold]Step 4: B2 Credentials[/bold]")
        self.ctx.console.print()

        # Check environment variables first
        env_b2_key = os.environ.get("SM_B2_KEY")
        env_b2_secret = os.environ.get("SM_B2_SECRET")
        env_passphrase = os.environ.get("SM_BACKUP_PASSPHRASE")

        # B2 Application Key ID
        if env_b2_key:
            env_b2_key = env_b2_key.strip()
            if not env_b2_key:
                self.ctx.console.warn("SM_B2_KEY is set but empty, prompting for input")
                env_b2_key = None
            else:
                self.ctx.console.print("  [green]Found SM_B2_KEY in environment[/green]")
                self.secrets["sm_b2_key"] = env_b2_key
                self.secrets_from_env["sm_b2_key"] = True
        else:
            self.ctx.console.print("  [bold]B2 Application Key ID[/bold]")
            self.ctx.console.print(
                "  [dim]Create at: B2 Cloud Storage > App Keys > Add a New Application Key[/dim]"
            )
            try:
                while True:
                    key_id = self.ctx.console.input("  Key ID: ")
                    key_id = key_id.strip()
                    if key_id:
                        self.secrets["sm_b2_key"] = key_id
                        self.secrets_from_env["sm_b2_key"] = False
                        break
                    self.ctx.console.warn("Key ID is required")
            except (EOFError, KeyboardInterrupt):
                self.ctx.console.print()
                self.ctx.console.warn("Setup cancelled")
                return False

        self.ctx.console.print()

        # B2 Application Key (secret)
        if env_b2_secret:
            env_b2_secret = env_b2_secret.strip()
            if not env_b2_secret:
                self.ctx.console.warn("SM_B2_SECRET is set but empty, prompting for input")
                env_b2_secret = None
            else:
                self.ctx.console.print("  [green]Found SM_B2_SECRET in environment[/green]")
                self.secrets["sm_b2_secret"] = env_b2_secret
                self.secrets_from_env["sm_b2_secret"] = True
        else:
            self.ctx.console.print("  [bold]B2 Application Key (secret)[/bold]")
            self.ctx.console.print(
                "  [dim]This is shown only once when you create the key.[/dim]"
            )
            try:
                while True:
                    # Use getpass for secure input
                    secret = getpass.getpass("  Application Key: ")
                    secret = secret.strip()
                    if secret:
                        self.secrets["sm_b2_secret"] = secret
                        self.secrets_from_env["sm_b2_secret"] = False
                        break
                    self.ctx.console.warn("Application Key is required")
            except (EOFError, KeyboardInterrupt):
                self.ctx.console.print()
                self.ctx.console.warn("Setup cancelled")
                return False

        self.ctx.console.print()

        # Backup encryption passphrase
        if env_passphrase:
            # Validate environment-sourced passphrase
            try:
                env_passphrase = validate_backup_passphrase(env_passphrase)
                self.ctx.console.print("  [green]Found SM_BACKUP_PASSPHRASE in environment[/green]")
                self.secrets["sm_backup_passphrase"] = env_passphrase
                self.secrets_from_env["sm_backup_passphrase"] = True
            except ValidationError as e:
                self.ctx.console.warn(f"SM_BACKUP_PASSPHRASE invalid: {e}")
                if e.hint:
                    self.ctx.console.hint(e.hint)
                self.ctx.console.print("  Prompting for valid passphrase...")
                env_passphrase = None  # Fall through to manual input
        # Manual input needed (either no env var or invalid env var)
        if not env_passphrase:
            self.ctx.console.print("  [bold]Backup Encryption Passphrase[/bold]")
            self.ctx.console.print(
                "  [dim]Used to encrypt backups at rest. Minimum 20 characters.[/dim]"
            )
            self.ctx.console.print(
                "  [yellow]Warning: Store this passphrase securely - you need it for restore![/yellow]"
            )
            try:
                while True:
                    passphrase = getpass.getpass("  Passphrase: ")

                    # Validate passphrase strength using centralized validator
                    try:
                        passphrase = validate_backup_passphrase(passphrase)
                    except ValidationError as e:
                        self.ctx.console.warn(str(e))
                        if e.hint:
                            self.ctx.console.hint(e.hint)
                        continue

                    # Confirm passphrase
                    confirm = getpass.getpass("  Confirm passphrase: ")
                    if passphrase != confirm:
                        self.ctx.console.warn("Passphrases do not match")
                        continue

                    self.secrets["sm_backup_passphrase"] = passphrase
                    self.secrets_from_env["sm_backup_passphrase"] = False
                    break

            except (EOFError, KeyboardInterrupt):
                self.ctx.console.print()
                self.ctx.console.warn("Setup cancelled")
                return False

        self.ctx.console.print()
        self.ctx.console.print("  [green]Credentials configured[/green]")
        self.ctx.console.print()
        return True

    def _review_configuration(self) -> bool:
        """Step 5: Display rich table review."""
        self.ctx.console.print("[bold]Step 5: Review Configuration[/bold]")
        self.ctx.console.print()

        # Build summary table
        table = Table(title="PostgreSQL Setup Configuration", show_header=True)
        table.add_column("Setting", style="cyan", no_wrap=True)
        table.add_column("Value")
        table.add_column("Notes", style="dim")

        # PostgreSQL settings
        pg_info = PG_VERSIONS.get(self.pg_version, {})
        table.add_row(
            "PostgreSQL Version",
            self.pg_version,
            pg_info.get("status", ""),
        )

        # PgBouncer settings
        table.add_row(
            "PgBouncer Port",
            str(self.pgbouncer_config["port"]),
            "",
        )
        mode_info = POOL_MODES.get(self.pgbouncer_config["pool_mode"], {})
        table.add_row(
            "Pool Mode",
            self.pgbouncer_config["pool_mode"],
            "[green]recommended[/green]" if mode_info.get("recommended") else "",
        )

        # Backup settings
        if self.backup_enabled:
            table.add_row("Backup", "[green]Enabled[/green]", "")
            table.add_row("B2 Bucket", self.backup_config["s3_bucket"], "")

            region_info = B2_REGIONS.get(self.backup_config["s3_region"], {})
            table.add_row(
                "B2 Region",
                region_info.get("name", self.backup_config["s3_region"]),
                "",
            )

            full_path = f"s3://{self.backup_config['s3_bucket']}{self.backup_config['repo_path']}/"
            table.add_row("Full Path", full_path, "")

            # Show credential source
            creds_source = []
            if self.secrets_from_env.get("sm_b2_key"):
                creds_source.append("env")
            else:
                creds_source.append("wizard")
            table.add_row(
                "Credentials",
                "[green]Configured[/green]",
                f"From {creds_source[0]}",
            )
        else:
            table.add_row("Backup", "[yellow]Disabled[/yellow]", "--skip-backup")

        self.ctx.console.print(table)
        self.ctx.console.print()

        if self.dry_run:
            self.ctx.console.print("[blue][DRY-RUN][/blue] Would apply this configuration")
            return True

        try:
            return self.ctx.console.confirm("Apply this configuration?")
        except (EOFError, KeyboardInterrupt):
            self.ctx.console.print()
            self.ctx.console.warn("Setup cancelled")
            return False

    def _apply_configuration(self) -> None:
        """Step 6: Apply configuration with progress feedback."""
        from sm.commands.postgres.setup import run_setup

        self.ctx.console.print()
        self.ctx.console.print("[bold]Applying configuration...[/bold]")
        self.ctx.console.print()

        try:
            # Build backup_config dict if backups enabled
            backup_config = None
            if self.backup_enabled:
                backup_config = {
                    "s3_endpoint": self.backup_config["s3_endpoint"],
                    "s3_region": self.backup_config["s3_region"],
                    "s3_bucket": self.backup_config["s3_bucket"],
                    "repo_path": self.backup_config["repo_path"],
                    "s3_key": self.secrets["sm_b2_key"],
                    "s3_secret": self.secrets["sm_b2_secret"],
                    "passphrase": self.secrets["sm_backup_passphrase"],
                }

            # Call existing setup function
            run_setup(
                self.ctx,
                self.pg_version,
                self.pgbouncer_config,
                backup_config,
                skip_backup=not self.backup_enabled,
            )

            # Log audit event
            self.audit.log_success(
                AuditEventType.CONFIG_MODIFY,
                "postgresql",
                f"postgresql-{self.pg_version}",
                message="PostgreSQL setup via wizard",
            )

            # Additional hints
            self.ctx.console.print()
            self.ctx.console.hint(f"Connect via PgBouncer on port {self.pgbouncer_config['port']}")
            self.ctx.console.hint("Check PostgreSQL: pg_isready -h 127.0.0.1 -p 5432")
            self.ctx.console.hint("Create a database: sm postgres db create -d myapp")
            if self.backup_enabled:
                self.ctx.console.hint("List backups: sm postgres backup list")

        except SMError as e:
            self.audit.log_failure(
                AuditEventType.CONFIG_MODIFY,
                "postgresql",
                f"postgresql-{self.pg_version}",
                error=str(e),
            )
            raise

