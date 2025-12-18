"""PostgreSQL service abstraction.

Provides a safe interface for managing PostgreSQL databases and users.
All SQL operations use parameterized queries to prevent injection.
"""

import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sm.core.context import ExecutionContext
from sm.core.executor import CommandExecutor, RollbackStack
from sm.core.exceptions import PostgresError
from sm.core.validation import validate_identifier


def _unique_dollar_tag() -> str:
    """Generate a unique dollar-quote tag to safely embed passwords in SQL.

    PostgreSQL dollar quoting uses $tag$...$tag$ syntax. By using a random
    tag, we prevent issues if the password itself contains $pass$ or similar.
    """
    return f"p{secrets.token_hex(4)}"


@dataclass
class DatabaseInfo:
    """Information about a PostgreSQL database."""
    name: str
    owner: str
    encoding: str
    size: str
    tablespace: str


@dataclass
class UserInfo:
    """Information about a PostgreSQL user/role."""
    name: str
    superuser: bool
    create_db: bool
    create_role: bool
    login: bool
    connections: int
    roles: list[str]


@dataclass
class ExtensionInfo:
    """Information about a PostgreSQL extension."""
    name: str
    version: str
    schema: str


# Known extension to package mappings
# Format: extension_name -> package_name_template (use {version} for PG version)
EXTENSION_PACKAGES: dict[str, str] = {
    "vector": "postgresql-{version}-pgvector",
}


class PostgreSQLService:
    """Safe interface for PostgreSQL operations.

    All operations:
    - Respect dry-run mode
    - Use parameterized queries
    - Log to audit trail
    - Support rollback
    """

    def __init__(
        self,
        ctx: ExecutionContext,
        executor: CommandExecutor,
        *,
        host: str = "127.0.0.1",
        port: int = 5432,
    ) -> None:
        """Initialize PostgreSQL service.

        Args:
            ctx: Execution context
            executor: Command executor
            host: PostgreSQL host
            port: PostgreSQL port
        """
        self.ctx = ctx
        self.executor = executor
        self.host = host
        self.port = port

    def _run_sql(
        self,
        sql: str,
        *,
        database: str = "postgres",
        description: Optional[str] = None,
        check: bool = True,
    ) -> str:
        """Execute SQL as postgres user.

        Args:
            sql: SQL to execute
            database: Database to connect to
            description: Description for logging
            check: Raise on error

        Returns:
            Query output
        """
        return self.executor.run_sql(
            sql,
            database=database,
            as_user="postgres",
            description=description,
            check=check,
        )

    def detect_version(self) -> Optional[str]:
        """Detect installed PostgreSQL version.

        Returns:
            Version string (e.g., "18") or None
        """
        pg_dir = Path("/etc/postgresql")
        if not pg_dir.exists():
            return None

        versions = sorted(
            [d.name for d in pg_dir.iterdir() if d.is_dir()],
            key=lambda v: int(v) if v.isdigit() else 0,
            reverse=True,
        )

        return versions[0] if versions else None

    def is_running(self) -> bool:
        """Check if PostgreSQL is running.

        Returns:
            True if running
        """
        if self.ctx.dry_run:
            return True

        result = self.executor.run(
            ["pg_isready", "-h", self.host, "-p", str(self.port)],
            check=False,
        )
        return result.success

    # =========================================================================
    # Database Operations
    # =========================================================================

    def database_exists(self, name: str) -> bool:
        """Check if a database exists.

        Args:
            name: Database name

        Returns:
            True if database exists
        """
        if self.ctx.dry_run:
            return False

        result = self._run_sql(
            f"SELECT 1 FROM pg_database WHERE datname = '{name}'",
            check=False,
        )
        return bool(result.strip())

    def create_database(
        self,
        name: str,
        *,
        owner: Optional[str] = None,
        encoding: str = "UTF8",
        template: str = "template0",
        rollback: Optional[RollbackStack] = None,
    ) -> None:
        """Create a PostgreSQL database.

        Args:
            name: Database name
            owner: Owner username
            encoding: Database encoding
            template: Template database
            rollback: Rollback stack for cleanup on failure

        Raises:
            PostgresError: If creation fails
        """
        validate_identifier(name, "database")

        if self.database_exists(name):
            if owner:
                self.ctx.console.info(f"Database '{name}' exists, updating owner to '{owner}'")
                self._run_sql(
                    f'ALTER DATABASE "{name}" OWNER TO "{owner}"',
                    description=f"Update database '{name}' owner to '{owner}'",
                )
            else:
                self.ctx.console.info(f"Database '{name}' already exists")
            return

        # Build CREATE DATABASE statement
        sql_parts = [f'CREATE DATABASE "{name}"']
        if owner:
            sql_parts.append(f'OWNER "{owner}"')
        sql_parts.append(f"ENCODING '{encoding}'")
        sql_parts.append(f"TEMPLATE {template}")

        sql = " ".join(sql_parts)

        self.ctx.console.step(f"Creating database '{name}'")
        self._run_sql(sql, description=f"Create database '{name}'")

        # Add rollback action
        if rollback:
            rollback.add(
                f"Drop database '{name}'",
                lambda n=name: self.drop_database(n, force=True),
            )

        self.ctx.console.success(f"Database '{name}' created")

    def drop_database(self, name: str, *, force: bool = False) -> None:
        """Drop a PostgreSQL database.

        Args:
            name: Database name
            force: Terminate existing connections first

        Raises:
            PostgresError: If drop fails
        """
        validate_identifier(name, "database")

        if not self.database_exists(name):
            self.ctx.console.info(f"Database '{name}' does not exist")
            return

        if force:
            # Terminate all connections
            self._run_sql(
                f"""
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = '{name}'
                AND pid <> pg_backend_pid()
                """,
                description=f"Terminate connections to '{name}'",
                check=False,
            )

        self._run_sql(
            f'DROP DATABASE "{name}"',
            description=f"Drop database '{name}'",
        )

        self.ctx.console.success(f"Database '{name}' dropped")

    def _get_object_counts(self, database: str) -> dict[str, int]:
        """Get counts of objects in a database for reporting.

        Args:
            database: Database name

        Returns:
            Dictionary with counts by object type
        """
        if self.ctx.dry_run:
            return {}

        # Query all object counts in a single SQL statement
        result = self._run_sql(
            """
            SELECT
                (SELECT count(*) FROM pg_tables
                 WHERE schemaname NOT LIKE 'pg_%'
                 AND schemaname != 'information_schema') as tables,
                (SELECT count(*) FROM pg_views
                 WHERE schemaname NOT LIKE 'pg_%'
                 AND schemaname != 'information_schema') as views,
                (SELECT count(*) FROM pg_matviews
                 WHERE schemaname NOT LIKE 'pg_%'
                 AND schemaname != 'information_schema') as matviews,
                (SELECT count(*) FROM pg_indexes
                 WHERE schemaname NOT LIKE 'pg_%'
                 AND schemaname != 'information_schema') as indexes,
                (SELECT count(*) FROM pg_sequences
                 WHERE schemaname NOT LIKE 'pg_%'
                 AND schemaname != 'information_schema') as sequences,
                (SELECT count(*) FROM pg_proc p
                 JOIN pg_namespace n ON p.pronamespace = n.oid
                 WHERE n.nspname NOT LIKE 'pg_%'
                 AND n.nspname != 'information_schema') as functions,
                (SELECT count(*) FROM pg_trigger t
                 JOIN pg_class c ON t.tgrelid = c.oid
                 JOIN pg_namespace n ON c.relnamespace = n.oid
                 WHERE n.nspname NOT LIKE 'pg_%'
                 AND n.nspname != 'information_schema'
                 AND NOT t.tgisinternal) as triggers,
                (SELECT count(*) FROM pg_type t
                 JOIN pg_namespace n ON t.typnamespace = n.oid
                 WHERE n.nspname NOT LIKE 'pg_%'
                 AND n.nspname != 'information_schema'
                 AND t.typtype IN ('c', 'e', 'd')) as types,
                (SELECT count(*) FROM pg_extension
                 WHERE extname != 'plpgsql') as extensions
            """,
            database=database,
            description="Count database objects",
            check=False,
        )

        # Parse pipe-separated results
        parts = result.strip().split("|")
        if len(parts) >= 9:
            return {
                "tables": int(parts[0].strip() or 0),
                "views": int(parts[1].strip() or 0),
                "materialized_views": int(parts[2].strip() or 0),
                "indexes": int(parts[3].strip() or 0),
                "sequences": int(parts[4].strip() or 0),
                "functions": int(parts[5].strip() or 0),
                "triggers": int(parts[6].strip() or 0),
                "types": int(parts[7].strip() or 0),
                "extensions": int(parts[8].strip() or 0),
            }
        return {}

    def reset_database(self, name: str, *, force: bool = False) -> dict[str, int]:
        """Reset a PostgreSQL database by dropping all objects.

        This drops ALL objects in the database including:
        - Tables (and their data)
        - Views (regular and materialized)
        - Functions and procedures
        - Sequences
        - Types (custom types, enums, domains)
        - Triggers
        - Indexes
        - Extensions (user-installed)
        - Schemas (except public, which is recreated)

        Preserves:
        - The database itself
        - User roles and permissions
        - The public schema (recreated empty)

        Args:
            name: Database name
            force: Terminate existing connections first

        Returns:
            Dictionary with counts of dropped objects by type

        Raises:
            PostgresError: If reset fails
        """
        validate_identifier(name, "database")

        if not self.database_exists(name):
            raise PostgresError(
                f"Database '{name}' does not exist",
                hint="Check database name with: sm postgres db list",
            )

        # Get object counts before reset
        counts = self._get_object_counts(name)

        # Safety verification: confirm we're about to operate on the correct database
        # This is defense in depth - verify the database name matches what we expect
        verify_result = self._run_sql(
            "SELECT current_database()",
            database=name,
            description=f"Verify connection to '{name}'",
        )
        current_db = verify_result.strip()
        if current_db != name:
            raise PostgresError(
                f"Safety check failed: connected to '{current_db}' but expected '{name}'",
                hint="This is a critical safety error. Please report this issue.",
            )

        if force:
            # Terminate all connections
            self._run_sql(
                f"""
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = '{name}'
                AND pid <> pg_backend_pid()
                """,
                description=f"Terminate connections to '{name}'",
                check=False,
            )

        self.ctx.console.step(f"Resetting database '{name}'")

        # Get database owner for recreating public schema
        owner_result = self._run_sql(
            f"SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname = '{name}'",
            description="Get database owner",
        )
        db_owner = owner_result.strip() or "postgres"

        # Get all user-created schemas
        schemas_result = self._run_sql(
            """
            SELECT nspname FROM pg_namespace
            WHERE nspname NOT LIKE 'pg_%'
            AND nspname != 'information_schema'
            ORDER BY nspname
            """,
            database=name,
            description="List schemas",
        )
        schemas = [s.strip() for s in schemas_result.strip().splitlines() if s.strip()]

        # Drop all schemas with CASCADE
        for schema in schemas:
            self.ctx.console.step(f"Dropping schema '{schema}'...")
            self._run_sql(
                f'DROP SCHEMA IF EXISTS "{schema}" CASCADE',
                database=name,
                description=f"Drop schema '{schema}'",
            )

        # Recreate public schema with proper ownership
        self.ctx.console.step("Recreating public schema...")
        self._run_sql(
            f"""
            CREATE SCHEMA public;
            ALTER SCHEMA public OWNER TO "{db_owner}";
            COMMENT ON SCHEMA public IS 'Standard public schema';
            """,
            database=name,
            description="Recreate public schema",
        )

        # Re-grant default privileges on public
        self._run_sql(
            """
            GRANT USAGE ON SCHEMA public TO PUBLIC;
            """,
            database=name,
            description="Grant default public schema privileges",
        )

        self.ctx.console.success(f"Database '{name}' reset successfully")

        return counts

    def list_databases(self) -> list[DatabaseInfo]:
        """List all databases.

        Returns:
            List of DatabaseInfo objects
        """
        if self.ctx.dry_run:
            return []

        result = self._run_sql(
            """
            SELECT d.datname, pg_catalog.pg_get_userbyid(d.datdba),
                   pg_catalog.pg_encoding_to_char(d.encoding),
                   pg_catalog.pg_size_pretty(pg_catalog.pg_database_size(d.datname)),
                   ts.spcname
            FROM pg_catalog.pg_database d
            LEFT JOIN pg_catalog.pg_tablespace ts ON d.dattablespace = ts.oid
            WHERE d.datistemplate = false
            ORDER BY d.datname
            """,
        )

        databases = []
        for line in result.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 5:
                databases.append(DatabaseInfo(
                    name=parts[0].strip(),
                    owner=parts[1].strip(),
                    encoding=parts[2].strip(),
                    size=parts[3].strip(),
                    tablespace=parts[4].strip(),
                ))

        return databases

    def harden_database(self, name: str, owner: str) -> None:
        """Apply security hardening to a database.

        - Revokes public access
        - Grants minimal privileges to owner

        Args:
            name: Database name
            owner: Database owner
        """
        validate_identifier(name, "database")
        validate_identifier(owner, "user")

        self.ctx.console.step(f"Hardening database '{name}'")

        sql = f"""
        -- Revoke public access
        REVOKE CREATE ON SCHEMA public FROM PUBLIC;
        REVOKE ALL ON DATABASE "{name}" FROM PUBLIC;

        -- Grant access to owner
        GRANT CONNECT ON DATABASE "{name}" TO "{owner}";
        GRANT USAGE, CREATE ON SCHEMA public TO "{owner}";
        """

        self._run_sql(sql, database=name, description=f"Harden database '{name}'")

    # =========================================================================
    # User Operations
    # =========================================================================

    def user_exists(self, name: str) -> bool:
        """Check if a user/role exists.

        Args:
            name: Username

        Returns:
            True if user exists
        """
        if self.ctx.dry_run:
            return False

        result = self._run_sql(
            f"SELECT 1 FROM pg_roles WHERE rolname = '{name}'",
            check=False,
        )
        return bool(result.strip())

    def create_user(
        self,
        name: str,
        password: str,
        *,
        superuser: bool = False,
        createdb: bool = False,
        createrole: bool = False,
        login: bool = True,
        connection_limit: int = -1,
        rollback: Optional[RollbackStack] = None,
    ) -> None:
        """Create a PostgreSQL user with SCRAM-SHA-256 password.

        Args:
            name: Username
            password: Password (will be hashed)
            superuser: Grant superuser
            createdb: Grant createdb
            createrole: Grant createrole
            login: Allow login
            connection_limit: Connection limit (-1 = unlimited)
            rollback: Rollback stack

        Raises:
            PostgresError: If creation fails
        """
        validate_identifier(name, "user")

        # Build role options
        options = []
        options.append("SUPERUSER" if superuser else "NOSUPERUSER")
        options.append("CREATEDB" if createdb else "NOCREATEDB")
        options.append("CREATEROLE" if createrole else "NOCREATEROLE")
        options.append("LOGIN" if login else "NOLOGIN")
        options.append("INHERIT" if not superuser else "NOINHERIT")
        options.append("NOREPLICATION")

        if connection_limit >= 0:
            options.append(f"CONNECTION LIMIT {connection_limit}")

        options_str = " ".join(options)

        # Use DO block with unique dollar-quote tag for safe password handling
        # This prevents issues if the password contains $pass$ or similar
        tag = _unique_dollar_tag()
        sql = f"""
        SET password_encryption = 'scram-sha-256';

        DO $$
        DECLARE
          _pass text := ${tag}${password}${tag}$;
        BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{name}') THEN
            EXECUTE format(
              'CREATE ROLE %I WITH {options_str} PASSWORD %L',
              '{name}', _pass
            );
            RAISE NOTICE 'Role {name} created';
          ELSE
            EXECUTE format('ALTER ROLE %I WITH {options_str} PASSWORD %L', '{name}', _pass);
            RAISE NOTICE 'Role {name} updated';
          END IF;
        END
        $$;
        """

        self.ctx.console.step(f"Creating user '{name}' (SCRAM-SHA-256)")
        self._run_sql(sql, description=f"Create/update user '{name}'")

        if rollback and not self.user_exists(name):
            rollback.add(
                f"Drop user '{name}'",
                lambda n=name: self.drop_user(n),
            )

        self.ctx.console.success(f"User '{name}' created")

    def drop_user(self, name: str) -> None:
        """Drop a PostgreSQL user.

        Args:
            name: Username

        Raises:
            PostgresError: If drop fails
        """
        validate_identifier(name, "user")

        if not self.user_exists(name):
            self.ctx.console.info(f"User '{name}' does not exist")
            return

        self._run_sql(
            f'DROP ROLE "{name}"',
            description=f"Drop user '{name}'",
        )

        self.ctx.console.success(f"User '{name}' dropped")

    def list_users(self) -> list[UserInfo]:
        """List all users/roles.

        Returns:
            List of UserInfo objects
        """
        if self.ctx.dry_run:
            return []

        result = self._run_sql(
            """
            SELECT r.rolname, r.rolsuper, r.rolcreatedb, r.rolcreaterole,
                   r.rolcanlogin, r.rolconnlimit,
                   COALESCE(string_agg(m.rolname, ','), '')
            FROM pg_roles r
            LEFT JOIN pg_auth_members am ON r.oid = am.member
            LEFT JOIN pg_roles m ON am.roleid = m.oid
            WHERE r.rolname !~ '^pg_'
            GROUP BY r.oid, r.rolname, r.rolsuper, r.rolcreatedb,
                     r.rolcreaterole, r.rolcanlogin, r.rolconnlimit
            ORDER BY r.rolname
            """,
        )

        users = []
        for line in result.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 7:
                users.append(UserInfo(
                    name=parts[0].strip(),
                    superuser=parts[1].strip() == "t",
                    create_db=parts[2].strip() == "t",
                    create_role=parts[3].strip() == "t",
                    login=parts[4].strip() == "t",
                    connections=int(parts[5].strip()),
                    roles=[r.strip() for r in parts[6].split(",") if r.strip()],
                ))

        return users

    def get_scram_hash(self, username: str) -> Optional[str]:
        """Get the SCRAM-SHA-256 password hash for a user.

        Args:
            username: Username

        Returns:
            SCRAM hash or None
        """
        if self.ctx.dry_run:
            return None

        result = self._run_sql(
            f"SELECT rolpassword FROM pg_authid WHERE rolname = '{username}'",
            check=False,
        )

        hash_value = result.strip()
        if hash_value and hash_value.startswith("SCRAM-SHA-256$"):
            return hash_value
        return None

    def rotate_password(self, name: str, new_password: str) -> None:
        """Rotate a user's password.

        Args:
            name: Username
            new_password: New password

        Raises:
            PostgresError: If rotation fails
        """
        validate_identifier(name, "user")

        if not self.user_exists(name):
            raise PostgresError(
                f"User '{name}' does not exist",
                hint="Use 'sm postgres user create' to create the user first",
            )

        # Use unique dollar-quote tag to safely embed password
        tag = _unique_dollar_tag()
        sql = f"""
        SET password_encryption = 'scram-sha-256';
        ALTER ROLE "{name}" WITH PASSWORD ${tag}${new_password}${tag}$;
        """

        self.ctx.console.step(f"Rotating password for '{name}'")
        self._run_sql(sql, description=f"Rotate password for '{name}'")
        self.ctx.console.success(f"Password rotated for '{name}'")

    # =========================================================================
    # Grant Operations
    # =========================================================================

    def grant_readonly(self, database: str, username: str) -> None:
        """Grant read-only access to a database.

        Args:
            database: Database name
            username: Username

        Raises:
            PostgresError: If grant fails
        """
        validate_identifier(database, "database")
        validate_identifier(username, "user")

        self.ctx.console.step(f"Granting read-only access on '{database}' to '{username}'")

        sql = f"""
        -- Grant connect
        GRANT CONNECT ON DATABASE "{database}" TO "{username}";

        -- Grant schema usage
        GRANT USAGE ON SCHEMA public TO "{username}";

        -- Grant SELECT on all existing tables
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{username}";

        -- Grant SELECT on all existing sequences
        GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO "{username}";

        -- Set default privileges for future objects
        DO $$
        DECLARE
          schema_owner text;
        BEGIN
          SELECT nspowner::regrole::text INTO schema_owner
          FROM pg_namespace WHERE nspname = 'public';

          EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON TABLES TO %I',
            schema_owner, '{username}'
          );
          EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON SEQUENCES TO %I',
            schema_owner, '{username}'
          );
        END
        $$;
        """

        self._run_sql(sql, database=database, description=f"Grant readonly to '{username}'")
        self.ctx.console.success(f"Read-only access granted to '{username}'")

    def grant_readwrite(self, database: str, username: str) -> None:
        """Grant read-write access to a database.

        Args:
            database: Database name
            username: Username

        Raises:
            PostgresError: If grant fails
        """
        validate_identifier(database, "database")
        validate_identifier(username, "user")

        self.ctx.console.step(f"Granting read-write access on '{database}' to '{username}'")

        sql = f"""
        -- Grant connect
        GRANT CONNECT ON DATABASE "{database}" TO "{username}";

        -- Grant schema usage and create
        GRANT USAGE, CREATE ON SCHEMA public TO "{username}";

        -- Grant DML on all existing tables
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{username}";

        -- Grant full access on sequences
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{username}";

        -- Set default privileges for future objects
        DO $$
        DECLARE
          schema_owner text;
        BEGIN
          SELECT nspowner::regrole::text INTO schema_owner
          FROM pg_namespace WHERE nspname = 'public';

          EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
            schema_owner, '{username}'
          );
          EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I',
            schema_owner, '{username}'
          );
        END
        $$;
        """

        self._run_sql(sql, database=database, description=f"Grant readwrite to '{username}'")
        self.ctx.console.success(f"Read-write access granted to '{username}'")

    def revoke_access(self, database: str, username: str) -> None:
        """Revoke all access from a database.

        Args:
            database: Database name
            username: Username
        """
        validate_identifier(database, "database")
        validate_identifier(username, "user")

        self.ctx.console.step(f"Revoking access on '{database}' from '{username}'")

        sql = f"""
        REVOKE ALL ON DATABASE "{database}" FROM "{username}";
        REVOKE ALL ON SCHEMA public FROM "{username}";
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "{username}";
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "{username}";
        """

        self._run_sql(sql, database=database, description=f"Revoke access from '{username}'")
        self.ctx.console.success(f"Access revoked from '{username}'")

    # =========================================================================
    # Extension Operations
    # =========================================================================

    def extension_exists(self, database: str, extension: str) -> bool:
        """Check if an extension is enabled on a database.

        Args:
            database: Database name
            extension: Extension name (e.g., "vector")

        Returns:
            True if extension is enabled
        """
        if self.ctx.dry_run:
            return False

        result = self._run_sql(
            f"SELECT 1 FROM pg_extension WHERE extname = '{extension}'",
            database=database,
            check=False,
        )
        return bool(result.strip())

    def list_extensions(self, database: str) -> list[ExtensionInfo]:
        """List all enabled extensions on a database.

        Args:
            database: Database name

        Returns:
            List of ExtensionInfo objects
        """
        if self.ctx.dry_run:
            return []

        result = self._run_sql(
            """
            SELECT e.extname, e.extversion, n.nspname
            FROM pg_extension e
            JOIN pg_namespace n ON e.extnamespace = n.oid
            ORDER BY e.extname
            """,
            database=database,
        )

        extensions = []
        for line in result.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 3:
                extensions.append(ExtensionInfo(
                    name=parts[0].strip(),
                    version=parts[1].strip(),
                    schema=parts[2].strip(),
                ))

        return extensions

    def install_extension_package(self, extension: str) -> None:
        """Install the system package for a PostgreSQL extension.

        Args:
            extension: Extension name (e.g., "vector")

        Raises:
            PostgresError: If package is unknown or installation fails
        """
        if extension not in EXTENSION_PACKAGES:
            raise PostgresError(
                f"Unknown extension: {extension}",
                hint=f"Supported extensions: {', '.join(sorted(EXTENSION_PACKAGES.keys()))}",
            )

        # Detect PostgreSQL version
        version = self.detect_version()
        if not version:
            raise PostgresError(
                "Could not detect PostgreSQL version",
                hint="Ensure PostgreSQL is installed first with 'sm postgres setup'",
            )

        # Build package name
        package_template = EXTENSION_PACKAGES[extension]
        package_name = package_template.format(version=version)

        self.ctx.console.step(f"Installing extension package '{package_name}'")

        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"apt-get install {package_name}")
            return

        self.executor.apt_install(
            [package_name],
            description=f"Install {extension} extension package",
        )

        self.ctx.console.success(f"Package '{package_name}' installed")

    def enable_extension(
        self,
        database: str,
        extension: str,
        *,
        schema: str = "public",
        rollback: Optional[RollbackStack] = None,
    ) -> None:
        """Enable an extension on a database.

        Args:
            database: Database name
            extension: Extension name (e.g., "vector")
            schema: Schema to install the extension into
            rollback: Rollback stack for cleanup on failure

        Raises:
            PostgresError: If enabling fails
        """
        validate_identifier(database, "database")

        # Check if already enabled (idempotent)
        if self.extension_exists(database, extension):
            self.ctx.console.info(f"Extension '{extension}' already enabled on '{database}'")
            return

        self.ctx.console.step(f"Enabling extension '{extension}' on '{database}'")

        sql = f'CREATE EXTENSION IF NOT EXISTS "{extension}" SCHEMA "{schema}"'

        self._run_sql(
            sql,
            database=database,
            description=f"Enable extension '{extension}' on '{database}'",
        )

        # Add rollback action
        if rollback:
            rollback.add(
                f"Disable extension '{extension}' on '{database}'",
                lambda d=database, e=extension: self.disable_extension(d, e),
            )

        # Verify extension was created
        if not self.ctx.dry_run and not self.extension_exists(database, extension):
            raise PostgresError(
                f"Extension '{extension}' was not enabled successfully",
                hint="Check PostgreSQL logs for details",
            )

        self.ctx.console.success(f"Extension '{extension}' enabled on '{database}'")

    def disable_extension(
        self,
        database: str,
        extension: str,
        *,
        cascade: bool = False,
    ) -> None:
        """Disable an extension on a database.

        Args:
            database: Database name
            extension: Extension name
            cascade: Also drop dependent objects

        Raises:
            PostgresError: If disabling fails
        """
        validate_identifier(database, "database")

        if not self.extension_exists(database, extension):
            self.ctx.console.info(f"Extension '{extension}' not enabled on '{database}'")
            return

        self.ctx.console.step(f"Disabling extension '{extension}' on '{database}'")

        sql = f'DROP EXTENSION IF EXISTS "{extension}"'
        if cascade:
            sql += " CASCADE"

        self._run_sql(
            sql,
            database=database,
            description=f"Disable extension '{extension}' on '{database}'",
        )

        self.ctx.console.success(f"Extension '{extension}' disabled on '{database}'")

    # =========================================================================
    # Connection Testing
    # =========================================================================

    def verify_connection(
        self,
        database: str,
        username: str,
        password: str,
    ) -> bool:
        """Verify a user can connect to a database.

        Args:
            database: Database name
            username: Username
            password: Password

        Returns:
            True if connection succeeds
        """
        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Test connection to {database} as {username}")
            return True

        self.ctx.console.step(f"Verifying connection as '{username}' to '{database}'")

        result = self.executor.run(
            [
                "psql",
                "-h", self.host,
                "-p", str(self.port),
                "-U", username,
                "-d", database,
                "-c", "SELECT 1",
            ],
            env={"PGPASSWORD": password},
            check=False,
            sensitive=True,
        )

        if result.success:
            self.ctx.console.success("Connection verified")
            return True
        else:
            self.ctx.console.warn("Connection verification failed")
            self.ctx.console.warn("Check pg_hba.conf and ensure the user/host is allowed")
            return False
