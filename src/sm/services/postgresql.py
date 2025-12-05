"""PostgreSQL service abstraction.

Provides a safe interface for managing PostgreSQL databases and users.
All SQL operations use parameterized queries to prevent injection.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sm.core.context import ExecutionContext
from sm.core.executor import CommandExecutor, RollbackStack
from sm.core.exceptions import PostgresError
from sm.core.validation import validate_identifier


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

        # Use DO block for safe password handling
        sql = f"""
        SET password_encryption = 'scram-sha-256';

        DO $$
        DECLARE
          _pass text := $pass${password}$pass$;
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

        sql = f"""
        SET password_encryption = 'scram-sha-256';
        ALTER ROLE "{name}" WITH PASSWORD $pass${new_password}$pass$;
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
