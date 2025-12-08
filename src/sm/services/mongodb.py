"""MongoDB service abstraction.

Provides a safe interface for managing MongoDB databases and users.
Uses mongosh for all operations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sm.core.context import ExecutionContext
from sm.core.executor import CommandExecutor, RollbackStack
from sm.core.exceptions import MongoDBError
from sm.core.validation import validate_identifier


@dataclass
class DatabaseInfo:
    """Information about a MongoDB database."""
    name: str
    size_on_disk: int
    collections: int
    is_empty: bool


@dataclass
class UserInfo:
    """Information about a MongoDB user."""
    name: str
    database: str  # Auth database
    roles: list[dict]  # [{"role": "readWrite", "db": "mydb"}]


@dataclass
class RoleInfo:
    """Information about a MongoDB role."""
    role: str
    db: str


class MongoDBService:
    """Safe interface for MongoDB operations.

    All operations:
    - Respect dry-run mode
    - Use mongosh for execution
    - Log to audit trail
    - Support rollback
    """

    def __init__(
        self,
        ctx: ExecutionContext,
        executor: CommandExecutor,
        *,
        host: str = "127.0.0.1",
        port: int = 27017,
        auth_database: str = "admin",
    ) -> None:
        """Initialize MongoDB service.

        Args:
            ctx: Execution context
            executor: Command executor
            host: MongoDB host
            port: MongoDB port
            auth_database: Authentication database
        """
        self.ctx = ctx
        self.executor = executor
        self.host = host
        self.port = port
        self.auth_database = auth_database
        self._admin_credentials: Optional[tuple[str, str]] = None

    def set_admin_credentials(self, username: str, password: str) -> None:
        """Set admin credentials for authenticated operations.

        Args:
            username: Admin username
            password: Admin password
        """
        self._admin_credentials = (username, password)

    def _build_connection_uri(
        self,
        database: str = "admin",
        authenticated: bool = True,
    ) -> str:
        """Build MongoDB connection URI.

        Args:
            database: Database to connect to
            authenticated: Use admin credentials

        Returns:
            Connection URI string
        """
        if authenticated and self._admin_credentials:
            user, password = self._admin_credentials
            # URL-encode special characters in password
            from urllib.parse import quote_plus
            encoded_pass = quote_plus(password)
            return f"mongodb://{user}:{encoded_pass}@{self.host}:{self.port}/{database}?authSource={self.auth_database}"
        else:
            return f"mongodb://{self.host}:{self.port}/{database}"

    def _run_mongosh(
        self,
        javascript: str,
        *,
        database: str = "admin",
        description: Optional[str] = None,
        check: bool = True,
        authenticated: bool = True,
    ) -> str:
        """Execute JavaScript via mongosh.

        Args:
            javascript: JavaScript code to execute
            database: Database to connect to
            description: Description for logging
            check: Raise on error
            authenticated: Use admin credentials

        Returns:
            Command output

        Raises:
            MongoDBError: If execution fails
        """
        uri = self._build_connection_uri(database, authenticated)

        cmd = [
            "mongosh",
            uri,
            "--quiet",
            "--eval", javascript,
        ]

        if description:
            self.ctx.console.step(description)

        if self.ctx.dry_run:
            truncated_js = javascript[:100] + "..." if len(javascript) > 100 else javascript
            self.ctx.console.dry_run_msg(f"Execute: {truncated_js}")
            return ""

        result = self.executor.run(
            cmd,
            check=False,
            sensitive=True,  # Hide credentials in logs
        )

        if check and not result.success:
            raise MongoDBError(
                f"MongoDB operation failed: {description or 'unknown'}",
                details=[result.stderr] if result.stderr else None,
            )

        return result.stdout.strip()

    # =========================================================================
    # Version and Status
    # =========================================================================

    def detect_version(self) -> Optional[str]:
        """Detect installed MongoDB version.

        Returns:
            Version string (e.g., "7.0.14") or None
        """
        result = self.executor.run(
            ["mongod", "--version"],
            check=False,
        )
        if result.success:
            # Parse: "db version v7.0.x"
            for line in result.stdout.splitlines():
                if "db version" in line:
                    return line.split("v")[-1].split()[0]
        return None

    def is_running(self) -> bool:
        """Check if MongoDB is running.

        Returns:
            True if running
        """
        if self.ctx.dry_run:
            return True

        uri = self._build_connection_uri("admin", authenticated=False)
        result = self.executor.run(
            ["mongosh", uri, "--quiet", "--eval", "db.adminCommand('ping')"],
            check=False,
        )
        return result.success

    def is_auth_enabled(self) -> bool:
        """Check if MongoDB authentication is enabled.

        Returns:
            True if auth is enabled
        """
        if self.ctx.dry_run:
            return True

        # Try to run a command without auth - if it fails, auth is enabled
        uri = self._build_connection_uri("admin", authenticated=False)
        result = self.executor.run(
            ["mongosh", uri, "--quiet", "--eval", "db.adminCommand('listDatabases')"],
            check=False,
        )
        return not result.success

    # =========================================================================
    # Database Operations
    # =========================================================================

    def database_exists(self, name: str) -> bool:
        """Check if database exists.

        Args:
            name: Database name

        Returns:
            True if database exists
        """
        if self.ctx.dry_run:
            return False

        result = self._run_mongosh(
            f"db.adminCommand('listDatabases').databases.map(d => d.name).includes('{name}')",
            check=False,
        )
        return result.lower() == "true"

    def create_database(
        self,
        name: str,
        *,
        rollback: Optional[RollbackStack] = None,
    ) -> None:
        """Create a MongoDB database.

        Note: In MongoDB, databases are created implicitly when first
        collection is created. This creates an initialization collection.

        Args:
            name: Database name
            rollback: Rollback stack for cleanup on failure

        Raises:
            MongoDBError: If creation fails
        """
        validate_identifier(name, "database")

        if self.database_exists(name):
            self.ctx.console.info(f"Database '{name}' already exists")
            return

        self._run_mongosh(
            f"db.getSiblingDB('{name}').createCollection('_init')",
            description=f"Creating database '{name}'",
        )

        if rollback:
            rollback.add(
                f"Drop database '{name}'",
                lambda n=name: self.drop_database(n),
            )

        self.ctx.console.success(f"Database '{name}' created")

    def drop_database(self, name: str) -> None:
        """Drop a MongoDB database.

        Args:
            name: Database name

        Raises:
            MongoDBError: If drop fails
        """
        validate_identifier(name, "database")

        if not self.database_exists(name):
            self.ctx.console.info(f"Database '{name}' does not exist")
            return

        self._run_mongosh(
            f"db.getSiblingDB('{name}').dropDatabase()",
            description=f"Dropping database '{name}'",
        )
        self.ctx.console.success(f"Database '{name}' dropped")

    def list_databases(self, exclude_system: bool = True) -> list[DatabaseInfo]:
        """List all databases.

        Args:
            exclude_system: Exclude admin, config, local databases

        Returns:
            List of DatabaseInfo objects
        """
        if self.ctx.dry_run:
            return []

        result = self._run_mongosh(
            "JSON.stringify(db.adminCommand('listDatabases').databases)",
        )

        if not result:
            return []

        try:
            databases = []
            system_dbs = {"admin", "config", "local"}

            for db in json.loads(result):
                name = db["name"]
                if exclude_system and name in system_dbs:
                    continue

                databases.append(DatabaseInfo(
                    name=name,
                    size_on_disk=db.get("sizeOnDisk", 0),
                    collections=0,  # Would need separate query per db
                    is_empty=db.get("empty", False),
                ))

            return databases
        except json.JSONDecodeError:
            return []

    # =========================================================================
    # User Operations
    # =========================================================================

    def user_exists(self, name: str, database: str = "admin") -> bool:
        """Check if user exists.

        Args:
            name: Username
            database: Auth database

        Returns:
            True if user exists
        """
        if self.ctx.dry_run:
            return False

        result = self._run_mongosh(
            f"db.getSiblingDB('{database}').getUser('{name}') !== null",
            check=False,
        )
        return result.lower() == "true"

    def create_user(
        self,
        name: str,
        password: str,
        *,
        database: str = "admin",
        roles: Optional[list[dict]] = None,
        rollback: Optional[RollbackStack] = None,
    ) -> None:
        """Create a MongoDB user with SCRAM-SHA-256.

        Args:
            name: Username
            password: User password
            database: Auth database
            roles: List of role dicts [{"role": "readWrite", "db": "mydb"}]
            rollback: Rollback stack for cleanup on failure

        Raises:
            MongoDBError: If creation fails
        """
        validate_identifier(name, "user")

        if self.user_exists(name, database):
            self.ctx.console.info(f"User '{name}' already exists in '{database}'")
            return

        if roles is None:
            roles = []

        roles_json = json.dumps(roles)

        # Use SCRAM-SHA-256 (MongoDB 7.0 default)
        js = f"""
        db.getSiblingDB('{database}').createUser({{
            user: '{name}',
            pwd: '{password}',
            roles: {roles_json},
            mechanisms: ['SCRAM-SHA-256']
        }})
        """

        self._run_mongosh(
            js,
            description=f"Creating user '{name}' (SCRAM-SHA-256)",
        )

        if rollback:
            rollback.add(
                f"Drop user '{name}'",
                lambda n=name, d=database: self.drop_user(n, d),
            )

        self.ctx.console.success(f"User '{name}' created")

    def drop_user(self, name: str, database: str = "admin") -> None:
        """Drop a MongoDB user.

        Args:
            name: Username
            database: Auth database

        Raises:
            MongoDBError: If drop fails
        """
        validate_identifier(name, "user")

        if not self.user_exists(name, database):
            self.ctx.console.info(f"User '{name}' does not exist")
            return

        self._run_mongosh(
            f"db.getSiblingDB('{database}').dropUser('{name}')",
            description=f"Dropping user '{name}'",
        )
        self.ctx.console.success(f"User '{name}' dropped")

    def list_users(self, database: str = "admin") -> list[UserInfo]:
        """List users in a database.

        Args:
            database: Auth database to query

        Returns:
            List of UserInfo objects
        """
        if self.ctx.dry_run:
            return []

        result = self._run_mongosh(
            f"JSON.stringify(db.getSiblingDB('{database}').getUsers().users)",
        )

        if not result:
            return []

        try:
            users = []
            for user in json.loads(result):
                users.append(UserInfo(
                    name=user["user"],
                    database=user["db"],
                    roles=user.get("roles", []),
                ))
            return users
        except json.JSONDecodeError:
            return []

    def rotate_password(
        self,
        name: str,
        new_password: str,
        database: str = "admin",
    ) -> None:
        """Rotate user password.

        Args:
            name: Username
            new_password: New password
            database: Auth database

        Raises:
            MongoDBError: If user doesn't exist or update fails
        """
        validate_identifier(name, "user")

        if not self.user_exists(name, database):
            raise MongoDBError(
                f"User '{name}' does not exist",
                hint="Use 'sm mongodb user create' to create the user first",
            )

        js = f"""
        db.getSiblingDB('{database}').updateUser('{name}', {{
            pwd: '{new_password}',
            mechanisms: ['SCRAM-SHA-256']
        }})
        """

        self._run_mongosh(
            js,
            description=f"Rotating password for '{name}'",
        )
        self.ctx.console.success(f"Password rotated for '{name}'")

    # =========================================================================
    # Role Operations
    # =========================================================================

    def grant_role(
        self,
        username: str,
        role: str,
        database: str,
        auth_db: str = "admin",
    ) -> None:
        """Grant a role to a user.

        Args:
            username: User to grant role to
            role: Role name (e.g., "readWrite", "dbOwner")
            database: Database the role applies to
            auth_db: User's authentication database

        Raises:
            MongoDBError: If grant fails
        """
        js = f"""
        db.getSiblingDB('{auth_db}').grantRolesToUser('{username}', [
            {{ role: '{role}', db: '{database}' }}
        ])
        """

        self._run_mongosh(
            js,
            description=f"Granting {role}@{database} to '{username}'",
        )
        self.ctx.console.success(f"Granted {role}@{database} to '{username}'")

    def revoke_role(
        self,
        username: str,
        role: str,
        database: str,
        auth_db: str = "admin",
    ) -> None:
        """Revoke a role from a user.

        Args:
            username: User to revoke role from
            role: Role name
            database: Database the role applies to
            auth_db: User's authentication database

        Raises:
            MongoDBError: If revoke fails
        """
        js = f"""
        db.getSiblingDB('{auth_db}').revokeRolesFromUser('{username}', [
            {{ role: '{role}', db: '{database}' }}
        ])
        """

        self._run_mongosh(
            js,
            description=f"Revoking {role}@{database} from '{username}'",
        )
        self.ctx.console.success(f"Revoked {role}@{database} from '{username}'")

    # =========================================================================
    # Connection Verification
    # =========================================================================

    def verify_connection(
        self,
        database: str,
        username: str,
        password: str,
    ) -> bool:
        """Verify user can connect to database.

        Args:
            database: Database to connect to
            username: Username to test
            password: User's password

        Returns:
            True if connection successful
        """
        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Test connection to {database} as {username}")
            return True

        self.ctx.console.step(f"Verifying connection as '{username}' to '{database}'")

        from urllib.parse import quote_plus
        encoded_pass = quote_plus(password)
        uri = f"mongodb://{username}:{encoded_pass}@{self.host}:{self.port}/{database}?authSource={self.auth_database}"

        result = self.executor.run(
            ["mongosh", uri, "--quiet", "--eval", "db.runCommand({ping: 1})"],
            check=False,
            sensitive=True,
        )

        if result.success:
            self.ctx.console.success("Connection verified")
            return True
        else:
            self.ctx.console.warn("Connection verification failed")
            return False
