"""PostgreSQL ownership management service.

Provides functionality to view and transfer ownership of database objects.
Supports all PostgreSQL object types that can have owners.
"""

from dataclasses import dataclass

from sm.core.context import ExecutionContext
from sm.core.exceptions import PostgresError
from sm.core.executor import CommandExecutor


@dataclass
class DatabaseObject:
    """Information about a database object with ownership."""

    object_type: str  # table, sequence, function, etc.
    schema: str  # public, etc. (empty for schemas)
    name: str  # object name
    owner: str  # current owner
    signature: str | None = None  # for functions: name(arg_types)

    @property
    def qualified_name(self) -> str:
        """Get the fully qualified name (schema.name or just name for schemas)."""
        if self.schema:
            return f"{self.schema}.{self.name}"
        return self.name

    @property
    def display_name(self) -> str:
        """Get the display name for UI (uses signature for functions)."""
        if self.signature:
            if self.schema:
                return f"{self.schema}.{self.signature}"
            return self.signature
        return self.qualified_name

    def get_alter_statement(self, new_owner: str) -> str:
        """Generate the ALTER ... OWNER TO statement for this object."""
        type_upper = self.object_type.upper().replace("_", " ")

        if self.object_type == "schema":
            return f'ALTER SCHEMA "{self.name}" OWNER TO "{new_owner}"'

        if self.object_type in ("function", "procedure", "aggregate"):
            # Functions need the full signature
            if self.signature:
                return f'ALTER {type_upper} {self.schema}."{self.signature}" OWNER TO "{new_owner}"'
            return f'ALTER {type_upper} "{self.schema}"."{self.name}" OWNER TO "{new_owner}"'

        # Tables, views, sequences, types, domains, foreign tables
        return f'ALTER {type_upper} "{self.schema}"."{self.name}" OWNER TO "{new_owner}"'


# SQL query to fetch all objects with their owners
_LIST_OBJECTS_SQL = """
WITH objects AS (
    -- Tables
    SELECT 'table'::text as object_type, schemaname as schema, tablename as name,
           tableowner as owner, NULL::text as signature
    FROM pg_tables
    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')

    UNION ALL

    -- Views
    SELECT 'view', schemaname, viewname, viewowner, NULL
    FROM pg_views
    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')

    UNION ALL

    -- Materialized Views
    SELECT 'materialized_view', schemaname, matviewname, matviewowner, NULL
    FROM pg_matviews
    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')

    UNION ALL

    -- Sequences
    SELECT 'sequence', schemaname, sequencename, sequenceowner, NULL
    FROM pg_sequences
    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')

    UNION ALL

    -- Functions (including signature for ALTER)
    SELECT 'function', n.nspname, p.proname, pg_get_userbyid(p.proowner),
           p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
    FROM pg_proc p
    JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND p.prokind = 'f'

    UNION ALL

    -- Procedures
    SELECT 'procedure', n.nspname, p.proname, pg_get_userbyid(p.proowner),
           p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
    FROM pg_proc p
    JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND p.prokind = 'p'

    UNION ALL

    -- Aggregates
    SELECT 'aggregate', n.nspname, p.proname, pg_get_userbyid(p.proowner),
           p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
    FROM pg_proc p
    JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND p.prokind = 'a'

    UNION ALL

    -- Types (composite and enum only, excluding internal types)
    SELECT 'type', n.nspname, t.typname, pg_get_userbyid(t.typowner), NULL
    FROM pg_type t
    JOIN pg_namespace n ON t.typnamespace = n.oid
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND t.typtype IN ('c', 'e')

    UNION ALL

    -- Domains
    SELECT 'domain', n.nspname, t.typname, pg_get_userbyid(t.typowner), NULL
    FROM pg_type t
    JOIN pg_namespace n ON t.typnamespace = n.oid
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND t.typtype = 'd'

    UNION ALL

    -- Foreign Tables
    SELECT 'foreign_table', n.nspname, c.relname, pg_get_userbyid(c.relowner), NULL
    FROM pg_class c
    JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND c.relkind = 'f'

    UNION ALL

    -- Schemas (excluding system schemas)
    SELECT 'schema', '', nspname, pg_get_userbyid(nspowner), NULL
    FROM pg_namespace
    WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
      AND nspname NOT LIKE 'pg_temp_%'
      AND nspname NOT LIKE 'pg_toast_temp_%'
)
SELECT object_type, schema, name, owner, signature
FROM objects
ORDER BY object_type, schema, name;
"""


class OwnershipService:
    """Service for managing PostgreSQL object ownership.

    Provides methods to:
    - List all objects with their owners in a database
    - Transfer ownership of objects to a new owner
    - Validate that a role exists before transferring

    Usage:
        service = OwnershipService(ctx, executor)
        objects = service.list_objects("mydb")
        service.transfer_ownership("mydb", objects, "new_owner")
    """

    def __init__(self, ctx: ExecutionContext, executor: CommandExecutor) -> None:
        """Initialize the ownership service.

        Args:
            ctx: Execution context with flags (dry_run, verbose, etc.)
            executor: Command executor for running SQL
        """
        self.ctx = ctx
        self.executor = executor

    def _run_sql(
        self,
        sql: str,
        *,
        database: str = "postgres",
        description: str | None = None,
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

    def role_exists(self, role_name: str) -> bool:
        """Check if a PostgreSQL role exists.

        Args:
            role_name: Name of the role to check

        Returns:
            True if the role exists
        """
        if self.ctx.dry_run:
            return True  # Assume exists in dry-run

        result = self.executor.run_sql_format(
            "SELECT 1 FROM pg_roles WHERE rolname = %L",
            as_user="postgres",
            check=False,
            role_name=role_name,
        )
        return bool(result.strip())

    def list_objects(self, database: str) -> list[DatabaseObject]:
        """List all objects in a database with their owners.

        Args:
            database: Database name to query

        Returns:
            List of DatabaseObject instances
        """
        if self.ctx.dry_run:
            self.ctx.console.dry_run_msg(f"Query objects in database '{database}'")
            return []

        result = self._run_sql(
            _LIST_OBJECTS_SQL,
            database=database,
            description=f"List objects in '{database}'",
        )

        objects: list[DatabaseObject] = []
        for line in result.strip().splitlines():
            if not line.strip():
                continue

            parts = line.split("|")
            if len(parts) >= 4:
                obj = DatabaseObject(
                    object_type=parts[0].strip(),
                    schema=parts[1].strip(),
                    name=parts[2].strip(),
                    owner=parts[3].strip(),
                    signature=parts[4].strip() if len(parts) > 4 and parts[4].strip() else None,
                )
                objects.append(obj)

        return objects

    def list_objects_by_owner(
        self,
        database: str,
        owner: str | None = None,
        exclude_owner: str | None = None,
    ) -> list[DatabaseObject]:
        """List objects filtered by owner.

        Args:
            database: Database name
            owner: Only return objects owned by this role (optional)
            exclude_owner: Exclude objects owned by this role (optional)

        Returns:
            Filtered list of DatabaseObject instances
        """
        objects = self.list_objects(database)

        if owner:
            objects = [obj for obj in objects if obj.owner == owner]

        if exclude_owner:
            objects = [obj for obj in objects if obj.owner != exclude_owner]

        return objects

    def transfer_ownership(
        self,
        database: str,
        objects: list[DatabaseObject],
        new_owner: str,
        *,
        dry_run: bool = False,
    ) -> list[str]:
        """Transfer ownership of objects to a new owner.

        Args:
            database: Database containing the objects
            objects: List of objects to transfer
            new_owner: New owner role name
            dry_run: If True, only show what would be done

        Returns:
            List of ALTER statements executed

        Raises:
            PostgresError: If the new owner doesn't exist or transfer fails
        """
        # Validate new owner exists
        if not self.role_exists(new_owner):
            raise PostgresError(
                f"Role '{new_owner}' does not exist",
                hint="Create the role first with: sm postgres user create",
            )

        # Filter out objects already owned by the new owner
        objects_to_transfer = [obj for obj in objects if obj.owner != new_owner]

        if not objects_to_transfer:
            self.ctx.console.info(f"All selected objects are already owned by '{new_owner}'")
            return []

        statements: list[str] = []
        effective_dry_run = dry_run or self.ctx.dry_run

        for obj in objects_to_transfer:
            stmt = obj.get_alter_statement(new_owner)
            statements.append(stmt)

            if effective_dry_run:
                self.ctx.console.dry_run_msg(stmt)
            else:
                self._run_sql(
                    stmt,
                    database=database,
                    description=f"Transfer {obj.object_type} {obj.display_name} to {new_owner}",
                )

        return statements

    def transfer_all(
        self,
        database: str,
        new_owner: str,
        *,
        object_types: list[str] | None = None,
        schemas: list[str] | None = None,
        dry_run: bool = False,
    ) -> list[str]:
        """Transfer ownership of all objects (with optional filters) to a new owner.

        Args:
            database: Database name
            new_owner: New owner role name
            object_types: Filter by object types (e.g., ["table", "sequence"])
            schemas: Filter by schemas (e.g., ["public"])
            dry_run: If True, only show what would be done

        Returns:
            List of ALTER statements executed
        """
        objects = self.list_objects(database)

        # Apply filters
        if object_types:
            objects = [obj for obj in objects if obj.object_type in object_types]

        if schemas:
            # For schemas themselves, match by name; for other objects, match by schema
            objects = [
                obj for obj in objects
                if (obj.object_type == "schema" and obj.name in schemas)
                or (obj.object_type != "schema" and obj.schema in schemas)
            ]

        return self.transfer_ownership(database, objects, new_owner, dry_run=dry_run)
