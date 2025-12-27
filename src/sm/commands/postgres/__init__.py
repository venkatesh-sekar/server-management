"""PostgreSQL management commands."""

from sm.commands.postgres.user import app as user_app
from sm.commands.postgres.db import app as db_app
from sm.commands.postgres.db_user import app as db_user_app
from sm.commands.postgres.pgdump import app as pgdump_app
from sm.commands.postgres.backrest import app as backrest_app

__all__ = ["user_app", "db_app", "db_user_app", "pgdump_app", "backrest_app"]
