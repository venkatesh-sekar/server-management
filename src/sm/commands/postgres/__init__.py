"""PostgreSQL management commands."""

from sm.commands.postgres.user import app as user_app
from sm.commands.postgres.db import app as db_app
from sm.commands.postgres.extension import app as extension_app

__all__ = ["user_app", "db_app", "extension_app"]
