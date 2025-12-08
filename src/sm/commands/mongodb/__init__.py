"""MongoDB management commands."""

from sm.commands.mongodb.user import app as user_app
from sm.commands.mongodb.db import app as db_app
from sm.commands.mongodb.backup import app as backup_app
from sm.commands.mongodb.restore import app as restore_app

__all__ = ["user_app", "db_app", "backup_app", "restore_app"]
