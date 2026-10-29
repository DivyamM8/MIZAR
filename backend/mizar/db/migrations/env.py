"""Alembic environment. Migrations run programmatically via mizar.db.engine.upgrade_db."""

from alembic import context

from mizar.db.tables import metadata

connection = context.config.attributes.get("connection")
if context.is_offline_mode() or connection is None:
    raise RuntimeError("MIZAR migrations must be run through mizar.db.engine.upgrade_db")

context.configure(connection=connection, target_metadata=metadata, render_as_batch=True)
with context.begin_transaction():
    context.run_migrations()
