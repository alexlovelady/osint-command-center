from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from osintcc.db import (
    Base,
    models,  # noqa: F401  (register tables)
)
from osintcc.db.migrate import include_object

target_metadata = Base.metadata


def run_migrations() -> None:
    url = context.config.get_main_option("sqlalchemy.url")
    connectable = context.config.attributes.get("connection")
    if connectable is None:
        assert url is not None
        connectable = create_engine(url).connect()
    context.configure(connection=connectable, target_metadata=target_metadata, render_as_batch=True, include_object=include_object,
                      compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


run_migrations()
