from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import DateTime, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator):
    """Always timezone-aware UTC in Python; stored as naive UTC (SQLite drops tzinfo, so we re-attach it on read).

    Without this, API output has no zone designator and clients misread UTC instants as local time.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime rejected: all timestamps must be timezone-aware")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        return value.replace(tzinfo=UTC) if value is not None else None


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


def make_engine(db_path: Path | str, key: bytes | None = None) -> Engine:
    memory = str(db_path) == ":memory:"
    url = "sqlite://" if memory else f"sqlite:///{db_path}"
    kwargs: dict = {"future": True, "connect_args": {"check_same_thread": False, "timeout": 15}}
    if memory:
        kwargs["poolclass"] = StaticPool
    if key is not None:  # SQLCipher: same DB-API, but every connection must receive the key before anything else
        import sqlcipher3.dbapi2 as sqlcipher
        kwargs["module"] = sqlcipher
    engine = create_engine(url, **kwargs)

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        if key is not None:
            cur.execute(f"PRAGMA key=\"x'{key.hex()}'\"")
        cur.execute("PRAGMA foreign_keys=ON")
        if not memory:
            cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=15000")
        cur.close()

    return engine


def session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(engine, expire_on_commit=False, future=True)
