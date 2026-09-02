"""Database engine and session handling.

SQLAlchemy sits between the application and SQLite specifically so that the
move to PostgreSQL is a change to ECDAT_DATABASE_URL and nothing else.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    """Declarative base for every ORM table."""


def _engine_kwargs() -> dict:
    """Driver-specific engine options.

    SQLite refuses cross-thread use of a connection by default, and the scan
    runner works from a thread pool, so that check is disabled for SQLite only.
    PostgreSQL needs no equivalent and gets no special casing.
    """
    if settings.database_url.startswith("sqlite"):
        # The scan runner touches the session from worker threads.
        return {"connect_args": {"check_same_thread": False}}
    return {}


settings.data_dir.mkdir(parents=True, exist_ok=True)
engine = create_engine(settings.database_url, future=True, **_engine_kwargs())
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a request scoped session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def init_db() -> None:
    """Create tables. Safe to call on every startup."""
    from app.models import tables  # noqa: F401  (import registers the models)

    Base.metadata.create_all(bind=engine)
