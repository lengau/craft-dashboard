"""Database connection and session management."""

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def get_engine(
    database_url: str,
    pool_size: int = 2,
    max_overflow: int = 3,
    pool_recycle: int = 300,
    pool_timeout: int = 30,
) -> AsyncEngine:
    """Create an async SQLAlchemy engine.

    Args:
        database_url: PostgreSQL connection URL with asyncpg driver.
        pool_size: Number of persistent connections in the pool.
        max_overflow: Number of connections allowed beyond pool_size.
        pool_recycle: Recycle connections older than this many seconds.
        pool_timeout: Seconds to wait before timing out on pool checkout.

    Returns:
        An AsyncEngine instance.

    """
    return create_async_engine(
        database_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_recycle=pool_recycle,
        pool_timeout=pool_timeout,
        pool_pre_ping=True,
        echo=False,
    )


def get_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory bound to the given engine.

    Args:
        engine: The async SQLAlchemy engine.

    Returns:
        An async_sessionmaker that produces AsyncSession instances.

    """
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
