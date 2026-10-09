"""Tests for database connection management."""

from craft_dashboard.database import get_engine, get_session_factory


class TestGetEngine:
    """Tests for get_engine."""

    def test_creates_async_engine(self) -> None:
        """get_engine returns an AsyncEngine with the given URL."""
        engine = get_engine("postgresql+asyncpg://localhost/test_db")

        assert str(engine.url) == "postgresql+asyncpg://localhost/test_db"

    def test_engine_uses_pool_settings(self) -> None:
        """Engine has reasonable pool settings."""
        engine = get_engine("postgresql+asyncpg://localhost/test_db")

        assert engine.pool.size() == 2
        assert engine.pool._max_overflow == 3
        assert engine.pool._recycle == 300
        assert engine.pool.timeout() == 30

    def test_engine_custom_pool_settings(self) -> None:
        """get_engine honors custom pool parameters."""
        engine = get_engine(
            "postgresql+asyncpg://localhost/test_db",
            pool_size=4,
            max_overflow=6,
            pool_recycle=600,
            pool_timeout=15,
        )

        assert engine.pool.size() == 4
        assert engine.pool._max_overflow == 6
        assert engine.pool._recycle == 600
        assert engine.pool.timeout() == 15


class TestGetSessionFactory:
    """Tests for get_session_factory."""

    def test_creates_session_factory(self) -> None:
        """get_session_factory returns an async session maker."""
        engine = get_engine("postgresql+asyncpg://localhost/test_db")
        session_factory = get_session_factory(engine)

        assert session_factory is not None
