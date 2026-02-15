"""Database session management and connection handling."""

import os
import logging
from typing import AsyncGenerator, Optional
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    create_async_engine as sa_create_async_engine,
    AsyncSession,
    async_sessionmaker,
    AsyncEngine,
)
from sqlalchemy.pool import StaticPool

from .models import Base

logger = logging.getLogger(__name__)

# Global engine and session factory
_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def get_database_url() -> str:
    """Get the database URL from environment or default to SQLite.
    
    Returns:
        Database URL string. Defaults to SQLite file in data directory.
    """
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        # Convert postgresql:// to postgresql+asyncpg:// if needed
        if db_url.startswith("postgresql://"):
            return db_url.replace("postgresql://", "postgresql+asyncpg://")
        # Convert sqlite:// to sqlite+aiosqlite://
        if db_url.startswith("sqlite://"):
            return db_url.replace("sqlite://", "sqlite+aiosqlite://")
        return db_url
    
    # Default to SQLite in data directory
    data_dir = os.getenv("DATA_DIR", "./data")
    os.makedirs(data_dir, exist_ok=True)
    return f"sqlite+aiosqlite:///{data_dir}/payments.db"


def create_async_engine(
    database_url: Optional[str] = None,
    echo: bool = False,
    **kwargs
) -> AsyncEngine:
    """Create an async SQLAlchemy engine.
    
    Args:
        database_url: Database URL. If None, uses get_database_url().
        echo: If True, log all SQL statements.
        **kwargs: Additional arguments passed to create_async_engine.
    
    Returns:
        AsyncEngine instance.
    """
    url = database_url or get_database_url()
    
    # SQLite-specific configuration
    connect_args = {}
    poolclass = None
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        # Use StaticPool for in-memory databases (testing)
        if ":memory:" in url:
            poolclass = StaticPool
    
    engine_kwargs = {
        "echo": echo,
        "connect_args": connect_args,
        **kwargs
    }
    
    if poolclass:
        engine_kwargs["poolclass"] = poolclass
    
    return sa_create_async_engine(url, **engine_kwargs)


def get_async_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory.
    
    Args:
        engine: AsyncEngine instance.
    
    Returns:
        async_sessionmaker for creating sessions.
    """
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )


async def init_db(engine: Optional[AsyncEngine] = None, drop_existing: bool = False) -> None:
    """Initialize the database by creating all tables.
    
    Args:
        engine: AsyncEngine instance. If None, creates one from environment.
        drop_existing: If True, drops existing tables before creating.
    """
    global _engine, _session_factory
    
    if engine is None:
        _engine = create_async_engine()
    else:
        _engine = engine
    
    _session_factory = get_async_session_factory(_engine)
    
    async with _engine.begin() as conn:
        if drop_existing:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    
    logger.info("Database initialized successfully")


async def close_db() -> None:
    """Close the database connection."""
    global _engine, _session_factory
    
    if _engine:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Database connection closed")


def AsyncSessionLocal() -> async_sessionmaker[AsyncSession]:
    """Get the global session factory.
    
    Returns:
        async_sessionmaker for creating sessions.
    
    Raises:
        RuntimeError: If database is not initialized.
    """
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting database sessions.
    
    Yields:
        AsyncSession instance.
    
    Usage:
        @app.get("/")
        async def endpoint(db: AsyncSession = Depends(get_db)):
            ...
    """
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for getting database sessions.
    
    Usage:
        async with get_db_context() as db:
            ...
    """
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


class DatabaseManager:
    """Manager class for database lifecycle management.
    
    Useful for applications that need explicit control over database
    initialization and cleanup.
    """
    
    def __init__(
        self,
        database_url: Optional[str] = None,
        echo: bool = False
    ):
        """Initialize the database manager.
        
        Args:
            database_url: Database URL. If None, uses environment variable.
            echo: If True, log all SQL statements.
        """
        self._database_url = database_url
        self._echo = echo
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None
    
    async def init(self, drop_existing: bool = False) -> None:
        """Initialize the database.
        
        Args:
            drop_existing: If True, drops existing tables before creating.
        """
        self._engine = create_async_engine(
            database_url=self._database_url,
            echo=self._echo
        )
        self._session_factory = get_async_session_factory(self._engine)
        
        async with self._engine.begin() as conn:
            if drop_existing:
                await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database initialized successfully")
    
    async def close(self) -> None:
        """Close the database connection."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Database connection closed")
    
    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session.
        
        Yields:
            AsyncSession instance.
        """
        if self._session_factory is None:
            raise RuntimeError("Database not initialized. Call init() first.")
        
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    
    @property
    def engine(self) -> Optional[AsyncEngine]:
        """Get the database engine."""
        return self._engine
    
    @property
    def session_factory(self) -> Optional[async_sessionmaker[AsyncSession]]:
        """Get the session factory."""
        return self._session_factory
