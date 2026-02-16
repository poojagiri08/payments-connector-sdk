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

from . import models

logger = logging.getLogger(__name__)

# Global engine and session factory
_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def get_database_url() -> str:
    """
    Get database URL from environment variable.
    Supports both sync and async URLs.
    """
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        # Convert postgresql:// to postgresql+asyncpg://
        if db_url.startswith("postgresql://"):
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        # Convert postgres:// to postgresql+asyncpg://
        elif db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
        return db_url
    # Default to SQLite for local development/testing
    return "sqlite+aiosqlite:///./payments.db"


def create_async_engine(
    database_url: Optional[str] = None,
    echo: bool = False,
    pool_size: int = 5,
    max_overflow: int = 10,
) -> AsyncEngine:
    """
    Create an async SQLAlchemy engine.
    
    Args:
        database_url: Database connection URL. If None, uses get_database_url().
        echo: If True, log all SQL statements.
        pool_size: Number of connections to keep in the pool.
        max_overflow: Maximum overflow connections beyond pool_size.
    
    Returns:
        AsyncEngine instance.
    """
    url = database_url or get_database_url()
    
    # Use StaticPool for SQLite to maintain connection across async operations
    if "sqlite" in url:
        return sa_create_async_engine(
            url,
            echo=echo,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    
    return sa_create_async_engine(
        url,
        echo=echo,
        pool_size=pool_size,
        max_overflow=max_overflow,
    )


def get_async_session_factory(
    engine: Optional[AsyncEngine] = None,
) -> async_sessionmaker[AsyncSession]:
    """
    Get or create the async session factory.
    
    Args:
        engine: Optional engine. If None, uses global engine.
    
    Returns:
        async_sessionmaker instance.
    """
    global _session_factory
    
    if _session_factory is None:
        eng = engine or _engine
        if eng is None:
            raise RuntimeError(
                "Database not initialized. Call init_db() first."
            )
        _session_factory = async_sessionmaker(
            eng,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
    
    return _session_factory


async def init_db(
    database_url: Optional[str] = None,
    echo: bool = False,
    create_tables: bool = True,
) -> None:
    """
    Initialize the database connection and optionally create tables.
    
    Args:
        database_url: Database connection URL. If None, uses get_database_url().
        echo: If True, log all SQL statements.
        create_tables: If True, create all tables defined in models.
    """
    global _engine, _session_factory
    
    logger.info("Initializing database connection...")
    
    _engine = create_async_engine(database_url, echo=echo)
    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    
    if create_tables:
        async with _engine.begin() as conn:
            await conn.run_sync(models.Base.metadata.create_all)
            logger.info("Database tables created successfully.")
    
    logger.info("Database initialized successfully.")


async def close_db() -> None:
    """Close the database connection and clean up resources."""
    global _engine, _session_factory
    
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Database connection closed.")


# Alias for backward compatibility
AsyncSessionLocal = get_async_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency injection function for FastAPI.
    
    Yields:
        AsyncSession instance.
    
    Example:
        @app.get("/payments")
        async def list_payments(db: AsyncSession = Depends(get_db)):
            ...
    """
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for database sessions outside of FastAPI dependency injection.
    
    Yields:
        AsyncSession instance.
    
    Example:
        async with get_db_context() as db:
            payment = await db.get(Payment, payment_id)
    """
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


class DatabaseManager:
    """
    Database manager class for more explicit lifecycle control.
    
    Example:
        db_manager = DatabaseManager()
        await db_manager.initialize()
        
        async with db_manager.session() as session:
            # use session
            pass
        
        await db_manager.shutdown()
    """
    
    def __init__(
        self,
        database_url: Optional[str] = None,
        echo: bool = False,
        pool_size: int = 5,
        max_overflow: int = 10,
    ):
        self.database_url = database_url
        self.echo = echo
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None
    
    async def initialize(self, create_tables: bool = True) -> None:
        """Initialize the database connection."""
        self._engine = create_async_engine(
            self.database_url,
            self.echo,
            self.pool_size,
            self.max_overflow,
        )
        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
        
        if create_tables:
            async with self._engine.begin() as conn:
                await conn.run_sync(models.Base.metadata.create_all)
    
    async def shutdown(self) -> None:
        """Shutdown the database connection."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
    
    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session."""
        if self._session_factory is None:
            raise RuntimeError(
                "DatabaseManager not initialized. Call initialize() first."
            )
        
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
