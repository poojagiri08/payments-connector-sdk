"""Shared test fixtures and configuration."""

import os
import pytest
from unittest.mock import MagicMock, patch
from typing import Dict, Any

# Set up test environment variables before importing modules
os.environ.setdefault("STRIPE_API_KEY", "sk_test_dummy_key_for_testing")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test_secret")
os.environ.setdefault("API_KEY", "test_api_key_12345")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture
def mock_stripe_api_key():
    """Set up mock Stripe API key."""
    with patch.dict(os.environ, {"STRIPE_API_KEY": "sk_test_mock_key"}):
        yield "sk_test_mock_key"


@pytest.fixture
def mock_api_key():
    """Set up mock API key for authentication."""
    with patch.dict(os.environ, {"API_KEY": "test_api_key_12345"}):
        yield "test_api_key_12345"


@pytest.fixture
def valid_payment_request_data() -> Dict[str, Any]:
    """Return valid payment request data."""
    return {
        "amount": 1000,
        "currency": "USD",
        "merchant_id": "merchant_123",
        "idempotency_key": "test_idempotency_key_123",
        "payment_method": {"token": "pm_card_visa"},
        "intent": "authorize",
        "metadata": {"order_id": "order_456"}
    }


@pytest.fixture
def valid_api_payment_body() -> Dict[str, Any]:
    """Return valid API payment body."""
    return {
        "amount": 1000,
        "currency": "USD",
        "merchant_id": "merchant_123",
        "idempotency_key": "test_idempotency_key_123",
        "payment_method": {"token": "pm_card_visa"},
        "intent": "authorize",
        "metadata": {"order_id": "order_456"}
    }


@pytest.fixture
def mock_stripe_payment_intent():
    """Create a mock Stripe PaymentIntent."""
    mock_pi = MagicMock()
    mock_pi.id = "pi_1234567890abcdefghijklmno"
    mock_pi.status = "requires_capture"
    mock_pi.to_dict.return_value = {
        "id": "pi_1234567890abcdefghijklmno",
        "status": "requires_capture",
        "amount": 1000,
        "currency": "usd",
        "metadata": {}
    }
    return mock_pi


@pytest.fixture
def mock_stripe_payment_intent_3ds():
    """Create a mock Stripe PaymentIntent requiring 3DS."""
    mock_pi = MagicMock()
    mock_pi.id = "pi_1234567890abcdefghijklmno"
    mock_pi.status = "requires_action"
    mock_pi.to_dict.return_value = {
        "id": "pi_1234567890abcdefghijklmno",
        "status": "requires_action",
        "amount": 1000,
        "currency": "usd",
        "client_secret": "pi_xxx_secret_xxx",
        "next_action": {
            "type": "use_stripe_sdk",
            "use_stripe_sdk": {}
        },
        "metadata": {}
    }
    return mock_pi


@pytest.fixture
def mock_stripe_captured_intent():
    """Create a mock captured Stripe PaymentIntent."""
    mock_pi = MagicMock()
    mock_pi.id = "pi_1234567890abcdefghijklmno"
    mock_pi.status = "succeeded"
    mock_pi.to_dict.return_value = {
        "id": "pi_1234567890abcdefghijklmno",
        "status": "succeeded",
        "amount": 1000,
        "currency": "usd",
        "metadata": {}
    }
    return mock_pi


@pytest.fixture
def mock_stripe_refund():
    """Create a mock Stripe Refund."""
    mock_refund = MagicMock()
    mock_refund.id = "re_1234567890abcdefghijklmno"
    mock_refund.to_dict.return_value = {
        "id": "re_1234567890abcdefghijklmno",
        "amount": 500,
        "status": "succeeded"
    }
    return mock_refund


@pytest.fixture
def mock_stripe_canceled_intent():
    """Create a mock canceled Stripe PaymentIntent."""
    mock_pi = MagicMock()
    mock_pi.id = "pi_1234567890abcdefghijklmno"
    mock_pi.status = "canceled"
    mock_pi.to_dict.return_value = {
        "id": "pi_1234567890abcdefghijklmno",
        "status": "canceled",
        "metadata": {}
    }
    return mock_pi


@pytest.fixture
def auth_headers(mock_api_key):
    """Return headers with authentication."""
    return {
        "Authorization": f"Bearer {mock_api_key}",
        "X-Provider": "stripe",
        "X-Idempotency-Key": "test-idempotency-key"
    }


@pytest.fixture
def valid_payment_id():
    """Return a valid payment ID format."""
    return "pi_1234567890abcdefghijklmno"


@pytest.fixture
def invalid_payment_ids():
    """Return invalid payment ID formats."""
    return [
        "invalid_id",
        "pi_short",
        "px_1234567890abcdefghijklmno",
        "",
        "pi_!@#$%^&*()",
        "pi_" + "a" * 100
    ]


# Database fixtures for integration tests
@pytest.fixture
async def test_db_engine():
    """Create an in-memory SQLite database for testing."""
    from payments_sdk.database import Base, create_async_engine
    
    engine = create_async_engine(
        database_url="sqlite+aiosqlite:///:memory:",
        echo=False
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def test_db_session(test_db_engine):
    """Create a database session for testing."""
    from payments_sdk.database import get_async_session_factory
    
    session_factory = get_async_session_factory(test_db_engine)
    async with session_factory() as session:
        yield session
