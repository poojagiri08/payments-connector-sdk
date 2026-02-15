"""Tests for the payment service layer."""

import pytest
from unittest.mock import MagicMock

from payments_sdk.database import (
    Base,
    PaymentStatus,
    create_async_engine,
    get_async_session_factory,
)
from payments_sdk.services import PaymentService
from payments_sdk.connectors.base import PaymentRequest, PaymentResponse


@pytest.fixture
async def db_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_async_engine(
        database_url="sqlite+aiosqlite:///:memory:",
        echo=False
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine):
    """Create a database session for testing."""
    session_factory = get_async_session_factory(db_engine)
    async with session_factory() as session:
        yield session


@pytest.fixture
def payment_request():
    """Create a sample payment request."""
    return PaymentRequest(
        amount=1000,
        currency="USD",
        merchant_id="merchant_123",
        idempotency_key="test_key_123",
        payment_method={"token": "pm_card_visa"},
        intent="authorize",
        metadata={"order_id": "order_456"},
    )


@pytest.fixture
def authorized_response():
    """Create a sample authorized payment response."""
    return PaymentResponse(
        id="pi_1234567890abcdefghijklmno",
        status="authorized",
        provider_transaction_id="pi_1234567890abcdefghijklmno",
        provider_response_code="succeeded",
        raw_provider_response={"id": "pi_1234567890abcdefghijklmno", "status": "requires_capture"},
    )


@pytest.fixture
def captured_response():
    """Create a sample captured payment response."""
    return PaymentResponse(
        id="pi_1234567890abcdefghijklmno",
        status="captured",
        provider_transaction_id="pi_1234567890abcdefghijklmno",
        provider_response_code="succeeded",
        raw_provider_response={"id": "pi_1234567890abcdefghijklmno", "status": "succeeded"},
    )


@pytest.fixture
def refunded_response():
    """Create a sample refunded payment response."""
    return PaymentResponse(
        id="pi_1234567890abcdefghijklmno",
        status="refunded",
        provider_transaction_id="pi_1234567890abcdefghijklmno",
        provider_response_code="re_123",
        raw_provider_response={"id": "re_123", "status": "succeeded"},
    )


class TestPaymentService:
    """Tests for the PaymentService."""
    
    async def test_create_payment(self, db_session, payment_request, authorized_response):
        """Test creating a payment with persistence."""
        service = PaymentService(db_session)
        
        payment = await service.create_payment(
            request=payment_request,
            provider_response=authorized_response,
            provider="stripe",
            idempotency_key="test_key_123",
        )
        
        assert payment.id is not None
        assert payment.amount == 1000
        assert payment.currency == "USD"
        assert payment.status == "authorized"
        assert payment.provider_transaction_id == "pi_1234567890abcdefghijklmno"
        assert payment.merchant_id == "merchant_123"
        assert payment.metadata == {"order_id": "order_456"}
    
    async def test_create_payment_capture_immediate(self, db_session, payment_request):
        """Test creating a payment with capture_immediate intent."""
        payment_request.intent = "capture_immediate"
        
        captured_response = PaymentResponse(
            id="pi_123",
            status="captured",
            provider_transaction_id="pi_123",
            provider_response_code="succeeded",
        )
        
        service = PaymentService(db_session)
        
        payment = await service.create_payment(
            request=payment_request,
            provider_response=captured_response,
            provider="stripe",
            idempotency_key="test_key_capture",
        )
        
        assert payment.status == "captured"
        assert payment.captured_amount == 1000
    
    async def test_check_idempotency_new_request(self, db_session):
        """Test idempotency check for new request."""
        service = PaymentService(db_session)
        
        result = await service.check_idempotency(
            idempotency_key="new_key",
            endpoint="/payments",
            request_data={"amount": 1000},
        )
        
        assert result is None
    
    async def test_check_idempotency_returns_cached(self, db_session, payment_request, authorized_response):
        """Test idempotency check returns cached response."""
        service = PaymentService(db_session)
        
        # Create a payment first
        await service.create_payment(
            request=payment_request,
            provider_response=authorized_response,
            provider="stripe",
            idempotency_key="cached_key",
        )
        
        # Check idempotency with same key
        result = await service.check_idempotency(
            idempotency_key="cached_key",
            endpoint="/payments",
            request_data=payment_request.model_dump(),
        )
        
        assert result is not None
        assert result["status"] == "authorized"
    
    async def test_check_idempotency_conflict(self, db_session, payment_request, authorized_response):
        """Test idempotency check raises on conflict."""
        service = PaymentService(db_session)
        
        # Create a payment first
        await service.create_payment(
            request=payment_request,
            provider_response=authorized_response,
            provider="stripe",
            idempotency_key="conflict_key",
        )
        
        # Try with different request data
        with pytest.raises(ValueError, match="already been used"):
            await service.check_idempotency(
                idempotency_key="conflict_key",
                endpoint="/payments",
                request_data={"amount": 2000, "different": "data"},
            )
    
    async def test_capture_payment(self, db_session, payment_request, authorized_response, captured_response):
        """Test capturing a payment."""
        service = PaymentService(db_session)
        
        # Create a payment first
        payment = await service.create_payment(
            request=payment_request,
            provider_response=authorized_response,
            provider="stripe",
            idempotency_key="test_key_123",
        )
        
        # Capture the payment
        updated_payment = await service.capture_payment(
            provider_transaction_id="pi_1234567890abcdefghijklmno",
            amount=1000,
            provider_response=captured_response,
            idempotency_key="capture_key_123",
        )
        
        assert updated_payment.id == payment.id
        assert updated_payment.status == "captured"
        assert updated_payment.captured_amount == 1000
    
    async def test_refund_payment(self, db_session, payment_request, authorized_response, refunded_response):
        """Test refunding a payment."""
        service = PaymentService(db_session)
        
        # Create and capture a payment first
        payment = await service.create_payment(
            request=payment_request,
            provider_response=authorized_response,
            provider="stripe",
            idempotency_key="test_key_123",
        )
        payment.status = PaymentStatus.CAPTURED.value
        payment.captured_amount = 1000
        await db_session.flush()
        
        # Refund part of the payment
        updated_payment = await service.refund_payment(
            provider_transaction_id="pi_1234567890abcdefghijklmno",
            amount=500,
            provider_response=refunded_response,
            idempotency_key="refund_key_123",
        )
        
        assert updated_payment.refunded_amount == 500
        assert updated_payment.status == "partially_refunded"
    
    async def test_refund_payment_full(self, db_session, payment_request, authorized_response, refunded_response):
        """Test fully refunding a payment."""
        service = PaymentService(db_session)
        
        # Create and capture a payment first
        payment = await service.create_payment(
            request=payment_request,
            provider_response=authorized_response,
            provider="stripe",
            idempotency_key="test_key_123",
        )
        payment.status = PaymentStatus.CAPTURED.value
        payment.captured_amount = 1000
        await db_session.flush()
        
        # Full refund
        updated_payment = await service.refund_payment(
            provider_transaction_id="pi_1234567890abcdefghijklmno",
            amount=1000,
            provider_response=refunded_response,
            idempotency_key="refund_key_123",
        )
        
        assert updated_payment.refunded_amount == 1000
        assert updated_payment.status == "refunded"
    
    async def test_void_payment(self, db_session, payment_request, authorized_response):
        """Test voiding a payment."""
        service = PaymentService(db_session)
        
        # Create a payment first
        payment = await service.create_payment(
            request=payment_request,
            provider_response=authorized_response,
            provider="stripe",
            idempotency_key="test_key_123",
        )
        
        voided_response = PaymentResponse(
            id="pi_1234567890abcdefghijklmno",
            status="voided",
            provider_transaction_id="pi_1234567890abcdefghijklmno",
        )
        
        updated_payment = await service.void_payment(
            provider_transaction_id="pi_1234567890abcdefghijklmno",
            provider_response=voided_response,
            idempotency_key="void_key_123",
        )
        
        assert updated_payment.status == "voided"
    
    async def test_get_payment(self, db_session, payment_request, authorized_response):
        """Test getting a payment by ID."""
        service = PaymentService(db_session)
        
        payment = await service.create_payment(
            request=payment_request,
            provider_response=authorized_response,
            provider="stripe",
            idempotency_key="test_key_123",
        )
        
        retrieved = await service.get_payment(payment.id)
        
        assert retrieved is not None
        assert retrieved.id == payment.id
    
    async def test_get_payment_by_provider_id(self, db_session, payment_request, authorized_response):
        """Test getting a payment by provider transaction ID."""
        service = PaymentService(db_session)
        
        payment = await service.create_payment(
            request=payment_request,
            provider_response=authorized_response,
            provider="stripe",
            idempotency_key="test_key_123",
        )
        
        retrieved = await service.get_payment_by_provider_id(
            "pi_1234567890abcdefghijklmno"
        )
        
        assert retrieved is not None
        assert retrieved.id == payment.id
    
    async def test_get_payment_history(self, db_session, payment_request, authorized_response, captured_response):
        """Test getting payment history."""
        service = PaymentService(db_session)
        
        # Create a payment
        payment = await service.create_payment(
            request=payment_request,
            provider_response=authorized_response,
            provider="stripe",
            idempotency_key="test_key_123",
        )
        
        # Capture it
        await service.capture_payment(
            provider_transaction_id="pi_1234567890abcdefghijklmno",
            amount=1000,
            provider_response=captured_response,
            idempotency_key="capture_key_123",
        )
        
        history = await service.get_payment_history(payment.id)
        
        assert len(history) == 2
        # History is ordered by created_at desc, so capture should be first
        assert history[0]["action"] == "capture"
        assert history[1]["action"] == "authorize"
    
    async def test_list_payments_by_merchant(self, db_session, authorized_response):
        """Test listing payments by merchant."""
        service = PaymentService(db_session)
        
        # Create payments for different merchants
        for i in range(3):
            request = PaymentRequest(
                amount=1000 + i * 100,
                currency="USD",
                merchant_id="merchant_A",
                idempotency_key=f"key_a_{i}",
                payment_method={"token": "pm_card_visa"},
            )
            await service.create_payment(
                request=request,
                provider_response=authorized_response,
                provider="stripe",
                idempotency_key=f"key_a_{i}",
            )
        
        for i in range(2):
            request = PaymentRequest(
                amount=2000 + i * 100,
                currency="USD",
                merchant_id="merchant_B",
                idempotency_key=f"key_b_{i}",
                payment_method={"token": "pm_card_visa"},
            )
            await service.create_payment(
                request=request,
                provider_response=authorized_response,
                provider="stripe",
                idempotency_key=f"key_b_{i}",
            )
        
        payments_a = await service.list_payments_by_merchant("merchant_A")
        payments_b = await service.list_payments_by_merchant("merchant_B")
        
        assert len(payments_a) == 3
        assert len(payments_b) == 2
    
    async def test_status_mapping(self, db_session):
        """Test provider status mapping."""
        service = PaymentService(db_session)
        
        # Test various provider statuses
        assert service._map_provider_status("requires_capture") == "authorized"
        assert service._map_provider_status("requires_action") == "pending_mfa"
        assert service._map_provider_status("succeeded") == "captured"
        assert service._map_provider_status("canceled") == "voided"
        assert service._map_provider_status("unknown_status") == "pending"
