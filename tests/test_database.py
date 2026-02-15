"""Tests for database models and repository layer."""

import pytest
import asyncio
from datetime import datetime, timedelta

from payments_sdk.database import (
    Base,
    Payment,
    IdempotencyKey,
    TransactionHistory,
    PaymentStatus,
    TransactionAction,
    PaymentRepository,
    IdempotencyKeyRepository,
    TransactionHistoryRepository,
    create_async_engine,
    get_async_session_factory,
)


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


class TestPaymentModel:
    """Tests for the Payment model."""
    
    async def test_create_payment(self, db_session):
        """Test creating a payment record."""
        payment = Payment(
            amount=1000,
            currency="USD",
            provider="stripe",
            status=PaymentStatus.PENDING.value,
            merchant_id="merchant_123",
        )
        db_session.add(payment)
        await db_session.flush()
        
        assert payment.id is not None
        assert payment.amount == 1000
        assert payment.currency == "USD"
        assert payment.status == "pending"
        assert payment.created_at is not None
        assert payment.updated_at is not None
    
    async def test_payment_metadata_property(self, db_session):
        """Test Payment metadata property."""
        payment = Payment(
            amount=1000,
            currency="USD",
            provider="stripe",
            status=PaymentStatus.AUTHORIZED.value,
        )
        payment.metadata = {"order_id": "order_123", "customer": "cust_456"}
        db_session.add(payment)
        await db_session.flush()
        
        assert payment.metadata == {"order_id": "order_123", "customer": "cust_456"}
        assert payment.metadata_json is not None
    
    async def test_payment_to_dict(self, db_session):
        """Test Payment to_dict method."""
        payment = Payment(
            amount=1000,
            currency="USD",
            provider="stripe",
            status=PaymentStatus.CAPTURED.value,
            provider_transaction_id="pi_123",
            merchant_id="merchant_123",
        )
        payment.metadata = {"order_id": "order_123"}
        db_session.add(payment)
        await db_session.flush()
        
        result = payment.to_dict()
        
        assert result["amount"] == 1000
        assert result["currency"] == "USD"
        assert result["status"] == "captured"
        assert result["provider_transaction_id"] == "pi_123"
        assert result["merchant_id"] == "merchant_123"
        assert result["metadata"] == {"order_id": "order_123"}


class TestPaymentRepository:
    """Tests for the PaymentRepository."""
    
    async def test_create_payment(self, db_session):
        """Test creating a payment via repository."""
        repo = PaymentRepository(db_session)
        
        payment = await repo.create(
            amount=2500,
            currency="EUR",
            provider="stripe",
            merchant_id="merchant_456",
            metadata={"order_id": "order_789"},
            status=PaymentStatus.AUTHORIZED.value,
        )
        
        assert payment.id is not None
        assert payment.amount == 2500
        assert payment.currency == "EUR"
        assert payment.status == "authorized"
        assert payment.metadata == {"order_id": "order_789"}
    
    async def test_get_by_id(self, db_session):
        """Test getting a payment by ID."""
        repo = PaymentRepository(db_session)
        
        payment = await repo.create(
            amount=1000,
            currency="USD",
            provider="stripe",
        )
        
        retrieved = await repo.get_by_id(payment.id)
        
        assert retrieved is not None
        assert retrieved.id == payment.id
        assert retrieved.amount == 1000
    
    async def test_get_by_id_not_found(self, db_session):
        """Test getting a non-existent payment."""
        repo = PaymentRepository(db_session)
        
        retrieved = await repo.get_by_id("non-existent-id")
        
        assert retrieved is None
    
    async def test_get_by_provider_transaction_id(self, db_session):
        """Test getting a payment by provider transaction ID."""
        repo = PaymentRepository(db_session)
        
        payment = await repo.create(
            amount=1000,
            currency="USD",
            provider="stripe",
        )
        await repo.update_status(
            payment=payment,
            new_status=PaymentStatus.AUTHORIZED.value,
            provider_transaction_id="pi_test_123",
        )
        
        retrieved = await repo.get_by_provider_transaction_id("pi_test_123")
        
        assert retrieved is not None
        assert retrieved.id == payment.id
    
    async def test_update_status(self, db_session):
        """Test updating payment status."""
        repo = PaymentRepository(db_session)
        
        payment = await repo.create(
            amount=1000,
            currency="USD",
            provider="stripe",
            status=PaymentStatus.PENDING.value,
        )
        
        await repo.update_status(
            payment=payment,
            new_status=PaymentStatus.AUTHORIZED.value,
            provider_transaction_id="pi_xyz",
        )
        
        assert payment.status == "authorized"
        assert payment.provider_transaction_id == "pi_xyz"
    
    async def test_update_capture_amount(self, db_session):
        """Test updating captured amount."""
        repo = PaymentRepository(db_session)
        
        payment = await repo.create(
            amount=1000,
            currency="USD",
            provider="stripe",
            status=PaymentStatus.AUTHORIZED.value,
        )
        
        await repo.update_capture_amount(payment, 500)
        await repo.update_capture_amount(payment, 300)
        
        assert payment.captured_amount == 800
    
    async def test_update_refund_amount(self, db_session):
        """Test updating refunded amount."""
        repo = PaymentRepository(db_session)
        
        payment = await repo.create(
            amount=1000,
            currency="USD",
            provider="stripe",
            status=PaymentStatus.CAPTURED.value,
        )
        payment.captured_amount = 1000
        await db_session.flush()
        
        await repo.update_refund_amount(payment, 300)
        
        assert payment.refunded_amount == 300
        assert payment.status == "partially_refunded"
        
        await repo.update_refund_amount(payment, 700)
        
        assert payment.refunded_amount == 1000
        assert payment.status == "refunded"
    
    async def test_list_by_merchant(self, db_session):
        """Test listing payments by merchant."""
        repo = PaymentRepository(db_session)
        
        # Create payments for different merchants
        await repo.create(amount=1000, currency="USD", provider="stripe", merchant_id="merchant_A")
        await repo.create(amount=2000, currency="USD", provider="stripe", merchant_id="merchant_A")
        await repo.create(amount=3000, currency="USD", provider="stripe", merchant_id="merchant_B")
        
        payments_a = await repo.list_by_merchant("merchant_A")
        payments_b = await repo.list_by_merchant("merchant_B")
        
        assert len(payments_a) == 2
        assert len(payments_b) == 1
    
    async def test_list_by_status(self, db_session):
        """Test listing payments by status."""
        repo = PaymentRepository(db_session)
        
        await repo.create(amount=1000, currency="USD", provider="stripe", status=PaymentStatus.AUTHORIZED.value)
        await repo.create(amount=2000, currency="USD", provider="stripe", status=PaymentStatus.CAPTURED.value)
        await repo.create(amount=3000, currency="USD", provider="stripe", status=PaymentStatus.AUTHORIZED.value)
        
        authorized = await repo.list_by_status(PaymentStatus.AUTHORIZED.value)
        captured = await repo.list_by_status(PaymentStatus.CAPTURED.value)
        
        assert len(authorized) == 2
        assert len(captured) == 1


class TestIdempotencyKeyRepository:
    """Tests for the IdempotencyKeyRepository."""
    
    async def test_create_idempotency_key(self, db_session):
        """Test creating an idempotency key."""
        repo = IdempotencyKeyRepository(db_session)
        
        key = await repo.create(
            key="test_key_123",
            endpoint="/payments",
            payment_id=None,
            response_data={"id": "pi_123", "status": "authorized"},
            response_status_code=200,
        )
        
        assert key.id is not None
        assert key.key == "test_key_123"
        assert key.endpoint == "/payments"
        assert key.response_data == {"id": "pi_123", "status": "authorized"}
        assert key.expires_at > datetime.utcnow()
    
    async def test_get_by_key(self, db_session):
        """Test getting an idempotency key."""
        repo = IdempotencyKeyRepository(db_session)
        
        created = await repo.create(
            key="test_key_456",
            endpoint="/payments",
        )
        
        retrieved = await repo.get_by_key("test_key_456")
        
        assert retrieved is not None
        assert retrieved.id == created.id
    
    async def test_get_by_key_not_found(self, db_session):
        """Test getting a non-existent idempotency key."""
        repo = IdempotencyKeyRepository(db_session)
        
        retrieved = await repo.get_by_key("non-existent-key")
        
        assert retrieved is None
    
    async def test_compute_request_hash(self, db_session):
        """Test request hash computation."""
        repo = IdempotencyKeyRepository(db_session)
        
        data1 = {"amount": 1000, "currency": "USD"}
        data2 = {"currency": "USD", "amount": 1000}  # Same data, different order
        data3 = {"amount": 2000, "currency": "USD"}  # Different data
        
        hash1 = repo.compute_request_hash(data1)
        hash2 = repo.compute_request_hash(data2)
        hash3 = repo.compute_request_hash(data3)
        
        # Same data should produce same hash regardless of order
        assert hash1 == hash2
        # Different data should produce different hash
        assert hash1 != hash3
    
    async def test_check_idempotency_new_request(self, db_session):
        """Test idempotency check for new request."""
        repo = IdempotencyKeyRepository(db_session)
        
        existing, is_conflict = await repo.check_idempotency(
            key="new_key",
            endpoint="/payments",
            request_data={"amount": 1000},
        )
        
        assert existing is None
        assert is_conflict is False
    
    async def test_check_idempotency_cached_response(self, db_session):
        """Test idempotency check returns cached response."""
        repo = IdempotencyKeyRepository(db_session)
        
        request_hash = repo.compute_request_hash({"amount": 1000})
        await repo.create(
            key="cached_key",
            endpoint="/payments",
            response_data={"id": "pi_123"},
            request_hash=request_hash,
        )
        
        existing, is_conflict = await repo.check_idempotency(
            key="cached_key",
            endpoint="/payments",
            request_data={"amount": 1000},
        )
        
        assert existing is not None
        assert existing.response_data == {"id": "pi_123"}
        assert is_conflict is False
    
    async def test_check_idempotency_endpoint_conflict(self, db_session):
        """Test idempotency check detects endpoint conflict."""
        repo = IdempotencyKeyRepository(db_session)
        
        await repo.create(
            key="conflict_key",
            endpoint="/payments",
        )
        
        existing, is_conflict = await repo.check_idempotency(
            key="conflict_key",
            endpoint="/payments/pi_123/capture",  # Different endpoint
            request_data={"amount": 1000},
        )
        
        assert existing is not None
        assert is_conflict is True
    
    async def test_check_idempotency_request_data_conflict(self, db_session):
        """Test idempotency check detects request data conflict."""
        repo = IdempotencyKeyRepository(db_session)
        
        request_hash = repo.compute_request_hash({"amount": 1000})
        await repo.create(
            key="data_conflict_key",
            endpoint="/payments",
            request_hash=request_hash,
        )
        
        existing, is_conflict = await repo.check_idempotency(
            key="data_conflict_key",
            endpoint="/payments",
            request_data={"amount": 2000},  # Different amount
        )
        
        assert existing is not None
        assert is_conflict is True
    
    async def test_is_expired(self, db_session):
        """Test idempotency key expiration check."""
        repo = IdempotencyKeyRepository(db_session)
        
        # Create a key that expires in the past
        key = IdempotencyKey(
            key="expired_key",
            endpoint="/payments",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        db_session.add(key)
        await db_session.flush()
        
        assert key.is_expired() is True
        
        # Create a key that expires in the future
        key2 = IdempotencyKey(
            key="valid_key",
            endpoint="/payments",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(key2)
        await db_session.flush()
        
        assert key2.is_expired() is False


class TestTransactionHistoryRepository:
    """Tests for the TransactionHistoryRepository."""
    
    async def test_create_history(self, db_session):
        """Test creating transaction history."""
        payment_repo = PaymentRepository(db_session)
        history_repo = TransactionHistoryRepository(db_session)
        
        payment = await payment_repo.create(
            amount=1000,
            currency="USD",
            provider="stripe",
        )
        
        history = await history_repo.create(
            payment_id=payment.id,
            action=TransactionAction.AUTHORIZE.value,
            new_status=PaymentStatus.AUTHORIZED.value,
            amount=1000,
            provider_response_code="succeeded",
        )
        
        assert history.id is not None
        assert history.payment_id == payment.id
        assert history.action == "authorize"
        assert history.new_status == "authorized"
        assert history.amount == 1000
    
    async def test_get_by_payment_id(self, db_session):
        """Test getting history by payment ID."""
        payment_repo = PaymentRepository(db_session)
        history_repo = TransactionHistoryRepository(db_session)
        
        payment = await payment_repo.create(
            amount=1000,
            currency="USD",
            provider="stripe",
        )
        
        # Create multiple history entries
        await history_repo.create(
            payment_id=payment.id,
            action=TransactionAction.AUTHORIZE.value,
            new_status=PaymentStatus.AUTHORIZED.value,
        )
        await history_repo.create(
            payment_id=payment.id,
            action=TransactionAction.CAPTURE.value,
            previous_status=PaymentStatus.AUTHORIZED.value,
            new_status=PaymentStatus.CAPTURED.value,
        )
        
        history = await history_repo.get_by_payment_id(payment.id)
        
        assert len(history) == 2
    
    async def test_get_by_action(self, db_session):
        """Test getting history by action type."""
        payment_repo = PaymentRepository(db_session)
        history_repo = TransactionHistoryRepository(db_session)
        
        payment = await payment_repo.create(
            amount=1000,
            currency="USD",
            provider="stripe",
        )
        
        await history_repo.create(
            payment_id=payment.id,
            action=TransactionAction.AUTHORIZE.value,
            new_status=PaymentStatus.AUTHORIZED.value,
        )
        await history_repo.create(
            payment_id=payment.id,
            action=TransactionAction.CAPTURE.value,
            new_status=PaymentStatus.CAPTURED.value,
        )
        
        authorize_history = await history_repo.get_by_action(
            payment.id, 
            TransactionAction.AUTHORIZE.value
        )
        capture_history = await history_repo.get_by_action(
            payment.id, 
            TransactionAction.CAPTURE.value
        )
        
        assert len(authorize_history) == 1
        assert len(capture_history) == 1
    
    async def test_history_to_dict(self, db_session):
        """Test TransactionHistory to_dict method."""
        payment_repo = PaymentRepository(db_session)
        history_repo = TransactionHistoryRepository(db_session)
        
        payment = await payment_repo.create(
            amount=1000,
            currency="USD",
            provider="stripe",
        )
        
        history = await history_repo.create(
            payment_id=payment.id,
            action=TransactionAction.REFUND.value,
            previous_status=PaymentStatus.CAPTURED.value,
            new_status=PaymentStatus.REFUNDED.value,
            amount=500,
            provider_response_code="re_123",
            action_metadata={"reason": "customer_request"},
        )
        
        result = history.to_dict()
        
        assert result["payment_id"] == payment.id
        assert result["action"] == "refund"
        assert result["previous_status"] == "captured"
        assert result["new_status"] == "refunded"
        assert result["amount"] == 500
        assert result["action_metadata"] == {"reason": "customer_request"}
