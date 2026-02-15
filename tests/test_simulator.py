"""Tests for the SimulatorConnector."""

import pytest
from payments_sdk.connectors import (
    SimulatorConnector,
    SimulatorConfig,
    SimulatorScenario,
    PaymentRequest,
)


class TestSimulatorBasicOperations:
    """Test basic payment operations with the simulator."""

    def test_authorize_success(self):
        """Test successful authorization."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-key-1",
            payment_method={"token": "sim_card_success"}
        )
        response = connector.authorize(request)
        
        assert response.status == "authorized"
        assert response.provider_transaction_id is not None
        assert response.provider_transaction_id.startswith("sim_")

    def test_authorize_decline(self):
        """Test declined authorization."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-key-2",
            payment_method={"token": "sim_card_decline"}
        )
        response = connector.authorize(request)
        
        assert response.status == "failed"
        assert response.provider_response_code == "declined"

    def test_authorize_insufficient_funds(self):
        """Test insufficient funds scenario."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-key-3",
            payment_method={"token": "sim_card_insufficient"}
        )
        response = connector.authorize(request)
        
        assert response.status == "failed"
        assert response.provider_response_code == "insufficient_funds"


class TestSimulator3DS:
    """Test 3DS flow simulation."""

    def test_authorize_requires_3ds(self):
        """Test authorization requiring 3DS."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-3ds-1",
            payment_method={"token": "sim_card_3ds"}
        )
        response = connector.authorize(request)
        
        assert response.status == "pending_mfa"
        assert response.mfa is not None
        assert response.mfa["type"] == "3ds"
        assert "redirect_url" in response.mfa

    def test_complete_3ds_success(self):
        """Test successful 3DS completion."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-3ds-2",
            payment_method={"token": "sim_card_3ds"}
        )
        auth_response = connector.authorize(request)
        txn_id = auth_response.provider_transaction_id
        
        complete_response = connector.complete_3ds(txn_id, success=True)
        assert complete_response.status == "authorized"

    def test_complete_3ds_failure(self):
        """Test failed 3DS completion."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-3ds-3",
            payment_method={"token": "sim_card_3ds"}
        )
        auth_response = connector.authorize(request)
        txn_id = auth_response.provider_transaction_id
        
        complete_response = connector.complete_3ds(txn_id, success=False)
        assert complete_response.status == "failed"
        assert complete_response.provider_response_code == "3ds_failed"


class TestSimulatorCaptureRefundVoid:
    """Test capture, refund, and void operations."""

    def test_capture_authorized_payment(self):
        """Test capturing an authorized payment."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-capture-1",
            payment_method={"token": "sim_card_success"}
        )
        auth_response = connector.authorize(request)
        txn_id = auth_response.provider_transaction_id
        
        capture_response = connector.capture(txn_id, 1000)
        assert capture_response.status == "captured"

    def test_capture_nonexistent_payment(self):
        """Test capturing a nonexistent payment."""
        connector = SimulatorConnector()
        response = connector.capture("nonexistent_id", 1000)
        
        assert response.status == "failed"
        assert response.provider_response_code == "not_found"

    def test_refund_captured_payment(self):
        """Test refunding a captured payment."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-refund-1",
            payment_method={"token": "sim_card_success"}
        )
        auth_response = connector.authorize(request)
        txn_id = auth_response.provider_transaction_id
        connector.capture(txn_id, 1000)
        
        refund_response = connector.refund(txn_id, 1000)
        assert refund_response.status == "refunded"

    def test_partial_refund(self):
        """Test partial refund."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-partial-refund",
            payment_method={"token": "sim_card_success"}
        )
        auth_response = connector.authorize(request)
        txn_id = auth_response.provider_transaction_id
        connector.capture(txn_id, 1000)
        
        refund_response = connector.refund(txn_id, 500)
        assert refund_response.status == "partially_refunded"

    def test_void_authorized_payment(self):
        """Test voiding an authorized payment."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-void-1",
            payment_method={"token": "sim_card_success"}
        )
        auth_response = connector.authorize(request)
        txn_id = auth_response.provider_transaction_id
        
        void_response = connector.void(txn_id)
        assert void_response.status == "voided"


class TestSimulatorConfig:
    """Test configurable success/failure rates."""

    def test_success_rate_zero(self):
        """Test with 0% success rate."""
        config = SimulatorConfig(success_rate=0.0, seed=42)
        connector = SimulatorConnector(config=config)
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-fail-rate",
            payment_method={"token": "regular_card"}
        )
        response = connector.authorize(request)
        assert response.status == "failed"

    def test_3ds_rate_full(self):
        """Test with 100% 3DS rate."""
        config = SimulatorConfig(three_ds_rate=1.0, seed=42)
        connector = SimulatorConnector(config=config)
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-3ds-rate",
            payment_method={"token": "regular_card"}
        )
        response = connector.authorize(request)
        assert response.status == "pending_mfa"

    def test_timeout_simulation(self):
        """Test timeout simulation with special card."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-timeout",
            payment_method={"token": "sim_card_timeout"}
        )
        with pytest.raises(TimeoutError):
            connector.authorize(request)

    def test_reproducible_with_seed(self):
        """Test that results are reproducible with seed."""
        config1 = SimulatorConfig(success_rate=0.5, seed=12345)
        config2 = SimulatorConfig(success_rate=0.5, seed=12345)
        
        connector1 = SimulatorConnector(config=config1)
        connector2 = SimulatorConnector(config=config2)
        
        results1 = []
        results2 = []
        
        for i in range(5):
            req = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key=f"seed-test-{i}",
                payment_method={"token": "regular_card"}
            )
            results1.append(connector1.authorize(req).status)
            results2.append(connector2.authorize(req).status)
        
        assert results1 == results2


class TestSimulatorHelpers:
    """Test helper methods for testing."""

    def test_get_transaction(self):
        """Test retrieving a transaction."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-get-txn",
            payment_method={"token": "sim_card_success"}
        )
        response = connector.authorize(request)
        
        txn = connector.get_transaction(response.provider_transaction_id)
        assert txn is not None
        assert txn.amount == 1000
        assert txn.currency == "USD"

    def test_clear_transactions(self):
        """Test clearing transactions."""
        connector = SimulatorConnector()
        request = PaymentRequest(
            amount=1000,
            currency="USD",
            idempotency_key="test-clear",
            payment_method={"token": "sim_card_success"}
        )
        connector.authorize(request)
        assert len(connector.get_all_transactions()) == 1
        
        connector.clear_transactions()
        assert len(connector.get_all_transactions()) == 0

    def test_health_check(self):
        """Test health check."""
        config = SimulatorConfig(success_rate=0.8, delay_ms=100)
        connector = SimulatorConnector(config=config)
        
        health = connector.health_check()
        assert health["ok"] is True
        assert health["provider"] == "simulator"
        assert health["config"]["success_rate"] == 0.8

    def test_parse_webhook(self):
        """Test webhook parsing."""
        connector = SimulatorConnector()
        body = b'{"type": "payment.captured", "transaction_id": "sim_123"}'
        
        result = connector.parse_webhook({}, body)
        assert result["type"] == "payment.captured"
        assert result["provider"] == "simulator"
