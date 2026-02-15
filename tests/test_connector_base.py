"""Tests for ConnectorBase abstract class and data models."""

import pytest
from abc import ABC
from pydantic import ValidationError

from payments_sdk.connectors.base import (
    ConnectorBase,
    PaymentRequest,
    PaymentResponse,
    MFAData,
    ThreeDSChallengeData,
    ThreeDSChallengeResponse,
    ThreeDSCompleteRequest,
    MAX_AMOUNT
)


class TestConnectorBaseAbstraction:
    """Tests to verify ConnectorBase is properly abstract."""

    def test_cannot_instantiate_directly(self):
        """Test that ConnectorBase cannot be instantiated directly."""
        with pytest.raises(TypeError) as exc_info:
            ConnectorBase()
        assert "abstract" in str(exc_info.value).lower()

    def test_is_abstract_class(self):
        """Test that ConnectorBase inherits from ABC."""
        assert issubclass(ConnectorBase, ABC)

    def test_concrete_class_must_implement_all_methods(self):
        """Test that a concrete class must implement all abstract methods."""
        class IncompleteConnector(ConnectorBase):
            pass

        with pytest.raises(TypeError) as exc_info:
            IncompleteConnector()
        error_msg = str(exc_info.value)
        assert "authorize" in error_msg or "abstract" in error_msg.lower()

    def test_partial_implementation_fails(self):
        """Test that partial implementation still fails."""
        class PartialConnector(ConnectorBase):
            def authorize(self, request):
                return None

        with pytest.raises(TypeError):
            PartialConnector()

    def test_full_implementation_succeeds(self):
        """Test that full implementation can be instantiated."""
        class FullConnector(ConnectorBase):
            def authorize(self, request):
                return PaymentResponse(id="test", status="authorized")

            def capture(self, provider_transaction_id, amount):
                return PaymentResponse(id="test", status="captured")

            def refund(self, provider_transaction_id, amount):
                return PaymentResponse(id="test", status="refunded")

            def void(self, provider_transaction_id):
                return PaymentResponse(id="test", status="voided")

            def parse_webhook(self, headers, body):
                return {}

            def get_3ds_challenge(self, payment_id):
                return ThreeDSChallengeResponse(payment_id=payment_id, status="pending_mfa")

            def complete_3ds(self, payment_id, authentication_result=None):
                return PaymentResponse(id=payment_id, status="authorized")

        connector = FullConnector()
        assert connector is not None

    def test_health_check_has_default_implementation(self):
        """Test that health_check has a default implementation."""
        class MinimalConnector(ConnectorBase):
            def authorize(self, request):
                return PaymentResponse(id="test", status="authorized")

            def capture(self, provider_transaction_id, amount):
                return PaymentResponse(id="test", status="captured")

            def refund(self, provider_transaction_id, amount):
                return PaymentResponse(id="test", status="refunded")

            def void(self, provider_transaction_id):
                return PaymentResponse(id="test", status="voided")

            def parse_webhook(self, headers, body):
                return {}

            def get_3ds_challenge(self, payment_id):
                return ThreeDSChallengeResponse(payment_id=payment_id, status="pending_mfa")

            def complete_3ds(self, payment_id, authentication_result=None):
                return PaymentResponse(id=payment_id, status="authorized")

        connector = MinimalConnector()
        result = connector.health_check()
        assert result == {"ok": True}


class TestPaymentRequestModel:
    """Tests for PaymentRequest model validation."""

    def test_valid_payment_request(self, valid_payment_request_data):
        """Test creating a valid PaymentRequest."""
        req = PaymentRequest(**valid_payment_request_data)
        assert req.amount == 1000
        assert req.currency == "USD"
        assert req.idempotency_key == "test_idempotency_key_123"
        assert req.payment_method == {"token": "pm_card_visa"}

    def test_amount_must_be_positive(self):
        """Test that amount must be positive."""
        with pytest.raises(ValidationError) as exc_info:
            PaymentRequest(
                amount=0,
                currency="USD",
                idempotency_key="key123",
                payment_method={"token": "pm_test"}
            )
        assert "amount" in str(exc_info.value).lower()

    def test_amount_must_not_exceed_max(self):
        """Test that amount cannot exceed MAX_AMOUNT."""
        with pytest.raises(ValidationError) as exc_info:
            PaymentRequest(
                amount=MAX_AMOUNT + 1,
                currency="USD",
                idempotency_key="key123",
                payment_method={"token": "pm_test"}
            )
        assert "amount" in str(exc_info.value).lower()

    def test_amount_at_max_is_valid(self):
        """Test that amount at MAX_AMOUNT is valid."""
        req = PaymentRequest(
            amount=MAX_AMOUNT,
            currency="USD",
            idempotency_key="key123",
            payment_method={"token": "pm_test"}
        )
        assert req.amount == MAX_AMOUNT

    def test_currency_must_be_3_characters(self):
        """Test that currency must be exactly 3 characters."""
        with pytest.raises(ValidationError):
            PaymentRequest(
                amount=100,
                currency="US",
                idempotency_key="key123",
                payment_method={"token": "pm_test"}
            )

        with pytest.raises(ValidationError):
            PaymentRequest(
                amount=100,
                currency="USDD",
                idempotency_key="key123",
                payment_method={"token": "pm_test"}
            )

    def test_idempotency_key_required(self):
        """Test that idempotency_key is required."""
        with pytest.raises(ValidationError):
            PaymentRequest(
                amount=100,
                currency="USD",
                payment_method={"token": "pm_test"}
            )

    def test_idempotency_key_max_length(self):
        """Test that idempotency_key has max length of 255."""
        long_key = "a" * 256
        with pytest.raises(ValidationError):
            PaymentRequest(
                amount=100,
                currency="USD",
                idempotency_key=long_key,
                payment_method={"token": "pm_test"}
            )

    def test_intent_validation(self):
        """Test that intent must be valid value."""
        with pytest.raises(ValidationError):
            PaymentRequest(
                amount=100,
                currency="USD",
                idempotency_key="key123",
                payment_method={"token": "pm_test"},
                intent="invalid_intent"
            )

    def test_intent_authorize_valid(self):
        """Test that authorize intent is valid."""
        req = PaymentRequest(
            amount=100,
            currency="USD",
            idempotency_key="key123",
            payment_method={"token": "pm_test"},
            intent="authorize"
        )
        assert req.intent == "authorize"

    def test_intent_capture_immediate_valid(self):
        """Test that capture_immediate intent is valid."""
        req = PaymentRequest(
            amount=100,
            currency="USD",
            idempotency_key="key123",
            payment_method={"token": "pm_test"},
            intent="capture_immediate"
        )
        assert req.intent == "capture_immediate"

    def test_intent_defaults_to_authorize(self):
        """Test that intent defaults to authorize."""
        req = PaymentRequest(
            amount=100,
            currency="USD",
            idempotency_key="key123",
            payment_method={"token": "pm_test"}
        )
        assert req.intent == "authorize"

    def test_metadata_defaults_to_empty_dict(self):
        """Test that metadata defaults to empty dict."""
        req = PaymentRequest(
            amount=100,
            currency="USD",
            idempotency_key="key123",
            payment_method={"token": "pm_test"}
        )
        assert req.metadata == {}

    def test_merchant_id_optional(self):
        """Test that merchant_id is optional."""
        req = PaymentRequest(
            amount=100,
            currency="USD",
            idempotency_key="key123",
            payment_method={"token": "pm_test"}
        )
        assert req.merchant_id is None


class TestPaymentResponseModel:
    """Tests for PaymentResponse model."""

    def test_valid_response(self):
        """Test creating a valid PaymentResponse."""
        resp = PaymentResponse(
            id="pi_test123",
            status="authorized",
            provider_transaction_id="pi_test123"
        )
        assert resp.id == "pi_test123"
        assert resp.status == "authorized"

    def test_status_required(self):
        """Test that status is required."""
        with pytest.raises(ValidationError):
            PaymentResponse(id="test")

    def test_id_can_be_none(self):
        """Test that id can be None."""
        resp = PaymentResponse(id=None, status="failed")
        assert resp.id is None

    def test_mfa_data_optional(self):
        """Test that MFA data is optional."""
        resp = PaymentResponse(id="test", status="authorized")
        assert resp.mfa is None

    def test_response_with_mfa_data(self):
        """Test response with MFA data."""
        mfa = MFAData(
            type="3ds",
            redirect_url="/payments/pi_test/3ds"
        )
        resp = PaymentResponse(
            id="pi_test",
            status="pending_mfa",
            mfa=mfa
        )
        assert resp.mfa is not None
        assert resp.mfa.type == "3ds"

    def test_raw_provider_response_optional(self):
        """Test that raw_provider_response is optional."""
        resp = PaymentResponse(id="test", status="authorized")
        assert resp.raw_provider_response is None


class TestMFADataModel:
    """Tests for MFAData model."""

    def test_type_required(self):
        """Test that type is required."""
        with pytest.raises(ValidationError):
            MFAData(redirect_url="/test")

    def test_valid_mfa_data(self):
        """Test creating valid MFA data."""
        mfa = MFAData(
            type="3ds",
            redirect_url="/payments/test/3ds",
            next_action_type="use_stripe_sdk"
        )
        assert mfa.type == "3ds"
        assert mfa.redirect_url == "/payments/test/3ds"

    def test_with_challenge_data(self):
        """Test MFA data with challenge data."""
        challenge = ThreeDSChallengeData(
            acs_url="https://acs.example.com",
            client_secret="secret_xxx",
            transaction_id="txn_123",
            version="2.0"
        )
        mfa = MFAData(type="3ds", challenge_data=challenge)
        assert mfa.challenge_data is not None
        assert mfa.challenge_data.version == "2.0"


class TestThreeDSChallengeDataModel:
    """Tests for ThreeDSChallengeData model."""

    def test_all_fields_optional(self):
        """Test that all fields are optional."""
        data = ThreeDSChallengeData()
        assert data.acs_url is None
        assert data.client_secret is None
        assert data.transaction_id is None
        assert data.version is None

    def test_with_all_fields(self):
        """Test with all fields populated."""
        data = ThreeDSChallengeData(
            acs_url="https://acs.example.com/challenge",
            client_secret="pi_xxx_secret_yyy",
            transaction_id="txn_abc123",
            version="2.1"
        )
        assert data.acs_url == "https://acs.example.com/challenge"
        assert data.client_secret == "pi_xxx_secret_yyy"


class TestThreeDSChallengeResponseModel:
    """Tests for ThreeDSChallengeResponse model."""

    def test_required_fields(self):
        """Test that payment_id and status are required."""
        with pytest.raises(ValidationError):
            ThreeDSChallengeResponse(status="pending_mfa")

        with pytest.raises(ValidationError):
            ThreeDSChallengeResponse(payment_id="pi_test")

    def test_valid_response(self):
        """Test valid challenge response."""
        resp = ThreeDSChallengeResponse(
            payment_id="pi_test123",
            status="pending_mfa"
        )
        assert resp.payment_id == "pi_test123"
        assert resp.status == "pending_mfa"

    def test_with_mfa_data(self):
        """Test challenge response with MFA data."""
        mfa = MFAData(type="3ds")
        resp = ThreeDSChallengeResponse(
            payment_id="pi_test",
            status="pending_mfa",
            mfa=mfa
        )
        assert resp.mfa is not None


class TestThreeDSCompleteRequestModel:
    """Tests for ThreeDSCompleteRequest model."""

    def test_authentication_result_optional(self):
        """Test that authentication_result is optional."""
        req = ThreeDSCompleteRequest()
        assert req.authentication_result is None

    def test_with_authentication_result(self):
        """Test with authentication result provided."""
        req = ThreeDSCompleteRequest(authentication_result="success")
        assert req.authentication_result == "success"
